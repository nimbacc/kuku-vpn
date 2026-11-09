package app.kukuvpn.core.warp

import android.content.Context
import android.os.SystemClock
import io.nekohasekai.warpcore.Warpcore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.File

/**
 * Thin Kotlin facade over the [Warpcore] gomobile binding — the Aether-style
 * "connects anywhere" engine: Cloudflare WARP over MASQUE.
 *
 * Note: the engine lives in the COMBINED aar (libbox + warpcore are bound in a
 * single gomobile invocation, see third_party/corebind/doc.go), so the java
 * package is io.nekohasekai.warpcore.
 *
 * v1.2.7: the Go engine RACES BOTH wire formats at once (MASQUE over
 * HTTP/3, UDP 443 — and MASQUE over HTTP/2, plain TCP 443), each with its
 * own endpoint sweep, and the first one to prove a real round-trip wins.
 * On networks where the ISP filters UDP the TCP sweep wins in ~2-5s; on
 * UDP-friendly networks UDP wins. There is no H2-vs-H3 guesswork and no
 * serial fallback walk to sit through — [boot] is mode-free.
 *
 * Lifecycle (all calls are blocking, run them off the main thread):
 *  1. [ensureRegistered] — once per install; creates the CF device identity.
 *  2. [boot]             — the ONLY entry point to bring the tunnel up:
 *     single-flight, shared by the app-open prewarm and the connect flow.
 *     Returns only after the tunnel is verified with a real round-trip and
 *     the local SOCKS port accepts; sing-box then routes the profile through
 *     127.0.0.1:[SOCKS_PORT].
 *  3. [stop]             — tears the engine down; safe to call repeatedly.
 */
object WarpMasqueEngine {

    /** Local SOCKS5 port the engine exposes to sing-box. */
    const val SOCKS_PORT = 2085

    /**
     * v1.4.0 FLUX turbo: extra engine paths the background sweep boots after
     * the primary is live (socks ports SOCKS_PORT+1, SOCKS_PORT+2). The
     * sing-box urltest group ("proxy-fast", see SingBoxConfigBuilder) then
     * hot-swaps traffic onto whichever path currently answers fastest —
     * the FLUX-style always-on-the-fastest-edge rotation, plus a free
     * resilience upgrade when an edge degrades mid-session.
     * Sandbox-proven (v1.4.0): Cloudflare accepts concurrent long-lived
     * MASQUE sessions for the SAME device identity; the primary tunnel
     * carried traffic across interleaved rounds while an extra stayed live,
     * and a sing-box urltest over 2085/2086 + a deliberately dead 2087
     * passed 24/24 real requests (first-member fallback + dead-member
     * tolerance + live rotation all verified).
     */
    val FLUX_SOCKS_PORTS = listOf(SOCKS_PORT + 1, SOCKS_PORT + 2)

    /**
     * v1.2.7 hard cap on a full boot, enforced on the Kotlin side as a
     * second net under the Go sweep's own 45s cap. The first "eternal
     * Connecting" field report was a Go-side deadlock that outlived every
     * Go-side deadline; if anything wedges again, the connect flow now
     * tears the engine down from outside and fails loudly instead of
     * hanging forever.
     */
    private const val BOOT_HARD_CAP_MS = 60_000L

    @Volatile private var started = false

    /** Serializes boots; prewarm and connect share one boot. */
    private val bootMutex = Mutex()

    private val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun configDir(context: Context): String =
        File(context.filesDir, "warp_masque").absolutePath

    /** Creates the Cloudflare device identity on first use (idempotent). */
    fun ensureRegistered(context: Context) {
        val dir = configDir(context)
        val has = runCatching { Warpcore.hasConfig(dir) }.getOrDefault(false)
        if (!has) {
            Warpcore.register(dir) // blocking network call, ~2s, throws on failure
        }
    }

    /**
     * Single-flight engine boot.
     *
     * BUG (v1.2.4): the app-open prewarm and the connect flow both booted the
     * engine; the Go side rejects a second Start() while one is in flight
     * ("engine is already running"), so a tap during the prewarm sweep burned
     * MASQUE candidates on that error. Now every caller goes through here: the
     * second caller awaits the first, then reuses the running engine.
     *
     * BUG (v1.2.6): the reuse was MODE-GATED — a boot for the other transport
     * STOPPED the warm engine and re-swept. The SOCKS outbound is
     * transport-agnostic, so ANY warm engine is reused.
     *
     * BUG (v1.2.7): the tick watchdog used to start only AFTER the boot mutex
     * was acquired, so a connect tap landing during the app-open prewarm sat
     * SILENT for the whole prewarm boot — the "booting… then nothing, no
     * ticks" field report. The watchdog now covers the entire call: mutex
     * wait, registration and the Go sweep. And [start] is wrapped in a hard
     * [BOOT_HARD_CAP_MS] cap that tears the engine down from outside if the
     * Go side ever wedges (the v1.2.6 gVisor close-deadlock did exactly that).
     *
     * v1.3.0: [scanMode] ("turbo" | "balanced" | "thorough" | "stealth" |
     * "ironclad") tunes the Go sweep's budgets — see warpcore.scanParams.
     */
    suspend fun boot(
        context: Context,
        scanMode: String = "balanced",
        onTick: ((Long) -> Unit)? = null,
    ): Result<Unit> {
        val t0 = SystemClock.elapsedRealtime()
        val watchdog = onTick?.let { tick ->
            engineScope.launch {
                while (isActive) {
                    delay(5_000)
                    tick(SystemClock.elapsedRealtime() - t0)
                }
            }
        }
        try {
            return bootMutex.withLock {
                if (isRunning()) {
                    return@withLock Result.success(Unit) // warm engine — any mode wins
                }
                runCatching {
                    withContext(Dispatchers.IO) {
                        ensureRegistered(context)
                        stop() // stale instance — deterministic teardown, then a cold boot
                        start(context, scanMode)
                    }
                }
            }
        } finally {
            watchdog?.cancel()
        }
    }

    /**
     * App-open prewarm (v1.2.4): boot the engine in the background so the
     * FIRST tap finds a warm, already-validated tunnel instead of paying
     * the cold endpoint sweep. Since v1.2.7 the boot races both transports
     * (TCP 443 + UDP 443), so no mode decision is needed here.
     * Safe to call unconditionally: boot() is single-flight and reuses the
     * engine whatever mode it raced.
     */
    fun prewarm(context: Context, scanMode: String = "balanced") {
        engineScope.launch {
            runCatching { boot(context, scanMode) }
            // silent: the connect flow retries with full logging + fallback
        }
    }

    private suspend fun start(context: Context, scanMode: String) {
        stop() // deterministic teardown of any previous instance
        var bootError: Exception? = null
        val job = engineScope.launch {
            try {
                // v1.2.7: the engine RACES TCP-443/H2 and UDP-443/H3 sweeps
                // in parallel; v1.3.0 passes the user's scan mode which tunes
                // the sweep budgets (gomobile binds Go int as Java long)
                Warpcore.startAutoWithMode(configDir(context), SOCKS_PORT.toLong(), scanMode)
            } catch (e: Exception) {
                bootError = e // isolated job: no outer cancellation to honor
            }
        }
        try {
            withTimeout(BOOT_HARD_CAP_MS) { job.join() }
        } catch (e: TimeoutCancellationException) {
            // the Go sweep outlived every internal deadline (or wedged) —
            // tear it down from outside and fail loudly; the connect flow
            // moves to the next candidate instead of hanging forever
            stop()
            throw IllegalStateException("WARP engine boot exceeded ${BOOT_HARD_CAP_MS / 1000}s hard cap")
        }
        bootError?.let { throw it }
        started = true
    }

    /** Tears the engine down; safe to call repeatedly. */
    fun stop() {
        runCatching { Warpcore.stop() }
        started = false
    }

    fun isRunning(): Boolean =
        runCatching { Warpcore.isRunning() }.getOrDefault(false) && started

    /**
     * v1.4.0 FLUX turbo: how many background paths are currently live
     * (0..FLUX_SOCKS_PORTS.size). Extras boot in the background AFTER the
     * engine reports ready, so this is 0 right after boot and grows as the
     * sweep validates tunnels — logs only, nothing waits on it.
     */
    fun fluxPathCount(): Int =
        runCatching { Warpcore.extraCount().toInt() }.getOrDefault(0)
}
