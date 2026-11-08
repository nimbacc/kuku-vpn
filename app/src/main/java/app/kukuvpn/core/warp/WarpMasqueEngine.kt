package app.kukuvpn.core.warp

import android.content.Context
import android.os.SystemClock
import io.nekohasekai.warpcore.Warpcore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Thin Kotlin facade over the [Warpcore] gomobile binding — the Aether-style
 * "connects anywhere" engine: Cloudflare WARP over MASQUE.
 *
 * Note: the engine lives in the COMBINED aar (libbox + warpcore are bound in a
 * single gomobile invocation, see third_party/corebind/doc.go), so the java
 * package is io.nekohasekai.warpcore.
 *
 * MASQUE carries the WireGuard stream inside HTTP/3 (QUIC, UDP 443) or — on
 * networks where the ISP filters all UDP — HTTP/2 over plain TCP 443, which
 * is indistinguishable from ordinary HTTPS. This is the path that works when
 * the classic WireGuard-on-UDP sweep times out.
 *
 * Lifecycle (all calls are blocking, run them off the main thread):
 *  1. [ensureRegistered] — once per install; creates the CF device identity.
 *  2. [boot]             — the ONLY entry point to bring the tunnel up since
 *     v1.2.4: single-flight, mode-aware, and shared by the app-open prewarm
 *     and the connect flow. Returns only after the tunnel is verified with a
 *     real round-trip and the local SOCKS port accepts; sing-box then routes
 *     the profile through 127.0.0.1:[SOCKS_PORT].
 *  3. [stop]             — always before switching H3/H2 or tearing down.
 */
object WarpMasqueEngine {

    /** Local SOCKS5 port the engine exposes to sing-box. */
    const val SOCKS_PORT = 2085

    @Volatile private var started = false

    /** Transport mode of the RUNNING engine (null = not running / unknown). */
    @Volatile private var runningUseHttp2: Boolean? = null

    /** Serializes boots; prewarm and connect share one boot per mode. */
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
     * Single-flight engine boot (v1.2.4).
     *
     * BUG: the app-open prewarm and the connect flow both booted the engine;
     * the Go side rejects a second Start() while one is in flight ("engine is
     * already running"), so a tap during the prewarm sweep burned MASQUE
     * candidates on that error. Now every caller goes through here: the
     * second caller awaits the first, then REUSES the running engine when the
     * mode matches; an H2↔H3 mismatch stops and boots the requested mode.
     *
     * The engine's endpoint sweep is hard-bounded on the Go side and RACED
     * in waves of 4 (v1.2.5): ≤~20s worst case, ~2-5s typical, hard cap 45s.
     * [onTick] fires every ~5s meanwhile so the log shows progress instead
     * of a silent minute — the "frozen on booting engine" report.
     */
    suspend fun boot(
        context: Context,
        useHttp2: Boolean,
        onTick: ((Long) -> Unit)? = null,
    ): Result<Unit> = bootMutex.withLock {
        if (isRunning() && runningUseHttp2 == useHttp2) {
            return@withLock Result.success(Unit) // warm engine, right mode
        }
        runCatching {
            withContext(Dispatchers.IO) {
                ensureRegistered(context)
                stop() // wrong mode or stale instance — deterministic teardown
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
                    start(context, useHttp2)
                } finally {
                    watchdog?.cancel()
                }
            }
        }.onFailure { runningUseHttp2 = null }
    }

    /**
     * App-open prewarm (v1.2.4): boot the engine for the chain-leading mode
     * (MASQUE H2 over TCP 443 — the most survivable path) in the background
     * so the FIRST tap finds a warm, already-validated tunnel instead of
     * paying the cold endpoint sweep. Safe to call unconditionally: boot()
     * is single-flight and a no-op when the engine already runs in that mode.
     */
    fun prewarm(context: Context) {
        engineScope.launch {
            runCatching { boot(context, useHttp2 = true) }
            // silent: the connect flow retries with full logging + fallback
        }
    }

    fun start(context: Context, useHttp2: Boolean) {
        stop() // deterministic teardown of any previous instance
        // gomobile binds Go int as Java long
        Warpcore.start(configDir(context), SOCKS_PORT.toLong(), useHttp2)
        started = true
        runningUseHttp2 = useHttp2
    }

    /** Tears the engine down; safe to call repeatedly. */
    fun stop() {
        runCatching { Warpcore.stop() }
        started = false
        runningUseHttp2 = null
    }

    fun isRunning(): Boolean =
        runCatching { Warpcore.isRunning() }.getOrDefault(false) && started
}
