package app.kukuvpn.core.tor

import android.content.Context
import android.os.SystemClock
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * v1.6.0 — the REAL Tor backend.
 *
 * Binaries (per-ABI, executed as child processes from nativeLibraryDir):
 *  - libtor.so        — tor 0.4.8.16 (kmp-tor packaging, NDK r28). A shared
 *                       library exporting the libtor C API; our tiny
 *                       libtorrun.so shim dlopens it and calls tor_main.
 *  - libtorrun.so     — the shim (third_party/torshim/torrun.c, NDK-built).
 *  - liblyrebird.so   — obfs4 (+ meek_lite) pluggable transport.
 *  - libwebtunnel.so  — webtunnel pluggable transport.
 *
 * tor runs with a plain SOCKS5 inbound on 127.0.0.1:[SOCKS_PORT]; the sing-box
 * config for a tor candidate points its "proxy" outbound there
 * (OutboundFactory maps the tor transports to a socks outbound). Bootstrap
 * progress is watched through tor's own log file ("Bootstrapped N%") — the
 * tunnel is up only at 100% (a real circuit), not earlier.
 *
 * Bridges ("auto" mode): FRESH obfs4 + webtunnel lines bundled as assets
 * (refreshed by CI from the scriptzteam collector at every build; a committed
 * snapshot ships as the fallback) PLUS the two built-in SNOWFLAKE lines —
 * v1.6.8, after the field report that the bundled IP-based bridges were all
 * dead on the user's ISP (tor stuck at 10% for the whole boot cap). obfs4
 * rides liblyrebird.so, webtunnel rides libwebtunnel.so, snowflake rides
 * libsnowflake.so — lines whose transport binary is missing on this ABI are
 * filtered out, and if nothing usable remains the boot FAILS with an explicit
 * error (never a silent fall to WARP).
 *
 * "custom" mode: the user pastes their own Bridge lines verbatim.
 *
 * The chained variant (Kuku → Tor) reaches the tor network THROUGH the WARP
 * engine's SOCKS underlay via torrc `Socks5Proxy` — for networks where tor's
 * own reach is blocked but WARP gets out. Chained runs bridge-less: the WARP
 * underlay itself plays the bridge role.
 *
 * Loop safety: the VPN service already excludes the app's own UID from the
 * tunnel, so the child processes' sockets bypass the TUN.
 */
object TorEngine {

    const val SOCKS_PORT = 1089

    /** fromSubscription marker for both auto-managed Tor profiles. */
    const val SOURCE = "tor"
    const val TRANSPORT_STANDALONE = "tor"
    const val TRANSPORT_CHAINED = "kuku-tor"

    /** Bridge modes (AppSettings.torBridgeMode). */
    const val BRIDGE_MODE_AUTO = "auto"
    const val BRIDGE_MODE_CUSTOM = "custom"
    const val BRIDGE_MODE_NONE = "none"

    private const val TOR_BINARY = "libtor.so"
    private const val RUNNER_BINARY = "libtorrun.so"
    private const val LYREBIRD_BINARY = "liblyrebird.so"
    private const val WEBTUNNEL_BINARY = "libwebtunnel.so"
    private const val SNOWFLAKE_BINARY = "libsnowflake.so"
    private const val BOOT_CAP_MS = 240_000L
    // v1.6.8: a boot that makes NO new Bootstrap progress for this long is
    // dead — the field report showed tor stuck at 10% burning the whole 240s
    // cap on bridges the ISP had already blocked. Fail fast with the last %
    // so the chain can move to the next candidate.
    private const val STALL_CAP_MS = 120_000L
    private const val TICK_MS = 5_000L

    @Volatile private var proc: Process? = null
    @Volatile private var procUpstreamPort: Int? = null
    @Volatile private var tunnelUp: Boolean = false
    @Volatile private var lastProgress: Int = 0
    @Volatile private var lastWarning: String? = null
    private val mutex = Mutex()

    // v1.6.2 — ring buffer of the child's raw output (same as PsiphonEngine):
    // boot failures quote the tail so the real reason is always visible.
    private val tailLock = Any()
    private val outputTail = ArrayDeque<String>()

    private fun noteOutput(line: String) {
        synchronized(tailLock) {
            outputTail.addLast(line)
            while (outputTail.size > 40) outputTail.removeFirst()
        }
    }

    private fun tailQuote(n: Int = 4): String {
        val lines = synchronized(tailLock) { outputTail.toList() }
            .takeLast(n).map { it.trim().take(200) }.filter { it.isNotEmpty() }
        return if (lines.isEmpty()) "" else " — output: ${lines.joinToString(" | ")}"
    }

    val isRunning: Boolean get() = proc != null

    /** Human-readable bootstrap progress for boot-tick log lines. */
    fun lastProgressLabel(): String = "$lastProgress%"

    /**
     * Starts (or reuses) tor and returns once bootstrap reaches 100%. A
     * [Result] instead of a throw so a failed boot is a failed candidate —
     * the service reports the REAL failure to the user (v1.6.0 honesty).
     */
    suspend fun boot(
        context: Context,
        upstreamPort: Int?,
        bridgeMode: String,
        customBridges: String,
        onTick: (Long) -> Unit,
    ): Result<Unit> = mutex.withLock {
        if (proc != null) {
            if (procUpstreamPort == upstreamPort) return@withLock Result.success(Unit) // warm reuse
            stopInternal() // different wiring — cold restart
        }
        val libDir = context.applicationInfo.nativeLibraryDir
        val tor = File(libDir, TOR_BINARY)
        val runner = File(libDir, RUNNER_BINARY)
        if (!runner.exists()) {
            return@withLock Result.failure(IllegalStateException("$RUNNER_BINARY missing from APK"))
        }
        if (!tor.exists()) {
            return@withLock Result.failure(IllegalStateException("$TOR_BINARY missing from APK"))
        }

        // v1.6.2: stale orphaned tor/PT processes (app swept, children lived
        // on) hold the SOCKS port — kill same-UID leftovers before starting.
        val killed = app.kukuvpn.core.psiphon.PsiphonEngine.killStaleProcesses(
            listOf(RUNNER_BINARY, TOR_BINARY, LYREBIRD_BINARY, WEBTUNNEL_BINARY, SNOWFLAKE_BINARY)
        )
        if (killed > 0) {
            ServiceBridge.log("WARN", "tor: killed $killed stale process(es) from an earlier session")
        }

        val dir = File(context.filesDir, "tor").apply { mkdirs() }
        val dataDir = File(dir, "data").apply { mkdirs() }
        val logFile = File(dir, "tor.log")
        val torrc = File(dir, "torrc")

        val pluginObfs4 = File(libDir, LYREBIRD_BINARY)
        val pluginWebtunnel = File(libDir, WEBTUNNEL_BINARY)
        val pluginSnowflake = File(libDir, SNOWFLAKE_BINARY)
        val (pluginLines, bridgeLines) = resolveBridges(context, upstreamPort != null, bridgeMode, customBridges, pluginObfs4, pluginWebtunnel, pluginSnowflake)

        ServiceBridge.log(
            "INFO",
            "tor: ${bridgeLines.size} bridge line(s) (mode $bridgeMode, " +
                "obfs4=${pluginObfs4.exists()}, webtunnel=${pluginWebtunnel.exists()}, " +
                "snowflake=${pluginSnowflake.exists()})"
        )
        if (upstreamPort == null && bridgeLines.isEmpty() && bridgeMode != BRIDGE_MODE_NONE) {
            return@withLock Result.failure(
                IllegalStateException(
                    "no usable tor bridge lines for this build (mode: $bridgeMode) — " +
                        "paste your own bridges or switch the bridge mode"
                )
            )
        }
        torrc.writeText(buildTorrc(upstreamPort, dataDir.absolutePath, logFile.absolutePath, pluginLines, bridgeLines))
        // tor APPENDS to its log file — start every boot from a clean slate so
        // the progress watcher only ever sees THIS boot's Bootstrapped lines
        runCatching { logFile.writeText("") }

        val started = try {
            ProcessBuilder(runner.absolutePath, tor.absolutePath, "-f", torrc.absolutePath)
                .redirectErrorStream(true)
                .start()
        } catch (e: Exception) {
            return@withLock Result.failure(e)
        }
        proc = started
        procUpstreamPort = upstreamPort
        tunnelUp = false
        lastProgress = 0
        lastWarning = null
        outputTail.clear()

        // stdout/stderr pump: captures pre-log-file fatal errors (bad torrc,
        // missing binary permissions) — Bootstrapped progress comes from the
        // LOG FILE (tor's Log directive redirects the default stderr stream)
        Thread {
            try {
                started.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        noteOutput(line)
                        if (line.contains("[warn]", true) || line.contains("[err]", true) ||
                            line.contains("Failed", true)
                        ) {
                            lastWarning = line.trim().take(160)
                        }
                    }
                }
            } catch (_: Exception) {
                // stream torn down by stop() — expected
            }
        }.apply { isDaemon = true }.start()

        val startedAt = SystemClock.elapsedRealtime()
        val deadline = startedAt + BOOT_CAP_MS
        var lastTick = 0L
        var logReadOfs = 0L
        var lastProgressAt = startedAt
        try {
            while (!tunnelUp) {
                if (proc == null || !started.isAlive) {
                    throw IllegalStateException(
                        "tor exited early (progress $lastProgress%)" +
                            (lastWarning?.let { ": $it" } ?: "") + tailQuote()
                    )
                }
                val now = SystemClock.elapsedRealtime()
                // tail the tor log for Bootstrap progress + warnings
                runCatching {
                    if (logFile.exists() && logFile.length() > logReadOfs) {
                        val text = logFile.readText()
                        for (m in Regex("Bootstrapped (\\d+)%").findAll(text)) {
                            val pct = m.groupValues[1].toIntOrNull() ?: continue
                            if (pct > lastProgress) {
                                lastProgress = pct
                                lastProgressAt = now
                                if (pct >= 100) tunnelUp = true
                            }
                        }
                        for (line in text.lines()) {
                            if (line.contains("[warn]") || line.contains("[err]")) {
                                lastWarning = line.trim().take(160)
                            }
                        }
                        logReadOfs = text.length.toLong()
                    }
                }
                if (now > deadline) {
                    throw IllegalStateException(
                        "tor bootstrap timeout (${BOOT_CAP_MS / 1000}s, stuck at $lastProgress%)" +
                            (lastWarning?.let { " — $it" } ?: "") + tailQuote(2)
                    )
                }
                // v1.6.8: no NEW Bootstrap milestone for 2 minutes — the bridge
                // pool is dead/blocked on this network; fail now instead of
                // ticking to the 240s cap (the "6 minutes of nothing" report)
                if (now - lastProgressAt > STALL_CAP_MS) {
                    throw IllegalStateException(
                        "tor bootstrap stuck at $lastProgress% (no progress in ${STALL_CAP_MS / 1000}s) — " +
                            "the bundled bridges look blocked on this network — try the Kuku→Tor " +
                            "chain (WARP underlay), paste fresh bridges (Bridge mode → Custom), " +
                            "or switch the bridge mode" +
                            (lastWarning?.let { " — $it" } ?: "")
                    )
                }
                if (now - lastTick >= TICK_MS) {
                    lastTick = now
                    onTick(now - startedAt)
                }
                delay(500)
            }
            Result.success(Unit)
        } catch (e: kotlinx.coroutines.CancellationException) {
            stopInternal()
            throw e // service teardown must stay a cancellation upstream
        } catch (e: Exception) {
            stopInternal()
            Result.failure(e)
        }
    }

    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        val p = proc
        proc = null
        tunnelUp = false
        if (p != null) {
            runCatching { p.destroy() }
            // tor traps SIGTERM for a graceful stop (and takes its PTs down);
            // never let a wedged process linger
            Thread {
                try {
                    Thread.sleep(2_000)
                    if (p.isAlive) p.destroyForcibly()
                } catch (_: Exception) {
                }
            }.apply { isDaemon = true }.start()
        }
    }

    /**
     * Bridge configuration: returns (ClientTransportPlugin lines, Bridge lines).
     * Transports whose binary is missing on this ABI are dropped together with
     * their bridge lines; other transports (meek_lite/conjure pasted lines)
     * are dropped too — no bundled plugin — and an empty pool is a real error.
     */
    private fun resolveBridges(
        context: Context,
        upstream: Boolean,
        bridgeMode: String,
        customBridges: String,
        pluginObfs4: File,
        pluginWebtunnel: File,
        pluginSnowflake: File,
    ): Pair<List<String>, List<String>> {
        if (upstream) {
            // Kuku → Tor: the WARP underlay plays the bridge role — tor through
            // a clean foreign exit needs no bridges at all.
            return emptyList<String>() to emptyList<String>()
        }
        val plugins = buildList {
            if (pluginObfs4.exists()) add("ClientTransportPlugin obfs4 exec ${pluginObfs4.absolutePath}")
            if (pluginWebtunnel.exists()) add("ClientTransportPlugin webtunnel exec ${pluginWebtunnel.absolutePath}")
            if (pluginSnowflake.exists()) add("ClientTransportPlugin snowflake exec ${pluginSnowflake.absolutePath}")
        }
        val raw: List<String> = when (bridgeMode) {
            BRIDGE_MODE_CUSTOM -> customBridges.lines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
            BRIDGE_MODE_NONE -> return plugins to emptyList()
            else -> // auto: bundled fresh snapshots (CI-refreshed) + builtin snowflake
                (
                    context.assets.open("tor_bridges_obfs4.txt").bufferedReader().readLines() +
                        context.assets.open("tor_bridges_webtunnel.txt").bufferedReader().readLines() +
                        context.assets.open("tor_bridges_snowflake.txt").bufferedReader().readLines()
                    ).map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
        }
        val usable = raw.filter { line ->
            when {
                line.startsWith("obfs4") -> pluginObfs4.exists()
                line.startsWith("webtunnel") -> pluginWebtunnel.exists()
                line.startsWith("snowflake") -> pluginSnowflake.exists()
                // meek_lite / conjure / other pasted lines: no bundled plugin
                else -> false
            }
        }
        return plugins to usable
    }

    /**
     * Lazily registers the two auto-managed Tor candidates (the gool pattern):
     * standalone and Kuku-chained. Both ride 127.0.0.1:[SOCKS_PORT] through a
     * socks outbound; the transport name picks the wiring.
     */
    suspend fun ensureProfiles(context: Context) = withContext(Dispatchers.IO) {
        val store = (context.applicationContext as KukuApp).profileStore
        val have = store.snapshot().map { it.transport }.toSet()
        val missing = buildList {
            if (TRANSPORT_STANDALONE !in have) {
                add(
                    Profile(
                        name = context.getString(R.string.tor_profile_name),
                        type = ProfileType.WIREGUARD,
                        host = "127.0.0.1",
                        port = SOCKS_PORT,
                        transport = TRANSPORT_STANDALONE,
                        fromSubscription = SOURCE,
                    )
                )
            }
            if (TRANSPORT_CHAINED !in have) {
                add(
                    Profile(
                        name = context.getString(R.string.tor_chain_profile_name),
                        type = ProfileType.WIREGUARD,
                        host = "127.0.0.1",
                        port = SOCKS_PORT,
                        transport = TRANSPORT_CHAINED,
                        fromSubscription = SOURCE,
                    )
                )
            }
        }
        if (missing.isNotEmpty()) store.addAll(missing)
    }

    private fun buildTorrc(
        upstreamPort: Int?,
        dataDir: String,
        logPath: String,
        pluginLines: List<String>,
        bridgeLines: List<String>,
    ): String = buildString {
        appendLine("SocksPort 127.0.0.1:$SOCKS_PORT")
        appendLine("DataDirectory $dataDir")
        appendLine("Log notice file $logPath")
        appendLine("AvoidDiskWrites 1")
        appendLine("ClientOnly 1")
        appendLine("SafeLogging 1")
        if (upstreamPort != null) {
            // Kuku → Tor: tor (and its PTs, via TOR_PT_PROXY) reach the tor
            // network through the underlay's socks (MASQUE engine 2085 or the
            // WireGuard sidecar 2086 — the service picks the wire)
            appendLine("Socks5Proxy 127.0.0.1:$upstreamPort")
        }
        pluginLines.forEach { appendLine(it) }
        if (bridgeLines.isNotEmpty()) {
            appendLine("UseBridges 1")
            appendLine("UpdateBridgesFromAuthority 0")
            bridgeLines.forEach { appendLine("Bridge $it") }
        } else if (upstreamPort == null) {
            appendLine("UseBridges 0")
        }
    }
}
