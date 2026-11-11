package app.kukuvpn.core.tor

import android.content.Context
import android.os.SystemClock
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

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
 * v1.6.9 — the bridge DECAY, root-caused end to end: the scriptzteam
 * collector STOPPED UPDATING on 2026-07-29, and on the wire only ~11% of its
 * July obfs4 lines still accepted a TCP connection (verified from a clean
 * vantage) — random slices (v1.6.8) still drew from a mostly-dead pool, so
 * tor kept cycling corpses into the stall cap. This build adds the pieces
 * v1.6.8 could not have:
 *  1. TCP LIVENESS PRE-TEST (device side): every bundled obfs4/webtunnel line
 *     is dial-tested from the device (3 s timeout, parallel) BEFORE tor
 *     starts; dead lines are dropped and counted in the log. Snowflake lines
 *     (and anything unparsable) pass through untouched.
 *  2. FRESH FETCH: if fewer than [FRESH_FETCH_MIN_ALIVE] lines survive, the
 *     app quietly boots the WARP engine, pulls FRESH obfs4 + webtunnel lines
 *     (official bridges.torproject.org distribution + the collector dump)
 *     THROUGH that underlay, stops WARP again, TCP-tests the fetched lines
 *     on the direct path tor will actually use, and puts the survivors FIRST
 *     in torrc (newest distribution = least blocked). Budget: 90 s total,
 *     failures degrade to the bundled pool — never an exception.
 *  3. ROTATION RETRY: a stalled/timeout boot gets ONE more attempt on a
 *     rotated slice of the alive pool — with the v1.6.8 stall cap the retry
 *     is cheap (≤2 min), and a torrc with the same dead-at-handshake lines
 *     never recovers on its own.
 * CI ships only TCP-alive bridges too (official moat lines first + a random
 * slice of the alive collector pool).
 *
 * The chained variant (Kuku → Tor) reaches the tor network THROUGH the
 * engine's SOCKS underlay via torrc `Socks5Proxy` — for networks where tor's
 * own reach is blocked but WARP gets out. Chained runs bridge-less: the
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

    // v1.6.9 bridge pipeline budgets
    private const val TEST_TIMEOUT_MS = 3_000
    private const val TEST_CONCURRENCY = 32
    private const val FRESH_FETCH_MIN_ALIVE = 5
    private const val FETCH_BUDGET_MS = 90_000L
    private const val TORRC_BRIDGE_CAP = 40
    private const val ROTATION_SLICE = 40
    private const val BOOT_CAP_RETRY_MS = 180_000L

    // fresh-bridge sources (pulled through the WARP underlay when needed)
    private val FRESH_SOURCES = listOf(
        "https://bridges.torproject.org/bridges?transport=obfs4",
        "https://bridges.torproject.org/bridges?transport=webtunnel",
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-obfs4",
        "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/bridges-webtunnel",
    )
    private const val FRESH_SAMPLE_OBFS4 = 60
    private const val FRESH_SAMPLE_WEBTUNNEL = 30

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
        val (pluginLines, rawBridgeLines) = resolveBridges(context, upstreamPort != null, bridgeMode, customBridges, pluginObfs4, pluginWebtunnel, pluginSnowflake)

        ServiceBridge.log(
            "INFO",
            "tor: ${rawBridgeLines.size} bridge line(s) bundled (mode $bridgeMode, " +
                "obfs4=${pluginObfs4.exists()}, webtunnel=${pluginWebtunnel.exists()}, " +
                "snowflake=${pluginSnowflake.exists()})"
        )
        if (upstreamPort == null && rawBridgeLines.isEmpty() && bridgeMode != BRIDGE_MODE_NONE) {
            return@withLock Result.failure(
                IllegalStateException(
                    "no usable tor bridge lines for this build (mode: $bridgeMode) — " +
                        "paste your own bridges or switch the bridge mode"
                )
            )
        }

        // v1.6.9 — bridge pipeline: TCP liveness pre-test, fresh fetch through
        // the WARP underlay when the shipped snapshot has died on this device,
        // then a rotation retry when a boot stalls/times out. Chained boots
        // (upstreamPort != null) need no bridges at all.
        val pool: List<String> = if (upstreamPort != null || rawBridgeLines.isEmpty()) {
            rawBridgeLines
        } else {
            prepareBridgePool(context, rawBridgeLines, bridgeMode)
        }
        if (upstreamPort == null && pool.isEmpty() && bridgeMode != BRIDGE_MODE_NONE) {
            return@withLock Result.failure(
                IllegalStateException(
                    "tor bridges: every bundled bridge line failed the TCP liveness test " +
                        "and no fresh lines could be fetched (mode: $bridgeMode) — " +
                        "switch to the Kuku→Tor chain (it reaches the tor network through " +
                        "the underlay and needs no bridges), paste your own bridges, or retry later"
                )
            )
        }

        // boot attempts: (1) the head of the alive pool, (2) a rotated slice
        var rotation = 0
        var failure: Exception? = null
        while (true) {
            val slice = sliceFor(pool, rotation)
            if (rotation > 0) {
                ServiceBridge.log(
                    "WARN",
                    "tor: retrying bootstrap with a different ${slice.size} of ${pool.size} " +
                        "alive bridges (attempt ${rotation + 1})"
                )
            }
            torrc.writeText(buildTorrc(upstreamPort, dataDir.absolutePath, logFile.absolutePath, pluginLines, slice))
            // tor APPENDS to its log file — start every attempt from a clean
            // slate so the progress watcher only ever sees THIS attempt
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
            val cap = if (rotation == 0) BOOT_CAP_MS else BOOT_CAP_RETRY_MS
            val deadline = startedAt + cap
            var lastTick = 0L
            var logReadOfs = 0L
            var lastProgressAt = startedAt
            var stalledOrTimedOut = false
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
                        stalledOrTimedOut = true
                        throw IllegalStateException(
                            "tor bootstrap timeout (${cap / 1000}s, stuck at $lastProgress%)" +
                                (lastWarning?.let { " — $it" } ?: "") + tailQuote(2)
                        )
                    }
                    // v1.6.8: no NEW Bootstrap milestone for 2 minutes — the
                    // current bridge slice is dead/blocked on this network;
                    // fail now instead of ticking to the cap
                    if (now - lastProgressAt > STALL_CAP_MS) {
                        stalledOrTimedOut = true
                        throw IllegalStateException(
                            "tor bootstrap stuck at $lastProgress% (no progress in ${STALL_CAP_MS / 1000}s) — " +
                                "this bridge slice looks blocked on this network" +
                                (lastWarning?.let { " — $it" } ?: "")
                        )
                    }
                    if (now - lastTick >= TICK_MS) {
                        lastTick = now
                        onTick(now - startedAt)
                    }
                    delay(500)
                }
                return@withLock Result.success(Unit)
            } catch (e: kotlinx.coroutines.CancellationException) {
                stopInternal()
                throw e // service teardown must stay a cancellation upstream
            } catch (e: Exception) {
                failure = e
            }
            stopInternal()

            // v1.6.9 rotation: a STALL or TIMEOUT gets ONE retry on a rotated
            // slice of the alive pool (only when the pool is big enough for a
            // meaningfully different slice). Early exits (torrc error, process
            // death) never help from a retry. The v1.6.8 stall cap keeps the
            // retry cheap (≤2 min).
            if (stalledOrTimedOut && pool.size > ROTATION_SLICE && rotation == 0) {
                rotation++
                continue
            }
            return@withLock Result.failure(
                failure ?: IllegalStateException("tor boot failed")
            )
        }
        // unreachable: every path in the retry loop returns or continues —
        // but the withLock lambda must be typed Result<Unit>, and Kotlin
        // types a trailing `while (true)` as Unit without this line.
        @Suppress("UNREACHABLE_CODE")
        return@withLock Result.failure(IllegalStateException("tor boot loop exited unexpectedly"))
    }

    fun stop() {
        stopInternal()
    }

    /* --------------------- v1.6.9 bridge pipeline ------------------------- */

    /**
     * A parsed dial target for a bridge line. obfs4 dials the literal
     * host:port; webtunnel dials the url= fronting domain (the address field
     * is a documentation-IPv6 PLACEHOLDER by design — never dial it).
     * Snowflake lines (broker found via domain fronting by the client binary)
     * and any other unparsable line return null → passthrough, never tested.
     */
    private data class DialTarget(val line: String, val host: String, val port: Int)

    /**
     * Runs the v1.6.9 pool preparation for a standalone boot:
     *  1. TCP-test every bundled obfs4/webtunnel line (parallel, [TEST_TIMEOUT_MS]);
     *  2. fewer than [FRESH_FETCH_MIN_ALIVE] alive + auto mode → fetch fresh
     *     lines through the WARP underlay and test those on the direct path;
     *  3. fresh lines first (newest distribution = least blocked), bundled
     *     alive lines after.
     */
    private suspend fun prepareBridgePool(
        context: Context,
        rawLines: List<String>,
        bridgeMode: String,
    ): List<String> = withContext(Dispatchers.IO) {
        val pipelineStart = SystemClock.elapsedRealtime()
        val (bundledAlive, bundledDead) = livenessFilter(rawLines)
        ServiceBridge.log(
            "INFO",
            "tor bridges: bundled ${rawLines.size} → ${bundledAlive.size} TCP-alive, $bundledDead dead (dropped)"
        )

        val pool = bundledAlive.toMutableList()
        if (bundledAlive.size < FRESH_FETCH_MIN_ALIVE && bridgeMode == BRIDGE_MODE_AUTO) {
            ServiceBridge.log(
                "INFO",
                "tor bridges: fewer than $FRESH_FETCH_MIN_ALIVE alive — fetching fresh lines via the WARP underlay"
            )
            val fresh = fetchFreshBridgesViaWarp(context)
            if (fresh.isNotEmpty()) {
                pool.addAll(0, fresh) // fresh first
                ServiceBridge.log("INFO", "tor bridges: +${fresh.size} fresh alive line(s) added (WARP-fetched)")
            } else {
                ServiceBridge.log("WARN", "tor bridges: fresh fetch produced no alive lines — continuing on bundled only")
            }
        }
        ServiceBridge.log(
            "INFO",
            "tor bridges: pool ready (${pool.size} alive, ${SystemClock.elapsedRealtime() - pipelineStart}ms)"
        )
        pool
    }

    /**
     * TCP-dial-tests every parseable bridge line; dead lines are dropped.
     * Unparseable lines (snowflake, vanilla, meek_lite pastes…) pass through
     * UNTESTED — we never drop what we cannot evaluate.
     * Returns (kept lines, dropped count).
     */
    private suspend fun livenessFilter(lines: List<String>): Pair<List<String>, Int> =
        coroutineScope {
            val sem = Semaphore(TEST_CONCURRENCY)
            val results = lines.map { line ->
                async(Dispatchers.IO) {
                    val target = parseDialTarget(line)
                    if (target == null) {
                        line to true // unparseable — passthrough
                    } else {
                        sem.withPermit { line to tcpAlive(target.host, target.port) }
                    }
                }
            }.awaitAll()
            val kept = results.filter { it.second }.map { it.first }
            Pair(kept, lines.size - kept.size)
        }

    /** Plain TCP connect — the cheap liveness oracle (a dead bridge cannot accept). */
    private fun tcpAlive(host: String, port: Int): Boolean = try {
        Socket().use { s ->
            s.connect(InetSocketAddress(host, port), TEST_TIMEOUT_MS)
            true
        }
    } catch (_: Exception) {
        false
    }

    private fun parseDialTarget(line: String): DialTarget? {
        val t = line.trim()
        return when {
            t.startsWith("obfs4") -> {
                val addr = t.split(" ").getOrNull(1) ?: return null
                val host = addr.substringBeforeLast(':').trim('[', ']')
                val port = addr.substringAfterLast(':').toIntOrNull() ?: return null
                if (host.isEmpty()) return null
                DialTarget(t, host, port)
            }
            t.startsWith("webtunnel") -> {
                val m = Regex("url=https?://([^/:]+)(?::(\\d+))?").find(t) ?: return null
                DialTarget(t, m.groupValues[1], m.groupValues[2].toIntOrNull() ?: 443)
            }
            else -> null // snowflake / vanilla / meek_lite / conjure — leave untouched
        }
    }

    /**
     * Pulls FRESH bridge lines through a temporary WARP underlay: boots the
     * engine (unless already warm), fetches the official moat distribution
     * and the collector dump over its SOCKS, then stops the engine again —
     * standalone tor owns the exit, the underlay was only a delivery van.
     * Fetched lines are even-sampled and TCP-tested on the DIRECT path (the
     * one tor will use). Hard budget: [FETCH_BUDGET_MS], failures degrade to
     * an empty list — never an exception into the boot flow.
     */
    private suspend fun fetchFreshBridgesViaWarp(context: Context): List<String> =
        withContext(Dispatchers.IO) {
            val fresh = try {
                val t0 = SystemClock.elapsedRealtime()
                withTimeoutOrNull(FETCH_BUDGET_MS) {
                    val booted = WarpMasqueEngine.boot(context).isSuccess
                    if (!booted) return@withTimeoutOrNull emptyList<String>()
                    val socks = Proxy(
                        Proxy.Type.SOCKS,
                        InetSocketAddress("127.0.0.1", WarpMasqueEngine.SOCKS_PORT)
                    )
                    val lines = mutableListOf<String>()
                    for (url in FRESH_SOURCES) {
                        // keep a 15s reserve inside the budget for the tail
                        if (SystemClock.elapsedRealtime() - t0 > FETCH_BUDGET_MS - 15_000L) break
                        runCatching {
                            (URL(url).openConnection(socks) as HttpURLConnection).apply {
                                connectTimeout = 20_000
                                readTimeout = 25_000
                                setRequestProperty("User-Agent", "Mozilla/5.0")
                                inputStream.bufferedReader().useLines { l -> lines.addAll(l) }
                            }
                        }
                        if (lines.size > 12_000) break
                    }
                    sampleFreshLines(lines)
                } ?: emptyList()
            } finally {
                // the van leaves: standalone tor dials directly, the WARP
                // engine must not sit warm on the device's network
                WarpMasqueEngine.stop()
            }
            if (fresh.isEmpty()) return@withContext emptyList()
            val (alive, dead) = livenessFilter(fresh)
            ServiceBridge.log(
                "INFO",
                "tor bridges: fresh ${fresh.size} → ${alive.size} TCP-alive on the direct path, $dead dead"
            )
            alive
        }

    /**
     * Cleans + parses fetched raw text (HTML pages or plain dumps): strips
     * HTML residue, keeps only well-formed obfs4/webtunnel lines, drops
     * garbage addresses (private/reserved/known-anycast), dedupes, samples
     * (order-preserving: moat lines arrive first and stay first).
     */
    private fun sampleFreshLines(raw: List<String>): List<String> {
        val obfs4Seen = mutableSetOf<String>()
        val wtSeen = mutableSetOf<String>()
        val obfs4 = mutableListOf<String>()
        val wt = mutableListOf<String>()
        for (rawLine in raw) {
            val line = rawLine.replace(Regex("<[^>]+>"), "").replace("&amp;", "&").trim()
            when {
                line.startsWith("obfs4 ") && " cert=" in line -> {
                    val fp = Regex("\\b([0-9A-F]{40})\\b").find(line)?.groupValues?.get(1) ?: continue
                    if (fp in obfs4Seen) continue
                    val addr = line.split(" ").getOrNull(1) ?: continue
                    val host = addr.substringBeforeLast(':').trim('[', ']')
                    val port = addr.substringAfterLast(':').toIntOrNull() ?: continue
                    if (host.isEmpty() || port !in 1..65535 || isGarbageIp(host)) continue
                    obfs4Seen.add(fp)
                    obfs4.add(line)
                }
                line.startsWith("webtunnel ") -> {
                    val url = Regex("url=(\\S+)").find(line)?.groupValues?.get(1) ?: continue
                    if (url in wtSeen) continue
                    wtSeen.add(url)
                    wt.add(line)
                }
            }
        }
        return evenlySample(obfs4, FRESH_SAMPLE_OBFS4) + evenlySample(wt, FRESH_SAMPLE_WEBTUNNEL)
    }

    /** The same garbage-IP rule the CI snapshot builder applies. */
    private fun isGarbageIp(ip: String): Boolean = try {
        val o = java.net.InetAddress.getByName(ip)
        o.isSiteLocalAddress || o.isLoopbackAddress || o.isLinkLocalAddress ||
            o.isAnyLocalAddress || o.isMulticastAddress ||
            o.hostAddress.startsWith("1.0.0.") || o.hostAddress.startsWith("1.1.1.") ||
            o.hostAddress.startsWith("8.8.8.") || o.hostAddress.startsWith("8.8.4.")
    } catch (_: Exception) {
        true
    }

    /** Order-preserving even sample (the CI sampler's rule, mirrored). */
    private fun evenlySample(items: List<String>, n: Int): List<String> {
        if (items.size <= n) return items
        val step = items.size / n.toDouble()
        return List(n) { items[(it * step).toInt()] }
    }

    /** The torrc bridge slice for this rotation offset (pool keeps fresh lines first). */
    private fun sliceFor(pool: List<String>, rotation: Int): List<String> {
        val capped = pool.take(TORRC_BRIDGE_CAP + rotation * ROTATION_SLICE)
        if (rotation == 0 || capped.size <= ROTATION_SLICE) return capped.take(TORRC_BRIDGE_CAP)
        // rotate: start from an offset so the retry gets meaningfully new lines
        val offset = (rotation * ROTATION_SLICE) % pool.size.coerceAtLeast(1)
        val rotated = pool.drop(offset) + pool.take(offset)
        return rotated.take(TORRC_BRIDGE_CAP)
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
