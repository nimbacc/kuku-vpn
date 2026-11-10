package app.kukuvpn.core.psiphon

import android.content.Context
import android.os.SystemClock
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.Base64

/**
 * v1.5.0 — the Psiphon backend (the method the user asked for).
 *
 * The Psiphon tunnel core ships as a per-ABI ELF in the APK's jniLibs
 * (`libpsiphon.so`, built by CI with Go 1.22 from the pinned fork — the core
 * does not compile on modern Go). It runs as a CHILD PROCESS of the app and
 * exposes a plain SOCKS5 proxy on 127.0.0.1:[SOCKS_PORT]; the sing-box config
 * for a psiphon candidate simply points its "proxy" outbound there
 * (OutboundFactory maps the psiphon transports to a socks outbound).
 *
 * Loop safety: the VPN service already excludes the app's own UID from the
 * tunnel (addDisallowedApplication(self)), so the child process's sockets —
 * same UID — bypass the TUN and never loop back into it.
 *
 * Bootstrap data: the PUBLIC Psiphon server-list distribution values (the
 * same propagation/sponsor IDs and the official signed server-list URL that
 * open clients embed). The server list is fetched fresh on every cold boot
 * and signature-verified by the core itself; no secrets in this file.
 *
 * The chained variant (Kuku → Psiphon) reaches the Psiphon network THROUGH
 * the WARP engine's SOCKS underlay (UpstreamProxyURL) — for networks where
 * Psiphon's own fronting is blocked but WARP gets out.
 *
 * v1.6.2 — "psiphon core exited early" diagnostics (the user's device died
 * instantly while the same binary+config ran fine in the sandbox, and the
 * old pump DISCARDED every non-JSON line, hiding the cause):
 *  - every output line of the child (JSON notice or Go log/panic) lands in a
 *    ring buffer; boot failures carry the tail so the REAL reason is visible
 *    on the Home card and in the Logs page;
 *  - stale orphaned cores from a previous session (Android does not kill
 *    child processes when the app is swept) are SIGKILLed before boot — an
 *    orphan holding the SOCKS port makes every fresh core die at bind;
 *  - the SOCKS/HTTP ports are probed before start: occupied → explicit
 *    error naming the port, never a mystery exit;
 *  - one automatic retry with a CLEAN data store when the core dies at
 *    startup twice in a row (stale bolt/ledger locks after a hard kill).
 */
object PsiphonEngine {

    const val SOCKS_PORT = 1087
    const val HTTP_PORT = 1088

    /** fromSubscription marker for both auto-managed Psiphon profiles. */
    const val SOURCE = "psiphon"
    const val TRANSPORT_STANDALONE = "psiphon"
    const val TRANSPORT_CHAINED = "kuku-psiphon"

    private const val BINARY = "libpsiphon.so"
    // v1.6.0: raised from 90s — Psiphon's link-selection on a filtered Iranian
    // network legitimately takes 2–3 minutes; the old cap declared honest
    // attempts dead and the chain silently fell to WARP (the "it's fake" bug).
    private const val BOOT_CAP_MS = 240_000L
    private const val TICK_MS = 5_000L

    // public Psiphon bootstrap values (server-list distribution)
    private const val PROPAGATION = "FFFFFFFFFFFFFFFF"
    private const val SPONSOR = "FFFFFFFFFFFFFFFF"
    private const val SERVER_LIST_URL =
        "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
    private val SERVER_LIST_KEY = listOf(
        "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH",
        "5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5",
        "OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot",
        "LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6",
        "/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G",
        "stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O",
        "geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8",
        "u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz",
        "31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal",
        "KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
    ).joinToString("")

    @Volatile private var proc: Process? = null
    @Volatile private var procUpstream: Boolean = false
    @Volatile private var tunnelUp: Boolean = false
    @Volatile private var lastExitRegion: String = ""
    private val mutex = Mutex()

    // v1.6.2 — ring buffer of the child's RAW output (every line: JSON notices,
    // Go logs, panics). Boot failures quote the tail so the real reason is
    // never hidden again.
    private val tailLock = Any()
    private val outputTail = ArrayDeque<String>()

    private fun noteOutput(line: String) {
        synchronized(tailLock) {
            outputTail.addLast(line)
            while (outputTail.size > 40) outputTail.removeFirst()
        }
    }

    private fun tailSnapshot(): List<String> = synchronized(tailLock) { outputTail.toList() }

    /** The last [n] output lines, trimmed — the boot-failure evidence. */
    private fun tailQuote(n: Int = 4): String {
        val lines = tailSnapshot().takeLast(n)
            .map { it.trim().take(200) }
            .filter { it.isNotEmpty() }
        return if (lines.isEmpty()) "" else " — output: ${lines.joinToString(" | ")}"
    }

    val isRunning: Boolean get() = proc != null

    /** The exit region the core last reported via ConnectedServerRegion. */
    val exitRegion: String get() = lastExitRegion

    /**
     * Starts (or reuses) the Psiphon core and returns once its tunnel is
     * established ("Tunnels" count >= 1). [region] is the requested egress
     * country (ISO 3166-1 alpha-2, e.g. "US", "GB"; "" = best/any — the
     * core's own default). A [Result] instead of a throw so a failed boot is
     * just a failed candidate, never a dead chain.
     */
    suspend fun boot(
        context: Context,
        upstream: Boolean,
        region: String,
        onTick: (Long) -> Unit,
    ): Result<Unit> = mutex.withLock {
        if (proc != null) {
            if (procUpstream == upstream) return@withLock Result.success(Unit) // warm reuse
            stopInternal() // different wiring — cold restart
        }
        val bin = File(context.applicationInfo.nativeLibraryDir, BINARY)
        if (!bin.exists()) {
            return@withLock Result.failure(
                IllegalStateException(
                    "$BINARY missing for this device ABI (${android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "?"})"
                )
            )
        }

        // v1.6.2: an orphaned core from a previous session (app swept while
        // the child lived on) holds the SOCKS port forever — every new core
        // then dies instantly at bind. Kill same-UID stragglers first.
        val killed = killStaleProcesses(listOf(BINARY))
        if (killed > 0) {
            app.kukuvpn.bg.ServiceBridge.log(
                "WARN", "psiphon: killed $killed stale core process(es) from an earlier session"
            )
        }
        // explicit port probe — a busy port is a NAMED error, not a mystery exit
        for (port in intArrayOf(SOCKS_PORT, HTTP_PORT)) {
            if (portBusy(port)) {
                return@withLock Result.failure(
                    IllegalStateException(
                        "psiphon cannot start: TCP port $port is occupied by another process " +
                            "on this device — reboot the phone or free the port, then retry"
                    )
                )
            }
        }

        val dir = File(context.filesDir, "psiphon").apply { mkdirs() }
        val dataDir = File(dir, "data").apply { mkdirs() }
        val cfg = File(dir, "config.json")
        cfg.writeText(buildConfig(upstream, dataDir.absolutePath, region))

        var attempt = 0
        while (true) {
            attempt++
            outputTail.clear()
            val started = try {
                ProcessBuilder(bin.absolutePath, "-config", cfg.absolutePath)
                    .redirectErrorStream(true)
                    .start()
            } catch (e: Exception) {
                return@withLock Result.failure(
                    IllegalStateException("psiphon core failed to start: ${e.message}", e)
                )
            }
            proc = started
            procUpstream = upstream
            tunnelUp = false
            lastExitRegion = ""

            // output pump: JSON notices drive the tunnel state; EVERY line
            // (including Go logs/panics on stderr) lands in the ring buffer
            Thread {
                try {
                    started.inputStream.bufferedReader().useLines { lines ->
                        for (line in lines) {
                            noteOutput(line)
                            if (!line.startsWith("{")) continue
                            val obj = runCatching {
                                Json.parseToJsonElement(line).jsonObject
                            }.getOrNull() ?: continue
                            when (obj["noticeType"]?.jsonPrimitive?.content) {
                                "Tunnels" -> {
                                    val count = obj["data"]?.jsonObject
                                        ?.get("count")?.jsonPrimitive?.intOrNull ?: 0
                                    if (count >= 1) tunnelUp = true
                                }
                                "ConnectedServerRegion" -> {
                                    val regionName = obj["data"]?.jsonObject
                                        ?.get("serverRegion")?.jsonPrimitive?.content ?: "?"
                                    lastExitRegion = regionName
                                    app.kukuvpn.bg.ServiceBridge.log(
                                        "INFO", "psiphon exit region: $regionName"
                                    )
                                }
                                "AvailableEgressRegions" -> {
                                    val regions = obj["data"]?.jsonObject
                                        ?.get("regions")?.jsonArray
                                        ?.map { it.jsonPrimitive.content } ?: emptyList()
                                    if (regions.isNotEmpty()) {
                                        app.kukuvpn.bg.ServiceBridge.log(
                                            "INFO", "psiphon egress regions now: ${regions.joinToString(",")}"
                                        )
                                    }
                                }
                                else -> Unit
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
            var failure: Exception? = null
            try {
                while (!tunnelUp) {
                    if (proc == null || !started.isAlive) {
                        throw IllegalStateException(
                            "psiphon core exited immediately (attempt $attempt)" + tailQuote()
                        )
                    }
                    val now = SystemClock.elapsedRealtime()
                    if (now > deadline) {
                        throw IllegalStateException(
                            "psiphon boot timeout (${BOOT_CAP_MS / 1000}s)" +
                                (lastExitRegion.takeIf { it.isNotBlank() }?.let { " — last region: $it" } ?: "") +
                                tailQuote(2)
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

            // v1.6.2: an instant death is very often a stale data store (a
            // bolt/ledger lock from a hard-killed previous core). Wipe it and
            // give the core ONE clean retry before reporting failure.
            val earlyDeath = failure?.message?.contains("exited immediately") == true
            if (earlyDeath && attempt == 1) {
                stopInternal()
                app.kukuvpn.bg.ServiceBridge.log(
                    "WARN",
                    "psiphon core died at startup — wiping the data store and retrying once"
                )
                dataDir.deleteRecursively()
                dataDir.mkdirs()
                continue
            }
            stopInternal()
            return@withLock Result.failure(failure ?: IllegalStateException("psiphon boot failed"))
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
            // the core traps SIGTERM for a graceful stop; never let it linger
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
     * v1.6.2 — SIGKILL same-UID leftovers whose /proc cmdline matches any of
     * [needles]. Android orphans child processes when the app is swept; an
     * orphaned core keeps the SOCKS port bound and kills every future boot
     * instantly at bind. Returns how many processes were killed.
     */
    internal fun killStaleProcesses(needles: List<String>): Int {
        val self = android.os.Process.myPid()
        var killed = 0
        val procDir = File("/proc")
        val pids = procDir.listFiles()?.mapNotNull { it.name.toIntOrNull() } ?: return 0
        for (pid in pids) {
            if (pid == self) continue
            val cmd = runCatching {
                File("/proc/$pid/cmdline").readBytes().toString(Charsets.UTF_8)
            }.getOrNull() ?: continue
            if (needles.any { cmd.contains(it) }) {
                val killedOne = runCatching { android.os.Process.killProcess(pid) }.isSuccess
                try {
                    Thread.sleep(150)
                } catch (_: InterruptedException) {
                }
                runCatching { android.os.Process.sendSignal(pid, 9) }
                if (killedOne) killed++
            }
        }
        return killed
    }

    /** True when [port] cannot be bound on loopback right now. */
    private fun portBusy(port: Int): Boolean = try {
        ServerSocket().use {
            it.bind(InetSocketAddress("127.0.0.1", port), 1)
            false
        }
    } catch (_: Exception) {
        true
    }

    /**
     * Lazily registers the two auto-managed Psiphon candidates (the gool
     * pattern): standalone and Kuku-chained. Both ride 127.0.0.1:[SOCKS_PORT]
     * through a socks outbound; the transport name picks the wiring.
     */
    suspend fun ensureProfiles(context: Context) = withContext(Dispatchers.IO) {
        val store = (context.applicationContext as KukuApp).profileStore
        val have = store.snapshot().map { it.transport }.toSet()
        val missing = buildList {
            if (TRANSPORT_STANDALONE !in have) {
                add(
                    Profile(
                        name = context.getString(R.string.psiphon_profile_name),
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
                        name = context.getString(R.string.psiphon_chain_profile_name),
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

    private fun buildConfig(upstream: Boolean, dataDir: String, egressRegion: String): String = buildJsonObject {
        put("PropagationChannelId", PROPAGATION)
        put("SponsorId", SPONSOR)
        put("ClientPlatform", "android")
        put("ClientVersion", "1")
        if (egressRegion.isNotBlank() && egressRegion != "auto") {
            // ISO 3166-1 alpha-2 ("US", "GB", …) — the core selects servers
            // egressing from that country only (v1.6.0 exit-country picker)
            put("EgressRegion", egressRegion.uppercase())
        }
        putJsonArray("RemoteServerListURLs") {
            add(
                buildJsonObject {
                    put(
                        "URL",
                        Base64.getEncoder().encodeToString(SERVER_LIST_URL.toByteArray())
                    )
                }
            )
        }
        put("RemoteServerListSignaturePublicKey", SERVER_LIST_KEY)
        put("DataStoreDirectory", dataDir)
        put("LocalSocksProxyPort", SOCKS_PORT)
        put("LocalHttpProxyPort", HTTP_PORT)
        // in-proxy (device-coordinated tunnels) off — keep the footprint minimal
        put("InproxyTunnelProtocolPreferProbability", 0.0)
        put("InproxyTunnelProtocolSelectionProbability", 0.0)
        if (upstream) {
            put("UpstreamProxyURL", "socks5://127.0.0.1:${WarpMasqueEngine.SOCKS_PORT}")
        }
    }.toString()
}
