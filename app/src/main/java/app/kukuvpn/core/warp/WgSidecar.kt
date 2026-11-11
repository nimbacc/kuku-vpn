package app.kukuvpn.core.warp

import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.core.config.OutboundFactory
import app.kukuvpn.data.Profile
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.PlatformInterface
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * v1.6.5 — the WireGuard UNDERLAY for the chained candidates (Kuku → Psiphon,
 * Kuku → Tor).
 *
 * WHY IT EXISTS: the user's own device proved (via Aether) that the chain
 * "WireGuard underlay → Psiphon" connects instantly on their ISP, while the
 * MASQUE-engine underlay stalls forever at "Connecting". The MASQUE engine
 * (WarpMasqueEngine/warpcore) only speaks MASQUE — both wires are MASQUE
 * (H3/QUIC and H2/TCP) — so a WireGuard underlay was simply impossible.
 * This sidecar adds it: a small TUN-less libbox instance whose only inbound
 * is a local SOCKS5 listener and whose only outbound is the REAL WARP
 * WireGuard tunnel built from a registered wg-family profile. The child
 * cores point their upstream proxy at it, exactly like they pointed at the
 * MASQUE engine's SOCKS.
 *
 * Sandbox-proven mechanics (the same recipe, verified on the psiphon core
 * itself): the core routes EVERY phase — API, server list AND tunnel dials —
 * through UpstreamProxyURL when it is set.
 *
 * Lifecycle: one sidecar at a time, started by the service's chained-underlay
 * helper and torn down with the same discipline as WarpMasqueEngine.
 */
object WgSidecar {

    const val SOCKS_PORT = 2086

    @Volatile private var service: BoxService? = null
    private val mutex = Mutex()

    val isRunning: Boolean get() = service != null

    /**
     * Boots the sidecar over the first [candidates] profile that works.
     * Returns the winning profile, so the caller can log WHICH identity
     * carries the underlay.
     *
     * v1.7.2 ENDPOINT SWEEP: the sidecar used to try each candidate's fixed
     * registered endpoint only — but Iranian ISPs block 162.159.x anycast
     * IPs SELECTIVELY (the v1.0.2 discovery), so the WG underlay died on an
     * endpoint another one would carry. The plain-WARP WG path has swept
     * every anycast IP since v1.2.5; the sidecar now does the same with
     * [endpointPool] (host first, then the pool), which is exactly what the
     * Aether comparison showed: WG DOES carry the chain on this ISP — on the
     * right endpoint. A dead endpoint costs ≤8s (probe call timeout).
     */
    suspend fun boot(
        platform: PlatformInterface,
        candidates: List<Profile>,
        endpointPool: List<String> = emptyList(),
        endpointsPerCandidate: Int = 4,
    ): Result<Profile> =
        mutex.withLock {
            stopInternal()
            var lastErr: Exception? = null
            var tries = 0
            for (candidate in candidates.take(2)) {
                val endpoints = (listOf(candidate.host) + endpointPool).distinct().take(endpointsPerCandidate)
                for (ep in endpoints) {
                    tries++
                    val test = if (ep == candidate.host) candidate else candidate.copy(host = ep)
                    // v1.7.3: the FIRST attempt gets the patient cold probe (the
                    // WG handshake + WARP path setup + first TLS all land in
                    // that one window); the sweep attempts keep the tight cap
                    val started = bootOne(platform, test, cold = tries == 1)
                    if (started.isSuccess) {
                        if (ep != candidate.host) {
                            ServiceBridge.log(
                                "INFO",
                                "WireGuard underlay: registered endpoint was dead — " +
                                    "sweep found a working one ($ep) on attempt $tries"
                            )
                        }
                        return@withLock Result.success(test)
                    }
                    lastErr = started.exceptionOrNull() as? Exception
                    stopInternal() // partial boot — deterministic teardown, next endpoint
                }
            }
            Result.failure(
                lastErr ?: IllegalStateException("no usable WireGuard profile for the underlay")
            )
        }

    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        val s = service
        service = null
        if (s != null) {
            runCatching { s.close() }
        }
    }

    private suspend fun bootOne(platform: PlatformInterface, profile: Profile, cold: Boolean = false): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val config = buildConfig(profile)
                val svc = Libbox.newService(config, platform) // throws on bad config
                svc.start() // throws if the core cannot boot
                service = svc
                // listener evidence: does 127.0.0.1:2086 accept? (≤10s)
                var open = false
                repeat(20) {
                    if (open) return@repeat
                    open = runCatching {
                        java.net.Socket().use { s ->
                            s.connect(
                                java.net.InetSocketAddress("127.0.0.1", SOCKS_PORT),
                                400,
                            )
                            true
                        }
                    }.getOrDefault(false)
                    if (!open) delay(500)
                }
                if (!open) error("underlay listener did not open within 10s")
                // REAL health check: a listener without a working WG
                // handshake must fail HERE (→ next candidate / MASQUE
                // fallback), never inside the psiphon boot where it would
                // masquerade as a psiphon failure. The mixed inbound speaks
                // HTTP CONNECT too — push an actual request through.
                // v1.7.3 THE FIELD FIX (user log: ten probes, every one dying
                // at 8s on "dns: lookup failed for www.cloudflare.com" while
                // the wire itself was never the suspect): the probe URL was a
                // HOSTNAME, so every liveness check first had to push a DoH
                // query (TLS-inside-WireGuard) through the young tunnel — on
                // the user's ISP that extra handshake stalled past the cap
                // and EVERY endpoint looked dead. The probe now dials the IP
                // literal 1.1.1.1 directly: CONNECT 1.1.1.1:443 needs ZERO
                // DNS, so it measures exactly what it should — does the WG
                // wire carry TLS data. Dead endpoint still capped: 8s, the
                // cold first attempt 12s.
                val probe = OkHttpClient.Builder()
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .callTimeout((if (cold) 12 else 8).toLong(), TimeUnit.SECONDS)
                    .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", SOCKS_PORT)))
                    .build()
                probe.newCall(
                    Request.Builder().url("https://1.1.1.1/cdn-cgi/trace").build()
                ).execute().use { resp ->
                    if (!resp.isSuccessful) error("underlay probe failed: HTTP ${resp.code}")
                }
            }
        }

    /**
     * Minimal TUN-less box: local SOCKS in → WireGuard out. DNS rides the
     * tunnel itself — v1.7.3: plain UDP 1.1.1.1 detoured through the
     * WireGuard outbound, NOT the DoH the main core uses. Inside the WARP
     * tunnel the UDP query is already encrypted end-to-end (the ISP sees
     * only WG), so the DoH layer bought nothing and doubled the handshake
     * cost: TLS-inside-WireGuard was exactly what stalled past the probe
     * cap on the user's ISP (the ten × 8s "lookup failed" log). One UDP
     * round trip inside the wire resolves what Psiphon's dials still send
     * as hostnames (API buckets), and the liveness probe itself now needs
     * no DNS at all (1.1.1.1 literal).
     */
    private fun buildConfig(profile: Profile): String = buildJsonObject {
        putJsonObject("log") {
            put("level", "warn")
            put("timestamp", true)
        }
        putJsonObject("dns") {
            put("strategy", "ipv4_only")
            putJsonArray("servers") {
                add(buildJsonObject {
                    put("tag", "dns-remote")
                    put("address", "1.1.1.1")
                    put("detour", "sidecar-out")
                })
            }
            put("final", "dns-remote")
            put("independent_cache", true)
        }
        putJsonArray("inbounds") {
            add(buildJsonObject {
                put("type", "mixed")
                put("tag", "sidecar-in")
                put("listen", "127.0.0.1")
                put("listen_port", SOCKS_PORT)
                put("sniff", true)
            })
        }
        putJsonArray("outbounds") {
            add(OutboundFactory.build(profile, "sidecar-out"))
        }
        putJsonObject("route") {
            put("final", "sidecar-out")
        }
    }.toString()
}
