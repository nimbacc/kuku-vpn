package app.kukuvpn.core.verify

import app.kukuvpn.core.config.SingBoxConfigBuilder
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

data class Verdict(
    val ok: Boolean,
    val exitIp: String = "",
    val exitCountry: String = "", // v1.7.0: ISO-3166 alpha-2 from the Cloudflare trace ("loc=DE")
    val latencyMs: Long = 0,
    val reason: String = "",
)

/**
 * The RIX-style promise: "Connected" only counts when a real request has
 * passed through the tunnel and its answer has come back.
 *
 * The probe rides the local mixed inbound (127.0.0.1:2080) — if the core is
 * up but the tunnel is dead, the request times out and the profile FAILS.
 *
 * IMPORTANT (bug history): the probe used to be
 * `http://connectivitycheck.gstatic.com/generate_204` — plain HTTP. Android 9+
 * forbids cleartext by default (network security policy), so OkHttp refused
 * the request LOCALLY before any byte left the app and every candidate failed
 * with "CLEARTEXT communication not permitted", even on a healthy tunnel.
 * All probes are HTTPS now (verified live: gstatic answers 204, the trace
 * answers 200 with ip=…).
 *
 *  1. probe     : GET https://connectivitycheck.gstatic.com/generate_204 (expects 204)
 *                 fallback GET https://www.cloudflare.com/cdn-cgi/trace
 *                 (expects 200 + "ip=" line — also yields the exit IP directly)
 *  2. exit info : GET https://1.1.1.1/cdn-cgi/trace -> "ip=…" (after a 204 probe)
 */
object ConnectionVerifier {

    private data class Probe(val url: String, val expect204: Boolean)

    private val PROBES = listOf(
        Probe("https://connectivitycheck.gstatic.com/generate_204", expect204 = true),
        Probe("https://www.cloudflare.com/cdn-cgi/trace", expect204 = false),
    )

    private val probeClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .callTimeout(6, TimeUnit.SECONDS)
        .build()

    /** Tighter client for endpoint sweeps — a dead endpoint must cost ≈5s, not ≈13s. */
    private val sweepClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .callTimeout(5, TimeUnit.SECONDS)
        .build()

    fun verify(tries: Int = 2): Verdict {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", SingBoxConfigBuilder.PROXY_PORT))
        var lastReason = "unknown"
        repeat(tries) { attempt ->
            for (probe in PROBES) {
                val started = System.currentTimeMillis()
                try {
                    probeClient.newBuilder().proxy(proxy).build().newCall(
                        Request.Builder().url(probe.url).build()
                    ).execute().use { resp ->
                        if (probe.expect204 && resp.code == 204) {
                            val latency = System.currentTimeMillis() - started
                            // v1.7.2: the exit IP/country resolve ASYNC in the
                            // service after ACTIVE — no extra network on the
                            // verdict path, "Connected" shows instantly
                            return Verdict(true, latencyMs = latency)
                        }
                        if (!probe.expect204 && resp.code == 200) {
                            val text = resp.body?.string() ?: ""
                            val ip = text.lineSequence()
                                .firstOrNull { it.startsWith("ip=") }
                                ?.removePrefix("ip=") ?: ""
                            if (ip.isNotBlank()) {
                                val country = text.lineSequence()
                                    .firstOrNull { it.startsWith("loc=") }
                                    ?.removePrefix("loc=") ?: ""
                                val latency = System.currentTimeMillis() - started
                                return Verdict(true, ip, country, latency)
                            }
                        }
                        lastReason = "probe ${resp.code} ${probe.url.removePrefix("https://").substringBefore('/')} (attempt ${attempt + 1})"
                    }
                } catch (e: Exception) {
                    lastReason = "${e.message ?: "probe failed"} (attempt ${attempt + 1})"
                }
            }
        }
        return Verdict(false, reason = lastReason)
    }

    /** One shot check used while a tunnel is running (menu → test again). */
    fun quickCheck(): Boolean = verify(tries = 1).ok

    /**
     * Single-probe, single-attempt check for the endpoint sweep. Every dead
     * endpoint costs one DNS-failure cycle through the core (~5s worst case
     * with [sweepClient]) instead of two full probes (~13s) — across a
     * 5-endpoint sweep that is the difference between "connecting" for 25s
     * and for 65s.
     */
    fun verifySweep(): Verdict = singleProbe(sweepClient)

    /**
     * Cold-start verification (v1.2.3) for the FIRST endpoint of a session.
     *
     * BUG: the very first request through a freshly booted engine also pays
     * for the WARP/MASQUE path setup and the first TLS handshakes; field logs
     * show a warm probe at 3856ms — barely under the 5s sweep cap — so on a
     * cold ISP route the first attempt tipped over 5s, the candidate was
     * declared dead, and the whole fallback chain burned minutes on dead
     * endpoints ("first connect never works; after killing and reopening the
     * app it connects"). Two attempts with an 8s cap: a warm path still
     * passes on the first try in ~4s, a cold one gets the grace it needs.
     */
    fun verifyCold(): Verdict {
        val coldClient = probeClient.newBuilder()
            .connectTimeout(6, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .callTimeout(8, TimeUnit.SECONDS)
            .build()
        var last = Verdict(false, reason = "unknown")
        repeat(2) { attempt ->
            last = singleProbe(coldClient, attemptTag = " (cold attempt ${attempt + 1})")
            if (last.ok) return last
        }
        return last
    }

    private fun singleProbe(client: OkHttpClient, attemptTag: String = ""): Verdict {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", SingBoxConfigBuilder.PROXY_PORT))
        val started = System.currentTimeMillis()
        return try {
            client.newBuilder().proxy(proxy).build().newCall(
                Request.Builder().url(PROBES[0].url).build()
            ).execute().use { resp ->
                if (resp.code == 204) {
                    // v1.7.2: exit info resolves ASYNC after ACTIVE (see verify)
                    Verdict(true, latencyMs = System.currentTimeMillis() - started)
                } else {
                    Verdict(false, reason = "probe ${resp.code} ${PROBES[0].url.removePrefix("https://").substringBefore('/')}$attemptTag")
                }
            }
        } catch (e: Exception) {
            Verdict(false, reason = "${e.message ?: "probe failed"}$attemptTag")
        }
    }


    /**
     * v1.7.4: ip + country through a SOURCE CHAIN, now METHOD-AWARE. Field
     * history proves why this keeps needing sources: v1.7.2's single trace →
     * v1.7.3's ipwho.is → ip-api.com → ipinfo.io chain STILL came home flagless
     * ("باز هنگام وصل شدن با تور پرچم نمیاره") — a Tor exit can be challenged or
     * rate-limited by every one of those at once. The country lookups now query
     * the KNOWN exit IP (not "who am I") and lead with get.geojs.io, which has
     * no Cloudflare in front of it and is the classic Tor-user geo answer:
     *
     *   ip  : [tor? geojs first, else CF traces first] + check.torproject.org
     *   cc  : geojs ?ip= → ip-api.com/<ip> (plain HTTP) → ipinfo.io/<ip> → ipwho.is/<ip>
     *
     * Never throws; blank-blank means "no source answered" — and for Psiphon
     * candidates the service falls back to the core's own ConnectedServerRegion.
     */
    private val exitClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .callTimeout(10, TimeUnit.SECONDS)
        .build()

    fun fetchExitInfo(proxy: Proxy, viaTor: Boolean = false): Pair<String, String> {
        val client = exitClient.newBuilder().proxy(proxy).build()
        var ip = ""
        var cc = ""
        // --- combined sources (ip + country in one answer) ---
        val combined = if (viaTor) listOf(
            "https://get.geojs.io/v1/ip/geo.json",      // Tor-friendly, no CF
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
        ) else listOf(
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://get.geojs.io/v1/ip/geo.json",
        )
        for (url in combined) {
            val parsed = runCatching {
                client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching "" to ""
                    val body = resp.body?.string() ?: return@runCatching "" to ""
                    val traceIp = body.lineSequence()
                        .firstOrNull { it.startsWith("ip=") }?.removePrefix("ip=") ?: ""
                    val traceLoc = body.lineSequence()
                        .firstOrNull { it.startsWith("loc=") }?.removePrefix("loc=") ?: ""
                    if (traceIp.isNotBlank()) return@runCatching traceIp to traceLoc
                    // geojs JSON: "ip":"…","country_code":"XX"
                    val jIp = Regex("\"ip\"\\s*:\\s*\"([^\"]+)\"").find(body)?.groupValues?.get(1) ?: ""
                    val jCc = Regex("\"country_code\"\\s*:\\s*\"([A-Z]{2})\"").find(body)?.groupValues?.get(1) ?: ""
                    jIp to jCc
                }
            }.getOrDefault("" to "")
            if (parsed.first.isNotBlank()) {
                ip = parsed.first
                if (parsed.second.isNotBlank()) return ip to parsed.second
                break // have the IP; country comes from the per-IP chain below
            }
        }
        // --- ip-only fallback: the Tor Project's own check API (designed for exits) ---
        if (ip.isBlank()) {
            ip = runCatching {
                client.newCall(Request.Builder().url("https://check.torproject.org/api/ip").build())
                    .execute().use { resp ->
                        if (!resp.isSuccessful) return@runCatching ""
                        Regex("\"IP\"\\s*:\\s*\"([^\"]+)\"").find(resp.body?.string() ?: "")
                            ?.groupValues?.get(1) ?: ""
                    }
            }.getOrDefault("")
            if (ip.isBlank()) return "" to ""
        }
        // --- country-only chain, each source asked about the KNOWN exit IP ---
        if (cc.isBlank()) {
            cc = listOf(
                "https://get.geojs.io/v1/ip/country.json?ip=$ip" to
                    Regex("\"(?:country_code|country)\"\\s*:\\s*\"([A-Z]{2})\""),
                // plain HTTP, no CDN in front — answers where Cloudflare challenges
                "http://ip-api.com/json/$ip?fields=countryCode" to
                    Regex("\"countryCode\"\\s*:\\s*\"([A-Z]{2})\""),
                "https://ipinfo.io/$ip/json" to Regex("\"country\"\\s*:\\s*\"([A-Z]{2})\""),
                "https://ipwho.is/$ip" to Regex("\"country_code\"\\s*:\\s*\"([A-Z]{2})\""),
            ).firstNotNullOfOrNull { (url, rx) ->
                runCatching {
                    client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                        if (!resp.isSuccessful) return@runCatching null
                        rx.find(resp.body?.string() ?: "")?.groupValues?.get(1)
                    }
                }.getOrNull()
            } ?: ""
        }
        return ip to cc
    }
}
