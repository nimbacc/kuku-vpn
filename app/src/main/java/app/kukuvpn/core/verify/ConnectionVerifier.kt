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
     * v1.7.2: ip + country through a SOURCE CHAIN. The single 1.1.1.1 trace
     * was blind on some exits — Cloudflare serves cdn-cgi to a Tor exit with
     * a challenge (no ip= line at all), which is exactly the user's report
     * ("Tor connects but the IP field is empty"). Chain:
     *   1. https://1.1.1.1/cdn-cgi/trace          → ip= + loc=
     *   2. https://www.cloudflare.com/cdn-cgi/trace → ip= + loc= (different edge path)
     *   3. https://check.torproject.org/api/ip    → {"IP":"…","IsTor":true} — Tor-friendly, IP only
     *   4. country only: https://ipwho.is/        → "country_code":"XX" (when steps 1-3 gave an IP but no loc)
     * Never throws; blank-blank means "no source answered".
     */
    fun fetchExitInfo(proxy: Proxy): Pair<String, String> {
        val client = probeClient.newBuilder().proxy(proxy).build()
        for (url in listOf(
            "https://1.1.1.1/cdn-cgi/trace",
            "https://www.cloudflare.com/cdn-cgi/trace",
        )) {
            val (ip, loc) = runCatching {
                client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching "" to ""
                    val lines = resp.body?.string()?.lineSequence() ?: emptySequence()
                    val ip = lines.firstOrNull { it.startsWith("ip=") }?.removePrefix("ip=") ?: ""
                    val loc = lines.firstOrNull { it.startsWith("loc=") }?.removePrefix("loc=") ?: ""
                    ip to loc
                }
            }.getOrDefault("" to "")
            if (ip.isNotBlank()) return ip to loc
        }
        // Tor-friendly source: the Tor Project's own check API answers from
        // Tor exits where Cloudflare will not.
        val torIp = runCatching {
            client.newCall(Request.Builder().url("https://check.torproject.org/api/ip").build())
                .execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching ""
                    Regex("\"IP\"\\s*:\\s*\"([^\"]+)\"").find(resp.body?.string() ?: "")
                        ?.groupValues?.get(1) ?: ""
                }
        }.getOrDefault("")
        if (torIp.isBlank()) return "" to ""
        // best-effort country for the flag — failure costs the flag, not the IP
        val cc = runCatching {
            client.newCall(Request.Builder().url("https://ipwho.is/").build()).execute().use { resp ->
                if (!resp.isSuccessful) return@runCatching ""
                Regex("\"country_code\"\\s*:\\s*\"([A-Z]{2})\"").find(resp.body?.string() ?: "")
                    ?.groupValues?.get(1) ?: ""
            }
        }.getOrDefault("")
        return torIp to cc
    }
}
