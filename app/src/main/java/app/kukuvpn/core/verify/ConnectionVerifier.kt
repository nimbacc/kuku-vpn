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
                            return Verdict(true, fetchExitIp(proxy), latency)
                        }
                        if (!probe.expect204 && resp.code == 200) {
                            val text = resp.body?.string() ?: ""
                            val ip = text.lineSequence()
                                .firstOrNull { it.startsWith("ip=") }
                                ?.removePrefix("ip=") ?: ""
                            if (ip.isNotBlank()) {
                                val latency = System.currentTimeMillis() - started
                                return Verdict(true, ip, latency)
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

    private fun fetchExitIp(proxy: Proxy): String = runCatching {
        probeClient.newBuilder().proxy(proxy).build().newCall(
            Request.Builder().url("https://1.1.1.1/cdn-cgi/trace").build()
        ).execute().use { resp ->
            resp.body?.string()
                ?.lineSequence()
                ?.firstOrNull { it.startsWith("ip=") }
                ?.removePrefix("ip=") ?: ""
        }
    }.getOrDefault("")
}
