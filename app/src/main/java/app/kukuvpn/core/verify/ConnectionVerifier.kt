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
 *  1. probe     : GET http://connectivitycheck.gstatic.com/generate_204 (expects 204)
 *  2. exit info : GET https://1.1.1.1/cdn-cgi/trace -> "ip=…" (exit IP for the UI)
 */
object ConnectionVerifier {

    private val probeClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .callTimeout(10, TimeUnit.SECONDS)
        .build()

    fun verify(tries: Int = 3): Verdict {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", SingBoxConfigBuilder.PROXY_PORT))
        var lastReason = "unknown"
        repeat(tries) { attempt ->
            val started = System.currentTimeMillis()
            runCatching {
                probeClient.newBuilder().proxy(proxy).build().newCall(
                    Request.Builder().url("http://connectivitycheck.gstatic.com/generate_204").build()
                ).execute().use { resp ->
                    if (resp.code == 204) {
                        val latency = System.currentTimeMillis() - started
                        val exitIp = fetchExitIp(proxy)
                        return Verdict(true, exitIp, latency)
                    }
                    lastReason = "probe HTTP ${resp.code} (attempt ${attempt + 1})"
                }
            }.onFailure { lastReason = "${it.message ?: "probe failed"} (attempt ${attempt + 1})" }
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
