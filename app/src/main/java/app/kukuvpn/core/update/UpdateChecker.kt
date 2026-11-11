package app.kukuvpn.core.update

import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * v1.7.0 — in-app update check against the project's GitHub releases.
 * The GitHub API is plain HTTPS and works through the tunnel or direct;
 * there is no telemetry here — one GET when the user taps "check".
 */
object UpdateChecker {

    private const val API_LATEST = "https://api.github.com/repos/nimbacc/kuku-vpn/releases/latest"

    data class Release(val tag: String, val url: String)

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .callTimeout(15, TimeUnit.SECONDS)
        .build()

    /** Latest release tag + HTML url, or a failure with the real reason. */
    fun latest(): Result<Release> = runCatching {
        client.newCall(
            Request.Builder()
                .url(API_LATEST)
                .header("Accept", "application/vnd.github+json")
                .build()
        ).execute().use { resp ->
            require(resp.isSuccessful) { "GitHub API ${resp.code}" }
            val body = resp.body?.string() ?: error("empty response")
            // hand-rolled minimal parse — a JSON dependency just for two fields
            // is not worth it (kotlinx has no DOM parser on the JVM here)
            val tag = Regex("\"tag_name\"\\s*:\\s*\"([^\"]+)\"").find(body)?.groupValues?.get(1)
                ?: error("no tag_name in response")
            val url = Regex("\"html_url\"\\s*:\\s*\"([^\"]+)\"").find(body)?.groupValues?.get(1)
                ?: "https://github.com/nimbacc/kuku-vpn/releases"
            Release(tag.removePrefix("v"), url)
        }
    }

    /** True when [remote] is newer than [local] (both "1.2.3" style). */
    fun isNewer(remote: String, local: String): Boolean {
        val r = remote.split('.').map { it.trim().toIntOrNull() ?: 0 }
        val l = local.split('.').map { it.trim().toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(r.size, l.size)) {
            val rv = r.getOrElse(i) { 0 }
            val lv = l.getOrElse(i) { 0 }
            if (rv != lv) return rv > lv
        }
        return false
    }
}
