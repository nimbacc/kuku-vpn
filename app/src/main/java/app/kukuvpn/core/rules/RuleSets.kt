package app.kukuvpn.core.rules

import app.kukuvpn.data.AppSettings
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * v1.7.0 — local sing-box rule-sets for the routing features the user asked
 * for (Iranian bypass + ad block).
 *
 * WHY local, not remote rule_sets: sing-box downloads a `remote` rule_set at
 * service start and a failed download FAILS THE WHOLE TUNNEL. That is the one
 * thing this app must never do to the user again (the v1.2.2/v1.6.3 lessons).
 * So Kuku fetches the .srs files itself (jsDelivr CDN first — reachable in
 * Iran far more reliably than raw.githubusercontent — then raw as fallback),
 * caches them under filesDir/rules, and hands the config builder only the
 * files that are READY. If nothing is ready, the tunnel simply runs without
 * the bypass — a routing nicety must never cost the connection itself.
 *
 * Sources (canonical sing-box rule-set releases, upstream SagerNet):
 *   geosite-category-ir.srs      — Iranian domains
 *   geoip-ir.srs                 — Iranian IP ranges
 *   geosite-category-ads-all.srs — ad/tracker domains
 */
object RuleSets {

    const val TAG_GEOSITE_IR = "geosite-ir"
    const val TAG_GEOIP_IR = "geoip-ir"
    const val TAG_GEOSITE_ADS = "geosite-ads"

    /** What the caller needs to know: ready tag→path + tags that failed. */
    data class Result(val ready: Map<String, String>, val failed: List<String>)

    private data class Def(val tag: String, val fileName: String, val urls: List<String>)

    private val DEFS = listOf(
        Def(
            TAG_GEOSITE_IR, "geosite-category-ir.srs", listOf(
                "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ir.srs",
                "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ir.srs",
            )
        ),
        Def(
            TAG_GEOIP_IR, "geoip-ir.srs", listOf(
                "https://cdn.jsdelivr.net/gh/SagerNet/sing-geoip@rule-set/geoip-ir.srs",
                "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs",
            )
        ),
        Def(
            TAG_GEOSITE_ADS, "geosite-category-ads-all.srs", listOf(
                "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-category-ads-all.srs",
                "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
            )
        ),
    )

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .build()

    /** A sane rule file is way over 1 KB; anything smaller is a broken partial. */
    private const val MIN_SRS_BYTES = 1024L

    /**
     * Fetch/collect every rule-set the requested features need. Never throws —
     * failures degrade to "rule not applied" (returned in [Result.failed]).
     */
    fun ensure(context: android.content.Context, settings: AppSettings): Result {
        val wanted = mutableListOf<String>()
        if (settings.irBypass) wanted += listOf(TAG_GEOSITE_IR, TAG_GEOIP_IR)
        if (settings.adBlock) wanted += TAG_GEOSITE_ADS
        if (wanted.isEmpty()) return Result(emptyMap(), emptyList())

        val dir = File(context.filesDir, "rules").apply { mkdirs() }
        val ready = mutableMapOf<String, String>()
        val failed = mutableListOf<String>()
        for (tag in wanted) {
            val def = DEFS.firstOrNull { it.tag == tag } ?: continue
            val target = File(dir, def.fileName)
            if (!isUsable(target) && !download(def, target)) {
                failed += tag
                continue
            }
            ready[tag] = target.absolutePath
        }
        return Result(ready, failed)
    }

    private fun isUsable(f: File) = f.isFile && f.length() >= MIN_SRS_BYTES

    private fun download(def: Def, target: File): Boolean {
        for (url in def.urls) {
            try {
                client.newCall(Request.Builder().url(url).build()).execute().use { resp ->
                    if (!resp.isSuccessful) return@use
                    val bytes = resp.body?.bytes() ?: return@use
                    if (bytes.size < MIN_SRS_BYTES) return@use
                    // write-then-rename so a killed download never leaves a
                    // truncated .srs that would poison every later connect
                    val tmp = File(target.absolutePath + ".part")
                    tmp.writeBytes(bytes)
                    if (!tmp.renameTo(target)) {
                        tmp.copyTo(target, overwrite = true)
                        tmp.delete()
                    }
                    return true
                }
            } catch (ignored: Exception) {
                // next mirror
            }
        }
        return isUsable(target)
    }
}
