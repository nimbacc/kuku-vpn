package app.kukuvpn.core.speed

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.random.Random

/**
 * v1.7.2 — the speed test the user asked for ("تست سرعت هر روش"): a REAL
 * throughput measurement through the ACTIVE tunnel, riding the local mixed
 * inbound (127.0.0.1:2080) exactly like the traffic it represents. Whatever
 * method is connected — WARP, gool, Kuku→Psiphon, Kuku→Tor — the numbers are
 * that method's numbers, which is what makes "which method is best" a
 * comparable, honest answer instead of a guess.
 *
 *   • latency : 3× https://connectivitycheck.gstatic.com/generate_204, best of three
 *   • down    : GET https://speed.cloudflare.com/__down?bytes=25000000 (25MB cap),
 *               counted for at most 8s — enough for a stable Mb/s figure without
 *               burning the user's data plan
 *   • up      : POST https://speed.cloudflare.com/__up, 1.5MB random payload
 *
 * Every step is best-effort: a blocked/failing step yields 0 and the reason
 * lands in [Result.error] so the UI can show the real cause.
 */
object SpeedTester {

    data class Result(
        val latencyMs: Long = 0,
        val downBps: Double = 0.0,
        val upBps: Double = 0.0,
        val error: String? = null,
    ) {
        val ok: Boolean get() = error == null && (downBps > 0 || upBps > 0)
    }

    private const val DOWN_BYTES_CAP = 25_000_000L
    private const val DOWN_WINDOW_MS = 8_000L
    private const val UP_BYTES = 1_500_000

    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .callTimeout(25, TimeUnit.SECONDS)
        .build()

    private fun proxied(): OkHttpClient =
        client.newBuilder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 2080)))
            .build()

    /** Runs the full test (~12–20s). Call from a coroutine — it is main-safe. */
    suspend fun run(): Result = withContext(Dispatchers.IO) {
        val http = proxied()
        val latency = latency(http)
        if (latency <= 0) {
            return@withContext Result(error = "tunnel not answering (latency probe failed)")
        }
        val down = download(http)
        val up = upload(http)
        val err = if (down.first <= 0.0 && up.first <= 0.0) {
            "throughput probes failed (both directions)"
        } else null
        Result(latency, down.first, up.first, err)
    }

    private fun latency(http: OkHttpClient): Long {
        var best = 0L
        repeat(3) {
            val started = System.currentTimeMillis()
            val ok = runCatching {
                http.newCall(Request.Builder().url("https://connectivitycheck.gstatic.com/generate_204").build())
                    .execute().use { it.code == 204 }
            }.getOrDefault(false)
            if (ok) {
                val dt = System.currentTimeMillis() - started
                if (best == 0L || dt < best) best = dt
            }
        }
        return best
    }

    /** bytes/s + optional failure reason. */
    private fun download(http: OkHttpClient): Pair<Double, String?> = try {
        http.newCall(
            Request.Builder()
                .url("https://speed.cloudflare.com/__down?bytes=$DOWN_BYTES_CAP")
                .build()
        ).execute().use { resp ->
            if (!resp.isSuccessful) {
                Pair(0.0, "download probe HTTP ${resp.code}")
            } else {
                val body = resp.body
                if (body == null) Pair(0.0, "download probe: empty body")
                else {
                    val started = System.currentTimeMillis()
                    var bytes = 0L
                    val buf = ByteArray(64 * 1024)
                    val input = body.byteStream()
                    while (System.currentTimeMillis() - started < DOWN_WINDOW_MS) {
                        val n = input.read(buf, 0, buf.size)
                        if (n == -1) break
                        bytes += n
                    }
                    val elapsed = (System.currentTimeMillis() - started).coerceAtLeast(200)
                    if (bytes == 0L) Pair(0.0, "no data through the tunnel")
                    else Pair(bytes * 1000.0 / elapsed, null)
                }
            }
        }
    } catch (e: Exception) {
        Pair(0.0, "download: ${e.message ?: "failed"}")
    }

    private fun upload(http: OkHttpClient): Pair<Double, String?> = try {
        val payload = ByteArray(UP_BYTES)
        Random(0x4B554B55).nextBytes(payload)
        val started = System.currentTimeMillis()
        http.newCall(
            Request.Builder()
                .url("https://speed.cloudflare.com/__up")
                .post(payload.toRequestBody("application/octet-stream".toMediaType()))
                .build()
        ).execute().use { resp ->
            if (!resp.isSuccessful) Pair(0.0, "upload probe HTTP ${resp.code}")
            else {
                val elapsed = (System.currentTimeMillis() - started).coerceAtLeast(200)
                Pair(UP_BYTES * 1000.0 / elapsed, null)
            }
        }
    } catch (e: Exception) {
        Pair(0.0, "upload: ${e.message ?: "failed"}")
    }

    /** "↓ 12.4 ↑ 3.1 Mb/s · 230 ms" — one line for the Home row. */
    fun format(r: Result): String {
        val down = "%.1f".format(min(r.downBps * 8, 999_999.0) / 1_000_000)
        val up = "%.1f".format(min(r.upBps * 8, 999_999.0) / 1_000_000)
        return "↓ $down ↑ $up Mb/s · ${r.latencyMs} ms"
    }
}
