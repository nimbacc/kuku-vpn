package app.kukuvpn.core.warp

import android.content.Context
import android.os.Build
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Lifecycle of the automatic free-WARP setup, surfaced on the Home empty card. */
enum class WarpSetup { IDLE, REGISTERING, READY, FAILED }

/**
 * Gives the app a working server out of the box, the same model used by
 * WARP-based clients (e.g. aether): register a per-install device with
 * Cloudflare's free WARP service and store the result as a regular WIREGUARD
 * profile, so one tap on Connect is enough — no subscription, no config.
 *
 * Flow (identical to wgcf/aether): POST https://api.cloudflareclient.com/v0a2158/reg
 * with a client-minted X25519 public key; the response carries the Cloudflare
 * peer key, the endpoint, the tunnel addresses and the `client_id` whose three
 * bytes become the WireGuard "reserved" field.
 */
object WarpRegistrar {

    /** Marker stored in Profile.fromSubscription so we can find our profile again. */
    const val WARP_SOURCE = "warp"

    private const val API = "https://api.cloudflareclient.com/v0a2158/reg"
    private const val DEFAULT_PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    private const val DEFAULT_HOST = "engage.cloudflareclient.com"
    private const val DEFAULT_PORT = 2408

    private val json = Json { ignoreUnknownKeys = true }
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private val _status = MutableStateFlow(WarpSetup.IDLE)
    val status: StateFlow<WarpSetup> = _status

    /**
     * Idempotent: called on every app start. Registers only when no WARP-marked
     * profile exists; silently skips if the user deleted it on purpose.
     */
    suspend fun ensureProfile(context: Context) = withContext(Dispatchers.IO) {
        val store = (context.applicationContext as KukuApp).profileStore
        if (store.snapshot().any { it.fromSubscription == WARP_SOURCE }) {
            _status.value = WarpSetup.READY
            return@withContext
        }
        if (store.isWarpDeleted()) return@withContext

        _status.value = WarpSetup.REGISTERING
        val profile = runCatching { register(context) }.getOrNull()
        if (profile != null) {
            store.addAll(listOf(profile)) // auto-selects when nothing else is selected
            _status.value = WarpSetup.READY
        } else {
            _status.value = WarpSetup.FAILED
        }
    }

    private fun register(context: Context): Profile {
        val privateKey = X25519.generatePrivateKey()
        val publicKey = X25519.publicKeyFromPrivate(privateKey)

        var root: kotlinx.serialization.json.JsonObject? = null
        repeat(2) {
            if (root == null) {
                root = runCatching { postRegistration(X25519.toBase64(publicKey)) }.getOrNull()
            }
        }
        val resp = root ?: error("WARP registration unreachable")

        val config = resp["config"]?.jsonObject ?: error("no config in WARP response")
        val peer = config["peers"]?.jsonArray?.firstOrNull()?.jsonObject ?: error("no peer in WARP response")

        val endpoint = peer["endpoint"]?.jsonObject
        val hostPort = endpoint?.get("host")?.jsonPrimitive?.content ?: "$DEFAULT_HOST:$DEFAULT_PORT"
        val host = hostPort.substringBeforeLast(':').ifBlank { DEFAULT_HOST }
        val port = hostPort.substringAfterLast(':').toIntOrNull() ?: DEFAULT_PORT

        val addresses = config["interface"]?.jsonObject
            ?.get("addresses")?.jsonObject ?: error("no addresses in WARP response")
        val v4 = addresses["v4"]?.jsonPrimitive?.content ?: "172.16.0.2"
        val v6 = addresses["v6"]?.jsonPrimitive?.content ?: ""
        val wgAddresses = buildList {
            add("$v4/32")
            if (v6.isNotBlank()) add("$v6/128")
        }.joinToString(",")

        // client_id is 3 bytes base64-encoded; they become the WG "reserved" field.
        val clientId = config["client_id"]?.jsonPrimitive?.content ?: ""

        return Profile(
            name = context.getString(R.string.warp_profile_name),
            type = ProfileType.WIREGUARD,
            host = host,
            port = port,
            publicKey = peer["public_key"]?.jsonPrimitive?.content ?: DEFAULT_PEER_KEY,
            privateKey = X25519.toBase64(privateKey),
            wgAddresses = wgAddresses,
            wgMtu = 1280, // conservative MTU that works on both Wi-Fi and cellular
            wgReserved = clientId,
            fromSubscription = WARP_SOURCE,
        )
    }

    private fun postRegistration(publicKeyB64: String): kotlinx.serialization.json.JsonObject {
        val tos = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.000'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())

        val body = json.encodeToString(
            buildJsonObject {
                put("fcm_token", "")
                put("install_id", "")
                put("key", publicKeyB64)
                put("locale", "en_US")
                put("model", Build.MODEL ?: "Android")
                put("tos", tos)
                put("serial_number", UUID.randomUUID().toString())
            }
        )

        val request = Request.Builder()
            .url(API)
            .header("User-Agent", "okhttp/3.12.1")
            .header("CF-Client-Version", "a-6.30-3536")
            .post(body.toRequestBody("application/json".toMediaType()))
            .build()

        http.newCall(request).execute().use { resp ->
            if (!resp.isSuccessful) error("WARP registration HTTP ${resp.code}")
            val text = resp.body?.string() ?: error("empty WARP response body")
            return json.parseToJsonElement(text).jsonObject
        }
    }
}
