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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
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
 * Cloudflare's free WARP service and store the result as regular WIREGUARD
 * profiles, so one tap on Connect is enough — no subscription, no config.
 *
 * Flow (identical to wgcf/aether): POST https://api.cloudflareclient.com/v0a2158/reg
 * with a client-minted X25519 public key; the response carries the Cloudflare
 * peer key, the endpoint, the tunnel addresses and the `client_id` whose three
 * bytes become the WireGuard "reserved" field.
 *
 * Two hard-won details:
 *  - The endpoint MUST be a plain IP. With a hostname, the core resolves it
 *    through the configured DNS which detours through the tunnel itself —
 *    the tunnel cannot come up before resolution → deadlock (verified with
 *    real sing-box 1.11.15: "resolve endpoint domain … deadline exceeded").
 *  - Four port variants (2408/500/1701/4500) share one identity, so the
 *    fallback engine automatically tries the next port when an ISP filters
 *    one of them.
 */
object WarpRegistrar {

    /** Marker stored in Profile.fromSubscription so we can find our profiles again. */
    const val WARP_SOURCE = "warp"

    /** v1.3.0: marker for the WARP×2 (gool) inner-hop profile — a SECOND,
     *  independent WARP identity whose WireGuard tunnel rides INSIDE the
     *  MASQUE engine's socks. Excluded from the smart chain; used only when
     *  the user pins the gool method on the Connection page. */
    const val WARP_GOOL_SOURCE = "warp-gool"

    /** Profile.transport value of the gool inner-hop profile. */
    const val TRANSPORT_GOOL_WG = "gool"

    /** Profile.transport values that route through the local MASQUE engine. */
    const val TRANSPORT_MASQUE = "masque"       // HTTP/3 over QUIC (UDP 443)
    const val TRANSPORT_MASQUE_H2 = "masque-h2" // HTTP/2 over TCP 443 — survives full UDP blocks

    private const val API = "https://api.cloudflareclient.com/v0a2158/reg"
    private const val DEFAULT_PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

    /**
     * MTU for the gool inner WireGuard tunnel: the MASQUE tunnel's netstack
     * carries packets up to 1280 B; the inner WG data packet adds ~32 B of
     * WG+UDP+IP overhead on top of the inner IP packet, so the inner MTU
     * must leave headroom. 1140 is safe on both H3 and H2 carriers (proven
     * end-to-end in the sandbox with a real request over the double tunnel).
     */
    private const val GOOL_MTU = 1140

    /** Anycast WARP endpoint — same value wgcf uses. */
    private const val DEFAULT_ENDPOINT_IP = "162.159.192.1"
    private val FALLBACK_PORTS = listOf(2408, 500, 1701, 4500)
    private val IP_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")

    private val json = Json { ignoreUnknownKeys = true }
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    private val _status = MutableStateFlow(WarpSetup.IDLE)
    val status: StateFlow<WarpSetup> = _status

    /**
     * Idempotent: called on every app start.
     *  - no WARP profiles + not opted out  → register a fresh identity, add MASQUE + 4 port variants
     *  - legacy profiles with a hostname endpoint → wipe and re-register (DNS-deadlock build)
     *  - legacy installs without MASQUE profiles → inject them and steer the selection over
     *  - IP profiles but fewer than 4 → clone the stored identity into the missing ports
     */
    suspend fun ensureProfile(context: Context) = withContext(Dispatchers.IO) {
        val store = (context.applicationContext as KukuApp).profileStore
        val existing = store.snapshot().filter { it.fromSubscription == WARP_SOURCE }

        when {
            existing.isEmpty() && store.isWarpDeleted() -> Unit // user removed them on purpose

            existing.isEmpty() -> registerFresh(context, store)

            existing.any { !IP_REGEX.matches(it.host) && it.transport == "tcp" } -> {
                // v1 build used "engage.cloudflareclient.com" → the DNS deadlock bug;
                // remove the broken profiles and start clean.
                store.removeMatching { it.fromSubscription == WARP_SOURCE }
                registerFresh(context, store)
            }

            else -> {
                // v1.2.6: heal a DANGLING selection. The addAll() dedup bug (see
                // Stores.addAll) made masque-h2 and masque-h3 overwrite each other,
                // so the stored selected/lastGood ids could point at a profile that
                // no longer exists — the connect chain then ran with no leader at
                // all. Point the selection at a live WARP profile first.
                val selRaw = store.selectedId.first()
                if (selRaw != null && existing.none { it.id == selRaw }) {
                    val healed = existing.firstOrNull { it.transport == TRANSPORT_MASQUE_H2 }
                        ?: existing.firstOrNull { it.transport == TRANSPORT_MASQUE }
                        ?: existing.firstOrNull()
                    healed?.let { store.select(it.id) }
                }

                val additions = mutableListOf<Profile>()
                if (existing.none { it.transport == TRANSPORT_MASQUE_H2 }) {
                    additions += masqueProfile(context, TRANSPORT_MASQUE_H2)
                }
                if (existing.none { it.transport == TRANSPORT_MASQUE }) {
                    additions += masqueProfile(context, TRANSPORT_MASQUE)
                }
                val missing = FALLBACK_PORTS.filter { port -> existing.none { it.port == port } }
                if (missing.isNotEmpty()) {
                    val base = existing.first()
                    additions += missing.map { port -> variantOf(context, base, port) }
                }
                if (additions.isNotEmpty()) {
                    store.addAll(additions)
                    // Steering rule for legacy installs: if nothing ever verified
                    // (including a DANGLING lastGood id left behind by the addAll
                    // dedup bug — it resolves to no profile), OR the last-good
                    // profile is a plain WireGuard WARP endpoint (the exact path
                    // hostile ISPs filter), selection moves to MASQUE H2 so the
                    // very next connect takes the survivable path.
                    val lastGoodRaw = store.lastGoodId.first()
                    val lastGood = lastGoodRaw?.let { id ->
                        store.snapshot().firstOrNull { it.id == id }
                    }
                    val lastGoodIsPlainWgWarp = lastGood != null &&
                        lastGood.fromSubscription == WARP_SOURCE &&
                        !lastGood.transport.startsWith(TRANSPORT_MASQUE)
                    if (lastGood == null || lastGoodIsPlainWgWarp) {
                        additions.firstOrNull { it.transport == TRANSPORT_MASQUE_H2 }
                            ?.let { store.select(it.id) }
                    }
                }
                _status.value = WarpSetup.READY
            }
        }
    }

    private suspend fun registerFresh(context: Context, store: app.kukuvpn.data.ProfileStore) {
        _status.value = WarpSetup.REGISTERING
        // MASQUE candidates come first and don't depend on the WireGuard
        // registration succeeding — the engine mints its own identity.
        // H2 (TCP 443) is tried FIRST: on censorship-heavy networks (IR)
        // QUIC/UDP is throttled while plain-TLS-to-Cloudflare usually passes,
        // so the very first connect must attempt the most survivable path.
        // After the first success the engine pins that profile via lastGood.
        val profiles = buildList {
            add(masqueProfile(context, TRANSPORT_MASQUE_H2))
            add(masqueProfile(context, TRANSPORT_MASQUE))
            addAll(runCatching { registerAll(context) }.getOrDefault(emptyList()))
        }
        if (profiles.size >= 2) {
            store.addAll(profiles) // auto-selects when nothing is selected
            store.select(profiles.first().id) // MASQUE H2 (TCP 443) is the default path
            _status.value = WarpSetup.READY
        } else {
            _status.value = WarpSetup.FAILED
        }
    }

    /** One parsed /reg response, shared by the plain-WG and gool registrations. */
    private data class WgRegistration(
        val endpointIp: String,
        val ports: List<Int>,
        val v4: String,
        val v6: String,
        val clientId: String,
        val peerKey: String,
        val privB64: String,
    )

    /**
     * One registration → one parsed identity. Client-minted X25519 keypair,
     * POST /v0a2158/reg (identical to wgcf/aether), reserved = client_id bytes.
     */
    private fun registerIdentity(): WgRegistration {
        val privateKey = X25519.generatePrivateKey()
        val publicKey = X25519.publicKeyFromPrivate(privateKey)

        var root: JsonObject? = null
        repeat(2) {
            if (root == null) {
                root = runCatching { postRegistration(X25519.toBase64(publicKey)) }.getOrNull()
            }
        }
        val resp = root ?: error("WARP registration unreachable")

        val config = resp["config"]?.jsonObject ?: error("no config in WARP response")
        val peer = config["peers"]?.jsonArray?.firstOrNull()?.jsonObject ?: error("no peer in WARP response")

        val endpoint = peer["endpoint"]?.jsonObject
        // v4 looks like "162.159.192.4:0" (port 0 = placeholder) — keep the IP only.
        val endpointIp = endpoint?.get("v4")?.jsonPrimitive?.content
            ?.substringBeforeLast(':')
            ?.takeIf { IP_REGEX.matches(it) }
            ?: DEFAULT_ENDPOINT_IP
        val ports = endpoint?.get("ports")?.jsonArray
            ?.mapNotNull { it.jsonPrimitive.content.toIntOrNull() }
            ?.filter { it in FALLBACK_PORTS }
            ?.takeIf { it.isNotEmpty() }
            ?: FALLBACK_PORTS

        val addresses = config["interface"]?.jsonObject
            ?.get("addresses")?.jsonObject ?: error("no addresses in WARP response")
        val v4 = addresses["v4"]?.jsonPrimitive?.content ?: "172.16.0.2"
        val v6 = addresses["v6"]?.jsonPrimitive?.content ?: ""

        // client_id is 3 bytes base64-encoded; they become the WG "reserved" field.
        val clientId = config["client_id"]?.jsonPrimitive?.content ?: ""
        val peerKey = peer["public_key"]?.jsonPrimitive?.content ?: DEFAULT_PEER_KEY
        return WgRegistration(
            endpointIp = endpointIp,
            ports = ports,
            v4 = v4,
            v6 = v6,
            clientId = clientId,
            peerKey = peerKey,
            privB64 = X25519.toBase64(privateKey),
        )
    }

    /** One registration → four profiles, one per known-good WARP port. */
    private fun registerAll(context: Context): List<Profile> {
        val reg = registerIdentity()
        val wgAddresses = buildList {
            add("${reg.v4}/32")
            if (reg.v6.isNotBlank()) add("${reg.v6}/128")
        }.joinToString(",")

        return reg.ports.map { port ->
            Profile(
                name = if (port == FALLBACK_PORTS.first()) context.getString(R.string.warp_profile_name)
                else context.getString(R.string.warp_variant_name, port),
                type = ProfileType.WIREGUARD,
                host = reg.endpointIp,
                port = port,
                publicKey = reg.peerKey,
                privateKey = reg.privB64,
                wgAddresses = wgAddresses,
                wgMtu = 1280, // conservative MTU that works on both Wi-Fi and cellular
                wgReserved = reg.clientId,
                fromSubscription = WARP_SOURCE,
            )
        }
    }

    /**
     * v1.3.0 WARP×2 (gool): lazily registers the SECOND WARP identity used
     * as the inner hop of the double tunnel and stores it as one profile.
     * The inner WireGuard tunnel dials through the MASQUE engine's socks
     * (see SingBoxConfigBuilder — wireguard outbound with detour
     * "warp-underlay"). Only called when the user pins the gool method.
     * Throws when the CF API is unreachable — callers fall back to Smart.
     */
    suspend fun ensureGoolProfile(context: Context): Profile = withContext(Dispatchers.IO) {
        val store = (context.applicationContext as KukuApp).profileStore
        store.snapshot().firstOrNull { it.fromSubscription == WARP_GOOL_SOURCE }?.let {
            return@withContext it
        }
        val reg = registerIdentity()
        val profile = Profile(
            name = context.getString(R.string.warp_gool_name),
            type = ProfileType.WIREGUARD,
            host = reg.endpointIp,
            port = 2408,
            publicKey = reg.peerKey,
            privateKey = reg.privB64,
            wgAddresses = buildList {
                add("${reg.v4}/32")
                if (reg.v6.isNotBlank()) add("${reg.v6}/128")
            }.joinToString(","),
            wgMtu = GOOL_MTU,
            wgReserved = reg.clientId,
            transport = TRANSPORT_GOOL_WG,
            fromSubscription = WARP_GOOL_SOURCE,
        )
        store.addAll(listOf(profile))
        profile
    }

    /** Clone an already-stored WARP identity onto a new port — no re-registration. */
    private fun variantOf(context: Context, base: Profile, port: Int): Profile =
        base.copy(
            id = UUID.randomUUID().toString(),
            name = context.getString(R.string.warp_variant_name, port),
            port = port,
            createdAt = System.currentTimeMillis(),
        )

    /**
     * A local-engine candidate: sing-box sends everything to the in-process
     * MASQUE engine over SOCKS (127.0.0.1:SOCKS_PORT); the engine carries the
     * WireGuard stream to Cloudflare inside HTTP/3 or HTTP/2.
     */
    private fun masqueProfile(context: Context, transport: String): Profile = Profile(
        name = if (transport == TRANSPORT_MASQUE) context.getString(R.string.warp_profile_name)
        else context.getString(R.string.warp_masque_h2_name),
        type = ProfileType.WIREGUARD,
        host = "127.0.0.1",
        port = WarpMasqueEngine.SOCKS_PORT,
        transport = transport,
        wgMtu = 1280,
        fromSubscription = WARP_SOURCE,
    )

    private fun postRegistration(publicKeyB64: String): JsonObject {
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
