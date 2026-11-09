package app.kukuvpn.core.config

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Converts a [Profile] into a sing-box outbound object (schema of sing-box 1.11).
 * Fields that do not apply are omitted entirely (sing-box rejects unknown/empty
 * values like `"public_key": ""` on some types).
 */
object OutboundFactory {

    fun build(profile: Profile, tag: String = "proxy"): JsonObject = buildJsonObject {
        // MASQUE-engine candidates ride the in-process warpcore SOCKS5 proxy:
        // sing-box → 127.0.0.1:SOCKS_PORT → MASQUE(HTTP/3|HTTP/2) → Cloudflare.
        val masque = profile.type == ProfileType.WIREGUARD && profile.transport.startsWith("masque")
        put("type", if (masque) "socks" else profile.type.name.lowercase())
        put("tag", tag)
        put("server", profile.host)
        put("server_port", profile.port)

        when (profile.type) {
            ProfileType.VLESS -> {
                put("uuid", profile.uuid)
                if (profile.flow.isNotBlank()) put("flow", profile.flow)
                buildTls(this, profile)
                buildTransport(this, profile)
            }
            ProfileType.VMESS -> {
                put("uuid", profile.uuid)
                put("security", profile.method.ifBlank { "auto" })
                put("alter_id", 0)
                buildTls(this, profile)
                buildTransport(this, profile)
            }
            ProfileType.TROJAN -> {
                put("password", profile.password)
                buildTls(this, profile, trojanDefaultTls = true)
                buildTransport(this, profile)
            }
            ProfileType.SHADOWSOCKS -> {
                put("method", profile.method)
                put("password", profile.password)
            }
            ProfileType.HYSTERIA2 -> {
                put("password", profile.password)
                if (profile.upMbps > 0) put("up_mbps", profile.upMbps)
                if (profile.downMbps > 0) put("down_mbps", profile.downMbps)
                if (profile.obfs.isNotBlank()) {
                    put("obfs", buildJsonObject {
                        put("type", profile.obfs) // "salamander"
                        if (profile.obfsPassword.isNotBlank()) put("password", profile.obfsPassword)
                    })
                }
                buildTls(this, profile, trojanDefaultTls = true)
            }
            ProfileType.TUIC -> {
                put("uuid", profile.uuid)
                put("password", profile.password)
                put("congestion_control", profile.congestionControl.ifBlank { "cubic" })
                buildTls(this, profile, trojanDefaultTls = true)
            }
            ProfileType.WIREGUARD -> {
                if (masque) {
                    put("version", "5")
                } else {
                    put("local_address", cidrList(profile.wgAddresses))
                    put("private_key", profile.privateKey)
                    put("peer_public_key", profile.publicKey)
                    if (profile.preSharedKey.isNotBlank()) put("pre_shared_key", profile.preSharedKey)
                    put("mtu", profile.wgMtu)
                    parseReserved(profile.wgReserved)?.let { put("reserved", JsonArray(it)) }
                    // v1.3.0 WARP×2 (gool): the inner WireGuard tunnel dials
                    // through the MASQUE engine's socks — SingBoxConfigBuilder
                    // emits the "warp-underlay" outbound this tag points to.
                    if (profile.transport == "gool") put("detour", "warp-underlay")
                }
            }
            ProfileType.SSH -> {
                put("user", profile.sshUser.ifBlank { "root" })
                if (profile.password.isNotBlank()) put("password", profile.password)
                if (profile.sshPrivateKey.isNotBlank()) put("private_key", profile.sshPrivateKey)
                if (profile.sshHostKey.isNotBlank()) {
                    putJsonArray("host_key") { add(profile.sshHostKey) }
                }
            }
        }
    }

    /** TLS / Reality block shared by vless, vmess, trojan, hysteria2 and tuic. */
    private fun buildTls(o: kotlinx.serialization.json.JsonObjectBuilder, p: Profile, trojanDefaultTls: Boolean = false) {
        val useTls = p.security == "tls" || p.security == "reality" || (trojanDefaultTls && p.security.isBlank())
        if (!useTls) return
        val reality = p.security == "reality"
        o.putJsonObject("tls") {
            put("enabled", true)
            if (p.sni.isNotBlank()) put("server_name", p.sni)
            if (p.allowInsecure) put("insecure", true)
            if (p.alpn.isNotBlank()) putJsonArray("alpn") { p.alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { add(it) } }
            if (p.fingerprint.isNotBlank()) {
                putJsonObject("utls") {
                    put("enabled", true)
                    put("fingerprint", p.fingerprint)
                }
            }
            if (reality) {
                putJsonObject("reality") {
                    put("enabled", true)
                    put("public_key", p.publicKey)
                    if (p.shortId.isNotBlank()) put("short_id", p.shortId)
                }
            }
        }
    }

    /** Stream transport block for vless / vmess / trojan (tcp means: omit). */
    private fun buildTransport(o: kotlinx.serialization.json.JsonObjectBuilder, p: Profile) {
        val t = p.transport.ifBlank { "tcp" }
        if (t == "tcp") return
        o.putJsonObject("transport") {
            when (t) {
                "ws" -> {
                    put("type", "ws")
                    if (p.path.isNotBlank()) put("path", p.path)
                    if (p.hostHeader.isNotBlank()) {
                        putJsonObject("headers") { put("Host", p.hostHeader) }
                    }
                }
                "grpc" -> {
                    put("type", "grpc")
                    if (p.serviceName.isNotBlank()) put("service_name", p.serviceName)
                }
                "httpupgrade" -> {
                    put("type", "httpupgrade")
                    if (p.path.isNotBlank()) put("path", p.path)
                    if (p.hostHeader.isNotBlank()) put("host", p.hostHeader)
                }
            }
        }
    }

    private fun cidrList(raw: String): JsonArray =
        JsonArray(raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { JsonPrimitive(it) })

    /** "1,2,3" -> [1,2,3]; base64 -> bytes; empty -> null. */
    private fun parseReserved(raw: String): List<kotlinx.serialization.json.JsonElement>? {
        if (raw.isBlank()) return null
        return runCatching {
            if (raw.contains(',')) raw.split(',').map { kotlinx.serialization.json.JsonPrimitive(it.trim().toInt()) }
            else java.util.Base64.getDecoder().decode(raw.trim()).map { kotlinx.serialization.json.JsonPrimitive(it.toInt() and 0xFF) }
        }.getOrNull()
    }
}
