package app.kukuvpn.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.UUID

enum class ProfileType { VLESS, VMESS, TROJAN, SHADOWSOCKS, HYSTERIA2, TUIC, WIREGUARD, SSH }

/**
 * One importable node. All protocols share this flat model; fields that do not
 * apply to a protocol simply stay empty. Serialisable so DataStore can persist
 * the whole list as JSON.
 */
@Serializable
data class Profile(
    @SerialName("id") val id: String = UUID.randomUUID().toString(),
    @SerialName("name") val name: String,
    @SerialName("type") val type: ProfileType,
    @SerialName("host") val host: String = "",
    @SerialName("port") val port: Int = 0,
    // auth
    @SerialName("uuid") val uuid: String = "",       // vless / vmess / tuic
    @SerialName("password") val password: String = "", // trojan / ss / hy2 / tuic / ssh
    @SerialName("method") val method: String = "",   // ss cipher, vmess security (scy)
    // transport for vless / vmess / trojan
    @SerialName("transport") val transport: String = "tcp", // tcp | ws | grpc | httpupgrade
    @SerialName("path") val path: String = "",
    @SerialName("hostHeader") val hostHeader: String = "",
    @SerialName("serviceName") val serviceName: String = "",
    // TLS / Reality
    @SerialName("security") val security: String = "", // tls | reality | none
    @SerialName("sni") val sni: String = "",
    @SerialName("fingerprint") val fingerprint: String = "",
    @SerialName("publicKey") val publicKey: String = "", // reality pbk, wg peer public key
    @SerialName("shortId") val shortId: String = "",     // reality sid
    @SerialName("flow") val flow: String = "",           // xtls-rprx-vision
    @SerialName("alpn") val alpn: String = "",
    @SerialName("allowInsecure") val allowInsecure: Boolean = false,
    // hysteria2
    @SerialName("obfs") val obfs: String = "",
    @SerialName("obfsPassword") val obfsPassword: String = "",
    @SerialName("upMbps") val upMbps: Int = 0,
    @SerialName("downMbps") val downMbps: Int = 0,
    // tuic
    @SerialName("congestionControl") val congestionControl: String = "cubic",
    // wireguard
    @SerialName("privateKey") val privateKey: String = "",
    @SerialName("preSharedKey") val preSharedKey: String = "",
    @SerialName("wgAddresses") val wgAddresses: String = "", // comma-separated CIDRs
    @SerialName("wgDns") val wgDns: String = "",
    @SerialName("wgMtu") val wgMtu: Int = 1420,
    @SerialName("wgReserved") val wgReserved: String = "",   // base64 or "1,2,3"
    // ssh
    @SerialName("sshUser") val sshUser: String = "",
    @SerialName("sshPrivateKey") val sshPrivateKey: String = "", // PEM text
    @SerialName("sshHostKey") val sshHostKey: String = "",
    // metadata
    @SerialName("fromSubscription") val fromSubscription: String = "",
    @SerialName("createdAt") val createdAt: Long = System.currentTimeMillis(),
) {
    /** Short summary shown in the profile list, e.g. "VLESS · reality · example.com:443". */
    fun summary(): String {
        val sec = when (type) {
            ProfileType.VLESS, ProfileType.TROJAN, ProfileType.VMESS ->
                security.ifBlank { if (port == 443) "tls?" else "tcp" }
            ProfileType.SHADOWSOCKS -> method.ifBlank { "ss" }
            ProfileType.HYSTERIA2 -> if (obfs.isNotBlank()) "obfs" else "quic"
            ProfileType.TUIC -> congestionControl
            ProfileType.WIREGUARD -> "wg"
            ProfileType.SSH -> "ssh"
        }
        return "${type.name.lowercase()} · $sec · $host:$port"
    }
}
