package app.kukuvpn.core.links

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import java.net.URI
import java.net.URLDecoder
import java.util.Base64

/**
 * Parses every share-link scheme Kuku VPN understands into [Profile]s:
 * vless:// vmess:// trojan:// ss:// hysteria2://(hy2://) tuic:// ssh:// wireguard://
 * A single input string may contain several links (one per line or mixed text).
 */
object ShareLinkParser {

    private val SCHEMES = listOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "ssh", "wireguard")

    fun parse(input: String): List<Profile> {
        val out = mutableListOf<Profile>()
        // pull candidate links out of arbitrary text
        val candidates = SCHEMES.map { Regex.escape(it) }
            .joinToString("|").let { scheme -> Regex("($scheme)://[^\\s\"'<>]+") }
            .findAll(input.replace("\n", " ")).map { it.value }.toList()
        val lines = if (candidates.isNotEmpty()) candidates else input.lines().map { it.trim() }.filter { it.isNotEmpty() }
        for (line in lines) {
            runCatching { parseOne(line) }.getOrNull()?.let { out.add(it) }
        }
        return out
    }

    fun isSupported(input: String): Boolean =
        SCHEMES.any { input.trimStart().startsWith("$it://") } && parse(input).isNotEmpty()

    private fun parseOne(link: String): Profile? {
        val scheme = link.substringBefore("://").lowercase()
        return when (scheme) {
            "vless" -> parseVless(link)
            "vmess" -> parseVmess(link)
            "trojan" -> parseTrojan(link)
            "ss" -> parseShadowsocks(link)
            "hysteria2", "hy2" -> parseHysteria2(link)
            "tuic" -> parseTuic(link)
            "ssh" -> parseSsh(link)
            "wireguard" -> parseWireguard(link)
            else -> null
        }
    }

    /* -------------------------------- helpers ------------------------------ */

    private fun dec(s: String): String = URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

    private fun b64(s: String): String = String(
        Base64.getMimeDecoder().decode(s.padEnd(s.length + (4 - s.length % 4) % 4, '=')),
        Charsets.UTF_8,
    )

    /** host:port from the URI authority, tolerating userinfo before '@'. */
    private fun authority(uri: URI): Pair<String, Int> {
        val afterUser = uri.rawAuthority.substringAfterLast('@')
        val host = afterUser.substringBeforeLast(':')
        val port = afterUser.substringAfterLast(':').toIntOrNull() ?: 443
        return host to port
    }

    private fun uriParams(uri: URI): Map<String, String> =
        uri.rawQuery?.split('&')?.mapNotNull {
            val kv = it.split('=', limit = 2)
            if (kv.size == 2) dec(kv[0]) to dec(kv[1]) else null
        }?.toMap() ?: emptyMap()

    private fun nameOf(uri: URI, fallback: String): String =
        uri.fragment?.let { dec(it) }?.takeIf { it.isNotBlank() } ?: fallback

    /* ------------------------------- schemes ------------------------------- */

    private fun parseVless(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        return Profile(
            name = nameOf(uri, "vless $host"),
            type = ProfileType.VLESS,
            host = host, port = port,
            uuid = uri.userInfo ?: return null,
            transport = q["type"]?.ifBlank { "tcp" } ?: "tcp",
            path = q["path"] ?: "",
            hostHeader = q["host"] ?: "",
            serviceName = q["serviceName"] ?: "",
            security = q["security"] ?: "none",
            sni = q["sni"] ?: "",
            fingerprint = q["fp"] ?: "",
            publicKey = q["pbk"] ?: "",
            shortId = q["sid"] ?: "",
            flow = q["flow"] ?: "",
            alpn = q["alpn"] ?: "",
            allowInsecure = q["allowInsecure"] == "1" || q["insecure"] == "1",
        )
    }

    private fun parseVmess(link: String): Profile? {
        val payload = link.removePrefix("vmess://")
        val json = kotlinx.serialization.json.Json.parseToJsonElement(b64(payload)).jsonObjectSafe() ?: return null
        fun str(k: String) = json[k]?.toString()?.trim('"') ?: ""
        return Profile(
            name = str("ps").ifBlank { "vmess ${str("add")}" },
            type = ProfileType.VMESS,
            host = str("add"),
            port = str("port").toIntOrNull() ?: return null,
            uuid = str("id"),
            method = str("scy").ifBlank { "auto" },
            transport = str("net").ifBlank { "tcp" },
            path = str("path") ?: "",
            hostHeader = str("host") ?: "",
            serviceName = str("path").takeIf { str("net") == "grpc" } ?: "",
            security = str("tls").ifBlank { "none" },
            sni = str("sni") ?: "",
            fingerprint = str("fp") ?: "",
            alpn = str("alpn") ?: "",
            allowInsecure = str("verify_cert") == "false" || str("allowInsecure") == "1",
        )
    }

    private fun parseTrojan(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        return Profile(
            name = nameOf(uri, "trojan $host"),
            type = ProfileType.TROJAN,
            host = host, port = port,
            password = uri.userInfo ?: return null,
            transport = q["type"]?.ifBlank { "tcp" } ?: "tcp",
            path = q["path"] ?: "",
            hostHeader = q["host"] ?: "",
            serviceName = q["serviceName"] ?: "",
            security = q["security"]?.ifBlank { "tls" } ?: "tls",
            sni = q["sni"] ?: "",
            fingerprint = q["fp"] ?: "",
            alpn = q["alpn"] ?: "",
            allowInsecure = q["allowInsecure"] == "1" || q["insecure"] == "1",
        )
    }

    private fun parseShadowsocks(link: String): Profile? {
        val uri = URI(link)
        val fragment = nameOf(uri, "ss")
        val body = link.removePrefix("ss://").substringBefore('#')
        return if (uri.rawAuthority?.contains('@') == true) {
            // SIP002: ss://userinfo@host:port  (userinfo may be base64 of method:password)
            val (host, port) = authority(uri)
            val userinfo = dec(uri.userInfo ?: "")
            val methodPass = if (userinfo.contains(':')) userinfo
            else runCatching { b64(uri.userInfo ?: "") }.getOrDefault(userinfo)
            Profile(
                name = fragment, type = ProfileType.SHADOWSOCKS,
                host = host, port = port,
                method = methodPass.substringBefore(':'),
                password = methodPass.substringAfter(':', ""),
            )
        } else {
            // legacy: ss://base64(method:password@host:port)#name
            val decoded = b64(body)
            val userinfo = decoded.substringBeforeLast('@')
            val auth = decoded.substringAfterLast('@')
            Profile(
                name = fragment, type = ProfileType.SHADOWSOCKS,
                host = auth.substringBeforeLast(':'),
                port = auth.substringAfterLast(':').toIntOrNull() ?: return null,
                method = userinfo.substringBefore(':'),
                password = userinfo.substringAfter(':', ""),
            )
        }
    }

    private fun parseHysteria2(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        return Profile(
            name = nameOf(uri, "hy2 $host"),
            type = ProfileType.HYSTERIA2,
            host = host, port = port,
            password = uri.userInfo ?: return null,
            security = "tls",
            sni = q["sni"] ?: "",
            obfs = q["obfs"] ?: "",
            obfsPassword = q["obfs-password"] ?: q["obfsPassword"] ?: "",
            allowInsecure = q["insecure"] == "1",
        )
    }

    private fun parseTuic(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        val userinfo = uri.userInfo ?: return null
        return Profile(
            name = nameOf(uri, "tuic $host"),
            type = ProfileType.TUIC,
            host = host, port = port,
            uuid = userinfo.substringBefore(':'),
            password = userinfo.substringAfter(':', ""),
            congestionControl = q["congestion_control"] ?: "cubic",
            security = "tls",
            sni = q["sni"] ?: "",
            alpn = q["alpn"] ?: "",
            allowInsecure = q["insecure"] == "1" || q["allow_insecure"] == "1",
        )
    }

    private fun parseSsh(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        return Profile(
            name = nameOf(uri, "ssh $host"),
            type = ProfileType.SSH,
            host = host, port = port,
            sshUser = uri.userInfo ?: "root",
            password = q["password"] ?: "",
            sshPrivateKey = q["private_key"]?.let { runCatching { b64(it) }.getOrNull() } ?: "",
            sshHostKey = q["host_key"] ?: "",
        )
    }

    private fun parseWireguard(link: String): Profile? {
        val uri = URI(link)
        val (host, port) = authority(uri)
        val q = uriParams(uri)
        return Profile(
            name = nameOf(uri, "wg $host"),
            type = ProfileType.WIREGUARD,
            host = host, port = port,
            privateKey = uri.userInfo ?: return null,
            publicKey = q["publicKey"] ?: return null,
            preSharedKey = q["presharedKey"] ?: "",
            wgAddresses = q["addresses"] ?: q["address"] ?: "172.16.0.2/32",
            wgDns = q["dns"] ?: "",
            wgMtu = q["mtu"]?.toIntOrNull() ?: 1420,
            wgReserved = q["reserved"] ?: "",
        )
    }

    private fun kotlinx.serialization.json.JsonElement.jsonObjectSafe(): kotlinx.serialization.json.JsonObject? =
        this as? kotlinx.serialization.json.JsonObject
}
