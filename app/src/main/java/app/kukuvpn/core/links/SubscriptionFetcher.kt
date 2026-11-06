package app.kukuvpn.core.links

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Downloads a subscription URL and converts its content into profiles.
 * Supported bodies:
 *  1. sing-box JSON config (object with "outbounds")
 *  2. base64 blob of share links (the classic v2ray format)
 *  3. plain text containing share links
 */
object SubscriptionFetcher {

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    fun fetch(url: String, sourceLabel: String = url): List<Profile> {
        val body = client.newCall(
            Request.Builder()
                .url(url.trim())
                .header("User-Agent", "KukuVPN/1.0")
                .build()
        ).execute().use { resp ->
            if (!resp.isSuccessful) error("HTTP ${resp.code}")
            resp.body?.string() ?: error("empty response")
        }
        return parseBody(body, sourceLabel)
    }

    fun parseBody(body: String, sourceLabel: String): List<Profile> {
        val trimmed = body.trim()

        // 1) sing-box JSON
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            runCatching { return fromSingBoxJson(trimmed, sourceLabel) }
        }

        // 2) base64 blob -> links
        val decoded = runCatching {
            String(Base64.getMimeDecoder().decode(trimmed), Charsets.UTF_8)
        }.getOrNull()
        val candidate = decoded?.takeIf { it.contains("://") } ?: trimmed

        // 3) plain share links
        val links = ShareLinkParser.parse(candidate)
        require(links.isNotEmpty()) { "no usable profile found in subscription" }
        return links.map { it.copy(fromSubscription = sourceLabel) }
    }

    private fun fromSingBoxJson(text: String, sourceLabel: String): List<Profile> {
        val root = Json.parseToJsonElement(text)
        val outbounds = when (root) {
            is JsonObject -> root["outbounds"]?.jsonArray
            else -> root.jsonArray // some providers ship a bare array of outbounds
        } ?: error("no outbounds in JSON subscription")
        val converted = outbounds.mapNotNull { el ->
            (el as? JsonObject)?.let { outboundToProfile(it) }
        }.filter { it.host.isNotBlank() }
        require(converted.isNotEmpty()) { "no supported outbound in JSON subscription" }
        return converted.map { it.copy(fromSubscription = sourceLabel) }
    }

    /** Reverse conversion: a sing-box outbound object -> Profile (best effort). */
    fun outboundToProfile(o: JsonObject): Profile? {
        val type = (o["type"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: return null
        val tag = (o["tag"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: type
        fun s(k: String) = (o[k] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ""
        fun i(k: String) = (o[k] as? kotlinx.serialization.json.JsonPrimitive)?.content?.toIntOrNull() ?: 0
        val tls = o["tls"] as? JsonObject
        fun tlsS(k: String) = (tls?.get(k) as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ""
        val reality = tls?.get("reality") as? JsonObject
        val transport = o["transport"] as? JsonObject
        fun trS(k: String) = (transport?.get(k) as? kotlinx.serialization.json.JsonPrimitive)?.content ?: ""
        val obfs = o["obfs"] as? JsonObject

        return when (type) {
            "vless", "vmess", "trojan" -> Profile(
                name = tag, type = ProfileType.valueOf(type.uppercase()),
                host = s("server"), port = i("server_port"),
                uuid = s("uuid"), password = s("password"),
                method = if (type == "vmess") s("security").ifBlank { "auto" } else "",
                transport = trS("type").ifBlank { "tcp" },
                path = trS("path") ?: "",
                hostHeader = ((transport?.get("headers") as? JsonObject)?.get("Host") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                serviceName = trS("service_name") ?: "",
                security = when {
                    reality != null -> "reality"
                    tlsS("enabled") == "true" -> "tls"
                    else -> "none"
                },
                sni = tlsS("server_name"),
                fingerprint = ((tls?.get("utls") as? JsonObject)?.get("fingerprint") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                publicKey = (reality?.get("public_key") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                shortId = (reality?.get("short_id") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                flow = s("flow"), alpn = tlsS("alpn"),
                allowInsecure = tlsS("insecure") == "true",
            )
            "shadowsocks" -> Profile(
                name = tag, type = ProfileType.SHADOWSOCKS,
                host = s("server"), port = i("server_port"),
                method = s("method"), password = s("password"),
            )
            "hysteria2" -> Profile(
                name = tag, type = ProfileType.HYSTERIA2,
                host = s("server"), port = i("server_port"),
                password = s("password"),
                upMbps = i("up_mbps"), downMbps = i("down_mbps"),
                obfs = (obfs?.get("type") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                obfsPassword = (obfs?.get("password") as? kotlinx.serialization.json.JsonPrimitive)?.content ?: "",
                security = "tls", sni = tlsS("server_name"),
                allowInsecure = tlsS("insecure") == "true",
            )
            "tuic" -> Profile(
                name = tag, type = ProfileType.TUIC,
                host = s("server"), port = i("server_port"),
                uuid = s("uuid"), password = s("password"),
                congestionControl = s("congestion_control").ifBlank { "cubic" },
                security = "tls", sni = tlsS("server_name"),
            )
            "wireguard" -> Profile(
                name = tag, type = ProfileType.WIREGUARD,
                host = s("server"), port = i("server_port"),
                privateKey = s("private_key"),
                publicKey = s("peer_public_key"),
                preSharedKey = s("pre_shared_key"),
                wgAddresses = (o["local_address"] as? kotlinx.serialization.json.JsonArray)
                    ?.joinToString(",") { it.toString().trim('"') } ?: "",
                wgMtu = i("mtu").takeIf { it > 0 } ?: 1420,
                wgReserved = (o["reserved"] as? kotlinx.serialization.json.JsonArray)
                    ?.joinToString(",") { it.toString().trim('"') } ?: "",
            )
            "ssh" -> Profile(
                name = tag, type = ProfileType.SSH,
                host = s("server"), port = i("server_port"),
                sshUser = s("user"), password = s("password"),
                sshPrivateKey = s("private_key"),
                sshHostKey = (o["host_key"] as? kotlinx.serialization.json.JsonArray)
                    ?.firstOrNull()?.toString()?.trim('"') ?: "",
            )
            else -> null
        }
    }
}
