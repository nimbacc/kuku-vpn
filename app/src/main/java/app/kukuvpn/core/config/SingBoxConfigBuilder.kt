package app.kukuvpn.core.config

import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Builds the complete sing-box configuration JSON (sing-box 1.11 schema).
 *
 * Layout:
 *  - VPN mode:  tun inbound (fd comes from Android VpnService via PlatformInterface)
 *               + mixed inbound on 127.0.0.1:2080 for the real-connection probe.
 *  - Proxy mode: mixed inbound only — nothing is captured from the device.
 *
 * The probe inbound is what makes the RIX-style "verified connection" possible:
 * the app fires a real HTTP request through 127.0.0.1:2080 and only marks the
 * tunnel as CONNECTED when the response comes back through the exit.
 */
object SingBoxConfigBuilder {

    const val PROXY_PORT = 2080
    const val TUN_TAG = "tun-in"
    const val MIXED_TAG = "mixed-in"

    /** Returns the config as a JSON string — exactly what Libbox.newService expects. */
    fun build(profile: Profile, settings: AppSettings): String = buildJsonObject {
        putJsonObject("log") {
            put("level", "info")
            put("timestamp", true)
        }

        putJsonObject("dns") {
            putJsonArray("servers") {
                add(buildJsonObject {
                    put("tag", "dns-remote")
                    put("address", "tcp://1.1.1.1")
                    put("detour", "proxy")
                })
                add(buildJsonObject {
                    put("tag", "dns-local")
                    put("address", "local")
                    put("detour", "direct")
                })
            }
            put("final", "dns-remote")
            put("independent_cache", true)
        }

        putJsonArray("inbounds") {
            if (settings.vpnMode) {
                add(buildJsonObject {
                    put("type", "tun")
                    put("tag", TUN_TAG)
                    put("inet4_address", buildJsonArray { add("172.19.0.1/30") })
                    put("inet6_address", buildJsonArray { add("fdfe:dcba:9876::1/126") })
                    put("mtu", 9000)
                    put("auto_route", false)   // Android VpnService owns routing
                    put("strict_route", false)
                    put("stack", "gvisor")
                    put("sniff", true)
                })
            }
            add(buildJsonObject {
                put("type", "mixed")
                put("tag", MIXED_TAG)
                put("listen", "127.0.0.1")
                put("listen_port", PROXY_PORT)
                put("sniff", true)
            })
        }

        putJsonArray("outbounds") {
            add(OutboundFactory.build(profile, "proxy"))
            add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
            add(buildJsonObject { put("type", "dns"); put("tag", "dns-out") })
        }

        putJsonObject("route") {
            putJsonArray("rules") {
                add(buildJsonObject {
                    put("protocol", "dns")
                    put("outbound", "dns-out")
                })
                add(buildJsonObject {
                    put("ip_is_private", true)
                    put("outbound", "direct")
                })
            }
            put("final", "proxy")
            put("auto_detect_interface", true)
        }
    }.toString()
}
