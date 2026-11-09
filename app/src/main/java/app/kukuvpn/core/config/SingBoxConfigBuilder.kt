package app.kukuvpn.core.config

import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.core.warp.WarpRegistrar
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

        // BUG HISTORY (v1.2.2): dns-remote used to be "tcp://1.1.1.1" (DNS over
        // TCP port 53, detour proxy). Many free socks5 providers block ALL
        // connections to port 53 from their exit (anti DNS-abuse policy), so
        // every exchange died with "socks5: request rejected, code=4" (host
        // unreachable). The probe still passed — OkHttp sends CONNECT with the
        // hostname and the socks5 server resolves remotely — so the UI showed
        // Connected while every app's DNS failed: instagram/facebook logs full
        // of "dns: exchange failed", 0 B of traffic.
        // FIX: DNS over HTTPS (https://1.1.1.1/dns-query). It is still tunneled
        // through the proxy (Iranian direct DNS is poisoned), but now rides
        // TCP 443 — the exact same path app traffic uses, which the provider
        // MUST allow for the tunnel to be useful at all. IP-literal URL means
        // no bootstrap resolution is needed.
        // "strategy: ipv4_only" keeps apps off IPv6 targets, which many socks5
        // exits cannot reach (AAAA answered → connect hangs → more "dead" apps).
        putJsonObject("dns") {
            put("strategy", "ipv4_only")
            putJsonArray("servers") {
                add(buildJsonObject {
                    put("tag", "dns-remote")
                    put("address", "https://1.1.1.1/dns-query")
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
                    // auto_route MUST be true on Android: libbox forwards it to
                    // TunOptions.autoRoute and the service's openTun() then installs
                    // the default routes (0.0.0.0/0 + ::/0) and the DNS server on the
                    // VpnService.Builder. With "false" the TUN comes up with no
                    // routes at all: the verifier (via 127.0.0.1:2080) still passes
                    // and the UI shows Connected, but device traffic bypasses the
                    // tunnel entirely -> "connected yet nothing loads", 0 B stats.
                    put("auto_route", true)
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
            // v1.3.0 WARP×2 (gool): the "proxy" outbound is the INNER WireGuard
            // tunnel and dials through the MASQUE engine's socks — the second
            // hop rides inside the first. Proven end-to-end in the sandbox
            // (real request → warp=on with a DIFFERENT exit IP than the outer
            // hop) before shipping.
            if (profile.transport == WarpRegistrar.TRANSPORT_GOOL_WG) {
                add(buildJsonObject {
                    put("type", "socks")
                    put("tag", "warp-underlay")
                    put("server", "127.0.0.1")
                    put("server_port", WarpMasqueEngine.SOCKS_PORT)
                    put("version", "5")
                })
            }
            add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
            add(buildJsonObject { put("type", "dns"); put("tag", "dns-out") })
        }

        // BUG HISTORY (v1.2.3): the stats tiles always showed 0 B down/up even
        // while the tunnel carried real traffic. In sing-box 1.11 traffic is
        // counted ONLY by the clash-api TrafficManager — libbox's
        // CommandServer.readStatus() reads clashServer.TrafficManager().Total()
        // and with no clash_api in the config clashServer is nil, so the
        // status/connections streams die instantly and every counter stays 0.
        // An EMPTY clash_api block is enough: external_controller stays unset,
        // so no TCP listener is opened (nothing exposed on localhost) — only
        // the byte counters and the connections list come alive.
        putJsonObject("experimental") {
            putJsonObject("clash_api") {
                put("default_mode", "Rule")
            }
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
