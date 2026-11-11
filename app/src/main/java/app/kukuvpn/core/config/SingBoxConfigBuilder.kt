package app.kukuvpn.core.config

import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileType
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
    const val LAN_SHARE_PORT = 2081 // v1.7.0 mixed inbound on 0.0.0.0 when lanShare is on
    const val TUN_TAG = "tun-in"
    const val MIXED_TAG = "mixed-in"

    /**
     * v1.4.0 FLUX turbo: the urltest group that owns the default route when
     * the engine rides. Members: the verified primary socks ("proxy" FIRST —
     * before the first urltest round completes, sing-box's Select() falls
     * back to the first member, so the very first request always lands on
     * the already-verified path), then the engine's background paths
     * (flux-x1/x2 on SOCKS_PORT+1/+2 — they come up seconds after the
     * engine reports ready and JOIN the rotation as they go live; a member
     * that never comes up simply fails its checks and is never selected).
     * Sandbox-proven 1.11.15: 24/24 real requests through a group with one
     * dead member, first-request fallback + rotation verified.
     */
    const val FLUX_TAG = "proxy-fast"

    /** Returns the config as a JSON string — exactly what Libbox.newService expects. */
    fun build(
        profile: Profile,
        settings: AppSettings,
        ruleFiles: Map<String, String> = emptyMap(), // v1.7.0 tag → .srs path (ready local rule-sets)
    ): String = buildJsonObject {
        val fluxPorts = fluxPortsFor(profile, settings)
        val routeTarget = if (fluxPorts.isNotEmpty()) FLUX_TAG else "proxy"
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
        // DNS over HTTPS — v1.7.0: the provider is user-selectable (Settings →
        // Routing & DNS). All three are IP-literal URLs so no bootstrap
        // resolution is needed (the original 1.2.2 reasoning still holds).
        val dohUrl = when (settings.dnsProvider) {
            "google" -> "https://8.8.8.8/dns-query"
            "quad9" -> "https://9.9.9.9/dns-query"
            else -> "https://1.1.1.1/dns-query" // default + unknown values
        }
        putJsonObject("dns") {
            put("strategy", "ipv4_only")
            putJsonArray("servers") {
                add(buildJsonObject {
                    put("tag", "dns-remote")
                    put("address", dohUrl)
                    // FLUX: DNS rides the urltest group too, so lookups take the
                    // currently-fastest path (falling back to "proxy" when the
                    // group does not exist for this profile)
                    put("detour", routeTarget)
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
            // v1.7.0 LAN share: a second mixed inbound on ALL interfaces —
            // other devices on the phone's hotspot/Wi-Fi set their proxy to
            // <phone-ip>:2081 and ride the same tunnel. Opt-in, default off;
            // only ever enable on a network you control.
            if (settings.lanShare) {
                add(buildJsonObject {
                    put("type", "mixed")
                    put("tag", "mixed-lan")
                    put("listen", "0.0.0.0")
                    put("listen_port", LAN_SHARE_PORT)
                    put("sniff", true)
                })
            }
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
            // v1.4.0 FLUX turbo: the engine's background paths + the urltest
            // group. Outbounds pointing at a not-yet-open loopback port are
            // harmless (creation never dials; failed urltest checks are
            // instant connection-refused and the member is never selected).
            if (fluxPorts.isNotEmpty()) {
                fluxPorts.forEachIndexed { i, port ->
                    add(buildJsonObject {
                        put("type", "socks")
                        put("tag", "flux-x${i + 1}")
                        put("server", "127.0.0.1")
                        put("server_port", port)
                        put("version", "5")
                    })
                }
                add(buildJsonObject {
                    put("type", "urltest")
                    put("tag", FLUX_TAG)
                    putJsonArray("outbounds") {
                        add("proxy") // FIRST: the pre-rotation fallback member
                        fluxPorts.forEachIndexed { i, _ -> add("flux-x${i + 1}") }
                    }
                    put("url", "http://www.gstatic.com/generate_204")
                    put("interval", "2m")
                    put("tolerance", 50)
                    put("idle_timeout", "30m")
                })
            }
            add(buildJsonObject { put("type", "direct"); put("tag", "direct") })
            // v1.7.0 ad block: the deprecated-but-still-supported block outbound
            // (a 1.11-compatible alternative to the newer reject ACTION)
            if (ruleFiles.containsKey(app.kukuvpn.core.rules.RuleSets.TAG_GEOSITE_ADS)) {
                add(buildJsonObject { put("type", "block"); put("tag", "ads-block") })
            }
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
            // v1.7.0: local rule-sets (binary .srs, pre-downloaded by RuleSets
            // with jsDelivr→raw fallback). ONLY files that are ready land here,
            // so a blocked CDN can never fail the connect — fail-open by design.
            val ruleSetEntries = ruleFiles.map { (tag, path) ->
                buildJsonObject {
                    put("type", "local")
                    put("tag", tag)
                    put("format", "binary")
                    put("path", path)
                }
            }
            if (ruleSetEntries.isNotEmpty()) {
                putJsonArray("rule_set") { ruleSetEntries.forEach { add(it) } }
            }
            putJsonArray("rules") {
                add(buildJsonObject {
                    put("protocol", "dns")
                    put("outbound", "dns-out")
                })
                // ad/tracker domains die here (checked before everything else)
                if (ruleFiles.containsKey(app.kukuvpn.core.rules.RuleSets.TAG_GEOSITE_ADS)) {
                    add(buildJsonObject {
                        put("rule_set", listOf(app.kukuvpn.core.rules.RuleSets.TAG_GEOSITE_ADS))
                        put("outbound", "ads-block")
                    })
                }
                // Iranian sites/apps go DIRECT — banking, government, domestic
                // news never pay the tunnel tax, foreign traffic still rides it
                if (settings.irBypass) {
                    if (ruleFiles.containsKey(app.kukuvpn.core.rules.RuleSets.TAG_GEOSITE_IR)) {
                        add(buildJsonObject {
                            put("rule_set", listOf(app.kukuvpn.core.rules.RuleSets.TAG_GEOSITE_IR))
                            put("outbound", "direct")
                        })
                    }
                    if (ruleFiles.containsKey(app.kukuvpn.core.rules.RuleSets.TAG_GEOIP_IR)) {
                        add(buildJsonObject {
                            put("rule_set", listOf(app.kukuvpn.core.rules.RuleSets.TAG_GEOIP_IR))
                            put("outbound", "direct")
                        })
                    }
                }
                add(buildJsonObject {
                    put("ip_is_private", true)
                    put("outbound", "direct")
                })
            }
            put("final", routeTarget)
            put("auto_detect_interface", true)
        }
    }.toString()

    /**
     * v1.4.0 FLUX turbo membership rule: engine-riding candidates (MASQUE
     * socks outbounds and the gool inner-hop, which rides the engine's
     * underlay) get the background paths + the urltest group. Plain
     * WireGuard and imported servers run without the engine — no group.
     * The H2/stealth transport has only ONE usable edge (v1.2.7 discovery),
     * so a stealth session is single-path by design: no group, no probes,
     * nothing but plain HTTPS on TCP 443 — exactly the DPI footprint
     * stealth promises.
     */
    fun fluxPortsFor(profile: Profile, settings: AppSettings): List<Int> {
        val engineRides = profile.type == ProfileType.WIREGUARD &&
            (profile.transport.startsWith("masque") || profile.transport == WarpRegistrar.TRANSPORT_GOOL_WG)
        if (!engineRides) return emptyList()
        if (settings.scanMode == "stealth") return emptyList()
        return WarpMasqueEngine.FLUX_SOCKS_PORTS
    }
}
