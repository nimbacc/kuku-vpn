package app.kukuvpn.core.fallback

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import kotlinx.coroutines.flow.first

/**
 * Builds the ranked chain of profiles to try when the selected one cannot
 * prove a real connection (RIX-style smart fallback).
 *
 * v1.6.7 — the Aether split (the user drew it on the Connection page):
 * PROTOCOL and NETWORK are two independent choices, freely combinable:
 *
 *   protocol = none    → the WARP chain (network decides the wire):
 *     smart (default) — the full ranked chain:
 *       1. MASQUE H2  (WARP over HTTP/2, TCP 443)   — survives full UDP filters
 *       2. MASQUE H3  (WARP over HTTP/3, UDP 443)
 *       3. plain WireGuard WARP ports
 *     masque — the MASQUE pair first, then the smart chain as a safety net
 *     wg     — the plain WireGuard WARP ports first, then the smart chain
 *     gool   — the WARP×2 inner-tunnel profile first, then the smart chain
 *
 *   protocol = psiphon / tor → ONLY that bundled core (v1.6.1 exclusivity —
 *     a failed Psiphon/Tor connect surfaces its real error, never a WARP
 *     substitution), and the NETWORK pin decides how the core reaches out:
 *     direct — the core connects STRAIGHT from the ISP. This is Aether's own
 *       architecture and the user's PROVEN fast path ("Aether connects in
 *       seconds on my ISP"); since v1.6.7 it is the FIRST thing tried — the
 *       v1.6.4–v1.6.6 era put the WARP-chained candidate first and the field
 *       logs show exactly how that burns: WG underlay reset by the ISP,
 *       MASQUE underlay alive but Psiphon silent for minutes.
 *     masque / wg — the core rides ONLY that WARP underlay wire (chained).
 *     smart — direct FIRST (Aether mode), then the WARP-chained candidate
 *       as the safety net for networks where the protocol itself is filtered.
 *
 * Per-network memory (the Aether "remembers which one worked on this
 * network" rule): when the store holds a profile that last VERIFIED on the
 * current network class (wifi vs cellular), it leads the WARP chain regardless
 * of the transport heuristics.
 */
class FallbackEngine(private val store: ProfileStore) {

    private fun isWarp(p: Profile) = p.fromSubscription == WARP_SOURCE
    private fun isMasque(p: Profile) = isWarp(p) && p.transport.startsWith("masque")
    private fun isGool(p: Profile) = p.fromSubscription == WARP_GOOL_SOURCE || p.transport == TRANSPORT_GOOL_WG

    private fun warpRank(p: Profile): Int = when {
        p.transport == TRANSPORT_MASQUE_H2 -> 0
        p.transport == TRANSPORT_MASQUE -> 1
        else -> 2
    }

    /** The default smart ranking over [pool] (gool profiles are never in it). */
    private fun rankSmart(
        pool: List<Profile>,
        selected: Profile?,
        lastGood: Profile?,
    ): List<Profile> {
        val masqueH2 = pool.firstOrNull { isWarp(it) && it.transport == TRANSPORT_MASQUE_H2 }
        val masqueH3 = pool.firstOrNull { isWarp(it) && it.transport == TRANSPORT_MASQUE }

        // demote a plain-WireGuard WARP selection behind the MASQUE pair
        val demoteSelected =
            selected != null && isWarp(selected) && !isMasque(selected) && !isGool(selected) && masqueH2 != null

        val ranked = buildList {
            if (!demoteSelected) selected?.let(::add)
            masqueH2?.let(::add)
            masqueH3?.let(::add)
            if (demoteSelected) selected?.let(::add)
            lastGood?.let(::add)
            addAll(pool.sortedByDescending { it.createdAt })
        }.distinctBy { it.id }.toMutableList()

        // stable-sort only the WARP block: h2 → h3 → plain wireguard, so the
        // four port variants keep their own order behind the MASQUE pair
        ranked.sortWith { a, b ->
            if (isWarp(a) && isWarp(b)) warpRank(a) - warpRank(b) else 0
        }
        return ranked
    }

    suspend fun chain(
        selectedId: String?,
        protocol: String,
        network: String,
        networkClass: String = "",
        failedIds: Set<String> = emptySet(),
        maxCandidates: Int = 8,
    ): List<Profile> {
        val all = store.snapshot()
        if (all.isEmpty()) return emptyList()

        // v1.6.7 — the bundled protocol cores: the PROTOCOL pin decides the
        // family, the NETWORK pin decides the underlay. Exclusive by
        // construction (v1.6.1): no WARP candidate can follow a failed
        // Psiphon/Tor, and no Psiphon/Tor candidate can hijack a plain-VPN
        // connect. DIRECT (Aether's architecture, the user's proven fast
        // path) leads every smart ordering.
        when (protocol) {
            PROTO_PSIPHON -> {
                // v1.7.4: the AI method leads when the user SELECTED it —
                // the US-egress core is the point of the pick, and the regular
                // auto-exit candidates stay behind it as the safety net
                // (a hard US egress that cannot connect costs the REGION, not
                // the protocol — the engine's own retry handles that).
                val selectedP = selectedId?.let { id -> all.firstOrNull { it.id == id } }
                val ai = all.filter { it.fromSubscription == PSIPHON_SOURCE && it.transport == PSIPHON_AI_TRANSPORT }
                val standalone = all.filter { it.fromSubscription == PSIPHON_SOURCE && it.transport == PSIPHON_TRANSPORT }
                val chained = all.filter { it.fromSubscription == PSIPHON_SOURCE && it.transport == PSIPHON_CHAIN_TRANSPORT }
                val base = when (network) {
                    NET_DIRECT -> standalone
                    // v1.7.3: a pinned wire LEADS, it no longer owns the
                    // protocol alone — the user's field log ("all 1 candidate
                    // (s) failed — last: timeout") shows the WG-pin death spiral:
                    // the pinned wire's underlay failed and the chain held
                    // NOTHING behind it, so a temporary wire outage turned into
                    // "Psiphon can't connect at all". The standalone core rides
                    // BEHIND the pinned chained candidate as the safety net —
                    // the protocol stays exclusive (v1.6.1), only the WIRE
                    // falls back, and the log says so honestly.
                    NET_MASQUE, NET_WG -> chained + standalone
                    else -> standalone + chained // smart: direct first, then the WARP chain
                }
                val ordered = if (selectedP?.transport == PSIPHON_AI_TRANSPORT) ai + base else base
                return ordered.filterNot { it.id in failedIds }.take(maxCandidates)
            }
            PROTO_TOR -> {
                val standalone = all.filter { it.fromSubscription == TOR_SOURCE && it.transport == TOR_TRANSPORT }
                val chained = all.filter { it.fromSubscription == TOR_SOURCE && it.transport == TOR_CHAIN_TRANSPORT }
                val ordered = when (network) {
                    NET_DIRECT -> standalone
                    // v1.7.3: same safety net as the Psiphon branch above
                    NET_MASQUE, NET_WG -> chained + standalone
                    else -> standalone + chained // smart: direct first, then the WARP chain
                }
                return ordered.filterNot { it.id in failedIds }.take(maxCandidates)
            }
        }

        // protocol = none: the plain-VPN WARP chain. The psiphon/tor profiles
        // are structurally OUT of this pool — "no protocol" can never end on a
        // protocol-core exit (the v1.6.1 honesty rule, now in the model itself).
        val goolProfiles = all.filter { isGool(it) }
        val pool = all.filterNot {
            isGool(it) || it.fromSubscription == PSIPHON_SOURCE || it.fromSubscription == TOR_SOURCE
        }
        if (pool.isEmpty()) return emptyList()
        val byId = pool.associateBy { it.id }
        val selected = selectedId?.let { byId[it] }
        val lastGood = store.lastGoodId.first()?.let { byId[it] }

        val pinned: List<Profile> = when (network) {
            NET_MASQUE -> pool.filter { isWarp(it) && isMasque(it) }
            NET_WG -> pool.filter { isWarp(it) && !isMasque(it) }
            NET_GOOL -> goolProfiles
            // smart (and a defensive direct→smart coercion — the UI never
            // offers Direct without a protocol core)
            else -> emptyList()
        }

        val base = if (pinned.isNotEmpty()) {
            // pin first, smart chain behind it as the safety net
            (pinned + rankSmart(pool, selected, lastGood)).distinctBy { it.id }
        } else {
            rankSmart(pool, selected, lastGood)
        }

        val ranked = base
            .filterNot { it.id in failedIds }
            .toMutableList()

        // per-network memory: lead with the profile that last verified on
        // THIS network class (wifi/cell) — even ahead of the transport rules
        val netLastGoodId = networkClass.takeIf { it == NETWORK_WIFI || it == NETWORK_CELL }
            ?.let { store.lastGoodForNetwork(it) }
        val netLastGood = netLastGoodId?.let { id -> ranked.firstOrNull { it.id == id } }
        if (netLastGood != null && ranked.firstOrNull()?.id != netLastGood.id) {
            ranked.removeAll { it.id == netLastGood.id }
            ranked.add(0, netLastGood)
        }
        return ranked.take(maxCandidates)
    }

    companion object {
        // literals mirror WarpRegistrar constants (kept here to avoid a core↔fallback cycle)
        private const val WARP_SOURCE = "warp"

        /**
         * v1.6.5 — ranked WireGuard-family candidates for the chained
         * UNDERLAY sidecar (WgSidecar): real WARP WireGuard registrations
         * only (no MASQUE-engine profiles, no gool doubles), lastGood first.
         * v1.6.7 field note: on the user's ISP the WireGuard wire gets reset
         * by the censor, so the sidecar is an explicit NETWORK=wg choice or
         * a smart-mode fallback leg — never the golden path (that is the
         * DIRECT protocol route now).
         */
        suspend fun wireguardUnderlayCandidates(store: ProfileStore, max: Int = 2): List<Profile> {
            val lastGood = runCatching { store.lastGoodId.first() }.getOrNull()
            return store.snapshot()
                .filter {
                    it.fromSubscription == WARP_SOURCE &&
                        it.type == app.kukuvpn.data.ProfileType.WIREGUARD &&
                        !it.transport.startsWith("masque") &&
                        it.transport != TRANSPORT_GOOL_WG
                }
                .sortedBy { it.id != lastGood } // lastGood first, order otherwise stable
                .take(max)
        }

        private const val WARP_GOOL_SOURCE = "warp-gool"
        private const val TRANSPORT_MASQUE = "masque"
        private const val TRANSPORT_MASQUE_H2 = "masque-h2"
        private const val TRANSPORT_GOOL_WG = "gool"

        // v1.6.7 protocol dimension values (AppSettings.protocol)
        const val PROTO_NONE = "none"
        const val PROTO_PSIPHON = "psiphon"
        const val PROTO_TOR = "tor"

        // v1.6.7 network dimension values (AppSettings.network)
        const val NET_SMART = "smart"
        const val NET_MASQUE = "masque"
        const val NET_WG = "wg"
        const val NET_GOOL = "gool"
        const val NET_DIRECT = "direct"

        // Psiphon backend markers (v1.5.0) — literals mirror PsiphonEngine
        private const val PSIPHON_SOURCE = "psiphon"
        private const val PSIPHON_TRANSPORT = "psiphon"
        private const val PSIPHON_CHAIN_TRANSPORT = "kuku-psiphon"
        // v1.7.4: the AI method's transport (US-egress Psiphon core)
        private const val PSIPHON_AI_TRANSPORT = "psiphon-ai"

        // Tor backend markers (v1.6.0) — literals mirror TorEngine
        private const val TOR_SOURCE = "tor"
        private const val TOR_TRANSPORT = "tor"
        private const val TOR_CHAIN_TRANSPORT = "kuku-tor"

        // network classes (per-network memory)
        const val NETWORK_WIFI = "wifi"
        const val NETWORK_CELL = "cell"
    }
}
