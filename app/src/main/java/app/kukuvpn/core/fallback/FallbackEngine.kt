package app.kukuvpn.core.fallback

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import kotlinx.coroutines.flow.first

/**
 * Builds the ranked chain of profiles to try when the selected one cannot
 * prove a real connection (RIX-style smart fallback).
 *
 * v1.3.0 — protocol-aware (the Aether-style Connection page):
 *
 *   smart (default) — the full ranked chain:
 *     1. MASQUE H2  (WARP over HTTP/2, TCP 443)   — survives full UDP filters
 *     2. MASQUE H3  (WARP over HTTP/3, UDP 443)
 *     3. plain WireGuard WARP ports
 *     4. everything else (user-imported servers, newest first)
 *
 *   masque — the MASQUE pair first, then the smart chain as a safety net
 *   wg     — the plain WireGuard WARP ports first, then the smart chain
 *   gool   — the WARP×2 inner-tunnel profile first, then the smart chain
 *   psiphon / kuku-psiphon — the bundled Psiphon core first (v1.5.0),
 *                            then the smart chain
 *
 * A pinned method that cannot connect must NEVER leave the app offline, so
 * every pin keeps the smart chain behind it — the pin decides what is tried
 * FIRST, not what is the only option.
 *
 * Per-network memory (the Aether "remembers which one worked on this
 * network" rule): when the store holds a profile that last VERIFIED on the
 * current network class (wifi vs cellular), it leads the chain regardless of
 * the transport heuristics — a profile proven on THIS network is a stronger
 * signal than any rule.
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
        protocol: String = PROTOCOL_SMART,
        networkClass: String = "",
        failedIds: Set<String> = emptySet(),
        maxCandidates: Int = 8,
    ): List<Profile> {
        val all = store.snapshot()
        if (all.isEmpty()) return emptyList()
        val byId = all.associateBy { it.id }
        val selected = selectedId?.let { byId[it] }
        val lastGood = store.lastGoodId.first()?.let { byId[it] }

        // gool profiles only ever appear when the user pinned the gool method
        val goolProfiles = all.filter { isGool(it) }
        val pool = all.filterNot { isGool(it) }

        val pinned: List<Profile> = when (protocol) {
            PROTOCOL_MASQUE -> pool.filter { isWarp(it) && isMasque(it) }
            PROTOCOL_WG -> pool.filter { isWarp(it) && !isMasque(it) }
            PROTOCOL_GOOL -> goolProfiles
            PROTOCOL_PSIPHON -> all.filter { it.fromSubscription == PSIPHON_SOURCE && it.transport == PSIPHON_TRANSPORT }
            PROTOCOL_KUKU_PSIPHON -> all.filter { it.fromSubscription == PSIPHON_SOURCE && it.transport == PSIPHON_CHAIN_TRANSPORT }
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
        private const val WARP_GOOL_SOURCE = "warp-gool"
        private const val TRANSPORT_MASQUE = "masque"
        private const val TRANSPORT_MASQUE_H2 = "masque-h2"
        private const val TRANSPORT_GOOL_WG = "gool"

        // protocol selector values (AppSettings.protocol)
        const val PROTOCOL_SMART = "smart"
        const val PROTOCOL_MASQUE = "masque"
        const val PROTOCOL_WG = "wg"
        const val PROTOCOL_GOOL = "gool"
        const val PROTOCOL_PSIPHON = "psiphon"
        const val PROTOCOL_KUKU_PSIPHON = "kuku-psiphon"

        // Psiphon backend markers (v1.5.0) — literals mirror PsiphonEngine
        private const val PSIPHON_SOURCE = "psiphon"
        private const val PSIPHON_TRANSPORT = "psiphon"
        private const val PSIPHON_CHAIN_TRANSPORT = "kuku-psiphon"

        // network classes (per-network memory)
        const val NETWORK_WIFI = "wifi"
        const val NETWORK_CELL = "cell"
    }
}
