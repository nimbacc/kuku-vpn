package app.kukuvpn.core.fallback

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import kotlinx.coroutines.flow.first

/**
 * Builds the ranked chain of profiles to try when the selected one cannot
 * prove a real connection (RIX-style smart fallback).
 *
 * WARP-aware ordering (the "open the app, tap once, it just works" rule):
 *
 *   1. MASQUE H2  (WARP over HTTP/2, TCP 443)   — survives full UDP filters
 *   2. MASQUE H3  (WARP over HTTP/3, UDP 443)
 *   3. plain WireGuard WARP ports
 *   4. everything else (user-imported servers, newest first)
 *
 * The user's selected profile still leads the chain EXCEPT when it is a plain
 * WireGuard WARP profile while a MASQUE candidate exists: hostile ISPs filter
 * WireGuard UDP first, so putting it first would burn a minute of CONNECTING
 * before the path that actually works is even tried.
 *
 * The winner is remembered via [ProfileStore.setLastGood] so the next
 * connect is fast.
 */
class FallbackEngine(private val store: ProfileStore) {

    private fun isWarp(p: Profile) = p.fromSubscription == WARP_SOURCE
    private fun isMasque(p: Profile) = isWarp(p) && p.transport.startsWith("masque")

    private fun warpRank(p: Profile): Int = when {
        p.transport == TRANSPORT_MASQUE_H2 -> 0
        p.transport == TRANSPORT_MASQUE -> 1
        else -> 2
    }

    suspend fun chain(selectedId: String?, failedIds: Set<String> = emptySet(), maxCandidates: Int = 8): List<Profile> {
        val all = store.snapshot()
        if (all.isEmpty()) return emptyList()
        val byId = all.associateBy { it.id }
        val selected = selectedId?.let { byId[it] }
        val lastGood = store.lastGoodId.first()?.let { byId[it] }

        val masqueH2 = all.firstOrNull { isWarp(it) && it.transport == TRANSPORT_MASQUE_H2 }
        val masqueH3 = all.firstOrNull { isWarp(it) && it.transport == TRANSPORT_MASQUE }

        // demote a plain-WireGuard WARP selection behind the MASQUE pair
        val demoteSelected =
            selected != null && isWarp(selected) && !isMasque(selected) && masqueH2 != null

        val ranked = buildList {
            if (!demoteSelected) selected?.let(::add)
            masqueH2?.let(::add)
            masqueH3?.let(::add)
            if (demoteSelected) selected?.let(::add)
            lastGood?.let(::add)
            addAll(all.sortedByDescending { it.createdAt })
        }
            .distinctBy { it.id }
            .filterNot { it.id in failedIds }
            .toMutableList()

        // stable-sort only the WARP block: h2 → h3 → plain wireguard, so the
        // four port variants keep their own order behind the MASQUE pair
        ranked.sortWith { a, b ->
            if (isWarp(a) && isWarp(b)) warpRank(a) - warpRank(b) else 0
        }
        return ranked.take(maxCandidates)
    }

    companion object {
        // literals mirror WarpRegistrar constants (kept here to avoid a core↔fallback cycle)
        private const val WARP_SOURCE = "warp"
        private const val TRANSPORT_MASQUE = "masque"
        private const val TRANSPORT_MASQUE_H2 = "masque-h2"
    }
}
