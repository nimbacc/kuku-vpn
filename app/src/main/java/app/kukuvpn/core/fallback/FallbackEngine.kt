package app.kukuvpn.core.fallback

import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import kotlinx.coroutines.flow.first

/**
 * Builds the ranked chain of profiles to try when the selected one cannot
 * prove a real connection (RIX-style smart fallback):
 *
 *   1. the profile the user picked
 *   2. the last profile that previously verified successfully
 *   3. every remaining profile, most recently added first
 *
 * The winner is remembered via [ProfileStore.setLastGood] so the next
 * connect is fast.
 */
class FallbackEngine(private val store: ProfileStore) {

    suspend fun chain(selectedId: String?, failedIds: Set<String> = emptySet(), maxCandidates: Int = 3): List<Profile> {
        val all = store.snapshot()
        if (all.isEmpty()) return emptyList()
        val byId = all.associateBy { it.id }
        val ranked = buildList {
            selectedId?.let { byId[it]?.let(::add) }
            store.lastGoodId.first()?.let { byId[it]?.let(::add) }
            addAll(all.sortedByDescending { it.createdAt })
        }.distinctBy { it.id }.filterNot { it.id in failedIds }
        return ranked.take(maxCandidates)
    }
}
