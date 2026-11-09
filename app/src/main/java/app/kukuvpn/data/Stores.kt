package app.kukuvpn.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val Context.profileDataStore by preferencesDataStore("kuku_profiles")
private val Context.settingsDataStore by preferencesDataStore("kuku_settings")

private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

/* ------------------------------- Profiles -------------------------------- */

private object ProfileKeys {
    val LIST = stringPreferencesKey("profiles_json")
    val SELECTED = stringPreferencesKey("selected_id")
    val LAST_GOOD = stringPreferencesKey("last_good_id")
    val SUBSCRIPTIONS = stringSetPreferencesKey("subscription_urls")
    // "1" once the user deleted the auto-created free WARP profile — never re-create it
    val WARP_DELETED = stringPreferencesKey("warp_deleted")
}

class ProfileStore(private val context: Context) {

    val profiles: Flow<List<Profile>> = context.profileDataStore.data.map { prefs ->
        prefs[ProfileKeys.LIST]?.let { runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull() } ?: emptyList()
    }

    val selectedId: Flow<String?> = context.profileDataStore.data.map { it[ProfileKeys.SELECTED] }
    val lastGoodId: Flow<String?> = context.profileDataStore.data.map { it[ProfileKeys.LAST_GOOD] }
    val subscriptions: Flow<Set<String>> = context.profileDataStore.data.map { it[ProfileKeys.SUBSCRIPTIONS] ?: emptySet() }

    suspend fun snapshot(): List<Profile> = profiles.first()

    /** True when the user deleted the auto-created free WARP profile on purpose. */
    suspend fun isWarpDeleted(): Boolean =
        context.profileDataStore.data.map { it[ProfileKeys.WARP_DELETED] == "1" }.first()

    suspend fun addAll(newOnes: List<Profile>) {
        if (newOnes.isEmpty()) return
        context.profileDataStore.edit { prefs ->
            val existing = prefs[ProfileKeys.LIST]?.let {
                runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull()
            } ?: emptyList()
            // de-duplicate by (type, transport, host, port, uuid/password) so re-importing
            // a sub refreshes it.
            // BUG HISTORY (v1.2.6): transport was NOT part of this key, and the two
            // auto MASQUE profiles (masque-h2 / masque-h3) share type+host+port
            // (127.0.0.1:2085) and carry no keys — so every addAll() made them
            // OVERWRITE each other. The store flip-flopped between the two on every
            // app open, the fallback chain permanently ran with only ONE MASQUE
            // transport, and on ISPs that filter UDP the chain held no working
            // candidate at all (all WireGuard ports + H3 dead, H2/TCP-443 missing).
            val keyOf = { p: Profile ->
                "${p.type}|${p.transport}|${p.host}|${p.port}|${p.uuid}|${p.password}|${p.privateKey}"
            }
            val merged = (existing.associateBy(keyOf) + newOnes.associateBy(keyOf)).values
            prefs[ProfileKeys.LIST] = json.encodeToString(merged.toList())
            if (prefs[ProfileKeys.SELECTED] == null) prefs[ProfileKeys.SELECTED] = newOnes.first().id
        }
    }

    suspend fun delete(id: String) {
        context.profileDataStore.edit { prefs ->
            val list = prefs[ProfileKeys.LIST]?.let {
                runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull()
            } ?: emptyList()
            val removed = list.filter { it.id == id }
            val rest = list.filterNot { it.id == id }
            prefs[ProfileKeys.LIST] = json.encodeToString(rest)
            // deleting the last auto-created free WARP profile opts out of re-creating it
            // ("warp" literal = WarpRegistrar.WARP_SOURCE, kept literal to avoid a core→data cycle)
            if (removed.any { it.fromSubscription == "warp" } && rest.none { it.fromSubscription == "warp" }) {
                prefs[ProfileKeys.WARP_DELETED] = "1"
            }
            if (prefs[ProfileKeys.SELECTED] == id) {
                val next = rest.firstOrNull()?.id
                if (next == null) prefs.remove(ProfileKeys.SELECTED) else prefs[ProfileKeys.SELECTED] = next
            }
            if (prefs[ProfileKeys.LAST_GOOD] == id) prefs.remove(ProfileKeys.LAST_GOOD)
        }
    }

    /**
     * Bulk removal by predicate (used for migrating auto-managed WARP profiles).
     * Selection falls back to the first survivor so the UI always has a valid pick.
     */
    suspend fun removeMatching(predicate: (Profile) -> Boolean) {
        context.profileDataStore.edit { prefs ->
            val list = prefs[ProfileKeys.LIST]?.let {
                runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull()
            } ?: emptyList()
            val rest = list.filterNot(predicate)
            if (rest.size == list.size) return@edit
            prefs[ProfileKeys.LIST] = json.encodeToString(rest)
            val removedIds = list.filter(predicate).map { it.id }.toSet()
            if (prefs[ProfileKeys.SELECTED] in removedIds) {
                val next = rest.firstOrNull()?.id
                if (next == null) prefs.remove(ProfileKeys.SELECTED) else prefs[ProfileKeys.SELECTED] = next
            }
            if (prefs[ProfileKeys.LAST_GOOD] in removedIds) prefs.remove(ProfileKeys.LAST_GOOD)
        }
    }

    suspend fun select(id: String) = context.profileDataStore.edit { it[ProfileKeys.SELECTED] = id }
    suspend fun setLastGood(id: String) = context.profileDataStore.edit { it[ProfileKeys.LAST_GOOD] = id }

    suspend fun addSubscription(url: String) = context.profileDataStore.edit {
        it[ProfileKeys.SUBSCRIPTIONS] = (it[ProfileKeys.SUBSCRIPTIONS] ?: emptySet()) + url
    }

    suspend fun removeSubscription(url: String) = context.profileDataStore.edit {
        it[ProfileKeys.SUBSCRIPTIONS] = (it[ProfileKeys.SUBSCRIPTIONS] ?: emptySet()) - url
    }
}

/* ------------------------------- Settings -------------------------------- */

enum class SplitMode { ALL, INCLUDE, EXCLUDE }

data class AppSettings(
    val theme: Int = 0,             // 0 system, 1 light, 2 dark
    val language: String = "",      // "" system, "fa", "en"
    val splitMode: SplitMode = SplitMode.ALL,
    val splitApps: Set<String> = emptySet(),
    val killSwitch: Boolean = true,
    val autoFallback: Boolean = true,
    val subAutoUpdate: Boolean = true,
    val vpnMode: Boolean = true,    // true full-device VPN, false local proxy only
)

private object SettingsKeys {
    val THEME = stringPreferencesKey("theme")
    val LANGUAGE = stringPreferencesKey("language")
    val SPLIT_MODE = stringPreferencesKey("split_mode")
    val SPLIT_APPS = stringSetPreferencesKey("split_apps")
    val KILL_SWITCH = stringPreferencesKey("kill_switch")
    val AUTO_FALLBACK = stringPreferencesKey("auto_fallback")
    val SUB_AUTO_UPDATE = stringPreferencesKey("sub_auto_update")
    val VPN_MODE = stringPreferencesKey("vpn_mode")
}

class SettingsStore(private val context: Context) {

    val settings: Flow<AppSettings> = context.settingsDataStore.data.map { p ->
        AppSettings(
            theme = p[SettingsKeys.THEME]?.toIntOrNull() ?: 0,
            language = p[SettingsKeys.LANGUAGE] ?: "",
            splitMode = p[SettingsKeys.SPLIT_MODE]?.let { runCatching { SplitMode.valueOf(it) }.getOrNull() } ?: SplitMode.ALL,
            splitApps = p[SettingsKeys.SPLIT_APPS] ?: emptySet(),
            killSwitch = p[SettingsKeys.KILL_SWITCH]?.toBooleanStrictOrNull() ?: true,
            autoFallback = p[SettingsKeys.AUTO_FALLBACK]?.toBooleanStrictOrNull() ?: true,
            subAutoUpdate = p[SettingsKeys.SUB_AUTO_UPDATE]?.toBooleanStrictOrNull() ?: true,
            vpnMode = p[SettingsKeys.VPN_MODE]?.toBooleanStrictOrNull() ?: true,
        )
    }

    suspend fun snapshot(): AppSettings = settings.first()

    suspend fun setTheme(v: Int) = context.settingsDataStore.edit { it[SettingsKeys.THEME] = v.toString() }
    suspend fun setLanguage(v: String) = context.settingsDataStore.edit { it[SettingsKeys.LANGUAGE] = v }
    suspend fun setSplitMode(v: SplitMode) = context.settingsDataStore.edit { it[SettingsKeys.SPLIT_MODE] = v.name }
    suspend fun setSplitApps(v: Set<String>) = context.settingsDataStore.edit { it[SettingsKeys.SPLIT_APPS] = v }
    suspend fun setKillSwitch(v: Boolean) = context.settingsDataStore.edit { it[SettingsKeys.KILL_SWITCH] = v.toString() }
    suspend fun setAutoFallback(v: Boolean) = context.settingsDataStore.edit { it[SettingsKeys.AUTO_FALLBACK] = v.toString() }
    suspend fun setSubAutoUpdate(v: Boolean) = context.settingsDataStore.edit { it[SettingsKeys.SUB_AUTO_UPDATE] = v.toString() }
    suspend fun setVpnMode(v: Boolean) = context.settingsDataStore.edit { it[SettingsKeys.VPN_MODE] = v.toString() }
}
