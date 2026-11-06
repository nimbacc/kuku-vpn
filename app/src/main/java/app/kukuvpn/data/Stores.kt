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
}

class ProfileStore(private val context: Context) {

    val profiles: Flow<List<Profile>> = context.profileDataStore.data.map { prefs ->
        prefs[ProfileKeys.LIST]?.let { runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull() } ?: emptyList()
    }

    val selectedId: Flow<String?> = context.profileDataStore.data.map { it[ProfileKeys.SELECTED] }
    val lastGoodId: Flow<String?> = context.profileDataStore.data.map { it[ProfileKeys.LAST_GOOD] }
    val subscriptions: Flow<Set<String>> = context.profileDataStore.data.map { it[ProfileKeys.SUBSCRIPTIONS] ?: emptySet() }

    suspend fun snapshot(): List<Profile> = profiles.first()

    suspend fun addAll(newOnes: List<Profile>) {
        if (newOnes.isEmpty()) return
        context.profileDataStore.edit { prefs ->
            val existing = prefs[ProfileKeys.LIST]?.let {
                runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull()
            } ?: emptyList()
            // de-duplicate by (type, host, port, uuid/password) so re-importing a sub refreshes it
            val keyOf = { p: Profile -> "${p.type}|${p.host}|${p.port}|${p.uuid}|${p.password}|${p.privateKey}" }
            val merged = (existing.associateBy { keyOf(it) } + newOnes.associateBy { keyOf(it) }).values
            prefs[ProfileKeys.LIST] = json.encodeToString(merged.toList())
            if (prefs[ProfileKeys.SELECTED] == null) prefs[ProfileKeys.SELECTED] = newOnes.first().id
        }
    }

    suspend fun delete(id: String) {
        context.profileDataStore.edit { prefs ->
            val list = prefs[ProfileKeys.LIST]?.let {
                runCatching { json.decodeFromString<List<Profile>>(it) }.getOrNull()
            } ?: emptyList()
            val rest = list.filterNot { it.id == id }
            prefs[ProfileKeys.LIST] = json.encodeToString(rest)
            if (prefs[ProfileKeys.SELECTED] == id) prefs[ProfileKeys.SELECTED] = rest.firstOrNull()?.id
            if (prefs[ProfileKeys.LAST_GOOD] == id) prefs.remove(ProfileKeys.LAST_GOOD)
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
