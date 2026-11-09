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
    // v1.3.0 Aether-style memory: which profile last VERIFIED per network
    // class — wifi and cellular remember independently, so switching networks
    // still starts with the profile that worked THERE ("the next connect is
    // quick").
    val LAST_GOOD_WIFI = stringPreferencesKey("last_good_wifi")
    val LAST_GOOD_CELL = stringPreferencesKey("last_good_cell")
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

    /**
     * v1.3.0 per-network memory (Aether Smart-style). networkClass is
     * "wifi" or "cell" (empty/other classes fall back to the plain lastGood).
     */
    suspend fun setLastGoodForNetwork(networkClass: String, id: String) = context.profileDataStore.edit {
        when (networkClass) {
            "wifi" -> it[ProfileKeys.LAST_GOOD_WIFI] = id
            "cell" -> it[ProfileKeys.LAST_GOOD_CELL] = id
        }
    }

    suspend fun lastGoodForNetwork(networkClass: String): String? =
        context.profileDataStore.data.map { prefs ->
            when (networkClass) {
                "wifi" -> prefs[ProfileKeys.LAST_GOOD_WIFI]
                "cell" -> prefs[ProfileKeys.LAST_GOOD_CELL]
                else -> null
            }
        }.first()

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
    // v1.3.0 Connection page (Aether-style method selector):
    // "smart" (engine races TCP-443 + UDP-443 and the chain ranks everything)
    // "masque" (WARP over MASQUE only) · "wg" (plain WireGuard only)
    // "gool" (WARP×2, second tunnel inside the first — experimental)
    val protocol: String = "smart",
    // v1.3.0 Scan mode: "turbo" | "balanced" | "thorough" | "stealth" | "ironclad"
    // (stealth = no UDP at all — only MASQUE over plain TCP 443)
    val scanMode: String = "balanced",
    // v1.6.0 Psiphon exit country (ISO 3166-1 alpha-2) — "auto" = let the
    // core pick the best server anywhere (the core's own default)
    val psiphonRegion: String = "auto",
    // v1.6.0 Tor bridges: "auto" (bundled fresh obfs4+webtunnel snapshots),
    // "custom" (torCustomBridges), "none" (bridge-less, only for clean
    // networks where guards are reachable directly)
    val torBridgeMode: String = "auto",
    // user-pasted bridge lines for torBridgeMode == "custom"
    val torCustomBridges: String = "",
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
    val PROTOCOL = stringPreferencesKey("protocol")
    val SCAN_MODE = stringPreferencesKey("scan_mode")
    val PSIPHON_REGION = stringPreferencesKey("psiphon_region")
    val TOR_BRIDGE_MODE = stringPreferencesKey("tor_bridge_mode")
    val TOR_CUSTOM_BRIDGES = stringPreferencesKey("tor_custom_bridges")
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
            protocol = p[SettingsKeys.PROTOCOL] ?: "smart",
            scanMode = p[SettingsKeys.SCAN_MODE] ?: "balanced",
            psiphonRegion = p[SettingsKeys.PSIPHON_REGION] ?: "auto",
            torBridgeMode = p[SettingsKeys.TOR_BRIDGE_MODE] ?: "auto",
            torCustomBridges = p[SettingsKeys.TOR_CUSTOM_BRIDGES] ?: "",
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
    suspend fun setProtocol(v: String) = context.settingsDataStore.edit { it[SettingsKeys.PROTOCOL] = v }
    suspend fun setScanMode(v: String) = context.settingsDataStore.edit { it[SettingsKeys.SCAN_MODE] = v }
    suspend fun setPsiphonRegion(v: String) = context.settingsDataStore.edit { it[SettingsKeys.PSIPHON_REGION] = v }
    suspend fun setTorBridgeMode(v: String) = context.settingsDataStore.edit { it[SettingsKeys.TOR_BRIDGE_MODE] = v }
    suspend fun setTorCustomBridges(v: String) = context.settingsDataStore.edit { it[SettingsKeys.TOR_CUSTOM_BRIDGES] = v }
}
