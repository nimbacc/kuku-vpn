package app.kukuvpn

import android.app.Application
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.SettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Tiny service locator — two DataStore-backed repositories shared by the UI
 * and the tunnel service. No Hilt/DI framework on purpose: one app, two stores.
 */
class KukuApp : Application() {

    lateinit var profileStore: ProfileStore
        private set
    lateinit var settingsStore: SettingsStore
        private set

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        profileStore = ProfileStore(this)
        settingsStore = SettingsStore(this)
        // One-tap free connect: make sure a Cloudflare WARP profile exists so the
        // app can connect without any user config. No-op when one is already
        // stored or when the user deleted it on purpose; retried on next start
        // if the registration fails (e.g. offline first launch).
        appScope.launch { WarpRegistrar.ensureProfile(this@KukuApp) }
    }
}
