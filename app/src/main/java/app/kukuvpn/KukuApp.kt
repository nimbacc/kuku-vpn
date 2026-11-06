package app.kukuvpn

import android.app.Application
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.SettingsStore

/**
 * Tiny service locator — two DataStore-backed repositories shared by the UI
 * and the tunnel service. No Hilt/DI framework on purpose: one app, two stores.
 */
class KukuApp : Application() {

    lateinit var profileStore: ProfileStore
        private set
    lateinit var settingsStore: SettingsStore
        private set

    override fun onCreate() {
        super.onCreate()
        profileStore = ProfileStore(this)
        settingsStore = SettingsStore(this)
    }
}
