package app.kukuvpn

import android.app.Application
import app.kukuvpn.bg.ServiceBridge
import app.kukuvpn.bg.TunnelState
import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.SettingsStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
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
        appScope.launch {
            WarpRegistrar.ensureProfile(this@KukuApp)
            prewarmEngine()
        }
    }

    /**
     * v1.2.4 prewarm: boot the WARP engine in the background the moment the
     * app opens, so the FIRST tap finds a warm, already-validated tunnel
     * instead of paying the cold endpoint sweep — the "first connect never
     * works until I kill and reopen the app" report, killed at the root.
     *
     * Only when the tunnel is OFF (never touch a live connection) and a
     * MASQUE WARP profile exists. Boot failures stay silent on purpose: the
     * connect flow retries with full logging and the fallback chain, and
     * WarpMasqueEngine.boot() is single-flight so a tap during the prewarm
     * simply waits for it.
     */
    private suspend fun prewarmEngine() {
        runCatching {
            if (ServiceBridge.state.value != TunnelState.OFF) return
            val hasMasque = profileStore.snapshot().any {
                it.fromSubscription == WarpRegistrar.WARP_SOURCE &&
                    it.transport.startsWith(WarpRegistrar.TRANSPORT_MASQUE)
            }
            if (hasMasque) {
                // v1.3.0: prewarm honors the user's scan mode
                val scanMode = settingsStore.settings.first().scanMode
                WarpMasqueEngine.prewarm(this, scanMode)
            }
        }
    }
}
