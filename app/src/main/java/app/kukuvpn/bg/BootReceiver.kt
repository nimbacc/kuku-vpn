package app.kukuvpn.bg

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Boot hook. Intentionally inert in v1.0: auto-connect after boot only makes
 * sense together with the system Always-on VPN setting, and silently starting
 * a tunnel without asking is bad manners. Wire it up when adding a
 * "connect on boot" setting.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // reserved for future "connect on boot" setting
    }
}
