package app.kukuvpn.bg

import android.content.ComponentName
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.kukuvpn.MainActivity
import app.kukuvpn.R

/**
 * v1.7.0 — the Quick Settings tile the user asked for: connect/disconnect
 * with one tap from the notification shade, without opening the app.
 *
 * The tile mirrors ServiceBridge.state (the same flow the UI reads), so it is
 * truthful even when the tunnel was started or stopped from inside the app.
 *
 * VPN permission cannot be requested from a tile (no activity in front) —
 * when the permission is missing the tap opens MainActivity, which runs the
 * regular permission flow, and the tile says "not ready" until then.
 */
class KukuTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        update()
    }

    override fun onClick() {
        super.onClick()
        val state = ServiceBridge.state.value
        when (state) {
            TunnelState.ACTIVE, TunnelState.CONNECTING, TunnelState.VERIFYING, TunnelState.PREPARING -> {
                ServiceBridge.disconnect(applicationContext)
            }
            TunnelState.OFF, TunnelState.ERROR -> {
                if (ServiceBridge.prepare(applicationContext) == null) {
                    ServiceBridge.connect(applicationContext)
                } else {
                    // open the app once so the user can grant VPN permission
                    openApp()
                }
            }
        }
        update()
    }

    private fun openApp() {
        val launch = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            val pi = android.app.PendingIntent.getActivity(
                this, 0, launch,
                android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(launch)
        }
    }

    private fun update() {
        val tile = qsTile ?: return
        val state = ServiceBridge.state.value
        when (state) {
            TunnelState.ACTIVE -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.state_active)
                }
            }
            TunnelState.CONNECTING, TunnelState.VERIFYING, TunnelState.PREPARING -> {
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.state_connecting)
                }
            }
            TunnelState.ERROR -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.state_error)
                }
            }
            TunnelState.OFF -> {
                tile.state = Tile.STATE_INACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.state_off)
                }
            }
        }
        runCatching { tile.icon = Icon.createWithResource(this, R.drawable.ic_tile) }
        tile.label = getString(R.string.app_name)
        tile.updateTile()
    }

    companion object {
        /** Optional external refresh (API 26+); the tile also refreshes itself
         *  every time the shade is opened (onStartListening). */
        fun requestUpdate(context: android.content.Context) {
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    TileService.requestUpdateTile(
                        context,
                        ComponentName(context, KukuTileService::class.java)
                    )
                }
            }
        }
    }
}
