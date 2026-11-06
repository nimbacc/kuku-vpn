package app.kukuvpn.bg

import android.content.Context
import android.content.Intent
import android.net.VpnService
import app.kukuvpn.data.Profile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Process-wide bridge between the UI and [KukuVpnService]. The service pushes
 * state/stats/logs into these flows; Compose screens collect them. Traffic
 * counters live on their own flow (the v1.0.7-style fix: a chatty stream must
 * never recompose the whole screen).
 */
object ServiceBridge {

    val state = MutableStateFlow(TunnelState.OFF)
    val stages = MutableStateFlow<Set<TunnelStage>>(emptySet())
    val stats = MutableStateFlow(SessionStats())
    val exitIp = MutableStateFlow("")
    val activeProfile = MutableStateFlow<Profile?>(null)
    val lastError = MutableStateFlow<String?>(null)
    val logs = MutableStateFlow<List<LogLine>>(emptyList())

    val isBusy: Boolean get() = state.value in setOf(TunnelState.CONNECTING, TunnelState.VERIFYING, TunnelState.PREPARING)

    fun resetSession() {
        stages.value = emptySet()
        stats.value = SessionStats()
        exitIp.value = ""
        activeProfile.value = null
        lastError.value = null
    }

    fun lit(stage: TunnelStage) {
        stages.value = stages.value + stage
    }

    fun log(level: String, message: String) {
        val line = LogLine(level = level.uppercase(), message = message)
        logs.value = (logs.value + line).takeLast(500)
    }

    fun clearLogs() {
        logs.value = emptyList()
    }

    /** Returns an Intent to launch when VPN permission is missing, else null. */
    fun prepare(context: Context): Intent? = VpnService.prepare(context)

    fun connect(context: Context) {
        val intent = Intent(context, KukuVpnService::class.java).setAction(KukuVpnService.ACTION_START)
        context.startForegroundService(intent)
    }

    fun disconnect(context: Context) {
        val intent = Intent(context, KukuVpnService::class.java).setAction(KukuVpnService.ACTION_STOP)
        context.startService(intent)
    }
}
