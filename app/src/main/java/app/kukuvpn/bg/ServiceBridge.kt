package app.kukuvpn.bg

import android.content.Context
import android.content.Intent
import android.net.VpnService
import app.kukuvpn.data.Profile
import go.Seq
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.Connections
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Process-wide bridge between the UI and [KukuVpnService]. The service pushes
 * state/stats/logs into these flows; Compose screens collect them. Traffic
 * counters live on their own flow (the v1.0.7-style fix: a chatty stream must
 * never recompose the whole screen).
 *
 * Stats source in sing-box 1.11.x: there are NO uplink/downlink fields in
 * StatusMessage (those arrive in 1.12). Instead we run two libbox CommandClients:
 *  - CommandStatus     → connectionsIn/Out + memory, every statusInterval
 *  - CommandConnections → full connection list with per-connection
 *    uplinkTotal/downlinkTotal, summed here into session bytes.
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

    /* ------------------------- live stats clients ------------------------- */

    private val statsScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var statusClient: CommandClient? = null
    private var connectionsClient: CommandClient? = null
    private var sessionStartMs = 0L

    @Volatile private var totalsIn = 0L
    @Volatile private var totalsOut = 0L
    @Volatile private var connsIn = 0
    @Volatile private var connsOut = 0

    fun startStatsClients() {
        stopStatsClients()
        sessionStartMs = System.currentTimeMillis()
        totalsIn = 0; totalsOut = 0; connsIn = 0; connsOut = 0
        statusClient = connectClient(CommandStatusHandler())
        connectionsClient = connectClient(CommandConnectionsHandler())
    }

    fun stopStatsClients() {
        destroyClient(statusClient); statusClient = null
        destroyClient(connectionsClient); connectionsClient = null
    }

    private fun connectClient(handler: CommandClientHandler): CommandClient? {
        val options = CommandClientOptions().apply {
            command = if (handler is CommandConnectionsHandler) Libbox.CommandConnections else Libbox.CommandStatus
            statusInterval = 1_000_000_000L // 1 second, in nanoseconds
        }
        val client = CommandClient(handler, options)
        statsScope.launch {
            // the unix socket only exists after the core booted — retry like the official client
            for (i in 1..15) {
                delay(200L + i * 60L)
                try {
                    client.connect()
                } catch (ignored: Exception) {
                    continue
                }
                return@launch
            }
            runCatching { client.disconnect() }
        }
        return client
    }

    private fun destroyClient(client: CommandClient?) {
        if (client != null) {
            runCatching { client.disconnect() }
            runCatching { Seq.destroyRef(client.refnum) }
        }
    }

    private fun pushStats() {
        stats.value = SessionStats(
            bytesIn = totalsIn,
            bytesOut = totalsOut,
            uptimeSec = (System.currentTimeMillis() - sessionStartMs) / 1000,
            connectionsIn = connsIn.toLong(),
            connectionsOut = connsOut.toLong(),
        )
    }

    private class CommandStatusHandler : CommandClientHandler {
        override fun connected() {}
        override fun disconnected(message: String?) {}
        override fun clearLogs() {}
        override fun writeLogs(messageList: StringIterator?) {}
        override fun writeGroups(message: OutboundGroupIterator?) {}
        override fun writeConnections(message: Connections?) {}
        override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) {}
        override fun updateClashMode(newMode: String?) {}

        override fun writeStatus(message: StatusMessage) {
            ServiceBridge.connsIn = message.connectionsIn
            ServiceBridge.connsOut = message.connectionsOut
            ServiceBridge.pushStats()
        }
    }

    private class CommandConnectionsHandler : CommandClientHandler {
        override fun connected() {}
        override fun disconnected(message: String?) {}
        override fun clearLogs() {}
        override fun writeLogs(messageList: StringIterator?) {}
        override fun writeGroups(message: OutboundGroupIterator?) {}
        override fun writeStatus(message: StatusMessage) {}
        override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) {}
        override fun updateClashMode(newMode: String?) {}

        override fun writeConnections(message: Connections?) {
            if (message == null) return
            var din = 0L
            var dout = 0L
            val it = message.iterator()
            while (it.hasNext()) {
                val connection = it.next()
                din += connection.downlinkTotal
                dout += connection.uplinkTotal
            }
            ServiceBridge.totalsIn = din
            ServiceBridge.totalsOut = dout
            ServiceBridge.pushStats()
        }
    }
}
