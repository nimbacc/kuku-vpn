package app.kukuvpn.bg

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import app.kukuvpn.MainActivity
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.core.config.SingBoxConfigBuilder
import app.kukuvpn.core.fallback.FallbackEngine
import app.kukuvpn.core.verify.ConnectionVerifier
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.SettingsStore
import io.nekohasekai.libbox.BoxOptions
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LogMessage
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.WIFIState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The whole engine: runs libbox (sing-box) with an Android VPN interface,
 * verifies the tunnel with a real request, and applies RIX-style fallback.
 *
 * libbox API reference: sing-box 1.11.x, pkg io.nekohasekai.libbox (gomobile).
 * If a future libbox bump changes interface members, the Gradle error lists
 * them — see docs/BUILD-TROUBLESHOOTING.md for the 2-minute fix.
 */
class KukuVpnService : AndroidVpnService(), PlatformInterface, CommandServerHandler {

    companion object {
        const val ACTION_START = "app.kukuvpn.action.START"
        const val ACTION_STOP = "app.kukuvpn.action.STOP"
        private const val CHANNEL_ID = "tunnel"
        private const val NOTIF_ID = 100
        private const val MAX_CANDIDATES = 3
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stopping = AtomicBoolean(false)
    private val coreAlive = AtomicBoolean(false)

    private lateinit var profileStore: ProfileStore
    private lateinit var settingsStore: SettingsStore
    private var settings: AppSettings = AppSettings()

    private var commandServer: CommandServer? = null
    private var boxService: BoxService? = null
    private var tunPfd: ParcelFileDescriptor? = null

    /* ----------------------------- lifecycle ------------------------------ */

    override fun onCreate() {
        super.onCreate()
        val app = application as KukuApp
        profileStore = app.profileStore
        settingsStore = app.settingsStore
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> scope.launch { stopTunnel(clean = true) }
            else -> scope.launch { runTunnel() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    /* ------------------------------ the engine ---------------------------- */

    private suspend fun runTunnel() {
        if (ServiceBridge.state.value !in setOf(TunnelState.OFF, TunnelState.ERROR)) {
            if (ServiceBridge.isBusy) return // second tap while connecting = cancel (handled below)
            return
        }
        stopping.set(false)
        settings = settingsStore.snapshot()
        startNotif(getString(R.string.notif_connecting), ongoing = true)

        ServiceBridge.resetSession()
        ServiceBridge.state.value = TunnelState.PREPARING

        val chain = buildChain()
        if (chain.isEmpty()) {
            fail("no profile available")
            return
        }

        val failed = mutableSetOf<String>()
        for (candidate in chain) {
            if (stopping.get()) return
            ServiceBridge.activeProfile.value = candidate
            ServiceBridge.log("INFO", "trying profile: ${candidate.name} (${candidate.summary()})")
            ServiceBridge.state.value = TunnelState.CONNECTING
            try {
                startCore(candidate)
                ServiceBridge.lit(TunnelStage.CORE)

                waitListener()
                ServiceBridge.lit(TunnelStage.LISTENER)

                ServiceBridge.state.value = TunnelState.VERIFYING
                val verdict = ConnectionVerifier.verify()
                if (!verdict.ok) error("verification failed: ${verdict.reason}")

                ServiceBridge.lit(TunnelStage.TUNNEL)
                ServiceBridge.lit(TunnelStage.EXIT)
                ServiceBridge.exitIp.value = verdict.exitIp
                ServiceBridge.state.value = TunnelState.ACTIVE
                profileStore.select(candidate.id)
                profileStore.setLastGood(candidate.id)
                coreAlive.set(true)
                startNotif(
                    getString(R.string.notif_active) +
                        (verdict.exitIp.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""),
                    ongoing = true,
                )
                ServiceBridge.log("INFO", "tunnel verified, exit=${verdict.exitIp.ifBlank { "?" }} latency=${verdict.latencyMs}ms")
                return
            } catch (e: Exception) {
                ServiceBridge.log("ERROR", "${candidate.name}: ${e.message}")
                failed += candidate.id
                stopCore()
            }
        }

        if (settings.autoFallback && chain.size > failed.size) return // unreachable, kept for clarity
        fail("all ${chain.size} candidate(s) failed")
    }

    private suspend fun buildChain(): List<Profile> {
        val selectedId = profileStore.selectedId.first()
        return if (settings.autoFallback) {
            FallbackEngine(profileStore).chain(selectedId, maxCandidates = MAX_CANDIDATES)
        } else {
            profileStore.snapshot().filter { it.id == selectedId }
        }
    }

    private suspend fun startCore(profile: Profile) {
        stopCore()
        if (commandServer == null) {
            commandServer = Libbox.newCommandServer(this, filesDir.absolutePath, 0)
            commandServer?.start()
        }
        val config = SingBoxConfigBuilder.build(profile, settings)
        val options = BoxOptions().apply {
            setConfig(config)
            setWorkingDir(filesDir.absolutePath)
            setPlatformInterface(this@KukuVpnService)
            setCommandServer(commandServer)
        }
        boxService = Libbox.newBoxService(options)
        boxService?.start() // throws if the core cannot boot (bad config, port busy…)
    }

    /** The listener stage needs evidence: does 127.0.0.1:2080 accept? (≤15s) */
    private suspend fun waitListener() {
        repeat(30) {
            if (stopping.get()) throw InterruptedException("cancelled")
            val open = runCatching {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress("127.0.0.1", SingBoxConfigBuilder.PROXY_PORT), 400)
                    true
                }
            }.getOrDefault(false)
            if (open) return
            delay(500)
        }
        error("core listener did not open within 15s")
    }

    private fun fail(message: String) {
        ServiceBridge.state.value = TunnelState.ERROR
        ServiceBridge.lastError.value = message
        ServiceBridge.log("ERROR", message)
        scope.launch {
            stopCore()
            // Kill-switch behaviour: if a tunnel was actually established and
            // the user wants protection, the VPN interface stays up so traffic
            // blackholes instead of leaking. Only the notification changes.
            if (!settings.killSwitch || tunPfd == null || !settings.vpnMode) {
                withContext(Dispatchers.Main) {
                    startNotif(getString(R.string.state_error), ongoing = false)
                    stopForeground(ServiceInfo.STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            } else {
                startNotif(getString(R.string.notif_kill_switch), ongoing = true)
            }
        }
    }

    private fun stopCore() {
        coreAlive.set(false)
        runCatching { boxService?.close() }.onFailure { ServiceBridge.log("WARN", "close core: ${it.message}") }
        boxService = null
    }

    private suspend fun stopTunnel(clean: Boolean) {
        stopping.set(true)
        stopCore()
        runCatching { commandServer?.close() }
        commandServer = null
        runCatching { tunPfd?.close() }
        tunPfd = null
        ServiceBridge.state.value = TunnelState.OFF
        ServiceBridge.resetSession()
        if (clean) {
            withContext(Dispatchers.Main) {
                stopForeground(ServiceInfo.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /* ---------------------- libbox.PlatformInterface ----------------------- */

    override fun openTun(options: TunOptions): Int {
        val builder = Builder()
        builder.setSession("Kuku VPN")
        builder.setMtu(options.mtu.takeIf { it > 0 } ?: 9000)

        var hasAddress = false
        options.inet4Address.each { cidr -> hasAddress = addAddress(builder, cidr) || hasAddress }
        options.inet6Address.each { cidr -> hasAddress = addAddress(builder, cidr) || hasAddress }
        if (!hasAddress) builder.addAddress("172.19.0.1", 30)

        var hasRoute = false
        options.routes.each { cidr -> hasRoute = addRoute(builder, cidr) || hasRoute }
        if (!hasRoute) {
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }
        options.dnsServerAddresses.each { runCatching { builder.addDnsServer(it) } }

        applySplitTunnel(builder)

        val pfd = builder.establish()
            ?: throw IllegalStateException("establish() returned null (VPN permission/always-on conflict)")
        tunPfd = pfd
        return pfd.detachFd()
    }

    private fun applySplitTunnel(builder: Builder) {
        val self = packageName
        when (settings.splitMode) {
            app.kukuvpn.data.SplitMode.ALL -> runCatching { builder.addDisallowedApplication(self) }
            app.kukuvpn.data.SplitMode.INCLUDE ->
                settings.splitApps.forEach { runCatching { builder.addAllowedApplication(it) } }
            app.kukuvpn.data.SplitMode.EXCLUDE ->
                (settings.splitApps + self).forEach { runCatching { builder.addDisallowedApplication(it) } }
        }
    }

    private fun addAddress(builder: Builder, cidr: String): Boolean = runCatching {
        val ip = cidr.substringBefore('/')
        val prefix = cidr.substringAfter('/', "32").toIntOrNull() ?: 32
        builder.addAddress(ip, prefix)
        true
    }.getOrDefault(false)

    private fun addRoute(builder: Builder, cidr: String): Boolean = runCatching {
        val ip = cidr.substringBefore('/')
        val prefix = cidr.substringAfter('/', "0").toIntOrNull() ?: 0
        builder.addRoute(ip, prefix)
        true
    }.getOrDefault(false)

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        runCatching { protect(fd) }
    }

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String?,
        sourcePort: Int,
        destinationAddress: String?,
        destinationPort: Int,
    ): ConnectionOwner = throw UnsupportedOperationException("per-connection owner is not supported")

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) = Unit
    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) = Unit

    override fun getInterfaces(): NetworkInterfaceIterator = object : NetworkInterfaceIterator {
        override fun hasNext(): Boolean = false
        override fun next(): io.nekohasekai.libbox.NetworkInterface =
            throw NoSuchElementException("no interfaces")
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun clearDNSCache() = Unit
    override fun readWIFIState(): WIFIState? = null
    override fun localDNSTransport(): io.nekohasekai.libbox.LocalDNSTransport? = null

    /* --------------------- libbox.CommandServerHandler --------------------- */

    override fun writeLogs(message: LogMessage) {
        ServiceBridge.log(message.level ?: "INFO", message.message ?: "")
    }

    override fun writeStatus(message: StatusMessage) {
        // counters flow on their own stream — screens that need them subscribe directly
        ServiceBridge.stats.value = SessionStats(
            bytesIn = message.`in`,
            bytesOut = message.out,
            uptimeSec = message.uptime,
            connectionsIn = message.connectionsIn,
            connectionsOut = message.connectionsOut,
        )
    }

    override fun connected() = Unit
    override fun disConnected() = Unit
    override fun postServiceClose() = Unit

    override fun serviceStop() {
        // the core asked to stop (config reload, fatal error, or it simply died)
        scope.launch {
            ServiceBridge.log("WARN", "core stopped")
            if (settings.killSwitch && settings.vpnMode && tunPfd != null &&
                ServiceBridge.state.value == TunnelState.ACTIVE && !stopping.get()
            ) {
                // unexpected death: keep the (now dead-end) VPN interface up → no leak
                ServiceBridge.state.value = TunnelState.ERROR
                ServiceBridge.lastError.value = "tunnel lost (kill switch active)"
                startNotif(getString(R.string.notif_kill_switch), ongoing = true)
            } else {
                stopTunnel(clean = true)
            }
        }
    }

    override fun serviceReload() = Unit

    override fun getSystemProxyStatus(): SystemProxyStatus? = null
    override fun setSystemProxyEnabled(enabled: Boolean) = Unit

    /* --------------------------- notification ------------------------------ */

    private suspend fun startNotif(text: String, ongoing: Boolean) {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val contentIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, KukuVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync) // replace with a proper vector in v1.1
            .setContentTitle("Kuku VPN")
            .setContentText(text)
            .setContentIntent(contentIntent)
            .addAction(0, getString(R.string.notif_action_stop), stopIntent)
            .setOngoing(ongoing)
            .build()
        withContext(Dispatchers.Main) {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, notif)
            }
        }
    }
}

/** gomobile StringIterator is a plain java Iterator — small sugar for Kotlin. */
private inline fun StringIterator?.each(action: (String) -> Unit) {
    if (this == null) return
    while (hasNext()) action(next())
}
