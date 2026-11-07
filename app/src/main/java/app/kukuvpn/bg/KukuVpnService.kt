package app.kukuvpn.bg

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import app.kukuvpn.MainActivity
import app.kukuvpn.KukuApp
import app.kukuvpn.R
import app.kukuvpn.core.config.SingBoxConfigBuilder
import app.kukuvpn.core.fallback.FallbackEngine
import app.kukuvpn.core.verify.ConnectionVerifier
import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.ProfileType
import app.kukuvpn.data.SettingsStore
import go.Seq
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.SystemProxyStatus
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface as JNetworkInterface
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The whole engine: runs libbox (sing-box 1.11.x) with an Android VPN interface,
 * verifies the tunnel with a real request, and applies RIX-style fallback.
 *
 * Signatures follow the REAL generated AAR (javap of libbox.aar from CI):
 *  - core service is created with Libbox.newService(configJson, platformInterface)
 *  - command server is CommandServer(handler, maxLines)
 *  - PlatformInterface has 15 members incl. writeLog/sendNotification
 *  - CommandServerHandler has exactly 4 members (serviceReload, postServiceClose,
 *    getSystemProxyStatus, setSystemProxyEnabled) — UI-side callbacks live in
 *    CommandClientHandler (see ServiceBridge).
 */
class KukuVpnService : AndroidVpnService(), PlatformInterface {

    companion object {
        const val ACTION_START = "app.kukuvpn.action.START"
        const val ACTION_STOP = "app.kukuvpn.action.STOP"
        private const val CHANNEL_ID = "tunnel"
        private const val CORE_NOTIF_CHANNEL = "core"
        private const val NOTIF_ID = 100
        private const val MAX_CANDIDATES = 6

        /**
         * Cloudflare WARP anycast IPs. ISPs in Iran filter them selectively
         * (162.159.x is the classic engage range, 188.114.x is the alternate
         * range many Iranian users still reach), so every WARP candidate is
         * swept across all of them before the next port variant is tried.
         * Verified live with sing-box 1.11.15: all four establish tunnels.
         */
        private val WARP_ENDPOINT_IPS = listOf(
            "162.159.192.1", "162.159.193.10", "188.114.97.1", "188.114.96.1",
        )

        @Volatile private var libboxReady = false
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val stopping = AtomicBoolean(false)

    private lateinit var profileStore: ProfileStore
    private lateinit var settingsStore: SettingsStore
    private var settings: AppSettings = AppSettings()

    private var commandServer: CommandServer? = null
    private var boxService: BoxService? = null
    private var tunPfd: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** Core → app service callbacks. Only these four exist in libbox 1.11.x. */
    private val serverHandler = object : CommandServerHandler {
        override fun serviceReload() {
            // the core asked for a reload (e.g. config touched) — restart the tunnel
            scope.launch {
                ServiceBridge.log("INFO", "core requested reload")
                val last = ServiceBridge.activeProfile.value
                if (last != null) {
                    runCatching { stopCore() }
                    runTunnelWith(last)
                }
            }
        }

        override fun postServiceClose() {
            // not used on Android (same as the official client)
        }

        override fun getSystemProxyStatus(): SystemProxyStatus =
            SystemProxyStatus().apply { available = false; enabled = false }

        override fun setSystemProxyEnabled(enabled: Boolean) = Unit
    }

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

    override fun onRevoke() {
        // VPN permission revoked or another VPN took over — tear everything down
        scope.launch { stopTunnel(clean = true) }
        super.onRevoke()
    }

    /* ------------------------------ the engine ---------------------------- */

    private suspend fun runTunnel() {
        if (ServiceBridge.state.value !in setOf(TunnelState.OFF, TunnelState.ERROR)) {
            if (ServiceBridge.isBusy) return // second tap while connecting = ignored
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

        var lastCandidateError: String? = null
        for (candidate in chain) {
            if (stopping.get()) return
            ServiceBridge.activeProfile.value = candidate
            ServiceBridge.log("INFO", "trying profile: ${candidate.name} (${candidate.summary()})")
            ServiceBridge.state.value = TunnelState.CONNECTING

            // MASQUE candidates boot the in-process engine first; the endpoint
            // sweep only applies to plain WireGuard candidates.
            val isMasque = candidate.type == ProfileType.WIREGUARD &&
                candidate.transport.startsWith("masque")
            if (isMasque) {
                // Registration/tunnel boot throws on failure (e.g. CF API
                // unreachable) — treat it like any other candidate error and
                // fall through to the next candidate instead of killing the
                // whole connection chain.
                try {
                    ServiceBridge.log("INFO", "booting WARP MASQUE engine (${candidate.transport})")
                    WarpMasqueEngine.ensureRegistered(this)
                    WarpMasqueEngine.start(
                        this,
                        useHttp2 = candidate.transport == WarpRegistrar.TRANSPORT_MASQUE_H2,
                    ) // blocking; throws with the engine's real error on failure
                    ServiceBridge.log("INFO", "WARP MASQUE engine ready (socks 127.0.0.1:${WarpMasqueEngine.SOCKS_PORT})")
                } catch (e: Exception) {
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: MASQUE engine: ${e.message}")
                    continue
                }
            }

            // WARP candidates sweep every known anycast IP — the identity is
            // identical, only the UDP endpoint changes, so no re-registration.
            val endpoints = if (candidate.fromSubscription == WarpRegistrar.WARP_SOURCE && !isMasque)
                (listOf(candidate.host) + WARP_ENDPOINT_IPS).distinct()
            else listOf(candidate.host)

            var lastError: Exception? = null
            for (ip in endpoints) {
                if (stopping.get()) return
                val attempt = if (ip == candidate.host) candidate else candidate.copy(host = ip)
                ServiceBridge.log("INFO", "endpoint ${attempt.host}:${attempt.port}")
                try {
                    startCore(attempt)
                    ServiceBridge.lit(TunnelStage.CORE)

                    waitListener()
                    ServiceBridge.lit(TunnelStage.LISTENER)

                    ServiceBridge.state.value = TunnelState.VERIFYING
                    // tries=1 → fast sweep (each probe still hits 2 HTTPS URLs);
                    // a false negative just moves on to the next endpoint.
                    val verdict = ConnectionVerifier.verify(tries = 1)
                    if (!verdict.ok) error("verification failed: ${verdict.reason}")

                    ServiceBridge.lit(TunnelStage.TUNNEL)
                    ServiceBridge.lit(TunnelStage.EXIT)
                    ServiceBridge.exitIp.value = verdict.exitIp
                    ServiceBridge.state.value = TunnelState.ACTIVE
                    profileStore.select(candidate.id)
                    profileStore.setLastGood(candidate.id)
                    ServiceBridge.startStatsClients()
                    startNotif(
                        getString(R.string.notif_active) +
                            (verdict.exitIp.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""),
                        ongoing = true,
                    )
                    ServiceBridge.log(
                        "INFO",
                        "tunnel verified via ${attempt.host}:${attempt.port}, " +
                            "exit=${verdict.exitIp.ifBlank { "?" }} latency=${verdict.latencyMs}ms"
                    )
                    return
                } catch (e: Exception) {
                    lastError = e
                    ServiceBridge.log("ERROR", "${candidate.name} @ ${attempt.host}:${attempt.port}: ${e.message}")
                    if (isMasque) WarpMasqueEngine.stop()
                    stopCore()
                }
            }
            lastCandidateError = lastError?.message
        }

        // surface the real cause on the Home card, not just the count
        fail(
            "all ${chain.size} candidate(s) failed" +
                (lastCandidateError?.let { " — last: $it" } ?: "")
        )
    }

    /** Used by serviceReload() to bounce a single profile without the fallback chain. */
    private suspend fun runTunnelWith(profile: Profile) {
        ServiceBridge.state.value = TunnelState.CONNECTING
        try {
            startCore(profile)
            waitListener()
            ServiceBridge.state.value = TunnelState.ACTIVE
        } catch (e: Exception) {
            ServiceBridge.log("ERROR", "reload failed: ${e.message}")
            stopCore()
            fail(e.message ?: "reload failed")
        }
    }

    private suspend fun buildChain(): List<Profile> {
        val selectedId = profileStore.selectedId.first()
        return if (settings.autoFallback) {
            FallbackEngine(profileStore).chain(selectedId, maxCandidates = MAX_CANDIDATES)
        } else {
            profileStore.snapshot().filter { it.id == selectedId }
        }
    }

    private fun ensureLibbox() {
        if (libboxReady) return
        val baseDir = filesDir
        baseDir.mkdirs()
        val workingDir = getExternalFilesDir(null) ?: filesDir
        workingDir.mkdirs()
        val tempDir = cacheDir
        tempDir.mkdirs()
        Libbox.setup(SetupOptions().also {
            it.basePath = baseDir.absolutePath
            it.workingPath = workingDir.absolutePath
            it.tempPath = tempDir.absolutePath
            it.fixAndroidStack = false
        })
        runCatching { Libbox.redirectStderr(File(workingDir, "stderr.log").absolutePath) }
        libboxReady = true
    }

    private suspend fun startCore(profile: Profile) {
        stopCore()
        ensureLibbox()
        if (commandServer == null) {
            val server = CommandServer(serverHandler, 300)
            server.start()
            commandServer = server
        }
        val config = SingBoxConfigBuilder.build(profile, settings) // JSON string
        val service = Libbox.newService(config, this) // throws on bad config
        service.start() // throws if the core cannot boot (port busy, missing fields…)
        boxService = service
        commandServer?.setService(service)
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
        ServiceBridge.stopStatsClients()
        scope.launch {
            stopCore()
            WarpMasqueEngine.stop()
            // Kill-switch behaviour: if a tunnel was actually established and
            // the user wants protection, the VPN interface stays up so traffic
            // blackholes instead of leaking. Only the notification changes.
            if (!settings.killSwitch || tunPfd == null || !settings.vpnMode) {
                withContext(Dispatchers.Main) {
                    startNotif(getString(R.string.state_error), ongoing = false)
                    ServiceCompat.stopForeground(this@KukuVpnService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            } else {
                startNotif(getString(R.string.notif_kill_switch), ongoing = true)
            }
        }
    }

    private fun stopCore() {
        val service = boxService
        boxService = null
        commandServer?.setService(null)
        if (service != null) {
            runCatching { service.close() }
                .onFailure { ServiceBridge.log("WARN", "close core: ${it.message}") }
            runCatching { Seq.destroyRef(service.refnum) }
        }
        // NOTE: the MASQUE engine is intentionally NOT stopped here —
        // startCore() calls this first and the engine must outlive it.
    }

    private suspend fun stopTunnel(clean: Boolean) {
        stopping.set(true)
        ServiceBridge.stopStatsClients()
        stopCore()
        WarpMasqueEngine.stop()
        commandServer?.let { server ->
            runCatching { server.close() }
            runCatching { Seq.destroyRef(server.refnum) }
        }
        commandServer = null
        tunPfd?.let { runCatching { it.close() } }
        tunPfd = null
        ServiceBridge.state.value = TunnelState.OFF
        ServiceBridge.resetSession()
        if (clean) {
            withContext(Dispatchers.Main) {
                ServiceCompat.stopForeground(this@KukuVpnService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /* ---------------------- libbox.PlatformInterface ----------------------- */

    override fun openTun(options: TunOptions): Int {
        if (prepare(this) != null) error("android: missing vpn permission")

        val builder = Builder()
            .setSession("Kuku VPN")
            .setMtu(options.mtu)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val inet4 = options.inet4Address
        while (inet4.hasNext()) {
            val prefix = inet4.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }
        val inet6 = options.inet6Address
        while (inet6.hasNext()) {
            val prefix = inet6.next()
            builder.addAddress(prefix.address(), prefix.prefix())
        }

        if (options.autoRoute) {
            builder.addDnsServer(options.dnsServerAddress.value)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val inet4Routes = options.inet4RouteAddress
                if (inet4Routes.hasNext()) {
                    while (inet4Routes.hasNext()) {
                        val p = inet4Routes.next()
                        builder.addRoute(p.address(), p.prefix())
                    }
                } else {
                    builder.addRoute("0.0.0.0", 0)
                }
                val inet6Routes = options.inet6RouteAddress
                if (inet6Routes.hasNext()) {
                    while (inet6Routes.hasNext()) {
                        val p = inet6Routes.next()
                        builder.addRoute(p.address(), p.prefix())
                    }
                } else {
                    builder.addRoute("::", 0)
                }
                val inet4Exclude = options.inet4RouteExcludeAddress
                while (inet4Exclude.hasNext()) {
                    builder.excludeRoute(inet4Exclude.next().toIpPrefix())
                }
                val inet6Exclude = options.inet6RouteExcludeAddress
                while (inet6Exclude.hasNext()) {
                    builder.excludeRoute(inet6Exclude.next().toIpPrefix())
                }
            } else {
                val inet4Range = options.inet4RouteRange
                while (inet4Range.hasNext()) {
                    val p = inet4Range.next()
                    builder.addRoute(p.address(), p.prefix())
                }
                val inet6Range = options.inet6RouteRange
                while (inet6Range.hasNext()) {
                    val p = inet6Range.next()
                    builder.addRoute(p.address(), p.prefix())
                }
            }
        }

        applySplitTunnel(builder)
        applyCoreSplitTunnel(builder, options)

        val pfd = builder.establish()
            ?: error("android: the application is not prepared or is revoked")
        tunPfd = pfd
        return pfd.fd
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

    /** Packages requested by the sing-box config itself (include_package/exclude_package). */
    private fun applyCoreSplitTunnel(builder: Builder, options: TunOptions) {
        val include = options.includePackage
        while (include.hasNext()) runCatching { builder.addAllowedApplication(include.next()) }
        val exclude = options.excludePackage
        while (exclude.hasNext()) runCatching { builder.addDisallowedApplication(exclude.next()) }
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        runCatching { protect(fd) }
    }

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            error("android: findConnectionOwner requires API 29 (useProcFS below)")
        }
        val uid = getSystemService(ConnectivityManager::class.java).getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        if (uid == Process.INVALID_UID) error("android: connection owner not found")
        return uid
    }

    override fun packageNameByUid(uid: Int): String {
        val packages = packageManager.getPackagesForUid(uid)
        if (packages.isNullOrEmpty()) error("android: package not found")
        return packages[0]
    }

    override fun uidByPackageName(packageName: String): Int {
        return try {
            packageManager.getPackageUid(packageName, 0)
        } catch (e: Exception) {
            error("android: package not found")
        }
    }

    private fun notifyDefaultInterface(listener: InterfaceUpdateListener, network: Network) {
        val cm = getSystemService(ConnectivityManager::class.java)
        val lp = cm.getLinkProperties(network) ?: return
        val name = lp.interfaceName ?: return
        val nif = runCatching { JNetworkInterface.getByName(name) }.getOrNull() ?: return
        val caps = cm.getNetworkCapabilities(network)
        listener.updateDefaultInterface(
            name,
            nif.index,
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true,
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true,
        )
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = notifyDefaultInterface(listener, network)
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                notifyDefaultInterface(listener, network)
        }
        networkCallback = cb
        runCatching { cm.registerDefaultNetworkCallback(cb) }
        cm.activeNetwork?.let { notifyDefaultInterface(listener, it) }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkCallback?.let { cb ->
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb) }
        }
        networkCallback = null
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val cm = getSystemService(ConnectivityManager::class.java)
        val javaInterfaces = JNetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
        val interfaces = mutableListOf<io.nekohasekai.libbox.NetworkInterface>()
        for (network in cm.allNetworks) {
            val lp = cm.getLinkProperties(network) ?: continue
            val caps = cm.getNetworkCapabilities(network) ?: continue
            val name = lp.interfaceName ?: continue
            val jif = javaInterfaces.firstOrNull { it.name == name } ?: continue
            val box = io.nekohasekai.libbox.NetworkInterface()
            box.name = name
            box.dnsServer = StringArray(lp.dnsServers.mapNotNull { it.hostAddress }.iterator())
            box.type = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                else -> Libbox.InterfaceTypeOther
            }
            box.index = jif.index
            runCatching { box.mtu = jif.mtu }
            box.addresses = StringArray(jif.interfaceAddresses.map { it.toPrefix() }.iterator())
            var flags = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                flags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            }
            if (jif.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
            if (jif.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
            if (jif.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
            box.flags = flags
            box.metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            interfaces.add(box)
        }
        return InterfaceArray(interfaces.iterator())
    }

    override fun underNetworkExtension(): Boolean = false
    override fun includeAllNetworks(): Boolean = false
    override fun clearDNSCache() = Unit

    override fun readWIFIState(): WIFIState? = null // needs location permission; core handles null

    override fun writeLog(message: String) {
        ServiceBridge.log("INFO", message)
    }

    override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CORE_NOTIF_CHANNEL) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CORE_NOTIF_CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
        val builder = NotificationCompat.Builder(this, notification.identifier)
            .setContentTitle(notification.title)
            .setContentText(notification.body)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setAutoCancel(true)
        nm.notify(notification.typeID, builder.build())
    }

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
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
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

/** same helper as the official client (io.nekohasekai.sfa.ktx.Wrappers) */
private fun RoutePrefix.toIpPrefix(): IpPrefix = IpPrefix(java.net.InetAddress.getByName(address()), prefix())

private fun InterfaceAddress.toPrefix(): String {
    val addr = address
    return if (addr is Inet6Address) {
        "${Inet6Address.getByAddress(addr.address).hostAddress}/${networkPrefixLength}"
    } else {
        "${addr.hostAddress}/${networkPrefixLength}"
    }
}

/** gomobile iterator shims (same pattern as the official client). */
private class StringArray(private val iterator: Iterator<String>) : StringIterator {
    override fun len(): Int = 0 // not used by the core
    override fun hasNext(): Boolean = iterator.hasNext()
    override fun next(): String = iterator.next()
}

private class InterfaceArray(
    private val iterator: Iterator<io.nekohasekai.libbox.NetworkInterface>,
) : NetworkInterfaceIterator {
    override fun hasNext(): Boolean = iterator.hasNext()
    override fun next(): io.nekohasekai.libbox.NetworkInterface = iterator.next()
}
