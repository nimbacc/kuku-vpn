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
import android.net.NetworkRequest
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
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
        // 6 auto WARP profiles (2 MASQUE + 4 WireGuard ports) + a user profile
        // and its last-good fallback must all fit in one chain
        private const val MAX_CANDIDATES = 8

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
    private var callbackThread: HandlerThread? = null

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
        if (intent == null) {
            // START_STICKY restart after the system killed the process: the
            // core died with it, so "reconnecting" here would only show a
            // ghost CONNECTING state with the app closed. Let it go — the
            // user reconnects with one tap.
            stopSelf()
            return START_NOT_STICKY
        }
        when (intent.action) {
            ACTION_STOP -> scope.launch {
                // flip the UI first — teardown (core close + engine stop) can
                // take seconds and the button must answer instantly
                ServiceBridge.state.value = TunnelState.OFF
                stopTunnel(clean = true)
            }
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
        // After the first plain-WireGuard WARP candidate has swept every
        // anycast IP, the remaining port variants reuse the SAME identity —
        // they only try their own port on the registered endpoint instead of
        // repeating the whole sweep (cuts the worst-case dead-ISP wait from
        // ~5 minutes to under a minute).
        var warpWgSwept = false
        // v1.2.3: the FIRST endpoint of the session is verified with the
        // patient cold-start probe (2×8s). A warm path passes in ~4s, but the
        // very first request also pays for WARP path setup and the first TLS
        // handshakes — with the flat 5s sweep cap that attempt could marginally
        // miss, the candidate got declared dead and the whole chain burned
        // minutes on dead endpoints ("first connect never works; only after
        // killing and reopening the app"). Every later endpoint keeps the
        // tight sweep probe.
        var coldEndpointPending = true
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
                if (WarpMasqueEngine.isRunning()) {
                    // v1.2.6: the engine is already validated (app-open prewarm
                    // or a previous candidate's boot) — USE it. The SOCKS
                    // outbound is transport-agnostic, so the profile's h2/h3
                    // label only decides how a COLD boot sweeps. Killing a warm
                    // engine to re-boot in the profile's own mode burned a
                    // working tunnel and re-paid the whole sweep.
                    ServiceBridge.log(
                        "INFO",
                        "reusing warm WARP engine (socks 127.0.0.1:${WarpMasqueEngine.SOCKS_PORT})"
                    )
                } else try {
                    ServiceBridge.log("INFO", "booting WARP MASQUE engine (${candidate.transport})")
                    val bootStart = android.os.SystemClock.elapsedRealtime()
                    // v1.2.4: single-flight boot shared with the app-open
                    // prewarm — a tap while the prewarm sweep is running now
                    // WAITS for it instead of colliding with the engine's
                    // "already running" guard. v1.2.5: the engine RACES its
                    // endpoints in waves of 4 (≤~20s worst, ~2-5s typical) and
                    // onTick keeps the log alive so a slow cold boot never
                    // looks frozen again. v1.2.6: any warm engine is reused,
                    // whatever mode it runs.
                    WarpMasqueEngine.boot(
                        this,
                        useHttp2 = candidate.transport == WarpRegistrar.TRANSPORT_MASQUE_H2,
                        onTick = { ms -> ServiceBridge.log("INFO", "engine booting… ${ms / 1000}s") },
                    ).getOrThrow()
                    ServiceBridge.log(
                        "INFO",
                        "WARP MASQUE engine ready (socks 127.0.0.1:${WarpMasqueEngine.SOCKS_PORT}, " +
                            "${android.os.SystemClock.elapsedRealtime() - bootStart}ms)"
                    )
                } catch (e: Exception) {
                    // the service is being torn down (stop tap / destroy) — the
                    // chain must not march on; also keeps cancellation noise out
                    // of the candidate log (the "Job was cancelled" report)
                    if (e is kotlinx.coroutines.CancellationException) return
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: MASQUE engine: ${e.message}")
                    continue
                }
            }
            // a cancel that landed during the (blocking, ≤~20s) engine
            // boot must not march on into a doomed core start
            if (stopping.get()) return

            // WARP candidates sweep every known anycast IP — the identity is
            // identical, only the UDP endpoint changes, so no re-registration.
            val endpoints = if (candidate.fromSubscription == WarpRegistrar.WARP_SOURCE && !isMasque) {
                if (warpWgSwept) listOf(candidate.host)
                else (listOf(candidate.host) + WARP_ENDPOINT_IPS).distinct()
            } else listOf(candidate.host)

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
                    // sweep-optimised probe: one HTTPS request, tight timeouts
                    // (worst case ≈5s per dead endpoint instead of ≈13s);
                    // the session's FIRST endpoint uses the patient cold probe
                    val verifyStart = android.os.SystemClock.elapsedRealtime()
                    val verdict =
                        if (coldEndpointPending) ConnectionVerifier.verifyCold()
                        else ConnectionVerifier.verifySweep()
                    coldEndpointPending = false
                    if (!verdict.ok) {
                        error(
                            "verification failed: ${verdict.reason} " +
                                "(after ${android.os.SystemClock.elapsedRealtime() - verifyStart}ms)"
                        )
                    }

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
                    if (e is kotlinx.coroutines.CancellationException) return // service teardown
                    lastError = e
                    ServiceBridge.log("ERROR", "${candidate.name} @ ${attempt.host}:${attempt.port}: ${e.message}")
                    if (isMasque) WarpMasqueEngine.stop()
                    stopCore()
                }
            }
            if (candidate.fromSubscription == WarpRegistrar.WARP_SOURCE && !isMasque) warpWgSwept = true
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
        // v1.2.4: the auto-managed WARP family is ONE method with several
        // transports — always rank it (H2/TCP first, then H3/UDP, then the WG
        // ports), even when autoFallback is off: picking "Cloudflare WARP
        // (Free)" selects the method, not a specific UDP-vs-TCP wire format.
        // User-imported profiles keep strict autoFallback semantics.
        val selectedIsWarp = profileStore.snapshot()
            .firstOrNull { it.id == selectedId }
            ?.fromSubscription == WarpRegistrar.WARP_SOURCE
        return if (settings.autoFallback || selectedIsWarp) {
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
            // NOTE on kill switch: a failure tears the core (and with it the
            // tun interface) down completely, so there is no blackhole left to
            // hold. The old build showed a fake "kill switch active"
            // notification while traffic actually flowed direct — the ERROR
            // state is surfaced honestly instead.
            withContext(Dispatchers.Main) {
                startNotif(getString(R.string.state_error), ongoing = false)
                ServiceCompat.stopForeground(this@KukuVpnService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
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
        // The tun fd belongs to the VpnService created in openTun(). libbox
        // closes it in service.close(), but if that ever fails the stale
        // interface (tun14/tun16…) keeps routing 0.0.0.0/0 into a dead core and
        // poisons the network monitor — close our handle too (double-close is
        // harmless).
        tunPfd?.let { runCatching { it.close() } }
        tunPfd = null
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

        // Release the previous interface BEFORE creating a new one: a leaked fd
        // keeps the old tun alive next to the new one (tun14 + tun16 coexisting
        // was observed in the field) and the stale entry corrupts the network
        // monitor's view of the world.
        tunPfd?.let { runCatching { it.close() } }
        tunPfd = null

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

    /** "tun0", "tun14"… — VPN interfaces are never valid dial targets. */
    private fun isVpnInterfaceName(name: String): Boolean {
        val n = name.lowercase()
        return n.startsWith("tun") || n.startsWith("tap")
    }

    /** Best non-VPN network right now (wifi/ethernet preferred over cellular). */
    private fun bestUnderlyingNetwork(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks
            .mapNotNull { net -> cm.getNetworkCapabilities(net)?.let { net to it } }
            .filterNot { (_, caps) -> caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
            .filter { (_, caps) -> caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
            .maxByOrNull { (_, caps) -> when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 3
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
                else -> 1
            } }
            ?.first
    }

    private fun notifyDefaultInterface(listener: InterfaceUpdateListener, network: Network) {
        val cm = getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(network)
        // THE critical guard (field-verified, run #17 logs): since Android P,
        // registerDefaultNetworkCallback reports the VPN's own tun as the
        // "default network". If the tun is ever reported, libbox treats it as
        // the default interface, outbound sockets dial into the tunnel itself
        // and the whole core blackholes ("updated default interface tun14",
        // "no available network interface", DNS timeouts, eternal CONNECTING).
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return
        val lp = cm.getLinkProperties(network) ?: return
        val name = lp.interfaceName ?: return
        if (isVpnInterfaceName(name)) return
        val nif = runCatching { JNetworkInterface.getByName(name) }.getOrNull() ?: return
        listener.updateDefaultInterface(
            name,
            nif.index,
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true,
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true,
        )
    }

    /**
     * Same contract as the official client (DefaultNetworkListener): track the
     * real UNDERLYING default network, never the VPN's own interface.
     *
     *  - API 31+ : registerBestMatchingNetworkCallback (REQUEST semantics —
     *              excludes the VPN network)
     *  - API 28-30: requestNetwork (same, and registerDefaultNetworkCallback
     *              returns the VPN since P — see notifyDefaultInterface)
     *  - API 24-27: registerDefaultNetworkCallback (pre-P it never reports VPN)
     */
    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        closeDefaultInterfaceMonitor(listener) // defensive: no double registration across core restarts
        val cm = getSystemService(ConnectivityManager::class.java)
        val thread = HandlerThread("kuku-netmon").also { it.start() }
        callbackThread = thread
        val handler = Handler(thread.looper)
        val request = NetworkRequest.Builder().apply {
            addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        }.build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = notifyDefaultInterface(listener, network)
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                notifyDefaultInterface(listener, network)
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                notifyDefaultInterface(listener, network)
        }
        networkCallback = cb
        runCatching {
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    cm.registerBestMatchingNetworkCallback(request, cb, handler)
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ->
                    cm.requestNetwork(request, cb, handler)
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ->
                    cm.registerDefaultNetworkCallback(cb, handler)
                else ->
                    cm.registerDefaultNetworkCallback(cb)
            }
        }.onFailure { ServiceBridge.log("WARN", "net monitor register: ${it.message}") }
        // immediate initial value — the callbacks correct it within milliseconds
        bestUnderlyingNetwork()?.let { notifyDefaultInterface(listener, it) }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkCallback?.let { cb ->
            runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb) }
        }
        networkCallback = null
        callbackThread?.quitSafely()
        callbackThread = null
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val cm = getSystemService(ConnectivityManager::class.java)
        val javaInterfaces = JNetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
        val interfaces = mutableListOf<io.nekohasekai.libbox.NetworkInterface>()
        for (network in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            // our own tun (and any other VPN) must never appear as an
            // "available network" — a stale tun14/tun16 in this list is what
            // produced "no available network interface" in the field
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val lp = cm.getLinkProperties(network) ?: continue
            val name = lp.interfaceName ?: continue
            if (isVpnInterfaceName(name)) continue
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
