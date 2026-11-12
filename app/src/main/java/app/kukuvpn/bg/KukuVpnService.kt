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
import android.os.Looper
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
import app.kukuvpn.core.rules.RuleSets
import app.kukuvpn.core.tor.TorEngine
import app.kukuvpn.core.verify.ConnectionVerifier
import app.kukuvpn.core.warp.WarpMasqueEngine
import app.kukuvpn.core.warp.WgSidecar
import app.kukuvpn.core.psiphon.PsiphonEngine
import app.kukuvpn.core.warp.WarpRegistrar
import app.kukuvpn.data.AppSettings
import app.kukuvpn.data.Profile
import app.kukuvpn.data.ProfileStore
import app.kukuvpn.data.ProfileType
import app.kukuvpn.data.SettingsStore
import app.kukuvpn.ui.components.flagOf
import app.kukuvpn.ui.components.formatSpeed
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
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface as JNetworkInterface
import java.net.Proxy
import java.util.concurrent.TimeUnit
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
                sessionEpoch++ // v1.7.2: invalidate any pending auto-reconnect bounce
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
        sessionEpoch++ // v1.7.2: invalidate any pending auto-reconnect bounce
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
        // v1.7.0 EMERGENCY (panic) mode: for heavy-filtering days the user
        // should not have to re-pin anything — with the switch on, this
        // connect uses the FULL ranked chain for the chosen protocol (direct
        // first, then every underlay) with the most patient sweep. Announced
        // honestly in the log; the protocol pin itself is NOT overwritten —
        // the v1.6.1 exclusivity rule stays intact.
        if (settings.emergencyMode &&
            (settings.network != FallbackEngine.NET_SMART || settings.scanMode != "thorough")
        ) {
            settings = settings.copy(network = FallbackEngine.NET_SMART, scanMode = "thorough")
            ServiceBridge.log("INFO", "EMERGENCY mode: full ranked chain + thorough sweep for this connect")
        }
        // v1.6.7 Aether split: the two independent Connection-page pins.
        val protocol = settings.protocol
        val network = settings.network
        ServiceBridge.log("INFO", "protocol: $protocol · network: $network · scan mode: ${settings.scanMode}")
        if (protocol == FallbackEngine.PROTO_NONE && network == FallbackEngine.NET_GOOL) {
            // lazily register the SECOND WARP identity used as the inner hop;
            // on failure the chain falls back to the ranked smart candidates
            try {
                WarpRegistrar.ensureGoolProfile(this)
            } catch (e: Exception) {
                ServiceBridge.log("WARN", "WARP×2 identity: ${e.message} — falling back to Smart")
            }
        }
        // v1.5.0 Psiphon backends: lazily register the bundled-Psiphon
        // candidates (standalone + Kuku→Psiphon). v1.6.1: a registration
        // failure must FAIL the connect with the real error — falling through
        // to the WARP chain here is exactly the silent substitution the user
        // ordered removed.
        if (protocol == FallbackEngine.PROTO_PSIPHON) {
            try {
                PsiphonEngine.ensureProfiles(this)
            } catch (e: Exception) {
                fail("psiphon profiles: ${e.message}")
                return
            }
        }
        // v1.6.0 Tor backends: lazily register the bundled-Tor candidates
        // (standalone + Kuku→Tor) — same exclusive failure rule (v1.6.1)
        if (protocol == FallbackEngine.PROTO_TOR) {
            try {
                TorEngine.ensureProfiles(this)
            } catch (e: Exception) {
                fail("tor profiles: ${e.message}")
                return
            }
        }
        startNotif(getString(R.string.notif_connecting), ongoing = true)

        ServiceBridge.resetSession()
        ServiceBridge.state.value = TunnelState.PREPARING

        // v1.6.1: psiphon/tor pins are EXCLUSIVE (FallbackEngine returns only
        // that family) — a WARP candidate can no longer follow a pinned
        // Psiphon/Tor, so a failed pin now ends in an honest ERROR state with
        // the real failure reason instead of a WARP substitution.
        var chain = buildChain()
        // stealth scan mode: no raw-UDP wire format at all — drop the plain
        // WireGuard WARP candidates (their handshake is bare UDP on the wire);
        // MASQUE (TCP-443 capable) and gool (WG-over-MASQUE) stay. Never let
        // the filter empty the chain.
        if (settings.scanMode == "stealth") {
            val filtered = chain.filterNot {
                it.fromSubscription == WarpRegistrar.WARP_SOURCE && it.transport == "tcp"
            }
            if (filtered.isNotEmpty()) {
                ServiceBridge.log("INFO", "scan mode stealth: ${chain.size - filtered.size} UDP candidate(s) skipped")
                chain = filtered
            }
        }
        // v1.6.8: the wiring that last verified on this network leads —
        // no more re-burning the dead direct/WG attempts on every connect
        chain = leadWithRememberedWiring(chain)
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
            // v1.6.8: the underlay wire THIS candidate rode ("", "wg", "masque")
            // — recorded into the wiring memory when the candidate verifies
            var underlayWireUsed = ""
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
                    // v1.2.7: the engine RACES both wire formats at once
                    // (MASQUE over TCP 443 + MASQUE over UDP 443), so the
                    // profile's h2/h3 label no longer chooses a boot mode.
                    ServiceBridge.log(
                        "INFO",
                        "booting WARP engine (racing TCP-443 + UDP-443 sweeps, scan: ${settings.scanMode})"
                    )
                    val bootStart = android.os.SystemClock.elapsedRealtime()
                    // single-flight boot shared with the app-open prewarm —
                    // a tap while the prewarm sweep is running WAITS for it
                    // (ticks keep flowing the whole time now), then reuses
                    // the running engine. The boot hard-caps at 60s: if the
                    // Go side ever wedges it is torn down from outside and
                    // the chain moves on instead of hanging forever.
                    WarpMasqueEngine.boot(
                        this,
                        scanMode = settings.scanMode,
                        onTick = { ms ->
                            ServiceBridge.log("INFO", "engine booting… ${ms / 1000}s")
                            notifProgress("WARP ${ms / 1000}s")
                        },
                    ).getOrThrow()
                    ServiceBridge.log(
                        "INFO",
                        "WARP engine ready (socks 127.0.0.1:${WarpMasqueEngine.SOCKS_PORT}, " +
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
            // v1.5.0 Psiphon candidates boot the bundled Psiphon core (child
            // process, SOCKS on 127.0.0.1:1087). The chained variant rides an
            // underlay — v1.6.7: the WIRE is the NETWORK pin (direct/masque/wg
            // or smart) — see bootChainedUnderlay.
            val isPsiphon = candidate.fromSubscription == PsiphonEngine.SOURCE
            if (isPsiphon) {
                val chained = candidate.transport == PsiphonEngine.TRANSPORT_CHAINED
                var underlayPort: Int? = null
                if (chained) try {
                    val underlay = bootChainedUnderlay("Kuku→Psiphon", underlayWire(FallbackEngine.PROTO_PSIPHON))
                    underlayPort = underlay.socksPort
                    underlayWireUsed = underlay.wire
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) return
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: underlay: ${e.message}")
                    continue
                }
                if (!chained) {
                    // standalone Psiphon owns the exit — warm underlays would
                    // sit unused on the device's network
                    WarpMasqueEngine.stop()
                    WgSidecar.stop()
                }
                try {
                    // v1.7.4: the AI candidate forces the US egress — the regular
                    // candidates keep whatever the Settings exit-country picker says
                    val isAiCandidate = candidate.transport == PsiphonEngine.TRANSPORT_AI
                    val region = if (isAiCandidate) PsiphonEngine.AI_EGRESS_REGION else settings.psiphonRegion
                    PsiphonEngine.boot(
                        this,
                        upstreamPort = underlayPort,
                        region = region,
                        onTick = { ms ->
                            val detail = "psiphon ${ms / 1000}s${PsiphonEngine.lastProgressLabel()}"
                            ServiceBridge.log("INFO", "psiphon booting… $detail")
                            notifProgress(detail)
                        },
                    ).getOrThrow()
                    ServiceBridge.log(
                        "INFO",
                        "psiphon core ready (socks 127.0.0.1:${PsiphonEngine.SOCKS_PORT}${
                            underlayPort?.let { ", underlay socks $it" } ?: ""
                        }${
                            region.takeIf { it.isNotBlank() && it != "auto" }
                                ?.let { ", egress $it${if (isAiCandidate) " (AI)" else ""}" } ?: ""
                        })"
                    )
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) return
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: psiphon core: ${e.message}")
                    if (chained) {
                        WarpMasqueEngine.stop()
                        WgSidecar.stop()
                    }
                    continue
                }
            }
            // v1.6.0 Tor candidates boot the bundled tor core (child process
            // via the libtorrun shim, SOCKS on 127.0.0.1:1089). The chained
            // variant rides the v1.6.7 NETWORK-pin underlay (torrc Socks5Proxy).
            val isTor = candidate.fromSubscription == TorEngine.SOURCE
            if (isTor) {
                val chained = candidate.transport == TorEngine.TRANSPORT_CHAINED
                var underlayPort: Int? = null
                if (chained) try {
                    val underlay = bootChainedUnderlay("Kuku→Tor", underlayWire(FallbackEngine.PROTO_TOR))
                    underlayPort = underlay.socksPort
                    underlayWireUsed = underlay.wire
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) return
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: underlay: ${e.message}")
                    continue
                }
                if (!chained) {
                    // standalone Tor owns the exit — warm underlays would sit
                    // unused on the device's network
                    WarpMasqueEngine.stop()
                    WgSidecar.stop()
                }
                try {
                    TorEngine.boot(
                        this,
                        upstreamPort = underlayPort,
                        bridgeMode = settings.torBridgeMode,
                        customBridges = settings.torCustomBridges,
                        onTick = { ms ->
                            val detail = "tor ${ms / 1000}s (bootstrap ${TorEngine.lastProgressLabel()})"
                            ServiceBridge.log("INFO", "tor booting… $detail")
                            notifProgress(detail)
                        },
                    ).getOrThrow()
                    ServiceBridge.log(
                        "INFO",
                        "tor core ready (socks 127.0.0.1:${TorEngine.SOCKS_PORT}${underlayPort?.let { ", underlay socks $it" } ?: ""})"
                    )
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) return
                    lastCandidateError = e.message
                    ServiceBridge.log("ERROR", "${candidate.name}: tor core: ${e.message}")
                    if (chained) {
                        WarpMasqueEngine.stop()
                        WgSidecar.stop()
                    }
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
                    ServiceBridge.exitCountry.value = verdict.exitCountry
                    ServiceBridge.state.value = TunnelState.ACTIVE
                    profileStore.select(candidate.id)
                    profileStore.setLastGood(candidate.id)
                    // v1.3.0 per-network memory (Aether-style): which profile
                    // last VERIFIED on this network class (wifi vs cellular)
                    val netClass = currentNetworkClass()
                    if (netClass.isNotEmpty()) {
                        profileStore.setLastGoodForNetwork(netClass, candidate.id)
                    }
                    // v1.6.8: remember the protocol wiring that just VERIFIED
                    // (direct vs Kuku→core over which underlay wire) — the next
                    // connect on this network leads with it instead of
                    // re-burning the dead candidates first
                    if (isPsiphon || isTor) {
                        val proto = if (isPsiphon) FallbackEngine.PROTO_PSIPHON else FallbackEngine.PROTO_TOR
                        val chainedCand = candidate.transport == PsiphonEngine.TRANSPORT_CHAINED ||
                            candidate.transport == TorEngine.TRANSPORT_CHAINED
                        val wiring =
                            if (chainedCand) "chained:" + underlayWireUsed.ifEmpty { "masque" }
                            else "direct"
                        runCatching { settingsStore.setWiring(proto, netClass.ifEmpty { "any" }, wiring) }
                        ServiceBridge.log(
                            "INFO",
                            "wiring memory: $proto on ${netClass.ifEmpty { "any" }} → $wiring"
                        )
                    }
                    ServiceBridge.startStatsClients()
                    val flag = flagOf(verdict.exitCountry)
                    startNotif(
                        getString(R.string.notif_active) +
                            (verdict.exitIp.takeIf { it.isNotBlank() }?.let { " · $it" } ?: "") +
                            (if (flag.isNotBlank()) " $flag" else ""),
                        ongoing = true,
                    )
                    startNotifSpeedLoop()
                    // v1.7.2: exit IP/country resolve in the BACKGROUND (the
                    // verdict no longer blocks on it — "Connected" shows
                    // instantly; the tile + notification fill in after)
                    resolveExitInfoInBackground(verdict.exitIp)
                    // v1.7.2: auto-reconnect when the UNDERLYING network
                    // switches (Wi-Fi ↔ data) — the wiring memory leads with
                    // the wire that last verified on the NEW network class
                    startNetworkWatch()
                    // v1.7.1: rule-set downloads happen HERE — through the LIVE
                    // tunnel, in the background, never on the connect path (the
                    // v1.7.0 synchronous fetch inside startCore stalled every
                    // Psiphon/Tor candidate behind blocked-CDN timeouts). Cached
                    // files serve every later connect; failure costs nothing.
                    scope.launch {
                        val r = RuleSets.ensure(this@KukuVpnService, settings)
                        if (r.fetched.isNotEmpty()) {
                            ServiceBridge.log(
                                "INFO",
                                "rule-sets fetched through the tunnel for the next connect: ${r.fetched.joinToString()}"
                            )
                        }
                    }
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
                    if (isPsiphon) {
                        PsiphonEngine.stop()
                        if (candidate.transport == PsiphonEngine.TRANSPORT_CHAINED) {
                            WarpMasqueEngine.stop()
                            WgSidecar.stop()
                        }
                    }
                    if (isTor) {
                        TorEngine.stop()
                        if (candidate.transport == TorEngine.TRANSPORT_CHAINED) {
                            WarpMasqueEngine.stop()
                            WgSidecar.stop()
                        }
                    }
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

    /**
     * v1.6.8 — the Aether memory rule for the protocol cores: the wiring
     * (direct vs Kuku→core over a specific underlay wire) that last VERIFIED
     * on this network class leads the chain, so the next connect skips the
     * dead candidates (the field log: direct Psiphon burned its 75s no-sign
     * window and the WG underlay burned ~30s — on EVERY connect) before
     * reaching the path that actually works. Only the Smart network pin
     * reorders; explicit Direct/MASQUE/WG pins stay absolute. A failed
     * remembered path self-heals: the chain continues and the winner that
     * verifies next overwrites the memory.
     */
    private suspend fun leadWithRememberedWiring(chain: List<Profile>): List<Profile> {
        if (settings.network != FallbackEngine.NET_SMART) return chain
        val proto = when {
            chain.any { it.fromSubscription == PsiphonEngine.SOURCE } -> FallbackEngine.PROTO_PSIPHON
            chain.any { it.fromSubscription == TorEngine.SOURCE } -> FallbackEngine.PROTO_TOR
            else -> return chain // plain-VPN chain: profile lastGood already handles memory
        }
        val memo = settingsStore.wiringFor(proto, currentNetworkClass().ifEmpty { "any" }) ?: return chain
        val leadChained = memo.startsWith("chained")
        val isChained = { p: Profile ->
            p.transport == PsiphonEngine.TRANSPORT_CHAINED || p.transport == TorEngine.TRANSPORT_CHAINED
        }
        val reordered = chain.sortedBy { p -> if (leadChained == isChained(p)) 0 else 1 }
        if (reordered.firstOrNull()?.id != chain.firstOrNull()?.id) {
            ServiceBridge.log(
                "INFO",
                "wiring memory: $memo verified earlier on this network — " +
                    (if (leadChained) "Kuku→core chain" else "direct core") + " leads"
            )
        }
        return reordered
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
        // v1.6.7: the two-dimension pins (protocol × network) drive the chain;
        // a pinned network (masque/wg/gool) bypasses autoFallback — the user
        // explicitly chose what to try first; the smart chain still rides
        // behind it as the safety net (see FallbackEngine).
        val selectedIsWarp = profileStore.snapshot()
            .firstOrNull { it.id == selectedId }
            ?.fromSubscription in setOf(WarpRegistrar.WARP_SOURCE, WarpRegistrar.WARP_GOOL_SOURCE)
        return if (settings.protocol != FallbackEngine.PROTO_NONE ||
            settings.network != FallbackEngine.NET_SMART || settings.autoFallback || selectedIsWarp
        ) {
            FallbackEngine(profileStore).chain(
                selectedId,
                protocol = settings.protocol,
                network = settings.network,
                networkClass = currentNetworkClass(),
                maxCandidates = MAX_CANDIDATES,
            )
        } else {
            profileStore.snapshot().filter { it.id == selectedId }
        }
    }

    /**
     * "wifi" | "cell" — the class of the best underlying (non-VPN) network
     * right now; keys the per-network last-good memory (v1.3.0).
     */
    private fun currentNetworkClass(): String {
        val network = bestUnderlyingNetwork() ?: return ""
        val caps = getSystemService(ConnectivityManager::class.java)
            .getNetworkCapabilities(network) ?: return ""
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> FallbackEngine.NETWORK_CELL
            else -> FallbackEngine.NETWORK_WIFI // wifi + ethernet
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
        // v1.7.1: connect path uses ONLY cached rule files — ZERO network here.
        // (v1.7.0 fetched them synchronously per candidate; on a censored ISP
        // that added 40–80s of dead CDN timeouts to every connect, which the
        // Psiphon/Tor boot budgets turned into "never connects".) Fresh files
        // download through the tunnel right after a verified connect.
        val rules = RuleSets.cached(this, settings)
        if (rules.failed.isNotEmpty()) {
            ServiceBridge.log(
                "WARN",
                "rule-sets not cached yet — this connect routes without them " +
                    "(they download through the tunnel after connect): ${rules.failed.joinToString()}"
            )
        }
        val config = SingBoxConfigBuilder.build(profile, settings, rules.ready) // JSON string
        // v1.4.0 FLUX turbo: when the engine rides, the config carries the
        // urltest group over the primary + background socks paths. Members
        // boot in the background AFTER the engine is ready and join the
        // rotation as they verify — traffic starts on the primary either way.
        val fluxPorts = SingBoxConfigBuilder.fluxPortsFor(profile, settings)
        if (fluxPorts.isNotEmpty()) {
            ServiceBridge.log(
                "INFO",
                "FLUX turbo: urltest group over socks " +
                    (listOf(WarpMasqueEngine.SOCKS_PORT) + fluxPorts).joinToString("/") +
                    " — traffic auto-switches to the fastest live path",
            )
        }
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

    /**
     * v1.6.7 — the chained candidates' underlay wire, straight from the
     * NETWORK pin (the Aether split the user drew: "Network" ≠ "Protocol"):
     *  - "wg"     → the REAL WireGuard sidecar only — a failure fails HONESTLY,
     *    it never switches wires behind the user's back;
     *  - "masque" → the MASQUE engine only (the pre-1.6.5 behavior);
     *  - "smart"  → WireGuard sidecar FIRST, MASQUE fallback — unless the
     *    v1.6.8 wiring memory remembers a wire this protocol VERIFIED with on
     *    this network class, which then leads (no dead-wire burn each connect).
     * Returns the underlay SOCKS port the child core must use as upstream
     * (2086 sidecar / 2085 MASQUE engine).
     */
    private suspend fun underlayWire(protocol: String): String = when (settings.network) {
        FallbackEngine.NET_WG -> "wg"
        FallbackEngine.NET_MASQUE -> "masque"
        else -> when (settingsStore.wiringFor(protocol, currentNetworkClass().ifEmpty { "any" })) {
            "chained:masque" -> "masque"
            "chained:wg" -> "wg"
            else -> "smart" // NET_SMART — and the defensive default
        }
    }

    /** v1.6.8 — the underlay result: the SOCKS port AND the wire that won. */
    private data class Underlay(val socksPort: Int, val wire: String)

    private suspend fun bootChainedUnderlay(label: String, wire: String): Underlay {
        // v1.6.6 FIX (the 1.6.5 field report): the sidecar is usually the
        // FIRST libbox user in a session. Without Setup, libbox's package-level
        // working path is empty and its always-on cache-file service opens
        // "cache.db" RELATIVE to the process cwd — on Android the read-only
        // "/" — so every chained boot died with "initialize cache-file: open
        // cache.db: read-only file system". startCore() always called
        // ensureLibbox(); this path never did. Sandbox-proven both ways with
        // the real libbox v1.11.15: without Setup → "initialize cache-file:
        // open cache.db: permission denied"; with Setup (this exact recipe) →
        // clean start + cache.db lands inside WorkingPath.
        ensureLibbox()
        if (wire != "masque") {
            val wgCandidates = FallbackEngine.wireguardUnderlayCandidates(profileStore)
            if (WgSidecar.isRunning) return Underlay(WgSidecar.SOCKS_PORT, "wg")
            if (wgCandidates.isNotEmpty()) {
                try {
                    // v1.7.2: the sidecar now SWEEPS the anycast pool like the
                    // plain-WARP WG path — the registered endpoint is often the
                    // blocked one while a sibling anycast IP carries the wire
                    val winner = WgSidecar.boot(this, wgCandidates, WARP_ENDPOINT_IPS).getOrThrow()
                    ServiceBridge.log(
                        "INFO",
                        "WireGuard underlay up for $label (profile \"${winner.name}\", " +
                            "socks 127.0.0.1:${WgSidecar.SOCKS_PORT})"
                    )
                    return Underlay(WgSidecar.SOCKS_PORT, "wg")
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (wire == "wg") {
                        // WireGuard-only honors the selection: an honest error
                        // beats a silent wire switch (the 1.6.1 honesty rule)
                        throw e
                    }
                    ServiceBridge.log(
                        "WARN",
                        "WireGuard underlay failed for $label: ${e.message} — " +
                            "falling back to the MASQUE engine"
                    )
                }
            } else {
                if (wire == "wg") {
                    error(
                        "no WireGuard profile registered yet — connect WARP once " +
                            "to mint WireGuard identities for the underlay"
                    )
                }
                ServiceBridge.log(
                    "WARN",
                    "no WireGuard profile registered yet for the $label underlay — " +
                        "using the MASQUE engine (connect WARP once to mint WireGuard identities)"
                )
            }
        }
        if (WgSidecar.isRunning) WgSidecar.stop()
        // v1.6.6: a warm engine is only as good as its egress. The 1.6.5 field
        // report: a warm MASQUE engine with a dead egress stalled the psiphon
        // boot for 3+ minutes with zero progress lines. Probe the wire with a
        // REAL request BEFORE pointing the child core at it; a dead warm
        // engine gets exactly one cold re-sweep, then the attempt fails fast
        // and visibly instead of hanging.
        var probed = false
        if (!WarpMasqueEngine.isRunning()) {
            ServiceBridge.log("INFO", "booting WARP (MASQUE) underlay for $label (scan: ${settings.scanMode})")
            WarpMasqueEngine.boot(
                this,
                scanMode = settings.scanMode,
                onTick = { ms -> ServiceBridge.log("INFO", "engine booting… ${ms / 1000}s") },
            ).getOrThrow()
        } else {
            probed = egressAlive(WarpMasqueEngine.SOCKS_PORT)
            if (!probed) {
                ServiceBridge.log(
                    "WARN",
                    "warm MASQUE engine failed the egress probe — tearing it down and re-sweeping once"
                )
                WarpMasqueEngine.stop()
                WarpMasqueEngine.boot(
                    this,
                    scanMode = settings.scanMode,
                    onTick = { ms -> ServiceBridge.log("INFO", "engine booting… ${ms / 1000}s") },
                ).getOrThrow()
            }
        }
        if (!probed && !egressAlive(WarpMasqueEngine.SOCKS_PORT)) {
            error(
                "MASQUE engine egress is dead (real-request probe failed) — " +
                    "this wire is not usable on this network"
            )
        }
        return Underlay(WarpMasqueEngine.SOCKS_PORT, "masque")
    }

    /**
     * v1.6.6 — push a REAL request through an underlay's local SOCKS. A
     * listener without a working exit must fail HERE (fast, with a clear
     * log line), never inside the child core's boot where it masquerades as
     * a psiphon/tor failure. Same pattern WgSidecar already proves on boot.
     */
    private suspend fun egressAlive(port: Int): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
                .build()
                .newCall(Request.Builder().url("https://www.cloudflare.com/cdn-cgi/trace").build())
                .execute().use { it.isSuccessful }
        }.getOrDefault(false)
    }

    private fun fail(message: String) {
        ServiceBridge.state.value = TunnelState.ERROR
        ServiceBridge.lastError.value = message
        ServiceBridge.log("ERROR", message)
        ServiceBridge.stopStatsClients()
        scope.launch {
            stopCore()
            WarpMasqueEngine.stop()
            WgSidecar.stop()
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
        WgSidecar.stop()
        PsiphonEngine.stop()
        TorEngine.stop()
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

    // v1.7.0: the notification is now LIVE — boot progress while connecting
    // (engine ticks), then download/upload speed every 2s while active. The
    // base text is kept so speed lines append to it instead of replacing it.
    private val notifHandler = Handler(Looper.getMainLooper())
    @Volatile private var notifBaseText = ""
    @Volatile private var lastNotifUpdateMs = 0L

    private fun buildNotif(text: String, ongoing: Boolean): android.app.Notification {
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
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync) // replace with a proper vector in v1.1
            .setContentTitle("Kuku VPN")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(contentIntent)
            .addAction(0, getString(R.string.notif_action_stop), stopIntent)
            .setOngoing(ongoing)
            .setOnlyAlertOnce(true)
            .build()
    }

    private suspend fun startNotif(text: String, ongoing: Boolean) {
        notifBaseText = text
        lastNotifUpdateMs = System.currentTimeMillis()
        val notif = buildNotif(text, ongoing)
        withContext(Dispatchers.Main) {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, notif)
            }
        }
    }

    /** Throttled in-place update of the foreground notification (main thread). */
    private fun updateNotif(text: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force && now - lastNotifUpdateMs < 900) return
        lastNotifUpdateMs = now
        notifHandler.post {
            runCatching {
                getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotif(text, ongoing = true))
            }
        }
    }

    /** Progress line under "Establishing tunnel…" — driven by the engine ticks. */
    private fun notifProgress(detail: String) {
        val d = if (detail.length > 90) detail.take(90) + "…" else detail
        updateNotif(getString(R.string.notif_connecting) + "\n" + d)
    }

    /**
     * v1.7.0: while ACTIVE, append a live speed line to the notification every
     * 2s (v2rayNG-style). The loop dies with the state change — no leaks.
     */
    private fun startNotifSpeedLoop() {
        scope.launch {
            var lastIn = ServiceBridge.stats.value.bytesIn
            var lastOut = ServiceBridge.stats.value.bytesOut
            while (ServiceBridge.state.value == TunnelState.ACTIVE && !stopping.get()) {
                delay(2000)
                val s = ServiceBridge.stats.value
                val dIn = (s.bytesIn - lastIn).coerceAtLeast(0) / 2
                val dOut = (s.bytesOut - lastOut).coerceAtLeast(0) / 2
                lastIn = s.bytesIn; lastOut = s.bytesOut
                val flag = flagOf(ServiceBridge.exitCountry.value)
                val base = notifBaseText.ifBlank { getString(R.string.notif_active) }
                updateNotif(
                    base + (if (flag.isNotBlank()) " $flag" else "") +
                        "\n▼ ${formatSpeed(dIn)} · ▴ ${formatSpeed(dOut)}",
                    force = true,
                )
            }
        }
    }

    /* ------------------ v1.7.2 exit info + auto-reconnect ------------------ */

    /** One epoch per user-visible session; a user stop invalidates pending bounces. */
    @Volatile private var sessionEpoch = 0L
    private var networkWatchJob: Job? = null

    /**
     * The verdict path no longer resolves the exit IP (v1.7.2) — do it here,
     * in the background, so the tile and notification fill in ~1-3s after
     * "Connected" without ever delaying the connect itself.
     *
     * v1.7.4: the source chain is METHOD-AWARE (a Tor exit gets geo answers
     * from Tor-friendly sources first) and, when every HTTP geo source still
     * refuses, the flag falls back to what the protocol core ITSELF reported:
     * Psiphon's ConnectedServerRegion notice ("psiphon exit region: US").
     */
    private fun resolveExitInfoInBackground(knownIp: String) {
        if (knownIp.isNotBlank()) return // the 200-trace probe already carried both
        val candidate = ServiceBridge.activeProfile.value
        val viaTor = candidate?.fromSubscription == TorEngine.SOURCE
        val viaPsiphon = candidate?.fromSubscription == PsiphonEngine.SOURCE
        scope.launch {
            val proxy = java.net.Proxy(
                java.net.Proxy.Type.HTTP,
                java.net.InetSocketAddress("127.0.0.1", SingBoxConfigBuilder.PROXY_PORT),
            )
            val (ip, geoCc) = ConnectionVerifier.fetchExitInfo(proxy, viaTor = viaTor)
            if (ip.isBlank() || ServiceBridge.state.value != TunnelState.ACTIVE) return@launch
            // last-resort country: the protocol core's own report beats nothing —
            // Psiphon tells us the exit region in its notices (the AI mode's
            // "is this really the US?" answer is exactly this field)
            var cc = geoCc
            if (cc.isBlank() && viaPsiphon) {
                cc = PsiphonEngine.exitRegion.trim().uppercase().take(2)
                if (cc.isNotBlank()) {
                    ServiceBridge.log("INFO", "country from psiphon core region: $cc")
                }
            }
            ServiceBridge.exitIp.value = ip
            ServiceBridge.exitCountry.value = cc
            val flag = flagOf(cc)
            notifBaseText = getString(R.string.notif_active) +
                " · $ip" + (if (flag.isNotBlank()) " $flag" else "")
            updateNotif(notifBaseText, force = true)
            ServiceBridge.log("INFO", "exit resolved: $ip ${cc.ifBlank { "?" }}")
        }
    }

    private fun currentNetworkId(): String? =
        bestUnderlyingNetwork()?.networkHandle?.toString()

    private fun networkLabel(): String = when (currentNetworkClass()) {
        FallbackEngine.NETWORK_WIFI -> "Wi-Fi"
        FallbackEngine.NETWORK_CELL -> "data"
        else -> "network"
    }

    /**
     * v1.7.2 AUTO-RECONNECT (the user's ask): while ACTIVE, watch the
     * UNDERLYING default network (never the tun — bestUnderlyingNetwork
     * filters TRANSPORT_VPN). A Wi-Fi ↔ data switch tears the session down
     * and re-runs the full chain; the wiring memory is kept PER NETWORK
     * CLASS, so the bounce leads with the wire that last verified on the
     * NEW network — effectively "auto-pick the best method" across Wi-Fi
     * and data without the user touching anything.
     */
    private fun startNetworkWatch() {
        val epoch = sessionEpoch
        networkWatchJob?.cancel()
        networkWatchJob = scope.launch {
            var last = currentNetworkId()
            var lastLabel = networkLabel()
            while (ServiceBridge.state.value == TunnelState.ACTIVE && !stopping.get() && epoch == sessionEpoch) {
                delay(2500)
                val now = currentNetworkId() ?: continue
                if (last == null) {
                    last = now; lastLabel = networkLabel(); continue
                }
                if (now != last) {
                    ServiceBridge.log("INFO", "network changed ($lastLabel → ${networkLabel()}) — auto-reconnect")
                    if (epoch != sessionEpoch || stopping.get()) return@launch
                    // THIS coroutine is the watcher — clear the field so the
                    // new session's startNetworkWatch() does not cancel the
                    // job that is currently executing the bounce
                    networkWatchJob = null
                    stopTunnel(clean = false)
                    if (epoch != sessionEpoch || stopping.get()) return@launch // user stopped meanwhile
                    settings = settingsStore.snapshot()
                    runTunnel()
                    return@launch
                }
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
