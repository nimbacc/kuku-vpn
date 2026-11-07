package app.kukuvpn.core.warp

import android.content.Context
import app.kukuvpn.warpcore.Warpcore
import java.io.File

/**
 * Thin Kotlin facade over the [Warpcore] gomobile binding — the Aether-style
 * "connects anywhere" engine: Cloudflare WARP over MASQUE.
 *
 * MASQUE carries the WireGuard stream inside HTTP/3 (QUIC, UDP 443) or — on
 * networks where the ISP filters all UDP — HTTP/2 over plain TCP 443, which
 * is indistinguishable from ordinary HTTPS. This is the path that works when
 * the classic WireGuard-on-UDP sweep times out.
 *
 * Lifecycle (all calls are blocking, run them off the main thread):
 *  1. [ensureRegistered] — once per install; creates the CF device identity.
 *  2. [start]            — returns only after the tunnel is verified with a
 *     real round-trip and the local SOCKS port accepts; sing-box then routes
 *     the profile through 127.0.0.1:[SOCKS_PORT].
 *  3. [stop]             — always before switching H3/H2 or tearing down.
 */
object WarpMasqueEngine {

    /** Local SOCKS5 port the engine exposes to sing-box. */
    const val SOCKS_PORT = 2085

    @Volatile private var started = false

    fun configDir(context: Context): String =
        File(context.filesDir, "warp_masque").absolutePath

    /** Creates the Cloudflare device identity on first use (idempotent). */
    fun ensureRegistered(context: Context) {
        val dir = configDir(context)
        val has = runCatching { Warpcore.hasConfig(dir) }.getOrDefault(false)
        if (!has) {
            Warpcore.register(dir) // blocking network call, ~2s, throws on failure
        }
    }

    /**
     * Brings the MASQUE tunnel up. Blocking — up to ~30s worst case; usually
     * 2-5s. Throws with the real engine error if the tunnel cannot come up.
     */
    fun start(context: Context, useHttp2: Boolean) {
        stop() // deterministic teardown of any previous instance
        Warpcore.start(configDir(context), SOCKS_PORT, useHttp2)
        started = true
    }

    /** Tears the engine down; safe to call repeatedly. */
    fun stop() {
        runCatching { Warpcore.stop() }
        started = false
    }

    fun isRunning(): Boolean =
        runCatching { Warpcore.isRunning() }.getOrDefault(false) && started
}
