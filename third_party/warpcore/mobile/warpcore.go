// Package warpcore is the gomobile binding that gives Kuku VPN the
// "one tap, works anywhere" WARP engine: Cloudflare WARP over MASQUE.
//
// MASQUE is what the official Cloudflare client (and Aether-style apps) use
// on hostile networks: the WireGuard stream is carried inside HTTP/3 (QUIC,
// UDP 443) or, when UDP is fully filtered, HTTP/2 over plain TCP 443 — it
// looks like ordinary HTTPS to the DPI box.
//
// Engine underneath: the vendored github.com/Diniboy1123/usque
// (Connect-IP / RFC 9484 reimplementation), MIT licensed.
//
// Threading model (all calls safe from Kotlin/Java):
//   - Register(configDir)  — once, on first launch (blocking, ~2s)
//   - Start(configDir, port, useHTTP2) — blocking until the tunnel carries
//     real traffic AND the SOCKS listener accepts; call from a background
//     thread. A nil error means the port is live and passing traffic.
//   - Stop() — always call before Start with a different mode; shuts the
//     listener down and waits for the port to be released.
package warpcore

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultSNI        = internal.ConnectSNI
	defaultMTU        = 1280
	defaultKeepalive  = 30 * time.Second
	defaultReconnect  = 1 * time.Second
	defaultUDPTtl     = 60 * time.Second
	defaultDNSTimeout = 2 * time.Second

	// BUG HISTORY (v1.2.5): the sweep used to try endpoints SERIALLY, 7s
	// each — with 7-8 candidates the first cold boot needed up to ~56s,
	// longer than anybody waits. The user saw the boot ticks, gave up,
	// disconnected (which threw ALL sweep progress away) and the retry
	// restarted the identical minute-long walk. Kill+reopen "worked" only
	// because an earlier completed session had cached its winning
	// endpoint. Endpoints are now RACED in waves: every member of a wave
	// dials in parallel, the first to prove a real round-trip wins and
	// the rest unwind. Worst case is 2 waves (~20s); the common case is
	// the first wave (~2-5s) — which also lets the app-open prewarm
	// actually finish before the user's first tap lands.
	waveSize = 4

	// per-attempt budget: a healthy edge validates in 0.5-3s; 9s tolerates
	// a cold first TLS+MASQUE handshake on a slow hostile network.
	waveBudget = 9 * time.Second

	// small stagger between wave members: avoids 4 simultaneous TLS
	// handshakes (CPU spike on low-end phones) and looks less like a
	// scanner to DPI.
	waveStagger = 300 * time.Millisecond

	// hard cap for the whole Start() sweep, safety net over the wave math.
	startHardCap = 45 * time.Second

	// Stop waits at most this long for the owning Start() to unwind.
	stopWait = 3 * time.Second
)

// sweepEndpointIPs — known-good WARP edges (anycast). MASQUE answers on
// port 443 for BOTH HTTP/3 (UDP) and HTTP/2 (TCP). The first endpoint that
// passes a real data-plane check wins; anything blocked by the ISP simply
// burns its slot and the sweep moves on.
var sweepEndpointIPs = []string{
	"162.159.198.1", "162.159.192.1", "162.159.193.1",
	"188.114.96.1", "188.114.97.1", "162.159.195.1",
}

// endpointCandidates returns the ordered endpoint list for the sweep: the
// configured/registered endpoint first (it is what the official client
// uses, and the cached winner of the last successful session), then the
// sweep list. Each candidate is validated with a REAL round-trip before it
// is accepted — Aether's rule: "a gateway is trusted once it actually
// passes traffic, not just when it answers the handshake".
func endpointCandidates(useHTTP2 bool) []net.Addr {
	seen := map[string]bool{}
	ips := make([]string, 0, len(sweepEndpointIPs)+2)
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	if useHTTP2 {
		add(config.AppConfig.EndpointH2V4)
		add(config.DefaultEndpointH2V4)
	} else {
		add(config.AppConfig.EndpointV4)
	}
	for _, ip := range sweepEndpointIPs {
		add(ip)
	}
	addrs := make([]net.Addr, 0, len(ips))
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if useHTTP2 {
			addrs = append(addrs, &net.TCPAddr{IP: parsed, Port: 443})
		} else {
			addrs = append(addrs, &net.UDPAddr{IP: parsed, Port: 443})
		}
	}
	return addrs
}

// engineState — one live engine, owned by exactly one Start() call.
//
// BUG HISTORY (v1.2.5): the old globals (stopFn/doneCh/activeSrv) were
// nil-ed both by Stop() and by Start()'s failure path with NO ownership
// check. A Stop() landing while the next Start() was already booting —
// disconnect during a slow boot sweep, then a fast second tap — erased the
// NEW engine's cancel closure and server handle. The result was exactly the
// field report "it connected incompletely and only killing the whole app
// fixed it": a half-state where nothing could stop the running engine and
// the next boot collided on the SOCKS port. Ownership is one pointer now:
// Stop takes the slot away FIRST, and every cleanup only acts when it still
// owns the slot.
type engineState struct {
	cancel   context.CancelFunc
	srv      *internal.SOCKS5Server
	finished chan struct{} // closed exactly once, when the owning Start() returns
}

var (
	mu        sync.Mutex // guards current
	current   *engineState
	isRunning atomic.Bool
)

// IsRunning reports whether the engine currently holds a tunnel.
func IsRunning() bool { return isRunning.Load() }

// Register creates a fresh WARP-over-MASQUE identity (account + enrolled
// device key) and persists it to <configDir>/config.json. Call once;
// the identity is reused forever after.
func Register(configDir string) error {
	mu.Lock()
	if current != nil {
		mu.Unlock()
		return fmt.Errorf("engine is running; stop it first")
	}
	mu.Unlock()
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("config dir: %w", err)
	}

	accountData, err := api.Register(internal.DefaultModel, internal.DefaultLocale, "", true)
	if err != nil {
		return fmt.Errorf("register account: %w", err)
	}

	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("generate device key: %w", err)
	}

	updated, err := api.EnrollKey(accountData.ID, accountData.Token, pubKey, "KukuVPN")
	if err != nil {
		return fmt.Errorf("enroll device key: %w", err)
	}

	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     updated.Config.Peers[0].Endpoint.V4[:len(updated.Config.Peers[0].Endpoint.V4)-2],
		EndpointV6:     updated.Config.Peers[0].Endpoint.V6[1 : len(updated.Config.Peers[0].Endpoint.V6)-3],
		EndpointH2V4:   config.DefaultEndpointH2V4,
		EndpointH2V6:   config.DefaultEndpointH2V6,
		EndpointPubKey: updated.Config.Peers[0].PublicKey,
		ID:             updated.ID,
		AccessToken:    accountData.Token,
		IPv4:           updated.Config.Interface.Addresses.V4,
		IPv6:           updated.Config.Interface.Addresses.V6,
	}
	return config.AppConfig.SaveConfig(configPath(configDir))
}

// HasConfig reports whether a usable identity exists under configDir.
func HasConfig(configDir string) bool {
	p := configPath(configDir)
	if _, err := os.Stat(p); err != nil {
		return false
	}
	return config.LoadConfig(p) == nil
}

// attemptResult is what a racing wave member reports when its endpoint
// proves a real round-trip.
type attemptResult struct {
	ep  net.Addr
	ctx context.Context // winner's attempt ctx (child of the engine root)
	dev tun.Device
	net *netstack.Net
}

// Start brings up the MASQUE tunnel and a SOCKS5 proxy on 127.0.0.1:port.
// It returns only after the tunnel is verified with a real round-trip AND
// the listener accepts, so a nil error means traffic can flow. useHTTP2
// selects HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC — the fallback
// for networks that filter UDP entirely.
func Start(configDir string, port int, useHTTP2 bool) error {
	rootCtx, rootCancel := context.WithCancel(context.Background())
	mu.Lock()
	if current != nil {
		mu.Unlock()
		rootCancel()
		return fmt.Errorf("engine is already running; stop it first")
	}
	st := &engineState{cancel: rootCancel, finished: make(chan struct{})}
	current = st // take ownership BEFORE any network work, so Stop() always finds a cancel
	mu.Unlock()

	ok := false
	defer func() {
		close(st.finished) // unblocks a Stop() that is waiting for us
		if !ok {
			// failed or interrupted start: unwind everything and
			// release the slot — but ONLY if we still own it (a
			// Stop() may have handed it to a newer Start() already)
			rootCancel()
			mu.Lock()
			if current == st {
				current = nil
			}
			mu.Unlock()
			isRunning.Store(false)
		}
		// on success the slot STAYS owned by us: Stop() must find
		// this engine to be able to stop it. The old build cleared
		// the slot here unconditionally — a successful boot became
		// unstoppable and the next boot collided on the SOCKS port
		// ("connected incompletely; only killing the app fixed it").
	}()

	if err := config.LoadConfig(configPath(configDir)); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return fmt.Errorf("peer key: %w", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, defaultSNI, false)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}

	localAddresses := []netip.Addr{}
	if v4, err := netip.ParseAddr(config.AppConfig.IPv4); err == nil {
		localAddresses = append(localAddresses, v4)
	}
	if v6, err := netip.ParseAddr(config.AppConfig.IPv6); err == nil {
		localAddresses = append(localAddresses, v6)
	}
	dnsAddrs := []netip.Addr{
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("149.112.112.112"),
	}

	// Aether-style endpoint sweep, v1.2.5: RACED in waves. Every candidate
	// must PROVE itself with a real data-plane round-trip (a TCP dial to
	// 1.1.1.1:53 through the tunnel) before it can win; a handshake alone
	// proves nothing on hostile networks. The winner's tunnel stays up,
	// every loser is cancelled and closed.
	var (
		ctx      context.Context
		tunDev   tun.Device
		tunNet   *netstack.Net
		endpoint net.Addr
		lastErr  error
	)
	candidates := endpointCandidates(useHTTP2)
	totalWaves := (len(candidates) + waveSize - 1) / waveSize
	startDeadline := time.Now().Add(startHardCap)

	for waveStart := 0; waveStart < len(candidates) && tunDev == nil; waveStart += waveSize {
		if rootCtx.Err() != nil {
			return fmt.Errorf("engine stopped during endpoint sweep")
		}
		waveEnd := waveStart + waveSize
		if waveEnd > len(candidates) {
			waveEnd = len(candidates)
		}
		wave := candidates[waveStart:waveEnd]
		waveNum := waveStart/waveSize + 1
		log.Printf("warpcore: racing %d endpoint(s), wave %d/%d (http2=%v)",
			len(wave), waveNum, totalWaves, useHTTP2)

		winnerCh := make(chan attemptResult, 1) // buffered: late losers never block

		// wave registry: the ONE place that closes losing devices.
		// netTun.Close() closes channels and PANICS on a second call,
		// so every attempt device is closed exactly once — here, by
		// the wave cleanup, never by the attempt goroutine itself.
		type regEntry struct {
			cancel context.CancelFunc
			dev    tun.Device
		}
		var (
			regMu  sync.Mutex
			reg    = map[net.Addr]regEntry{}
			winner net.Addr
		)

		for _, ep := range wave {
			go func(ep net.Addr) {
				attemptCtx, attemptCancel := context.WithCancel(rootCtx)
				attemptTun, attemptNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, defaultMTU)
				if err != nil {
					attemptCancel()
					return
				}
				regMu.Lock()
				reg[ep] = regEntry{attemptCancel, attemptTun}
				regMu.Unlock()

				go api.MaintainTunnel(attemptCtx, api.MaintainTunnelConfig{
					TLSConfig:         tlsConfig,
					KeepalivePeriod:   defaultKeepalive,
					InitialPacketSize: 0,
					Endpoint:          ep,
					Device:            api.NewNetstackAdapter(attemptTun),
					MTU:               defaultMTU,
					ReconnectDelay:    defaultReconnect,
					AlwaysReconnect:   true,
					UseHTTP2:          useHTTP2,
				})

				// BUG HISTORY (v1.2.4, kept in v1.2.5): one netstack
				// TCP dial answering with ISP silence (dropped SYNs,
				// no RST) must not block past the budget — each dial
				// races a hard timer for the remaining budget and the
				// attempt context is cancelled on timeout so the dial
				// and the tunnel goroutine unwind.
				deadline := time.Now().Add(waveBudget)
				if deadline.After(startDeadline) {
					deadline = startDeadline
				}
			attemptLoop:
				for time.Now().Before(deadline) {
					if attemptCtx.Err() != nil {
						break
					}
					dialDone := make(chan bool, 1)
					go func() {
						testConn, dialErr := attemptNet.DialContext(attemptCtx, "tcp", net.JoinHostPort("1.1.1.1", "53"))
						if dialErr == nil {
							_ = testConn.Close()
						}
						dialDone <- dialErr == nil
					}()
					timer := time.NewTimer(time.Until(deadline))
					select {
					case w := <-dialDone:
						timer.Stop()
						if w {
							select {
							case winnerCh <- attemptResult{ep: ep, ctx: attemptCtx, dev: attemptTun, net: attemptNet}:
								// we won; the wave cleanup skips us
							default:
								// another endpoint already won — fold
								attemptCancel()
							}
							return
						}
					case <-timer.C:
						attemptCancel() // hard stop: unblock hanging dial + MaintainTunnel
						break attemptLoop
					}
					time.Sleep(400 * time.Millisecond)
				}
				attemptCancel()
			}(ep)
			time.Sleep(waveStagger)
		}

		waveWait := waveBudget + time.Duration(len(wave))*waveStagger + 2*time.Second
		if end := time.Now().Add(waveWait); end.After(startDeadline) {
			waveWait = time.Until(startDeadline)
			if waveWait < 0 {
				waveWait = 0
			}
		}
		select {
		case res := <-winnerCh:
			winner = res.ep
			ctx, tunDev, tunNet, endpoint = res.ctx, res.dev, res.net, res.ep
			log.Printf("warpcore: endpoint %s validated (wave %d/%d)", res.ep, waveNum, totalWaves)
		case <-rootCtx.Done():
			// Stop() while the wave is racing: fall through to the
			// cleanup (which closes every attempt) and let the
			// loop-top check return "engine stopped" — no wait,
			// no leak.
		case <-time.After(waveWait):
			lastErr = fmt.Errorf("wave %d/%d: no endpoint carried traffic within %s",
				waveNum, totalWaves, waveBudget)
			log.Printf("warpcore: %v", lastErr)
		}

		// unwind the losers (cancel + close, exactly once each); the
		// winner's handles stay live. This also closes a LATE winner
		// whose result landed in the buffered channel after the wave
		// had already given up — the old design leaked that netstack.
		regMu.Lock()
		for ep, entry := range reg {
			if winner == nil || ep != winner {
				entry.cancel()
				_ = entry.dev.Close()
			}
		}
		reg = map[net.Addr]regEntry{}
		regMu.Unlock()
	}
	if tunDev == nil {
		rootCancel()
		return fmt.Errorf("tunnel did not come up on any of %d endpoint(s) in %d wave(s) (http2=%v): last: %v",
			len(candidates), totalWaves, useHTTP2, lastErr)
	}

	// Remember the winner so the NEXT Start() validates it first
	// (~1-2s instead of a fresh sweep) — Aether's "quick-reconnect to
	// the last known-good gateway". Saved per transport: H3 winner in
	// EndpointV4, H2 winner in EndpointH2V4; endpointCandidates()
	// already puts the stored endpoint at the front of the sweep.
	var ip string
	switch a := endpoint.(type) {
	case *net.UDPAddr:
		ip = a.IP.String()
	case *net.TCPAddr:
		ip = a.IP.String()
	}
	if ip != "" {
		if useHTTP2 {
			config.AppConfig.EndpointH2V4 = ip
		} else {
			config.AppConfig.EndpointV4 = ip
		}
		_ = config.AppConfig.SaveConfig(configPath(configDir))
	}

	resolver := &internal.TunnelDNSResolver{
		DNSAddrs: dnsAddrs,
		Timeout:  defaultDNSTimeout,
		TunNet:   tunNet,
	}
	server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
		Addr:       net.JoinHostPort("127.0.0.1", fmt.Sprint(port)),
		Resolver:   resolver,
		TunNet:     tunNet,
		UDPTimeout: defaultUDPTtl,
		Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "warpcore: ", 0),
	})
	if err != nil {
		rootCancel()
		_ = tunDev.Close()
		return fmt.Errorf("create socks server: %w", err)
	}

	// Register the server handle BEFORE the goroutine starts, so a Stop()
	// racing engine-ready can always shut the listener down.
	mu.Lock()
	st.srv = server
	mu.Unlock()
	isRunning.Store(true)

	go func() {
		defer isRunning.Store(false)
		if err := server.Start(); err != nil && ctx.Err() == nil {
			log.Printf("warpcore: socks server exited: %v", err)
		}
		_ = tunDev.Close()
	}()

	// Wait until the listener actually accepts before declaring readiness,
	// so "Start returned nil" also means "the SOCKS port is reachable".
	acceptDeadline := time.Now().Add(5 * time.Second)
	listening := false
	for time.Now().Before(acceptDeadline) {
		probe, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 300*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			listening = true
			break
		}
		if rootCtx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !listening {
		_ = server.Stop()
		rootCancel()
		_ = tunDev.Close()
		return fmt.Errorf("socks listener did not come up on port %d", port)
	}

	ok = true
	log.Printf("warpcore: engine ready (http2=%v, endpoint=%s)", useHTTP2, endpoint)
	return nil
}

// Stop tears the engine down and waits (up to stopWait) for the owning
// Start() to unwind. Safe to call when not running, safe to call while a
// Start() is still sweeping (the ownership handoff makes the old
// clobber-a-newer-Start race impossible).
func Stop() {
	mu.Lock()
	st := current
	current = nil // take the slot away FIRST — a newer Start() is unaffected
	mu.Unlock()

	if st == nil {
		isRunning.Store(false)
		return
	}
	if st.cancel != nil {
		st.cancel()
	}
	if st.srv != nil {
		_ = st.srv.Stop() // shuts the listener + relays down, so Start() returns
	}
	select {
	case <-st.finished:
	case <-time.After(stopWait):
	}
	isRunning.Store(false)
}

func configPath(configDir string) string {
	return fmt.Sprintf("%s/config.json", configDir)
}
