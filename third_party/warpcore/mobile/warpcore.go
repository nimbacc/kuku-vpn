// Package warpcore is the gomobile binding that gives Kuku VPN the
// "one tap, works anywhere" WARP engine: Cloudflare WARP over MASQUE.
//
// MASQUE is what the official Cloudflare client (and Aether-style apps) use
// on hostile networks: the WireGuard stream is carried inside HTTP/3 (QUIC,
// UDP 443) or, when UDP is fully filtered, HTTP/2 over plain TCP 443 — it
// looks like ordinary HTTPS to the DPI box.
//
// v1.2.7: StartAuto RACES BOTH wire formats at once (H3 over UDP 443 and
// H2 over TCP 443, each with its own endpoint sweep). On networks where
// the ISP filters UDP the H3 attempts die fast and the TCP sweep wins in
// ~2-5s; on UDP-friendly networks H3 wins. Either way the FIRST tap
// connects — there is no serial H2-then-H3 walk to time out.
//
// Engine underneath: the vendored github.com/Diniboy1123/usque
// (Connect-IP / RFC 9484 reimplementation), MIT licensed.
//
// Threading model (all calls safe from Kotlin/Java):
//   - Register(configDir)  — once, on first launch (blocking, ~2s)
//   - StartAuto(configDir, port) — blocking until the tunnel carries real
//     traffic AND the SOCKS listener accepts; call from a background
//     thread. A nil error means the port is live and passing traffic.
//   - Stop() — tears the engine down and waits for the boot to unwind.
package warpcore

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
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

	// v1.2.5 endpoint racing: endpoints are RACED in waves — every member
	// of a wave dials in parallel, the first to prove a real round-trip
	// wins and the rest unwind. With the H2 sweep limited to its single
	// real edge (see h2EndpointIP) the common case is one wave (~2-5s).
	waveSize = 4

	// per-attempt budget: a healthy edge validates in 0.5-3s; 9s tolerates
	// a cold first TLS+MASQUE handshake on a slow hostile network.
	waveBudget = 9 * time.Second

	// small stagger between wave members: avoids 4 simultaneous TLS
	// handshakes (CPU spike on low-end phones) and looks less like a
	// scanner to DPI.
	waveStagger = 300 * time.Millisecond

	// hard cap for the whole boot sweep, safety net over the wave math.
	startHardCap = 45 * time.Second

	// Stop waits at most this long for the owning Start() to unwind.
	stopWait = 3 * time.Second

	// closeDrainWait bounds how long closeTunDraining waits for
	// netTun.Close(). A pathological close must never wedge the sweep —
	// leaking one device beats deadlocking Start() forever (v1.2.7).
	closeDrainWait = 5 * time.Second

	// v1.4.0 FLUX turbo: after the primary tunnel is live (the user is
	// already online), the engine keeps sweeping the REMAINING endpoints in
	// the background and holds up to extraMax ADDITIONAL validated tunnels,
	// each behind its own local SOCKS port (base+1..base+extraMax). The
	// sing-box urltest group then hot-swaps traffic to whichever path
	// currently answers fastest — the FLUX-style "always on the fastest
	// edge" rotation, and a free resilience upgrade: if the primary edge
	// degrades, the group simply moves the traffic to a live extra path.
	// Extras are pure enrichment: nothing in this file's connect path
	// (the racing sweep + ownership model v1.2.5-v1.2.7 stabilized) waits
	// on them or depends on them.
	extraMax = 2

	// per-extra probe budget: extras probe endpoints that the boot sweep
	// ALREADY rejected seconds ago (handshake failures are per-edge, not
	// transient), so a long retry window mostly spams Cloudflare handshakes
	// for nothing. A validated extra answers in 0.1-2s (v1.4.0 sandbox:
	// 90-95ms); 6s leaves room for one cold retry without hammering.
	extraBudget = 6 * time.Second

	// hard cap for the whole background extras sweep.
	extraOverallCap = 40 * time.Second

	// how long bootExtras waits for an accepted extra's SOCKS listener.
	extraListenWait = 5 * time.Second
)

// sweepEndpointIPs — known-good WARP anycast edges for MASQUE over
// HTTP/3 (QUIC, UDP 443). The first endpoint that passes a real
// data-plane check wins; anything blocked by the ISP burns its slot.
//
// BUG HISTORY (v1.2.7): this list was ALSO used for the HTTP/2 sweep.
// Sandbox end-to-end proof: only 162.159.198.2 answers MASQUE over TCP
// with the pinned device certificate — every other anycast IP completes
// the TCP+TLS handshake and then fails x509 pinning ("remote endpoint has
// a different public key than what we trust in config.json"). Six dead
// TCP endpoints burned the whole H2 wave budget on every boot and kept
// feeding dead handshakes into the engine.
var sweepEndpointIPs = []string{
	"162.159.198.1", "162.159.192.1", "162.159.193.1",
	"188.114.96.1", "188.114.97.1", "162.159.195.1",
}

// h2EndpointIP is the ONE edge that serves MASQUE over HTTP/2 (TCP 443)
// with the pinned device certificate — usque's DefaultEndpointH2V4.
const h2EndpointIP = "162.159.198.2"

// endpointCandidates returns the ordered endpoint list for one transport's
// sweep: the configured/cached winner of the last successful session
// first, then the transport's own edge list. Each candidate is validated
// with a REAL round-trip before it is accepted — a gateway is trusted once
// it actually passes traffic, not just when it answers the handshake.
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
		add(h2EndpointIP)
	} else {
		add(config.AppConfig.EndpointV4)
		for _, ip := range sweepEndpointIPs {
			add(ip)
		}
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

// transportName is used in engine logs so a field report says which wire
// format actually connected.
func transportName(useHTTP2 bool) string {
	if useHTTP2 {
		return "tcp-443/h2"
	}
	return "udp-443/h3"
}

// scanParams is the tunable sweep profile behind the app's "Scan mode"
// setting (v1.3.0, the Aether-style Connection page). Every mode keeps the
// same wave-racing model — the knobs only change how hard and how long the
// sweep pushes:
//
//	turbo     — short budgets; connect fast or hand over to the next method
//	balanced  — the v1.2.7 defaults (9s waves, 45s cap)
//	thorough  — patient waves for networks where every edge is slow
//	stealth   — H2 over plain TCP 443 ONLY: no UDP at all, the tunnel is
//	            indistinguishable from ordinary HTTPS to the DPI box
//	ironclad  — the longest push; every transport, every endpoint
type scanParams struct {
	transports []bool
	waveBudget time.Duration
	hardCap    time.Duration
}

func scanParamsFor(mode string) scanParams {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "turbo":
		return scanParams{transports: []bool{false, true}, waveBudget: 6 * time.Second, hardCap: 20 * time.Second}
	case "thorough":
		return scanParams{transports: []bool{false, true}, waveBudget: 15 * time.Second, hardCap: 90 * time.Second}
	case "stealth":
		return scanParams{transports: []bool{true}, waveBudget: 12 * time.Second, hardCap: 60 * time.Second}
	case "ironclad":
		return scanParams{transports: []bool{false, true}, waveBudget: 18 * time.Second, hardCap: 120 * time.Second}
	default: // balanced
		return scanParams{transports: []bool{false, true}, waveBudget: waveBudget, hardCap: startHardCap}
	}
}

// engineState — one live engine, owned by exactly one boot call.
//
// BUG HISTORY (v1.2.5): the old globals (stopFn/doneCh/activeSrv) were
// nil-ed both by Stop() and by Start()'s failure path with NO ownership
// check. A Stop() landing while the next Start() was already booting —
// disconnect during a slow boot sweep, then a fast second tap — erased the
// NEW engine's cancel closure and server handle. Ownership is one pointer
// now: Stop takes the slot away FIRST, and every cleanup only acts when it
// still owns the slot.
type engineState struct {
	cancel   context.CancelFunc
	srv      *internal.SOCKS5Server
	extras   []*extraState // v1.4.0 FLUX background tunnels (socks base+1..)
	finished chan struct{} // closed exactly once, when the owning boot returns
}

// extraState — one live FLUX background tunnel: its cancel (parented to the
// engine root, so Stop's rootCancel unwinds it), its SOCKS listener and its
// netstack device (for closeTunDraining at teardown).
type extraState struct {
	cancel context.CancelFunc
	srv    *internal.SOCKS5Server
	dev    tun.Device
}

var (
	mu        sync.Mutex // guards current
	current   *engineState
	isRunning atomic.Bool
)

// IsRunning reports whether the engine currently holds a tunnel.
func IsRunning() bool { return isRunning.Load() }

// ExtraCount reports how many FLUX background tunnels are currently live
// (the primary tunnel is not counted). Bounded by extraMax; 0 until the
// background sweep starts validating extras. gomobile binds the return as
// a Java long.
func ExtraCount() int {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return 0
	}
	n := 0
	for _, ex := range current.extras {
		if ex != nil {
			n++
		}
	}
	return n
}

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

	// BUG HISTORY (v1.2.7): the API returns "162.159.198.2:443" and the
	// old code stripped the port by BYTE COUNT ([:len-2]), persisting
	// "162.159.198.2:4" on every fresh install. ParseIP then rejected it,
	// so the "preferred endpoint" hint was silently dead until the first
	// successful sweep overwrote it. Parse host:port properly.
	v4 := updated.Config.Peers[0].Endpoint.V4
	if host, _, err := net.SplitHostPort(v4); err == nil {
		v4 = host
	}
	v6 := updated.Config.Peers[0].Endpoint.V6
	if host, _, err := net.SplitHostPort(v6); err == nil {
		v6 = host
	}
	v6 = strings.Trim(v6, "[]")

	config.AppConfig = config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
		EndpointV4:     v4,
		EndpointV6:     v6,
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

// attemptResult is what a winning sweep attempt reports: its endpoint,
// the live attempt context and handles, and the cancel func so a LATE
// second winner can be folded without leaking a tunnel.
type attemptResult struct {
	ep     net.Addr
	ctx    context.Context
	cancel context.CancelFunc
	dev    tun.Device
	net    *netstack.Net
}

// closeTunDraining closes a netstack TUN device without deadlocking.
//
// BUG HISTORY (v1.2.7 — the "eternal Connecting" root cause): a losing
// attempt's netstack keeps retransmitting the sweep dial's SYN after the
// attempt is cancelled and its pump (the device's only reader) is gone.
// gVisor delivers every retransmission into the device queue through
// netTun.WriteNotify, which BLOCKS on a channel send once the queue is
// full — and that delivery runs while holding the TCP endpoint's user
// lock. netTun.Close() → stack.Close() → Endpoint.Abort() needs that very
// lock → the closing goroutine parked FOREVER. Start() never returned,
// the Kotlin boot mutex stayed locked behind it, and the app sat on
// "Connecting" with no further logs — reproduced exactly in the sandbox
// goroutine dump (chan send in netTun.WriteNotify holding the endpoint
// lock that Endpoint.Abort waits for).
//
// The drainer goroutine consumes the queue while Close() runs, releasing
// every parked sender so the lock frees and Close() completes; a hard
// timeout keeps a pathological close from ever wedging the engine again.
func closeTunDraining(dev tun.Device) error {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		bufs := [][]byte{buf}
		sizes := make([]int, 1)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := dev.Read(bufs, sizes, 0); err != nil {
				// device closed (incomingPacket closed → os.ErrClosed)
				return
			}
		}
	}()
	errCh := make(chan error, 1)
	go func() { errCh <- dev.Close() }()
	select {
	case err := <-errCh:
		close(stop)
		<-done // drainer exits once the closed channel returns ErrClosed
		return err
	case <-time.After(closeDrainWait):
		// Never wedge the sweep on a pathological close: leave the
		// drainer attached (it exits when Close eventually completes)
		// and move on. Leaking one device beats deadlocking Start().
		return nil
	}
}

// sweepTransport races one transport's endpoint candidates in waves and
// returns the first attempt that proves a real round-trip (a TCP dial to
// 1.1.1.1:53 THROUGH the tunnel). Attempts are parented to rootCtx so the
// winner's tunnel survives the sweep's own cancellation; `stop` (closed)
// means "another transport won / engine stopping — unwind NOW".
func sweepTransport(rootCtx context.Context, stop <-chan struct{}, startDeadline time.Time, tlsConfig *tls.Config, useHTTP2 bool, localAddresses []netip.Addr, dnsAddrs []netip.Addr, budget time.Duration) (attemptResult, error) {
	stopped := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	// wave registry: the ONE place that closes losing devices. netTun.Close()
	// must happen exactly once per device — see closeTunDraining for why the
	// close itself needs a drainer. Declared at sweep scope so a cancellation
	// between waves can still tear down everything the sweep owns.
	type regEntry struct {
		cancel context.CancelFunc
		dev    tun.Device
	}
	teardown := func(regMu *sync.Mutex, reg *map[net.Addr]regEntry, winner net.Addr, background bool) {
		regMu.Lock()
		entries := make([]regEntry, 0, len(*reg))
		for ep, entry := range *reg {
			if winner == nil || ep != winner {
				entries = append(entries, entry)
			}
		}
		*reg = map[net.Addr]regEntry{}
		regMu.Unlock()
		run := func() {
			for _, entry := range entries {
				entry.cancel()
				_ = closeTunDraining(entry.dev)
			}
		}
		if background {
			// the winner's tunnel is already validated — it must not wait
			// for loser teardown (drain-close can take ~1s each)
			go run()
		} else {
			run()
		}
	}

	candidates := endpointCandidates(useHTTP2)
	totalWaves := (len(candidates) + waveSize - 1) / waveSize
	var lastErr error

	// one registry for the whole sweep: teardown() empties it after every
	// wave/cancellation, so entries never survive a cleanup call
	var (
		regMu  sync.Mutex
		reg    = map[net.Addr]regEntry{}
		winner net.Addr
	)
	closeLosers := func(background bool) {
		teardown(&regMu, &reg, winner, background)
	}

	for waveStart := 0; waveStart < len(candidates); waveStart += waveSize {
		if stopped() || rootCtx.Err() != nil {
			// cancelled between waves: tear down everything this sweep
			// still owns, or the attempts would pump forever (they are
			// parented to rootCtx and the engine may live on for hours).
			// Background: nothing here waits on this sweep any more — the
			// boot (and a Stop()) must not block on loser teardown.
			closeLosers(true)
			return attemptResult{}, fmt.Errorf("%s sweep cancelled", transportName(useHTTP2))
		}
		waveEnd := waveStart + waveSize
		if waveEnd > len(candidates) {
			waveEnd = len(candidates)
		}
		wave := candidates[waveStart:waveEnd]
		waveNum := waveStart/waveSize + 1
		log.Printf("warpcore: racing %d %s endpoint(s), wave %d/%d",
			len(wave), transportName(useHTTP2), waveNum, totalWaves)

		winnerCh := make(chan attemptResult, 1) // buffered: late losers never block

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

				// one netstack TCP dial answering with ISP silence
				// (dropped SYNs, no RST) must not block past the budget —
				// each dial races a hard timer for the remaining budget
				// and the attempt context is cancelled on timeout so the
				// dial and the tunnel goroutine unwind.
				deadline := time.Now().Add(budget)
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
							case winnerCh <- attemptResult{ep: ep, ctx: attemptCtx, cancel: attemptCancel, dev: attemptTun, net: attemptNet}:
								// we won; the wave cleanup skips us
							default:
								// another endpoint already won — cancel ONLY. The device is still owned
								// by the wave registry (the ONE closer in this sweep): either the
								// registry still holds it and the wave teardown closes it, or teardown
								// already drain-closed it — closing here too would double-close
								// (netTun.Close panics on the second close, proven in the v1.4.0
								// sandbox before shipping).
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

		waveWait := budget + time.Duration(len(wave))*waveStagger + 2*time.Second
		if end := time.Now().Add(waveWait); end.After(startDeadline) {
			waveWait = time.Until(startDeadline)
			if waveWait < 0 {
				waveWait = 0
			}
		}
		select {
		case res := <-winnerCh:
			winner = res.ep
			log.Printf("warpcore: endpoint %s validated (%s, wave %d/%d)",
				res.ep, transportName(useHTTP2), waveNum, totalWaves)
			closeLosers(true) // background teardown, winner skipped
			return res, nil
		case <-stop:
			// another transport won / engine stopping — unwind everything
			// this sweep owns (winner == nil here → every live attempt),
			// or the attempts would pump forever (they are parented to
			// rootCtx and the engine may live on for hours). Background so
			// the winning boot (and Stop()) never waits on loser teardown.
			closeLosers(true)
			return attemptResult{}, fmt.Errorf("%s sweep cancelled", transportName(useHTTP2))
		case <-rootCtx.Done():
			// engine Stop() while the wave is racing — tear down in the
			// background and let the boot's outcome loop return promptly
			closeLosers(true)
			return attemptResult{}, fmt.Errorf("%s sweep cancelled", transportName(useHTTP2))
		case <-time.After(waveWait):
			lastErr = fmt.Errorf("%s wave %d/%d: no endpoint carried traffic within %s",
				transportName(useHTTP2), waveNum, totalWaves, budget)
			log.Printf("warpcore: %v", lastErr)
		}
		closeLosers(false)
	}
	// all waves exhausted — reg is empty by now; the final message carries
	// the last wave's failure for the boot error report
	return attemptResult{}, fmt.Errorf("%s: tunnel did not come up on any of %d endpoint(s) in %d wave(s): last: %v",
		transportName(useHTTP2), len(candidates), totalWaves, lastErr)
}

// addrIP extracts the IP string from a sweep endpoint address ("" for
// anything else).
func addrIP(ep net.Addr) string {
	switch a := ep.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	return ""
}

// waitLocalPort polls a loopback listener until it accepts (or the context
// / timeout ends).
func waitLocalPort(ctx context.Context, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		probe, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 300*time.Millisecond)
		if err == nil {
			_ = probe.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// probeTunnel proves a candidate extra tunnel carries real traffic and
// returns how long the first successful round-trip took (the FLUX probe
// RTT, logged for visibility). Mirrors the sweep's dial test: each dial
// races a hard timer for the remaining budget; unlike the sweep, a failed
// dial does NOT cancel the attempt — MaintainTunnel (AlwaysReconnect)
// self-heals and the next dial retries, so a tunnel that comes up a few
// seconds late is still harvested.
func probeTunnel(ctx context.Context, ns *netstack.Net, hardDeadline time.Time, budget time.Duration) (time.Duration, bool) {
	deadline := time.Now().Add(budget)
	if deadline.After(hardDeadline) {
		deadline = hardDeadline
	}
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return 0, false
		}
		t0 := time.Now()
		dialDone := make(chan bool, 1)
		go func() {
			testConn, err := ns.DialContext(ctx, "tcp", net.JoinHostPort("1.1.1.1", "53"))
			if err == nil {
				_ = testConn.Close()
			}
			dialDone <- err == nil
		}()
		timer := time.NewTimer(time.Until(deadline))
		select {
		case ok := <-dialDone:
			timer.Stop()
			if ok {
				return time.Since(t0), true
			}
		case <-timer.C:
			return 0, false
		case <-ctx.Done():
			timer.Stop()
			return 0, false
		}
		time.Sleep(400 * time.Millisecond)
	}
	return 0, false
}

// extraOffer — a validated background tunnel plus its probe RTT.
type extraOffer struct {
	res attemptResult
	rtt time.Duration
}

// bootExtras — v1.4.0 FLUX turbo background sweep.
//
// Runs AFTER startEngine returned success (the primary tunnel is verified
// and its SOCKS port accepts). Sweeps the remaining endpoints of the
// WINNING transport (same wire format the DPI box already tolerates),
// validates each with a real round-trip, and accepts up to extraMax of
// them, each behind its own SOCKS listener on base+1..base+extraMax.
// Accepted tunnels are registered in st.extras (Stop() closes their
// listeners; rootCancel unwinds their MaintainTunnel goroutines). Every
// unaccepted attempt is cancelled and drain-closed when the collector
// exits, so nothing leaks.
//
// Ownership discipline mirrors the v1.2.5 model: before every accept the
// collector re-checks that the engine still owns its slot (a Stop() that
// landed mid-sweep turns this into a no-op) and all tunnels hang off
// rootCtx, so engine teardown never needs to know this goroutine exists.
func bootExtras(rootCtx context.Context, st *engineState, tlsConfig *tls.Config, localAddresses []netip.Addr, dnsAddrs []netip.Addr, winH2 bool, winnerIP string, basePort int) {
	transport := transportName(winH2)

	// tracked live attempts: anything still in here at exit is folded
	type liveAttempt struct {
		res attemptResult
	}
	var (
		liveMu  sync.Mutex
		live    []liveAttempt
		spawnWG sync.WaitGroup
	)

	fold := func(res attemptResult) {
		res.cancel()
		_ = closeTunDraining(res.dev)
	}
	unaccept := func(res attemptResult) {
		liveMu.Lock()
		for i, a := range live {
			if a.res.dev == res.dev {
				live = append(live[:i], live[i+1:]...)
				break
			}
		}
		liveMu.Unlock()
	}
	ownsSlot := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return current == st && rootCtx.Err() == nil
	}

	candidates := endpointCandidates(winH2)
	taken := map[string]bool{winnerIP: true}
	spawned := 0
	offers := make(chan extraOffer, len(candidates))
	for _, ep := range candidates {
		ip := addrIP(ep)
		if ip == "" || taken[ip] {
			continue
		}
		taken[ip] = true
		spawned++
		spawnWG.Add(1)
		go func(ep net.Addr) {
			defer spawnWG.Done()
			attemptCtx, attemptCancel := context.WithCancel(rootCtx)
			dev, ns, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, defaultMTU)
			if err != nil {
				attemptCancel()
				return
			}
			res := attemptResult{ep: ep, ctx: attemptCtx, cancel: attemptCancel, dev: dev, net: ns}
			liveMu.Lock()
			live = append(live, liveAttempt{res: res})
			liveMu.Unlock()

			go api.MaintainTunnel(attemptCtx, api.MaintainTunnelConfig{
				TLSConfig:         tlsConfig,
				KeepalivePeriod:   defaultKeepalive,
				InitialPacketSize: 0,
				Endpoint:          ep,
				Device:            api.NewNetstackAdapter(dev),
				MTU:               defaultMTU,
				ReconnectDelay:    defaultReconnect,
				AlwaysReconnect:   true,
				UseHTTP2:          winH2,
			})

			rtt, ok := probeTunnel(attemptCtx, ns, time.Now().Add(extraOverallCap), extraBudget)
			if ok {
				offers <- extraOffer{res: res, rtt: rtt}
			}
			// on failure: leave in `live` — the collector's exit fold tears
			// it down (cancel + drain-close) once all offers are in
		}(ep)
	}
	if spawned == 0 {
		log.Printf("warpcore: FLUX — no extra endpoint candidates for %s, single-path session", transport)
		return
	}
	go func() {
		spawnWG.Wait()
		close(offers) // every attempt settled: offered or failed its probe
	}()
	log.Printf("warpcore: FLUX — sweeping %d extra path candidate(s) (%s), target + tunnels on socks ports %d..%d",
		spawned, transport, basePort+1, basePort+extraMax)

	deadline := time.Now().Add(extraOverallCap)
	accepted := 0
acceptLoop:
	for accepted < extraMax {
		remain := time.Until(deadline)
		if remain <= 0 || !ownsSlot() {
			break
		}
		select {
		case off, open := <-offers:
			if !open {
				break acceptLoop // all attempts settled, none left to accept
			}
			if !ownsSlot() {
				fold(off.res)
				continue
			}
			port := basePort + 1 + accepted
			resolver := &internal.TunnelDNSResolver{
				DNSAddrs: dnsAddrs,
				Timeout:  defaultDNSTimeout,
				TunNet:   off.res.net,
			}
			srv, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
				Addr:       net.JoinHostPort("127.0.0.1", fmt.Sprint(port)),
				Resolver:   resolver,
				TunNet:     off.res.net,
				UDPTimeout: defaultUDPTtl,
				Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "warpcore: ", 0),
			})
			if err != nil {
				log.Printf("warpcore: FLUX extra on %s: socks server: %v", off.res.ep, err)
				fold(off.res)
				continue
			}
			// register BEFORE the listener starts, so a Stop() racing this
			// accept always finds and closes it
			mu.Lock()
			if current != st || rootCtx.Err() != nil {
				mu.Unlock()
				_ = srv.Stop()
				fold(off.res)
				return
			}
			st.extras = append(st.extras, &extraState{cancel: off.res.cancel, srv: srv, dev: off.res.dev})
			mu.Unlock()
			unaccept(off.res)

			go func() {
				if err := srv.Start(); err != nil && rootCtx.Err() == nil {
					log.Printf("warpcore: FLUX extra socks server exited: %v", err)
				}
			}()
			if !waitLocalPort(rootCtx, port, extraListenWait) {
				_ = srv.Stop()
				mu.Lock()
				for i, ex := range st.extras {
					if ex.srv == srv {
						st.extras = append(st.extras[:i], st.extras[i+1:]...)
						break
					}
				}
				mu.Unlock()
				fold(off.res)
				continue
			}
			accepted++
			log.Printf("warpcore: FLUX extra path %d/%d live (socks 127.0.0.1:%d, endpoint=%s, probe=%dms)",
				accepted, extraMax, port, off.res.ep, off.rtt.Milliseconds())
		case <-rootCtx.Done():
			// engine stopped: Stop() closes listeners + rootCancel unwinds
			// the tunnels; still fold whatever is parked in `live`
			liveMu.Lock()
			rest := live
			live = nil
			liveMu.Unlock()
			for _, a := range rest {
				a.res.cancel()
				_ = closeTunDraining(a.res.dev)
			}
			return
		case <-time.After(remain):
		}
	}

	// fold every attempt we spawned but never accepted
	liveMu.Lock()
	rest := live
	live = nil
	liveMu.Unlock()
	for _, a := range rest {
		a.res.cancel()
		_ = closeTunDraining(a.res.dev)
	}
	if accepted > 0 {
		log.Printf("warpcore: FLUX ready — %d extra path(s) behind the primary", accepted)
	} else {
		log.Printf("warpcore: FLUX — no extra path validated, single-path session")
	}
}

// Start brings up the MASQUE tunnel over ONE transport (kept for tools and
// tests; the app uses StartAuto/StartAutoWithMode). useHTTP2 selects MASQUE
// over TCP+TLS/H2 instead of QUIC/H3.
func Start(configDir string, port int, useHTTP2 bool) error {
	p := scanParamsFor("")
	p.transports = []bool{useHTTP2}
	return startEngine(configDir, port, p)
}

// StartAuto brings the tunnel up by RACING BOTH wire formats at once with
// the balanced scan profile (the v1.2.7 behaviour, kept for compatibility):
// MASQUE over HTTP/3 (QUIC, UDP 443) and MASQUE over HTTP/2 (TCP 443), each
// with its own endpoint sweep. A nil error means real traffic is flowing
// through the SOCKS listener.
func StartAuto(configDir string, port int) error {
	return startEngine(configDir, port, scanParamsFor(""))
}

// StartAutoWithMode is StartAuto with the user's Scan mode applied (v1.3.0).
// mode: "turbo" | "balanced" | "thorough" | "stealth" | "ironclad" — anything
// else falls back to balanced. See scanParams for the exact knobs.
func StartAutoWithMode(configDir string, port int, mode string) error {
	return startEngine(configDir, port, scanParamsFor(mode))
}

func startEngine(configDir string, port int, p scanParams) error {
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
			// failed or interrupted boot: unwind everything and release
			// the slot — but ONLY if we still own it (a Stop() may have
			// handed it to a newer boot already)
			rootCancel()
			mu.Lock()
			if current == st {
				current = nil
			}
			mu.Unlock()
			isRunning.Store(false)
		}
		// on success the slot STAYS owned by us: Stop() must find this
		// engine to be able to stop it.
	}()

	if err := config.LoadConfig(configPath(configDir)); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// repair any legacy mangled endpoint (older builds sliced the port
	// off by byte count and could persist "1.2.3.4:4")
	if host, _, err := net.SplitHostPort(config.AppConfig.EndpointV4); err == nil && net.ParseIP(host) != nil {
		config.AppConfig.EndpointV4 = host
	}
	if host, _, err := net.SplitHostPort(config.AppConfig.EndpointH2V4); err == nil && net.ParseIP(host) != nil {
		config.AppConfig.EndpointH2V4 = host
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

	// Race the transports: one sweep per entry in `transports`, first
	// sweep to prove a real round-trip wins. The winner's attempt context
	// is parented to rootCtx (NOT the sweep), so closing the losing
	// sweep's stop channel cannot touch the winning tunnel.
	startDeadline := time.Now().Add(p.hardCap)
	type outcome struct {
		res attemptResult
		h2  bool
		err error
	}
	outCh := make(chan outcome, len(p.transports))
	stopH3 := make(chan struct{})
	stopH2 := make(chan struct{})
	for _, h2 := range p.transports {
		h2 := h2
		stopCh := stopH3
		if h2 {
			stopCh = stopH2
		}
		go func() {
			res, err := sweepTransport(rootCtx, stopCh, startDeadline, tlsConfig, h2, localAddresses, dnsAddrs, p.waveBudget)
			outCh <- outcome{res: res, h2: h2, err: err}
		}()
	}

	var (
		win     attemptResult
		winH2   bool
		haveWin bool
		lastErr error
		pending = len(p.transports)
	)
	for pending > 0 {
		select {
		case o := <-outCh:
			pending--
			if o.err == nil && o.res.dev != nil {
				if !haveWin {
					win, winH2, haveWin = o.res, o.h2, true
					if o.h2 {
						close(stopH3) // tell the H3 sweep to stand down NOW
					} else {
						close(stopH2)
					}
					continue
				}
				// a second winner raced in: fold it — one live tunnel max
				go func(r attemptResult) {
					r.cancel()
					_ = closeTunDraining(r.dev)
				}(o.res)
				continue
			}
			if lastErr == nil {
				lastErr = o.err
			}
		case <-rootCtx.Done():
			return fmt.Errorf("engine stopped during endpoint sweep")
		}
	}
	if !haveWin {
		rootCancel()
		return fmt.Errorf("tunnel did not come up across %d transport(s) within %s: last: %v",
			len(p.transports), p.hardCap, lastErr)
	}

	// Remember the winner so the NEXT boot validates it first (~1-2s
	// instead of a fresh sweep) — "quick-reconnect to the last known-good
	// gateway". Saved per transport: H3 winner in EndpointV4, H2 winner
	// in EndpointH2V4; endpointCandidates() puts the stored endpoint at
	// the front of its sweep.
	ip := ""
	switch a := win.ep.(type) {
	case *net.UDPAddr:
		ip = a.IP.String()
	case *net.TCPAddr:
		ip = a.IP.String()
	}
	if ip != "" {
		if winH2 {
			config.AppConfig.EndpointH2V4 = ip
		} else {
			config.AppConfig.EndpointV4 = ip
		}
		_ = config.AppConfig.SaveConfig(configPath(configDir))
	}

	resolver := &internal.TunnelDNSResolver{
		DNSAddrs: dnsAddrs,
		Timeout:  defaultDNSTimeout,
		TunNet:   win.net,
	}
	server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
		Addr:       net.JoinHostPort("127.0.0.1", fmt.Sprint(port)),
		Resolver:   resolver,
		TunNet:     win.net,
		UDPTimeout: defaultUDPTtl,
		Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "warpcore: ", 0),
	})
	if err != nil {
		rootCancel()
		_ = closeTunDraining(win.dev)
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
		err := server.Start()
		if err != nil && rootCtx.Err() == nil {
			// BUG HISTORY (v1.4.0, exposed by a stale port-holder in the
			// sandbox): when the listener dies on its own (bind failure,
			// EMFILE...) the old code closed the tunnel device under a LIVE
			// context — MaintainTunnel treats the closed device as a transient
			// loss and reconnects FOREVER ("Tunnel connection lost: failed to
			// read from TUN device: file already closed. Reconnecting..."
			// every second, hammering Cloudflare with handshakes). Unwind the
			// engine exactly like Stop() would: cancel first (the Maintain loop
			// exits via its ctx checks), release the slot, THEN close.
			log.Printf("warpcore: socks server exited: %v — unwinding engine", err)
			rootCancel()
			mu.Lock()
			if current == st {
				current = nil
			}
			mu.Unlock()
		}
		_ = closeTunDraining(win.dev)
	}()

	// Wait until the listener actually accepts before declaring readiness,
	// so "boot returned nil" also means "the SOCKS port is reachable".
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
		_ = closeTunDraining(win.dev)
		return fmt.Errorf("socks listener did not come up on port %d", port)
	}

	ok = true
	log.Printf("warpcore: engine ready (%s, endpoint=%s)", transportName(winH2), win.ep)

	// v1.4.0 FLUX turbo: the user is online — now widen the road. In the
	// background the engine validates up to extraMax MORE tunnels on the
	// remaining endpoints of the winning transport and exposes each on its
	// own SOCKS port (base+1..); sing-box's urltest group rotates traffic
	// onto whichever path is currently fastest. Pure enrichment: nothing in
	// the connect path waits on this, and a Stop() tears extras down via
	// the usual ownership path.
	go bootExtras(rootCtx, st, tlsConfig, localAddresses, dnsAddrs, winH2, ip, port)

	return nil
}

// Stop tears the engine down and waits (up to stopWait) for the owning
// boot to unwind. Safe to call when not running, safe to call while a
// boot is still sweeping (the ownership handoff makes the old
// clobber-a-newer-boot race impossible).
func Stop() {
	mu.Lock()
	st := current
	current = nil // take the slot away FIRST — a newer boot is unaffected
	mu.Unlock()

	if st == nil {
		isRunning.Store(false)
		return
	}
	if st.cancel != nil {
		st.cancel()
	}
	if st.srv != nil {
		_ = st.srv.Stop() // shuts the listener + relays down, so boot returns
	}
	// v1.4.0 FLUX: the background tunnels die via st.cancel (rootCancel)
	// above; their SOCKS listeners are NOT parented to that context, so
	// each gets an explicit Stop here. Snapshot under mu: bootExtras only
	// ever appends while the slot is still owned, so nothing new appears
	// after this point.
	mu.Lock()
	extras := st.extras
	st.extras = nil
	mu.Unlock()
	for _, ex := range extras {
		if ex != nil && ex.srv != nil {
			_ = ex.srv.Stop()
		}
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
