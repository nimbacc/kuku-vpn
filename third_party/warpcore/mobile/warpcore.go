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
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultSNI        = internal.ConnectSNI
	defaultMTU        = 1280
	defaultKeepalive  = 30 * time.Second
	defaultReconnect  = 1 * time.Second
	defaultUDPTtl     = 60 * time.Second
	defaultDNSTimeout = 2 * time.Second
	readyTimeout      = 25 * time.Second
)

var (
	mu        sync.Mutex // guards stopFn/doneCh/server handle swap
	stopFn    func()     // cancels the active engine (nil = none)
	doneCh    chan struct{}
	activeSrv *internal.SOCKS5Server
	isRunning atomic.Bool
)

// IsRunning reports whether the engine currently holds a tunnel.
func IsRunning() bool { return isRunning.Load() }

// Register creates a fresh WARP-over-MASQUE identity (account + enrolled
// device key) and persists it to <configDir>/config.json. Call once;
// the identity is reused forever after.
func Register(configDir string) error {
	mu.Lock()
	if stopFn != nil {
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

// Start brings up the MASQUE tunnel and a SOCKS5 proxy on 127.0.0.1:port.
// It returns only after the tunnel is verified with a real round-trip AND
// the listener accepts, so a nil error means traffic can flow. useHTTP2
// selects HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC — the fallback
// for networks that filter UDP entirely.
func Start(configDir string, port int, useHTTP2 bool) error {
	mu.Lock()
	if stopFn != nil {
		mu.Unlock()
		return fmt.Errorf("engine is already running; stop it first")
	}
	stopFn = func() {} // placeholder: blocks re-entry while starting
	doneCh = make(chan struct{})
	mu.Unlock()

	ok := false
	defer func() {
		if !ok {
			isRunning.Store(false)
			mu.Lock()
			stopFn = nil
			mu.Unlock()
		}
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

	endpoint, err := config.SelectEndpointFromConfig(useHTTP2, false, 443)
	if err != nil {
		return fmt.Errorf("select endpoint: %w", err)
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

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, defaultMTU)
	if err != nil {
		return fmt.Errorf("create netstack: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	setStop := func() { cancel() }
	mu.Lock()
	stopFn = setStop
	mu.Unlock()

	go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:         tlsConfig,
		KeepalivePeriod:   defaultKeepalive,
		InitialPacketSize: 0,
		Endpoint:          endpoint,
		Device:            api.NewNetstackAdapter(tunDev),
		MTU:               defaultMTU,
		ReconnectDelay:    defaultReconnect,
		AlwaysReconnect:   true,
		UseHTTP2:          useHTTP2,
	})

	// Gate the SOCKS listener on a real round-trip through the tunnel, so
	// "Start returned nil" always means "traffic can flow" for the caller.
	ready := false
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			_ = tunDev.Close()
			return fmt.Errorf("engine stopped before ready")
		}
		testConn, dialErr := tunNet.DialContext(ctx, "tcp", net.JoinHostPort("1.1.1.1", "53"))
		if dialErr == nil {
			_ = testConn.Close()
			ready = true
			break
		}
		time.Sleep(400 * time.Millisecond)
	}
	if !ready {
		cancel()
		_ = tunDev.Close()
		return fmt.Errorf("tunnel did not come up within %s (http2=%v)", readyTimeout, useHTTP2)
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
		cancel()
		_ = tunDev.Close()
		return fmt.Errorf("create socks server: %w", err)
	}

	// Remember the server so Stop() can shut the listener down deterministically.
	mu.Lock()
	activeSrv = server
	mu.Unlock()

	isRunning.Store(true)
	go func() {
		defer close(doneCh)
		defer isRunning.Store(false)
		defer cancel()
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
		if ctx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !listening {
		_ = server.Stop()
		cancel()
		_ = tunDev.Close()
		return fmt.Errorf("socks listener did not come up on port %d", port)
	}

	ok = true
	log.Printf("warpcore: engine ready (http2=%v, endpoint=%s)", useHTTP2, endpoint)
	return nil
}

// Stop tears the engine down and waits (up to a few seconds) for its port to
// be released. Safe to call when not running.
func Stop() {
	mu.Lock()
	fn := stopFn
	ch := doneCh
	srv := activeSrv
	mu.Unlock()

	if fn != nil {
		fn()
	}
	if srv != nil {
		_ = srv.Stop() // shuts the listener + relays down, so Start() returns
	}
	if ch != nil {
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
		}
	}
	mu.Lock()
	stopFn = nil
	doneCh = nil
	activeSrv = nil
	mu.Unlock()
	isRunning.Store(false)
}

func configPath(configDir string) string {
	return fmt.Sprintf("%s/config.json", configDir)
}
