package warpcore

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func waitPort(port string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

func traceOnce(client *http.Client) (string, error) {
	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func socksClient(port string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:" + port)
			},
		},
		Timeout: 25 * time.Second,
	}
}

func runE2E(t *testing.T, useH2 bool) {
	t.Helper()
	dir := t.TempDir()

	if err := Register(dir); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !HasConfig(dir) {
		t.Fatalf("HasConfig = false after Register")
	}

	port := "2085"
	if err := Start(dir, 2085, useH2); err != nil {
		t.Fatalf("Start(h2=%v): %v", useH2, err)
	}
	defer Stop()

	if !waitPort(port, 25*time.Second) {
		t.Fatalf("socks port never came up (h2=%v)", useH2)
	}

	client := socksClient(port)
	var text string
	for attempt := 1; attempt <= 5; attempt++ {
		body, err := traceOnce(client)
		if err == nil && strings.Contains(body, "warp=on") {
			t.Logf("PASS h2=%v — exit verified (warp=on)", useH2)
			return
		}
		if err != nil {
			text = err.Error()
		} else {
			text = body
		}
		t.Logf("attempt %d (h2=%v): %s", attempt, useH2, strings.TrimSpace(text))
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("trace never succeeded (h2=%v): %s", useH2, text)
}

func TestE2E_H3(t *testing.T)    { runE2E(t, false) }
func TestE2E_HTTP2(t *testing.T) { runE2E(t, true) }

// Restart with the SAME identity — the app's real usage pattern:
// H3 → H2 → H3 back-to-back in one process must all work.
func TestRestartSameIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := Register(dir); err != nil {
		t.Fatalf("Register: %v", err)
	}
	runOnExisting(t, dir, false)
	runOnExisting(t, dir, true)
	runOnExisting(t, dir, false)
}

func runOnExisting(t *testing.T, dir string, useH2 bool) {
	t.Helper()
	if err := Start(dir, 2085, useH2); err != nil {
		t.Fatalf("Start(h2=%v): %v", useH2, err)
	}
	defer Stop()
	client := socksClient("2085")
	var text string
	for attempt := 1; attempt <= 5; attempt++ {
		body, err := traceOnce(client)
		if err == nil && strings.Contains(body, "warp=on") {
			t.Logf("PASS h2=%v (attempt %d)", useH2, attempt)
			return
		}
		if err != nil {
			text = err.Error()
		} else {
			text = body
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("trace never succeeded (h2=%v): %s", useH2, text)
}

func TestStopIdempotent(t *testing.T) {
	Stop()
	Stop()
}

// traceField pulls one "key=value" line out of a cdn-cgi/trace body.
func traceField(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}

// v1.4.0 FLUX turbo proof: after the primary tunnel is live, the background
// sweep must bring up extra tunnels on socks base+1.. WITHOUT disturbing the
// primary. This answers the one open design question with real Cloudflare
// infrastructure: does CF accept CONCURRENT long-lived MASQUE sessions for
// the SAME device identity (one identity, several tunnels to different
// edges)? If the primary dies when extras come up, the whole FLUX model is
// dead and extras must move to second identities.
func TestE2E_FluxExtras(t *testing.T) {
	dir := t.TempDir()
	if err := Register(dir); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := Start(dir, 2085, false); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer Stop()

	if !waitPort("2085", 25*time.Second) {
		t.Fatalf("primary socks 2085 never came up")
	}

	// the primary must be verified BEFORE extras exist
	cl := socksClient("2085")
	body, err := traceOnce(cl)
	if err != nil || !strings.Contains(body, "warp=on") {
		t.Fatalf("primary trace failed before extras: err=%v body=%s", err, strings.TrimSpace(body))
	}
	t.Logf("primary live: ip=%s colo=%s", traceField(body, "ip"), traceField(body, "colo"))

	// wait for the background sweep to accept at least one extra. The H3
	// edge pool that serves MASQUE for THIS device cert is small (sandbox
	// v1.4.0: only 162.159.198.x answer; the rest reject the handshake with
	// CRYPTO_ERROR) — so one extra is a PASS, two is a bonus.
	deadline := time.Now().Add(75 * time.Second)
	for ExtraCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
	}
	if got := ExtraCount(); got < 1 {
		t.Fatalf("ExtraCount = %d, want >= 1", got)
	}
	t.Logf("FLUX accepted %d extra path(s)", ExtraCount())
	if !waitPort("2086", 10*time.Second) {
		t.Fatalf("extra socks 2086 did not come up")
	}

	// every accepted extra must be a real WARP exit; 2087 only exists when
	// two extras were accepted
	wantPorts := []string{"2086"}
	if ExtraCount() >= 2 {
		wantPorts = append(wantPorts, "2087")
	}
	for _, port := range wantPorts {
		ec := socksClient(port)
		ok := false
		for attempt := 1; attempt <= 4; attempt++ {
			b, err := traceOnce(ec)
			if err == nil && strings.Contains(b, "warp=on") {
				t.Logf("extra %s live: ip=%s colo=%s", port, traceField(b, "ip"), traceField(b, "colo"))
				ok = true
				break
			}
			t.Logf("extra %s attempt %d: err=%v body=%s", port, attempt, err, strings.TrimSpace(b))
			time.Sleep(2 * time.Second)
		}
		if !ok {
			t.Fatalf("extra socks %s never verified warp=on", port)
		}
	}

	// same-device concurrency stability: the primary must STILL carry
	// traffic with the extras held live — interleaved rounds over ~30s
	livePorts := append([]string{"2085"}, wantPorts...)
	for round := 1; round <= 4; round++ {
		for _, port := range livePorts {
			b, err := traceOnce(socksClient(port))
			if err != nil || !strings.Contains(b, "warp=on") {
				t.Fatalf("round %d: path %s died under concurrent load: err=%v body=%s",
					round, port, err, strings.TrimSpace(b))
			}
		}
		time.Sleep(5 * time.Second)
	}
	body, err = traceOnce(cl)
	if err != nil || !strings.Contains(body, "warp=on") {
		t.Fatalf("primary died after extras came up: err=%v body=%s", err, strings.TrimSpace(body))
	}
	t.Logf("primary still live after extras: ip=%s colo=%s — same-device multi-session OK",
		traceField(body, "ip"), traceField(body, "colo"))

	// teardown must close the extras too, and the identity must restart
	Stop()
	time.Sleep(2 * time.Second)
	if IsRunning() {
		t.Fatalf("IsRunning=true after Stop")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:2086", 500*time.Millisecond); err == nil {
		t.Fatalf("extra port 2086 still open after Stop")
	}
	if err := Start(dir, 2085, false); err != nil {
		t.Fatalf("restart with same identity: %v", err)
	}
	defer Stop()
	for attempt := 1; attempt <= 5; attempt++ {
		b, err := traceOnce(socksClient("2085"))
		if err == nil && strings.Contains(b, "warp=on") {
			t.Logf("PASS — restart verified (warp=on)")
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("restart never verified warp=on")
}
