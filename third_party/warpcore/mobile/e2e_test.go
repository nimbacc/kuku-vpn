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
