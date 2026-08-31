// cmd/daemon_integration_test.go
package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/control"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// freePort returns a currently-free TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestDaemonBootServeShutdown boots the real daemon command in-process against a
// mock target, drives a gateway request and the control socket, then cancels the
// context and asserts a clean (nil) shutdown.
func TestDaemonBootServeShutdown(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claviger.yaml")
	cfg := fmt.Sprintf(`
target: %s
identities:
  - name: alice
    type: form
    login_url: %s/login
    username: alice
    password: pw
    logout:
      status_codes: [401]
`, ts.URL, ts.URL)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "clv.sock")
	port := freePort(t)

	root := NewRootCmd()
	root.SetArgs([]string{
		"daemon",
		"--config", cfgPath,
		"--socket", sock,
		"--base-port", strconv.Itoa(port),
		"--refresh-interval", "50ms",
	})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- root.ExecuteContext(ctx) }()

	// Wait for the daemon to come up: the control socket is bound after the
	// gateway ports, so once it exists the gateway is listening too.
	deadline := time.Now().Add(5 * time.Second)
	for !control.SocketExists(sock) {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("daemon did not come up: %v", <-errc)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Control socket: status lists alice; creds establishes and returns a session.
	client := control.NewClient(sock)
	stResp, err := client.Status(context.Background())
	if err != nil {
		cancel()
		t.Fatalf("status: %v", err)
	}
	if len(stResp.Identities) != 1 || stResp.Identities[0].Name != "alice" {
		cancel()
		t.Fatalf("status identities = %+v, want one alice", stResp.Identities)
	}
	sess, err := client.Creds(context.Background(), "alice")
	if err != nil {
		cancel()
		t.Fatalf("creds: %v", err)
	}
	if sess.BearerToken == "" && len(sess.Cookies) == 0 {
		cancel()
		t.Fatal("creds returned an empty session")
	}

	// Gateway port: a request is proxied to the target with the session applied.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/whoami", port))
	if err != nil {
		cancel()
		t.Fatalf("gateway request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("gateway status = %d, want 200", resp.StatusCode)
	}

	// Clean shutdown: cancelling the context ends RunE with nil.
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down within 5s of cancel")
	}
}
