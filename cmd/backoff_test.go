// cmd/backoff_test.go
package cmd

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// A config with backoff.max_burst=1 must make the store rate-limit the second
// refresh; the default (10) would not. Refresh (unlike establish) always goes
// through the limiter, so two Refresh calls pin the wiring without any timing.
func TestBuildStoreAppliesBackoff(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(0).Handler()) // ttl 0 = tokens never self-expire
	defer ts.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claviger.yaml")
	cfg := fmt.Sprintf(`
target: %s
backoff:
  max_burst: 1
  window: 1h
identities:
  - name: alice
    type: form
    login_url: %s/login
    username: alice
    password: pw
`, ts.URL, ts.URL)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	st, _, _, err := buildStore(cfgPath, tlsFlags{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := st.Refresh(ctx, "alice"); err != nil {
		t.Fatalf("first refresh should succeed, got %v", err)
	}
	_, err = st.Refresh(ctx, "alice")
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("expected a rate-limit error from max_burst=1 on the second refresh, got %v", err)
	}
}
