package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// Drives the replay subcommand end to end against the mock auth server via a real
// config file, asserting both identities come back 200.
func TestReplaySubcommandE2E(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

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
  - name: bob
    type: form
    login_url: %s/login
    username: bob
    password: pw
    logout:
      status_codes: [401]
`, ts.URL, ts.URL, ts.URL)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "claviger.yaml")
	os.WriteFile(cfgPath, []byte(cfg), 0o600)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"replay", "--config", cfgPath, "--as", "alice", "--as", "bob", "--path", "/api/whoami"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("replay failed: %v\noutput:\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"alice", "bob", "200"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}
