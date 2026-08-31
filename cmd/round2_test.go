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

func writeReplayConfig(t *testing.T, url string) string {
	t.Helper()
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
`, url, url)
	p := filepath.Join(t.TempDir(), "claviger.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReplayRejectsPathWithoutSlash(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()
	cfg := writeReplayConfig(t, ts.URL)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"replay", "--config", cfg, "--as", "alice", "--path", "noslash"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("expected an error for --path without a leading slash")
	}
}

func TestReplayAllFailedExitsNonZero(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()
	cfg := writeReplayConfig(t, ts.URL)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	// Unknown identities -> every row errors -> non-zero exit.
	root.SetArgs([]string{"replay", "--config", cfg, "--as", "ghost1", "--as", "ghost2", "--path", "/api/whoami"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Fatal("expected a non-zero exit when all identities fail")
	}
}
