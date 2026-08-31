package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// When XDG_RUNTIME_DIR is set, the socket lands under it. That directory is
// guaranteed owner-only (0700) by the XDG spec, and the socket file itself is
// chmod'd 0600 at bind time, so the credential surface is owner-private.
func TestDefaultSocketPathUsesXDGRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, dir) {
		t.Fatalf("socket path %q not under XDG_RUNTIME_DIR %q", p, dir)
	}
	if filepath.Base(p) != "claviger.sock" {
		t.Fatalf("socket base = %q, want claviger.sock", filepath.Base(p))
	}
}

// With no XDG_RUNTIME_DIR, the fallback directory is one we create ourselves, so
// it must be created owner-only (0700), never world-readable.
func TestDefaultSocketPathFallbackDirIsOwnerOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", home)

	p, err := defaultSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(home, ".claviger")
	if filepath.Dir(p) != wantDir {
		t.Fatalf("socket dir = %q, want %q", filepath.Dir(p), wantDir)
	}
	info, err := os.Stat(wantDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("fallback dir mode = %o, want 0700", perm)
	}
}
