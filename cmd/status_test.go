package cmd

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/control"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestDeriveState(t *testing.T) {
	now := time.Now()
	rfc := func(d time.Duration) string { return now.Add(d).UTC().Format(time.RFC3339) }
	cases := []struct {
		s    control.IdentityStatus
		want string
	}{
		{control.IdentityStatus{Established: false}, "no-session"},
		{control.IdentityStatus{Established: true}, "live"},
		{control.IdentityStatus{Established: true, ExpiresAt: rfc(time.Hour)}, "live"},
		{control.IdentityStatus{Established: true, ExpiresAt: rfc(30 * time.Second)}, "expiring"},
		{control.IdentityStatus{Established: true, ExpiresAt: rfc(-time.Minute)}, "EXPIRED"},
	}
	for i, c := range cases {
		if got, _ := deriveState(c.s, now); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
}

func TestRenderStatusPlain(t *testing.T) {
	now := time.Now()
	st := control.StatusResponse{Identities: []control.IdentityStatus{
		{Name: "alice", Established: true, ExpiresAt: now.Add(time.Hour).UTC().Format(time.RFC3339)},
		{Name: "bob", Established: false, LastError: "idp down"},
	}}
	var buf bytes.Buffer
	renderStatus(&buf, st, now, false) // no color
	out := buf.String()
	for _, want := range []string{"IDENTITY", "STATE", "alice", "live", "bob", "no-session", "idp down"} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q:\n%s", want, out)
		}
	}
}

// header attaches to a running daemon over the socket: with an invalid --config,
// success proves it used the daemon rather than logging in standalone.
func TestHeaderAttachesToDaemon(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	st := store.New()
	st.Register(&recipe.FormPost{
		ID: "alice", LoginURL: ts.URL + "/login",
		Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
	})
	f, err := os.CreateTemp("", "clv*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sock := f.Name()
	f.Close()
	os.Remove(sock)
	defer os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, control.NewServer(st))

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"header", "alice", "--socket", sock, "--config", "/nonexistent.yaml"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("header via socket failed: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Authorization: Bearer") {
		t.Fatalf("output missing bearer header: %s", out.String())
	}
}
