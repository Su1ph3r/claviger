package control

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/session"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// shortSocketPath returns a unique, short socket path under the system temp dir,
// avoiding the ~104-char sun_path limit that t.TempDir() paths can exceed.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "clv*.sock")
	if err != nil {
		t.Fatal(err)
	}
	p := f.Name()
	f.Close()
	os.Remove(p)
	t.Cleanup(func() { os.Remove(p) })
	return p
}

func TestClientCredsAndStatusOverSocket(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	st := store.New()
	st.Register(&recipe.FormPost{
		ID: "alice", LoginURL: ts.URL + "/login",
		Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
	})

	sock := shortSocketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, NewServer(st))

	if !SocketExists(sock) {
		t.Fatal("SocketExists returned false for a live socket")
	}

	c := NewClient(sock)

	sess, err := c.Creds(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Identity != "alice" || sess.BearerToken == "" {
		t.Fatalf("creds = %+v, want alice with a bearer", sess)
	}

	status, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Identities) != 1 || status.Identities[0].Name != "alice" || !status.Identities[0].Established {
		t.Fatalf("status = %+v, want one established alice", status)
	}
	if status.Identities[0].ExpiresAt == "" {
		t.Fatal("status should carry an expiry (mock sends expires_in)")
	}
}

// stubCSRFRecipe yields a session carrying a captured CSRF token and an extra
// header, so a test can prove the control socket round-trips them.
type stubCSRFRecipe struct{ id string }

func (r stubCSRFRecipe) Identity() string { return r.id }
func (r stubCSRFRecipe) Establish(context.Context) (*session.Session, error) {
	return &session.Session{
		Identity:    r.id,
		BearerToken: "b",
		CSRF:        "csrf-token-xyz",
		Headers:     http.Header{"X-Extra": {"hval"}},
	}, nil
}
func (r stubCSRFRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return r.Establish(ctx)
}
func (r stubCSRFRecipe) Logout() recipe.LogoutSignature { return recipe.LogoutSignature{} }

// TestClientCredsPreservesCSRFAndHeaders pins that a daemon-attached session is
// byte-for-byte what a standalone login would apply: the captured CSRF token and
// any extra headers survive the /creds round-trip. Without them, daemon-attached
// replay would send a weaker request than standalone and corrupt the authz matrix.
func TestClientCredsPreservesCSRFAndHeaders(t *testing.T) {
	st := store.New()
	st.Register(stubCSRFRecipe{id: "multi"})

	sock := shortSocketPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, NewServer(st))

	sess, err := NewClient(sock).Creds(context.Background(), "multi")
	if err != nil {
		t.Fatal(err)
	}
	if sess.CSRF != "csrf-token-xyz" {
		t.Errorf("CSRF = %q, want it preserved over the control socket", sess.CSRF)
	}
	if sess.Headers.Get("X-Extra") != "hval" {
		t.Errorf("Headers = %v, want X-Extra preserved over the control socket", sess.Headers)
	}
}
