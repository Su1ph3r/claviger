package gateway

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/session"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// A non-loopback Host must be rejected before any credential is injected: this is
// the DNS-rebinding defense. A browser resolving evil.com to 127.0.0.1 still sends
// Host: evil.com.
func TestGatewayRejectsNonLoopbackHost(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	g, _ := newTestGateway(t, ts.URL, time.Minute)
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	req, _ := http.NewRequest("GET", front.URL+"/api/whoami", nil)
	req.Host = "evil.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for non-loopback Host", resp.StatusCode)
	}
}

// failingRefreshRecipe establishes once, then always fails to refresh.
type failingRefreshRecipe struct{ id string }

func (r *failingRefreshRecipe) Identity() string { return r.id }
func (r *failingRefreshRecipe) Establish(ctx context.Context) (*session.Session, error) {
	return &session.Session{Identity: r.id, BearerToken: "tok"}, nil
}
func (r *failingRefreshRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return nil, fmt.Errorf("refresh boom")
}
func (r *failingRefreshRecipe) Logout() recipe.LogoutSignature {
	return recipe.LogoutSignature{StatusCodes: []int{401}}
}

// A failed transparent reauth must be surfaced, not swallowed: otherwise a broken
// session authority silently degrades to a plain passthrough of the logout response.
func TestGatewaySurfacesReauthFailure(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("unauthenticated"))
	}))
	defer target.Close()

	rec := &failingRefreshRecipe{id: "alice"}
	st := store.New()
	st.Register(rec)
	g, err := New(st, map[string]recipe.Recipe{"alice": rec}, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	g.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	// The client still receives the logged-out response; the point is the failure
	// is no longer invisible.
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401 passthrough", resp.StatusCode)
	}
	if !strings.Contains(buf.String(), "reauth failed") {
		t.Fatalf("expected the reauth failure to be logged, got %q", buf.String())
	}
}
