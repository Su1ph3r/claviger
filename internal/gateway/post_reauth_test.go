package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/session"
	"github.com/Su1ph3r/claviger/internal/store"
)

// countingReauthRecipe establishes a session and counts successful refreshes.
type countingReauthRecipe struct {
	id       string
	refresh  int64
	sequence int64
}

func (r *countingReauthRecipe) Identity() string { return r.id }
func (r *countingReauthRecipe) Establish(ctx context.Context) (*session.Session, error) {
	n := atomic.AddInt64(&r.sequence, 1)
	return &session.Session{Identity: r.id, BearerToken: "tok" + string(rune('0'+n))}, nil
}
func (r *countingReauthRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	atomic.AddInt64(&r.refresh, 1)
	n := atomic.AddInt64(&r.sequence, 1)
	return &session.Session{Identity: r.id, BearerToken: "tok" + string(rune('0'+n))}, nil
}
func (r *countingReauthRecipe) Logout() recipe.LogoutSignature {
	return recipe.LogoutSignature{StatusCodes: []int{401}}
}

// A POST that hits a logout signal must re-authenticate the identity (so the next
// request is live) but must NOT be blindly replayed (delivered exactly once).
func TestGatewayPostReauthsWithoutReplay(t *testing.T) {
	var posts int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			atomic.AddInt64(&posts, 1)
		}
		w.WriteHeader(401)
		w.Write([]byte("unauthenticated"))
	}))
	defer target.Close()

	rec := &countingReauthRecipe{id: "alice"}
	st := store.New()
	st.Register(rec)
	g, err := New(st, map[string]recipe.Recipe{"alice": rec}, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Post(front.URL+"/api/do", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401 (POST not replayed, logout surfaced)", resp.StatusCode)
	}
	if got := atomic.LoadInt64(&posts); got != 1 {
		t.Fatalf("target received %d POSTs, want exactly 1 (no blind replay)", got)
	}
	if got := atomic.LoadInt64(&rec.refresh); got != 1 {
		t.Fatalf("recipe refreshed %d times, want 1 (a POST logout must still reauth)", got)
	}
}
