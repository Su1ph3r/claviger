package store

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
)

// expiringRecipe establishes a short-lived session and refreshes into a long-lived
// one, so a Get after the first session's expiry must trigger exactly one refresh.
type expiringRecipe struct {
	id        string
	ttl       time.Duration
	refreshes int64
}

func (r *expiringRecipe) Identity() string { return r.id }
func (r *expiringRecipe) Establish(ctx context.Context) (*session.Session, error) {
	return &session.Session{Identity: r.id, BearerToken: "est", ExpiresAt: time.Now().Add(r.ttl)}, nil
}
func (r *expiringRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	atomic.AddInt64(&r.refreshes, 1)
	return &session.Session{Identity: r.id, BearerToken: "ref", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (r *expiringRecipe) Logout() recipeLogoutSignature { return recipeLogoutSignature{} }

func TestGetRefreshesExpiredSession(t *testing.T) {
	r := &expiringRecipe{id: "a", ttl: 30 * time.Millisecond}
	s := New()
	s.Register(r)

	first, err := s.Get(context.Background(), "a")
	if err != nil || first.BearerToken != "est" {
		t.Fatalf("first get = %+v err %v", first, err)
	}

	// Wait past the cached session's expiry.
	time.Sleep(60 * time.Millisecond)

	second, err := s.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if second.BearerToken != "ref" {
		t.Fatalf("expected a refreshed session after expiry, got %q", second.BearerToken)
	}
	if got := atomic.LoadInt64(&r.refreshes); got != 1 {
		t.Fatalf("expected exactly 1 refresh on expiry, got %d", got)
	}

	// The refreshed session is long-lived, so a third Get is served from cache
	// without another re-auth.
	third, err := s.Get(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if third.BearerToken != "ref" || atomic.LoadInt64(&r.refreshes) != 1 {
		t.Fatalf("third get should be cached: token %q refreshes %d", third.BearerToken, atomic.LoadInt64(&r.refreshes))
	}
}

func TestIdentitiesSorted(t *testing.T) {
	s := New()
	for _, id := range []string{"charlie", "alice", "bob"} {
		s.Register(&countingRecipe{id: id})
	}
	got := s.Identities()
	want := []string{"alice", "bob", "charlie"}
	if len(got) != len(want) {
		t.Fatalf("Identities() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Identities() = %v, want sorted %v", got, want)
		}
	}
}
