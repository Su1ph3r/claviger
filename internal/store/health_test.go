package store

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthReflectsState(t *testing.T) {
	r := &expiringRecipe{id: "a", ttl: time.Hour}
	s := New()
	s.Register(r)

	h := s.Health()
	if len(h) != 1 || h[0].Name != "a" || h[0].Established {
		t.Fatalf("pre-get health = %+v, want a / not established", h)
	}

	if _, err := s.Get(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	h = s.Health()
	if !h[0].Established || h[0].ExpiresAt.IsZero() || h[0].LastRefresh.IsZero() || h[0].LastError != "" {
		t.Fatalf("post-get health = %+v, want established with expiry+refresh and no error", h[0])
	}
}

func TestRefreshExpiringRenewsOnlyNearExpiry(t *testing.T) {
	// establish returns a 5s-expiry session; refresh returns a 1h-expiry one.
	r := &expiringRecipe{id: "a", ttl: 5 * time.Second}
	s := New()
	s.Register(r)
	if _, err := s.Get(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}

	// Window covers the 5s expiry -> one refresh.
	if errs := s.RefreshExpiring(context.Background(), 10*time.Second); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if got := atomic.LoadInt64(&r.refreshes); got != 1 {
		t.Fatalf("refreshes = %d, want 1", got)
	}

	// The renewed session is 1h out, so a second call does nothing.
	s.RefreshExpiring(context.Background(), 10*time.Second)
	if got := atomic.LoadInt64(&r.refreshes); got != 1 {
		t.Fatalf("refreshes = %d, want still 1 (renewed session is far-future)", got)
	}
}
