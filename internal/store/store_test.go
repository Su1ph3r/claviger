// internal/store/store_test.go
package store

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
)

// countingRecipe records how many times Establish/Refresh run.
type countingRecipe struct {
	id        string
	refreshes int64
}

func (r *countingRecipe) Identity() string { return r.id }
func (r *countingRecipe) Establish(ctx context.Context) (*session.Session, error) {
	return &session.Session{Identity: r.id, BearerToken: "est"}, nil
}
func (r *countingRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	atomic.AddInt64(&r.refreshes, 1)
	time.Sleep(20 * time.Millisecond) // widen the race window
	return &session.Session{Identity: r.id, BearerToken: "ref"}, nil
}

// Logout is unused by the store but required by the interface.
func (r *countingRecipe) Logout() logoutSig { return logoutSig{} }

func TestGetEstablishesOnce(t *testing.T) {
	s := New()
	s.Register(&countingRecipe{id: "a"})
	sess, err := s.Get(context.Background(), "a")
	if err != nil || sess.BearerToken != "est" {
		t.Fatalf("get = %+v, err %v", sess, err)
	}
}

func TestRefreshIsSingleFlight(t *testing.T) {
	r := &countingRecipe{id: "a"}
	s := New()
	s.Register(r)
	if _, err := s.Get(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Refresh(context.Background(), "a")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&r.refreshes); got != 1 {
		t.Fatalf("refresh ran %d times, want 1 (single-flight)", got)
	}
}

func TestRefreshBackoffLimit(t *testing.T) {
	r := &countingRecipe{id: "a"}
	s := New()
	s.Register(r)
	if _, err := s.Get(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}

	// Default backoff ceiling is maxBurst=10 per 60s window. Sequential Refresh
	// calls each see a changed "before" pointer (the prior Refresh swapped it), so
	// each of the first 10 actually re-auths.
	for i := 0; i < 10; i++ {
		if _, err := s.Refresh(context.Background(), "a"); err != nil {
			t.Fatalf("refresh %d: unexpected error %v", i+1, err)
		}
	}
	if got := atomic.LoadInt64(&r.refreshes); got != 10 {
		t.Fatalf("after 10 refreshes, recipe ran %d times, want 10", got)
	}

	// The 11th refresh is over the window ceiling: it must error without calling
	// the recipe, so the auth target is not hammered.
	if _, err := s.Refresh(context.Background(), "a"); err == nil {
		t.Fatal("11th refresh: want rate-limit error, got nil")
	}
	if got := atomic.LoadInt64(&r.refreshes); got != 10 {
		t.Fatalf("after rate-limited refresh, recipe ran %d times, want 10 (11th must not re-auth)", got)
	}
}

type logoutSig = recipeLogoutSignature
