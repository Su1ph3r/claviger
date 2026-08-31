package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
)

// deadRefreshRecipe establishes a clock-live session but always fails to refresh,
// modeling an identity the gateway has proven logged-out whose renewal fails.
type deadRefreshRecipe struct{ id string }

func (r *deadRefreshRecipe) Identity() string { return r.id }
func (r *deadRefreshRecipe) Establish(ctx context.Context) (*session.Session, error) {
	return &session.Session{Identity: r.id, BearerToken: "live", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (r *deadRefreshRecipe) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return nil, fmt.Errorf("refresh fails")
}
func (r *deadRefreshRecipe) Logout() recipeLogoutSignature { return recipeLogoutSignature{} }

func TestFailedRefreshInvalidatesCachedSession(t *testing.T) {
	r := &deadRefreshRecipe{id: "a"}
	s := New()
	s.Register(r)

	first, err := s.Get(context.Background(), "a")
	if err != nil || first.BearerToken != "live" {
		t.Fatalf("first get = %+v err %v", first, err)
	}

	// A reactive refresh (as the gateway triggers on a logout signal) fails.
	if _, err := s.Refresh(context.Background(), "a"); err == nil {
		t.Fatal("expected the refresh to fail")
	}

	// The cached session was proven dead; the next Get must NOT hand it back as
	// live. It attempts a rate-limited refresh (which also fails here), so Get
	// returns an error rather than serving the known-dead session.
	if sess, err := s.Get(context.Background(), "a"); err == nil {
		t.Fatalf("Get returned session %+v after a proven-dead refresh; want an error (invalidated)", sess)
	}
}
