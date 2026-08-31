package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/session"
	"github.com/Su1ph3r/claviger/internal/store"
)

type failEstablish struct{ id string }

func (r failEstablish) Identity() string { return r.id }
func (r failEstablish) Establish(ctx context.Context) (*session.Session, error) {
	return nil, fmt.Errorf("idp down")
}
func (r failEstablish) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return nil, fmt.Errorf("idp down")
}
func (r failEstablish) Logout() recipe.LogoutSignature { return recipe.LogoutSignature{} }

// An unregistered identity is genuinely not found -> 404.
func TestCredsUnknownIdentityIs404(t *testing.T) {
	front := httptest.NewServer(NewServer(store.New()))
	defer front.Close()

	resp, err := http.Get(front.URL + "/creds/ghost")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown identity status = %d, want 404", resp.StatusCode)
	}
}

// A managed identity whose login fails is a transient upstream failure -> 502,
// not a misleading 404.
func TestCredsEstablishFailureIs502(t *testing.T) {
	st := store.New()
	st.Register(failEstablish{id: "alice"})
	front := httptest.NewServer(NewServer(st))
	defer front.Close()

	resp, err := http.Get(front.URL + "/creds/alice")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("establish-failure status = %d, want 502", resp.StatusCode)
	}
}
