package config

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestRecipesInjectTLSClient(t *testing.T) {
	ts := httptest.NewTLSServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()
	c := &Config{
		Target: ts.URL,
		TLS:    TLSConfig{Insecure: true},
		Identities: []IdentityConfig{{
			Name: "a", Type: "form", LoginURL: ts.URL + "/login",
			Username: "a", Password: "p", Logout: LogoutConfig{StatusCodes: []int{401}},
		}},
	}
	recipes, err := c.Recipes()
	if err != nil {
		t.Fatal(err)
	}
	// The recipe must reach the SELF-SIGNED login server, which only works if the
	// insecure TLS client was injected.
	if _, err := recipes["a"].Establish(context.Background()); err != nil {
		t.Fatalf("establish against self-signed target failed (TLS not injected?): %v", err)
	}
}
