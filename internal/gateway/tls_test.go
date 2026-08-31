// internal/gateway/tls_test.go
package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/httpx"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func mustInsecureClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := httpx.Client(httpx.TLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGatewayReachesSelfSignedTarget(t *testing.T) {
	ts := httptest.NewTLSServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()
	r := &recipe.FormPost{ID: "alice", LoginURL: ts.URL + "/login", Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}}, Client: mustInsecureClient(t)}
	st := store.New()
	st.Register(r)
	// Strict gateway -> the forward to the self-signed target fails (502).
	strict, _ := New(st, map[string]recipe.Recipe{"alice": r}, ts.URL)
	front := httptest.NewServer(strict.Handler("alice"))
	if resp, _ := http.Get(front.URL + "/api/whoami"); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("strict gateway status = %d, want 502 (self-signed target)", resp.StatusCode)
	}
	front.Close()
	// Insecure gateway reaches it.
	g, _ := New(st, map[string]recipe.Recipe{"alice": r}, ts.URL, WithTLS(httpx.TLSConfig{InsecureSkipVerify: true}))
	front2 := httptest.NewServer(g.Handler("alice"))
	defer front2.Close()
	if resp, _ := http.Get(front2.URL + "/api/whoami"); resp.StatusCode != 200 {
		t.Fatalf("insecure gateway status = %d, want 200", resp.StatusCode)
	}
}

// TestWithTLSKeepsRedirectPolicy confirms applying a TLS transport does not lose
// the gateway's no-follow redirect policy (a 302 to /login is a logout signal).
func TestWithTLSKeepsRedirectPolicy(t *testing.T) {
	st := store.New()
	g, err := New(st, map[string]recipe.Recipe{}, "https://example.test", WithTLS(httpx.TLSConfig{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	if g.client.CheckRedirect == nil {
		t.Fatal("CheckRedirect lost after WithTLS")
	}
	if err := g.client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect = %v, want ErrUseLastResponse", err)
	}
}
