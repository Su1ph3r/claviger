// internal/gateway/gateway_test.go
package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func newTestGateway(t *testing.T, targetURL string, ttl time.Duration) (*Gateway, *recipe.FormPost) {
	t.Helper()
	r := &recipe.FormPost{
		ID:        "alice",
		LoginURL:  targetURL + "/login",
		Username:  "alice",
		Password:  "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}, BodyContains: "unauthenticated"},
	}
	st := store.New()
	st.Register(r)
	g, err := New(st, map[string]recipe.Recipe{"alice": r}, targetURL)
	if err != nil {
		t.Fatal(err)
	}
	return g, r
}

func TestGatewayInjectsAuth(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	g, _ := newTestGateway(t, ts.URL, time.Minute)
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 (auth should be injected)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if want := `"user":"alice"`; !strings.Contains(string(body), want) {
		t.Fatalf("body %q missing %q", string(body), want)
	}
}

func TestGatewayReauthsAcrossExpiry(t *testing.T) {
	// TTL shorter than the gap between requests forces a mid-run expiry.
	ts := httptest.NewServer(mockauth.New(150 * time.Millisecond).Handler())
	defer ts.Close()

	g, _ := newTestGateway(t, ts.URL, 150*time.Millisecond)
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	// First request establishes and succeeds.
	r1, _ := http.Get(front.URL + "/api/whoami")
	if r1.StatusCode != 200 {
		t.Fatalf("first status = %d, want 200", r1.StatusCode)
	}

	// Let the token expire, then request again. The gateway must transparently
	// reauth and still return 200.
	time.Sleep(250 * time.Millisecond)
	r2, _ := http.Get(front.URL + "/api/whoami")
	if r2.StatusCode != 200 {
		t.Fatalf("second status = %d, want 200 (gateway should have reauthed)", r2.StatusCode)
	}
}
