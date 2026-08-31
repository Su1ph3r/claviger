package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// A percent-encoded reserved character in the path (e.g. an object id containing
// %2F) must reach the target verbatim, not be normalized to a different resource.
func TestGatewayPreservesEncodedPath(t *testing.T) {
	var gotPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(200)
	}))
	defer target.Close()

	g, err := New(store.New(), map[string]recipe.Recipe{}, target.URL)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g.Handler("anon"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/objects/foo%2Fbar")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotPath != "/objects/foo%2Fbar" {
		t.Fatalf("target saw path %q, want /objects/foo%%2Fbar preserved", gotPath)
	}
}

// A bearer-token API is normally CSRF-immune; the gateway must not re-introduce
// CSRF by injecting the warm token onto a cross-origin/cross-site browser request.
func TestGatewayRejectsCrossOriginAndCrossSite(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()
	g, _ := newTestGateway(t, ts.URL, time.Minute)
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	// Origin naming a non-loopback site -> rejected.
	req, _ := http.NewRequest("POST", front.URL+"/api/whoami", nil)
	req.Header.Set("Origin", "https://evil.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want 403", resp.StatusCode)
	}

	// Sec-Fetch-Site: cross-site -> rejected.
	req2, _ := http.NewRequest("POST", front.URL+"/api/whoami", nil)
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site status = %d, want 403", resp2.StatusCode)
	}

	// A CLI client sends neither header -> allowed and credential-injected.
	resp3, err := http.Get(front.URL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != 200 {
		t.Fatalf("CLI client status = %d, want 200", resp3.StatusCode)
	}
}

func TestIsLoopbackHostSpellings(t *testing.T) {
	accept := []string{"127.0.0.1:8888", "localhost:8888", "LOCALHOST:8888", "localhost.", "[::1]:8888", "::1", "127.0.0.2"}
	for _, h := range accept {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	reject := []string{"", "evil.com", "127.0.0.1.evil.com", "0.0.0.0", "example.com:80"}
	for _, h := range reject {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}
