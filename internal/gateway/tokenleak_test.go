package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// TestGatewayDoesNotForwardInternalHeaders pins that the gateway's internal
// headers never reach the target: X-Claviger-Identity (routing) and
// X-Claviger-Token (the shared-secret gate). Forwarding the token would leak the
// gateway secret into the pentest target and its logs.
func TestGatewayDoesNotForwardInternalHeaders(t *testing.T) {
	ma := mockauth.New(time.Minute)
	var mu sync.Mutex
	var gotToken, gotIdentity string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			ma.Handler().ServeHTTP(w, r) // let the recipe establish a session
			return
		}
		mu.Lock()
		gotToken = r.Header.Get("X-Claviger-Token")
		gotIdentity = r.Header.Get("X-Claviger-Identity")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	g, _ := newTestGateway(t, target.URL, time.Minute)
	g.RequireToken = "s3cret"
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	req, err := http.NewRequest(http.MethodGet, front.URL+"/api/thing", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Claviger-Token", "s3cret")      // a real client sends this to pass the gate
	req.Header.Set("X-Claviger-Identity", "smuggled") // a client must not be able to smuggle this
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway returned %d, want 200 (token should have passed the gate)", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotToken != "" {
		t.Errorf("target received X-Claviger-Token %q; the gateway secret leaked upstream", gotToken)
	}
	if gotIdentity != "" {
		t.Errorf("target received X-Claviger-Identity %q; the routing header leaked upstream", gotIdentity)
	}
}
