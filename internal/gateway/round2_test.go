package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// With RequireToken set, a request without the matching X-Claviger-Token header is
// rejected before any credential is injected; a request with it is allowed.
func TestGatewayRequiresToken(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	g, _ := newTestGateway(t, ts.URL, time.Minute)
	g.RequireToken = "s3cret"
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing token status = %d, want 403", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", front.URL+"/api/whoami", nil)
	req.Header.Set("X-Claviger-Token", "s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("with token status = %d, want 200", resp2.StatusCode)
	}
}
