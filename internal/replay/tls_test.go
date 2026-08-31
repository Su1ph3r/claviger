package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/httpx"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// A self-signed target is reachable only when replay is handed a TLS client that
// trusts it. The default (nil) client stays strict and records a per-identity
// error instead of crashing, and a supplied client is never mutated by Run.
func TestReplayUsesSuppliedTLSClient(t *testing.T) {
	ts := httptest.NewTLSServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	// The LOGIN itself must reach the self-signed target, so the recipe logs in
	// with an insecure client. What we are testing is the TLS policy of the
	// replay client on the request to the target, not the login transport.
	insecure, err := httpx.Client(httpx.TLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	newStore := func() *store.Store {
		st := store.New()
		st.Register(&recipe.FormPost{
			ID: "alice", LoginURL: ts.URL + "/login",
			Username: "alice", Password: "pw",
			Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
			Client:    insecure,
		})
		return st
	}

	// With an insecure replay client, the self-signed target is reached: status 200.
	results, err := Run(context.Background(), newStore(), []string{"alice"},
		"GET", ts.URL+"/api/whoami", http.Header{}, nil, insecure)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Err != nil || results[0].Status != 200 {
		t.Fatalf("insecure client row = %+v, want status 200 and no error", results[0])
	}

	// The supplied client must not be mutated: its CheckRedirect stays as it was
	// (nil). Run makes a shallow copy to force no-redirect internally.
	if insecure.CheckRedirect != nil {
		t.Fatal("Run mutated the caller's client CheckRedirect")
	}

	// With the default (nil) strict client, the self-signed target is rejected and
	// the failure is recorded per identity rather than crashing the run.
	strictResults, err := Run(context.Background(), newStore(), []string{"alice"},
		"GET", ts.URL+"/api/whoami", http.Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(strictResults) != 1 {
		t.Fatalf("got %d strict results, want 1", len(strictResults))
	}
	if strictResults[0].Err == nil {
		t.Fatalf("strict client row = %+v, want a recorded TLS error", strictResults[0])
	}
}
