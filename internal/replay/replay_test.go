package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestReplayAcrossIdentities(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	st := store.New()
	for _, name := range []string{"alice", "bob"} {
		st.Register(&recipe.FormPost{
			ID: name, LoginURL: ts.URL + "/login",
			Username: name, Password: "pw",
			Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
		})
	}

	results, err := Run(context.Background(), st, []string{"alice", "bob"},
		"GET", ts.URL+"/api/whoami", http.Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].Identity != "alice" || results[1].Identity != "bob" {
		t.Fatalf("results out of order: %s, %s", results[0].Identity, results[1].Identity)
	}
	for _, r := range results {
		if r.Status != 200 {
			t.Errorf("identity %s status = %d, want 200", r.Identity, r.Status)
		}
	}
}
