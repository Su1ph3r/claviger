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

// One identity's failure must not erase the rest of the fan-out: it is recorded in
// that identity's Result.Err while the others still produce rows.
func TestReplayCapturesPerIdentityError(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	st := store.New()
	st.Register(&recipe.FormPost{
		ID: "alice", LoginURL: ts.URL + "/login",
		Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
	})

	// "ghost" is not registered, so st.Get fails for it.
	results, err := Run(context.Background(), st, []string{"alice", "ghost"},
		"GET", ts.URL+"/api/whoami", http.Header{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (fan-out must not abort)", len(results))
	}
	if results[0].Identity != "alice" || results[0].Status != 200 || results[0].Err != nil {
		t.Fatalf("alice row = %+v, want status 200 and no error", results[0])
	}
	if results[1].Identity != "ghost" || results[1].Err == nil {
		t.Fatalf("ghost row = %+v, want a recorded per-identity error", results[1])
	}
}
