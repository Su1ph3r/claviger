package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestCredsEndpoint(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	st := store.New()
	st.Register(&recipe.FormPost{
		ID: "alice", LoginURL: ts.URL + "/login",
		Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
	})

	front := httptest.NewServer(NewServer(st))
	defer front.Close()

	resp, err := http.Get(front.URL + "/creds/alice")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Identity    string `json:"identity"`
		BearerToken string `json:"bearer_token"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Identity != "alice" || out.BearerToken == "" {
		t.Fatalf("creds = %+v", out)
	}
}

func TestStatusEndpoint(t *testing.T) {
	st := store.New()
	st.Register(&recipe.FormPost{ID: "alice", Signature: recipe.LogoutSignature{}})

	front := httptest.NewServer(NewServer(st))
	defer front.Close()

	resp, _ := http.Get(front.URL + "/status")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
