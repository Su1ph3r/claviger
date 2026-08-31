package recipe

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestFormPostEstablish(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	r := &FormPost{
		ID:        "alice",
		LoginURL:  ts.URL + "/login",
		Username:  "alice",
		Password:  "pw",
		Signature: LogoutSignature{StatusCodes: []int{401}},
	}
	sess, err := r.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess.BearerToken == "" {
		t.Fatal("expected a bearer token")
	}
	if sess.Identity != "alice" {
		t.Fatalf("identity = %q", sess.Identity)
	}
	found := false
	for _, c := range sess.Cookies {
		if c.Name == "session" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected session cookie captured")
	}
}

func TestFormPostRefreshReestablishes(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	r := &FormPost{
		ID:        "alice",
		LoginURL:  ts.URL + "/login",
		Username:  "alice",
		Password:  "pw",
		Signature: LogoutSignature{StatusCodes: []int{401}},
	}
	first, err := r.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Refresh(context.Background(), first)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second == nil || (second.BearerToken == "" && len(second.Cookies) == 0) {
		t.Fatal("refresh returned an empty session")
	}
}
