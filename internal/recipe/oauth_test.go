package recipe

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestOAuth2EstablishAndRefresh(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler())
	defer ts.Close()

	r := &OAuth2{
		ID:        "bob",
		TokenURL:  ts.URL + "/oauth/token",
		Username:  "bob",
		Password:  "pw",
		Signature: LogoutSignature{StatusCodes: []int{401}},
	}
	sess, err := r.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess.BearerToken == "" || sess.RefreshToken == "" {
		t.Fatal("expected access and refresh tokens")
	}

	refreshed, err := r.Refresh(context.Background(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.BearerToken == sess.BearerToken {
		t.Fatal("refresh should mint a new access token")
	}
	if refreshed.Identity != "bob" {
		t.Fatalf("identity = %q, want bob", refreshed.Identity)
	}
	_ = session.Session{}
}
