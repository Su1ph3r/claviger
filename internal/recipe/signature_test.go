package recipe

import (
	"net/http"
	"testing"
)

func TestSignatureMatchesStatus(t *testing.T) {
	sig := LogoutSignature{StatusCodes: []int{401, 403}}
	resp := &http.Response{StatusCode: 401, Header: http.Header{}}
	if !sig.Matches(resp, nil) {
		t.Fatal("should match 401")
	}
	resp.StatusCode = 200
	if sig.Matches(resp, nil) {
		t.Fatal("should not match 200")
	}
}

func TestSignatureMatchesBodyAndLocation(t *testing.T) {
	sig := LogoutSignature{BodyContains: "unauthenticated", LocationContains: "/login"}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	if !sig.Matches(resp, []byte(`{"error":"unauthenticated"}`)) {
		t.Fatal("should match body marker")
	}
	resp.Header.Set("Location", "https://t/login")
	if !sig.Matches(resp, nil) {
		t.Fatal("should match location marker")
	}
}
