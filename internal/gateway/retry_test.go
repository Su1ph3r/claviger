// internal/gateway/retry_test.go
package gateway

import "testing"

func TestIsIdempotent(t *testing.T) {
	safe := []string{"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "get"}
	for _, m := range safe {
		if !IsIdempotent(m) {
			t.Errorf("%s should be idempotent", m)
		}
	}
	unsafe := []string{"POST", "PATCH", "CONNECT", ""}
	for _, m := range unsafe {
		if IsIdempotent(m) {
			t.Errorf("%s should not be idempotent", m)
		}
	}
}
