// internal/gateway/retry.go
package gateway

import "strings"

var idempotentMethods = map[string]bool{
	"GET": true, "HEAD": true, "PUT": true,
	"DELETE": true, "OPTIONS": true, "TRACE": true,
}

// IsIdempotent reports whether a request with this method is safe to auto-retry
// after a transparent reauth. POST and PATCH are deliberately excluded.
func IsIdempotent(method string) bool {
	return idempotentMethods[strings.ToUpper(method)]
}
