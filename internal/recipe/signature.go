package recipe

import (
	"net/http"
	"strings"
)

// LogoutSignature describes how a target signals an expired or missing session.
type LogoutSignature struct {
	StatusCodes      []int
	LocationContains string
	BodyContains     string
}

// Matches reports whether the response looks logged out.
func (sig LogoutSignature) Matches(resp *http.Response, body []byte) bool {
	for _, code := range sig.StatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}
	if sig.LocationContains != "" && strings.Contains(resp.Header.Get("Location"), sig.LocationContains) {
		return true
	}
	if sig.BodyContains != "" && strings.Contains(string(body), sig.BodyContains) {
		return true
	}
	return false
}
