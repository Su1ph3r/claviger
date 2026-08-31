package cmd

import (
	"regexp"
	"testing"
)

func TestGenerateGatewayTokenRandomHex(t *testing.T) {
	a, err := generateGatewayToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateGatewayToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated tokens are identical; not random")
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(a) {
		t.Fatalf("token %q is not 32 hex chars", a)
	}
}
