package cmd

import "testing"

func TestNewRootCmd_HasName(t *testing.T) {
	root := NewRootCmd()
	if root.Use != "claviger" {
		t.Fatalf("root command Use = %q, want %q", root.Use, "claviger")
	}
}
