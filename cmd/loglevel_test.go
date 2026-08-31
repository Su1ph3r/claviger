package cmd

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"error": slog.LevelError,
		"warn":  slog.LevelWarn,
		"info":  slog.LevelInfo,
		"debug": slog.LevelDebug,
	}
	for in, want := range cases {
		got, err := parseLogLevel(in)
		if err != nil {
			t.Fatalf("parseLogLevel(%q) errored: %v", in, err)
		}
		if got != want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := parseLogLevel("bogus"); err == nil {
		t.Error("parseLogLevel(bogus) should error")
	}
}
