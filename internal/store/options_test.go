package store

import (
	"testing"
	"time"
)

func TestWithBackoff(t *testing.T) {
	s := New(WithBackoff(3, 5*time.Second))
	if s.maxBurst != 3 || s.window != 5*time.Second {
		t.Fatalf("backoff = %d/%s, want 3/5s", s.maxBurst, s.window)
	}
	// default still applies with no option.
	d := New()
	if d.maxBurst != 10 || d.window != 60*time.Second {
		t.Fatalf("default backoff = %d/%s", d.maxBurst, d.window)
	}
}
