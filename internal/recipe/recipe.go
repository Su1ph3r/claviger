package recipe

import (
	"context"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
)

// Recipe knows how to establish, recognize the loss of, and refresh a session
// for one identity.
type Recipe interface {
	Identity() string
	Establish(ctx context.Context) (*session.Session, error)
	Refresh(ctx context.Context, cur *session.Session) (*session.Session, error)
	Logout() LogoutSignature
}

// expiresAt converts an OAuth-style expires_in (seconds from now) into an absolute
// expiry time. A non-positive value means the server did not say, leaving the
// session's expiry unknown (zero time), in which case the store relies on the
// gateway's logout signature instead of a proactive refresh.
func expiresAt(expiresIn int) time.Time {
	if expiresIn <= 0 {
		return time.Time{}
	}
	// Clamp before the seconds->duration multiply so a server that mistakenly
	// reports the lifetime in milliseconds (a huge value) cannot overflow int64
	// nanoseconds and wrap to a past time (which would force endless refreshes).
	const maxSeconds = int64(1<<62) / int64(time.Second)
	s := int64(expiresIn)
	if s > maxSeconds {
		s = maxSeconds
	}
	return time.Now().Add(time.Duration(s) * time.Second)
}
