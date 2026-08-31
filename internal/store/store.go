// internal/store/store.go
package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/session"
)

// ErrUnknownIdentity is returned when an identity was never registered, so callers
// can distinguish "not managed" (a 404) from an authentication failure for a
// managed identity (a transient 5xx).
var ErrUnknownIdentity = errors.New("unknown identity")

// recipeLogoutSignature is aliased so tests can name the return type of Logout
// without importing recipe directly.
type recipeLogoutSignature = recipe.LogoutSignature

type entry struct {
	recipe   recipe.Recipe
	sessMu   sync.Mutex // guards session pointer, stamps, lastAuth, lastErr
	flightMu sync.Mutex // serializes establish/refresh (single-flight)
	session  *session.Session
	stamps   []time.Time // recent refresh times, for backoff
	lastAuth time.Time   // time of the last successful establish/refresh
	lastErr  string      // last establish/refresh error, cleared on success
}

// IdentityHealth is a read-only snapshot of one identity's session state, for the
// status/health surfaces. It never triggers a login.
type IdentityHealth struct {
	Name        string
	Established bool
	ExpiresAt   time.Time
	LastRefresh time.Time
	LastError   string
}

func (e *entry) snapshot() *session.Session {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	return e.session
}

func (e *entry) setSession(sess *session.Session) {
	e.sessMu.Lock()
	e.session = sess
	e.sessMu.Unlock()
}

// commit records a successful establish/refresh: the new session, the time, and a
// cleared error.
func (e *entry) commit(sess *session.Session, now time.Time) {
	e.sessMu.Lock()
	e.session = sess
	e.lastAuth = now
	e.lastErr = ""
	e.sessMu.Unlock()
}

// fail records the error text of a failed establish/refresh for the health view.
func (e *entry) fail(errText string) {
	e.sessMu.Lock()
	e.lastErr = errText
	e.sessMu.Unlock()
}

// rateLimited records a refresh attempt against the per-identity sliding window
// and returns an error when the burst ceiling is exceeded. Callers hold flightMu,
// so the window accounting counts actual refresh cycles, not coalesced callers.
func (e *entry) rateLimited(maxBurst int, window time.Duration, now time.Time) error {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	e.stamps = pruneOlderThan(e.stamps, now.Add(-window))
	if len(e.stamps) >= maxBurst {
		return fmt.Errorf("refresh rate limit hit for %q (%d in %s)", e.recipe.Identity(), maxBurst, window)
	}
	e.stamps = append(e.stamps, now)
	return nil
}

// Store owns the live session for each registered identity.
type Store struct {
	mu       sync.RWMutex
	entries  map[string]*entry
	maxBurst int
	window   time.Duration
}

// Option configures a Store at construction time.
type Option func(*Store)

// WithBackoff overrides the refresh rate-limit ceiling and window.
func WithBackoff(maxBurst int, window time.Duration) Option {
	return func(s *Store) {
		if maxBurst > 0 {
			s.maxBurst = maxBurst
		}
		if window > 0 {
			s.window = window
		}
	}
}

func New(opts ...Option) *Store {
	s := &Store{entries: map[string]*entry{}, maxBurst: 10, window: 60 * time.Second}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Store) Register(r recipe.Recipe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[r.Identity()] = &entry{recipe: r}
}

func (s *Store) lookup(id string) (*entry, error) {
	s.mu.RLock()
	e, ok := s.entries[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownIdentity, id)
	}
	return e, nil
}

// Get returns a live, non-expired session for the identity, establishing it on
// first use and refreshing it in place when the cached session has passed its
// expiry. Establish/refresh run under the flight lock so concurrent callers
// coalesce into one login instead of racing several.
func (s *Store) Get(ctx context.Context, id string) (*session.Session, error) {
	e, err := s.lookup(id)
	if err != nil {
		return nil, err
	}
	if sess := e.snapshot(); sess != nil && !sess.Expired(time.Now()) {
		return sess, nil
	}

	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	// Re-check under the lock: another caller may have established or refreshed
	// while we waited.
	cur := e.snapshot()
	if cur != nil && !cur.Expired(time.Now()) {
		return cur, nil
	}

	if cur == nil {
		// First use: establish. Establishment is not rate-limited; the backoff
		// guards repeated re-auth of an already-live identity.
		sess, err := e.recipe.Establish(ctx)
		if err != nil {
			e.fail(err.Error())
			return nil, err
		}
		e.commit(sess, time.Now())
		return sess, nil
	}

	// The cached session is expired: refresh it, honoring the backoff ceiling so a
	// short-lived-and-failing identity cannot hammer the auth endpoint.
	if err := e.rateLimited(s.maxBurst, s.window, time.Now()); err != nil {
		return nil, err
	}
	sess, err := e.recipe.Refresh(ctx, cur)
	if err != nil {
		e.fail(err.Error())
		return nil, err
	}
	e.commit(sess, time.Now())
	return sess, nil
}

// Refresh replaces the identity's session. It is single-flight per identity: every
// caller snapshots the "before" pointer prior to serializing on flightMu, so the
// first caller past the lock re-authenticates and the rest observe the swapped
// pointer and adopt the fresh session instead of re-authenticating again.
func (s *Store) Refresh(ctx context.Context, id string) (*session.Session, error) {
	e, err := s.lookup(id)
	if err != nil {
		return nil, err
	}

	// Snapshot the session we intend to replace BEFORE serializing, so all
	// concurrent callers share the same "before" pointer.
	before := e.snapshot()

	e.flightMu.Lock()
	defer e.flightMu.Unlock()

	// If another caller already refreshed while we waited, adopt their result.
	if cur := e.snapshot(); cur != before {
		return cur, nil
	}

	if err := e.rateLimited(s.maxBurst, s.window, time.Now()); err != nil {
		return nil, err
	}

	sess, err := e.recipe.Refresh(ctx, before)
	if err != nil {
		// This refresh was triggered because the session is believed dead (a gateway
		// logout signal). Since renewal failed, mark the cached session expired so the
		// next Get attempts a rate-limited refresh instead of continuing to serve a
		// token we could not renew (which /creds would otherwise hand out until the
		// clock expiry, or forever when ExpiresAt is unknown). Use a copy so a
		// concurrent reader of the shared session is never mutated underneath.
		e.fail(err.Error())
		if before != nil {
			stale := *before
			stale.ExpiresAt = time.Unix(0, 1) // non-zero past time => Expired() is true
			e.setSession(&stale)
		}
		return nil, err
	}
	e.commit(sess, time.Now())
	return sess, nil
}

// Identities returns the registered identity names in a stable (sorted) order so
// downstream port assignment and status listings are deterministic across runs.
func (s *Store) Identities() []string {
	s.mu.RLock()
	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	s.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

// RefreshExpiring proactively refreshes every established identity whose session
// expires within the window. Sessions with unknown expiry are skipped (the reactive
// logout-signal path handles those). Refresh is rate-limited and single-flight.
// Returns per-identity refresh errors, if any.
func (s *Store) RefreshExpiring(ctx context.Context, within time.Duration) map[string]error {
	now := time.Now()
	var errs map[string]error
	for _, h := range s.Health() {
		if !h.Established || h.ExpiresAt.IsZero() {
			continue
		}
		if h.ExpiresAt.Sub(now) < within {
			if _, err := s.Refresh(ctx, h.Name); err != nil {
				if errs == nil {
					errs = make(map[string]error)
				}
				errs[h.Name] = err
			}
		}
	}
	return errs
}

// Health returns a read-only snapshot of every identity's session state, sorted by
// name. It never triggers a login, so it is safe for a status view.
func (s *Store) Health() []IdentityHealth {
	s.mu.RLock()
	ents := make(map[string]*entry, len(s.entries))
	ids := make([]string, 0, len(s.entries))
	for id, e := range s.entries {
		ids = append(ids, id)
		ents[id] = e
	}
	s.mu.RUnlock()
	sort.Strings(ids)

	out := make([]IdentityHealth, 0, len(ids))
	for _, id := range ids {
		e := ents[id]
		e.sessMu.Lock()
		h := IdentityHealth{Name: id, LastRefresh: e.lastAuth, LastError: e.lastErr}
		if e.session != nil {
			h.Established = true
			h.ExpiresAt = e.session.ExpiresAt
		}
		e.sessMu.Unlock()
		out = append(out, h)
	}
	return out
}

func pruneOlderThan(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}
