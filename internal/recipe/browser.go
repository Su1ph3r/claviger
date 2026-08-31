package recipe

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/Su1ph3r/claviger/internal/session"
)

// Browser establishes a session by driving a real headless Chrome/Chromium
// through the target's login page. It is the recipe for logins that a plain HTTP
// script cannot reproduce: SSO redirects, SPA JavaScript, and (in headful mode)
// interactive MFA. chromedp is the only importer of a browser in this codebase;
// keep it isolated to this file so the rest of the daemon stays browser-free.
type Browser struct {
	ID                 string
	LoginURL           string
	UsernameSelector   string
	PasswordSelector   string
	SubmitSelector     string
	SuccessURLContains string // success when window.location.href contains this
	SuccessSelector    string // OR success when this element becomes visible
	Headful            bool   // true opens a visible window (for MFA); default headless
	Insecure           bool   // true tells Chrome to ignore certificate errors (self-signed IdP)
	BearerLocalStorage string // optional localStorage key -> Session.BearerToken
	Username           string
	Password           string
	Signature          LogoutSignature
	// Client is accepted for interface symmetry with the HTTP recipes so
	// config.Recipes can inject it uniformly. Chrome does its own TLS, so it is
	// unused here.
	Client *http.Client
}

func (r *Browser) Identity() string        { return r.ID }
func (r *Browser) Logout() LogoutSignature { return r.Signature }

// chromePath finds a Chrome/Chromium binary to drive. It checks, in order, the
// CLAVIGER_CHROME override, the common install locations, then PATH. An empty
// return means no browser was found, in which case Establish never launches
// Chrome and reports a clear error instead.
func chromePath() string {
	if p := os.Getenv("CLAVIGER_CHROME"); p != "" {
		return p
	}
	candidates := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/usr/bin/google-chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func (r *Browser) Establish(ctx context.Context) (*session.Session, error) {
	path := chromePath()
	if path == "" {
		return nil, fmt.Errorf("chrome/chromium not found (set CLAVIGER_CHROME)")
	}

	// Headless logins should finish in seconds; a headful MFA prompt needs room
	// for a human to type a code, so it gets a much longer ceiling.
	timeout := 60 * time.Second
	if r.Headful {
		timeout = 300 * time.Second
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(path),
		chromedp.Flag("headless", !r.Headful),
	)
	// Chrome does its own TLS validation, independent of the injected HTTP client.
	// When the effective policy is insecure (a self-signed IdP), tell Chrome to
	// ignore certificate errors so the login page loads instead of hanging to the
	// timeout.
	if r.Insecure {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	runCtx, cancelTimeout := context.WithTimeout(browserCtx, timeout)
	defer cancelTimeout()

	var cookies []*http.Cookie
	var token *string

	tasks := chromedp.Tasks{
		chromedp.Navigate(r.LoginURL),
		chromedp.WaitVisible(r.UsernameSelector, chromedp.ByQuery),
		chromedp.SendKeys(r.UsernameSelector, r.Username, chromedp.ByQuery),
		chromedp.SendKeys(r.PasswordSelector, r.Password, chromedp.ByQuery),
		chromedp.Click(r.SubmitSelector, chromedp.ByQuery),
		r.waitForSuccess(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			if err := network.Enable().Do(ctx); err != nil {
				return err
			}
			cs, err := network.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			for _, c := range cs {
				cookies = append(cookies, &http.Cookie{
					Name:   c.Name,
					Value:  c.Value,
					Domain: c.Domain,
					Path:   c.Path,
				})
			}
			return nil
		}),
	}
	if r.BearerLocalStorage != "" {
		tasks = append(tasks, chromedp.Evaluate(
			fmt.Sprintf("localStorage.getItem(%q)", r.BearerLocalStorage), &token))
	}

	if err := chromedp.Run(runCtx, tasks); err != nil {
		return nil, fmt.Errorf("browser login for %q failed: %w", r.ID, err)
	}

	sess := &session.Session{Identity: r.ID, Cookies: cookies}
	if token != nil {
		sess.BearerToken = *token
	}
	// A run that captured neither a cookie nor a bearer never really logged in;
	// reject it rather than caching an empty session that injects nothing.
	if len(sess.Cookies) == 0 && sess.BearerToken == "" {
		return nil, fmt.Errorf("browser login for %q captured no session material (no cookie and no token)", r.ID)
	}
	return sess, nil
}

// waitForSuccess returns the action that blocks until the login is judged
// complete: either a stable success element becomes visible, or the page URL
// comes to contain the configured fragment. The URL poll runs until the run
// context's deadline, so a login that never reaches the success URL fails with a
// timeout rather than hanging forever.
func (r *Browser) waitForSuccess() chromedp.Action {
	if r.SuccessSelector != "" {
		return chromedp.WaitVisible(r.SuccessSelector, chromedp.ByQuery)
	}
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for {
			var href string
			if err := chromedp.Evaluate("window.location.href", &href).Do(ctx); err != nil {
				return err
			}
			if r.SuccessURLContains != "" && strings.Contains(href, r.SuccessURLContains) {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	})
}

// Refresh re-runs the whole browser login; there is no incremental refresh.
func (r *Browser) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return r.Establish(ctx)
}
