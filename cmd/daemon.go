package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/claviger/internal/config"
	"github.com/Su1ph3r/claviger/internal/control"
	"github.com/Su1ph3r/claviger/internal/gateway"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
)

// generateGatewayToken returns a random 32-hex-character token for the
// --gateway-token auto mode. It is printed once at startup, not a login secret.
func generateGatewayToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// parseLogLevel maps a --log-level string to an slog.Level.
func parseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "error":
		return slog.LevelError, nil
	case "warn":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q (want error, warn, info, or debug)", s)
	}
}

// proactiveRefresh renews any established identity whose session expires within 2x
// the interval, so a session that no request happens to touch does not sit expired
// between runs. Sessions with unknown expiry are left to the reactive logout-signal
// path. Refresh is rate-limited and single-flight, so this cannot hammer the target.
func proactiveRefresh(ctx context.Context, st *store.Store, g *gateway.Gateway, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	within := 2 * interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// RefreshExpiring returns only the identities that failed to renew, so
			// there is no per-identity success to log; a single cycle heartbeat at
			// debug gives visibility without a branch that can never fire.
			failures := st.RefreshExpiring(ctx, within)
			for id, err := range failures {
				g.Logger.Warn("proactive refresh failed", "identity", id, "error", err)
			}
			g.Logger.Debug("proactive refresh cycle complete", "failures", len(failures))
		}
	}
}

// socketPath computes the default control-socket path without creating anything, so
// a client can resolve where a daemon would listen.
func socketPath() (string, error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".claviger")
	}
	return filepath.Join(dir, "claviger.sock"), nil
}

// defaultSocketPath returns the owner-private control-socket path and ensures its
// directory exists (0700). The socket serves live credentials, so it must live in a
// directory only its owner can enter, never a world-writable location like /tmp.
func defaultSocketPath() (string, error) {
	p, err := socketPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// buildStore loads config, applies any CLI TLS overrides to the global TLS block,
// then returns a populated store plus the recipe map. The overrides must land before
// Recipes() builds the per-identity HTTP clients, so a flag reaches the recipes.
func buildStore(path string, tls tlsFlags) (*store.Store, map[string]recipe.Recipe, *config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	applyTLSFlags(cfg, tls)
	recipes, err := cfg.Recipes()
	if err != nil {
		return nil, nil, nil, err
	}
	st := store.New(store.WithBackoff(cfg.Backoff.MaxBurst, cfg.Backoff.Window))
	for _, r := range recipes {
		st.Register(r)
	}
	return st, recipes, cfg, nil
}

// buildCSRFPolicies turns each identity's optional csrf config block into a
// gateway.CSRFPolicy, compiling the pattern here so a bad regex or an incomplete
// block fails at daemon start rather than on the first request. Identities without a
// csrf block are omitted. Returns nil when no identity declares a policy.
func buildCSRFPolicies(cfg *config.Config) (map[string]gateway.CSRFPolicy, error) {
	var out map[string]gateway.CSRFPolicy
	for _, id := range cfg.Identities {
		c := id.CSRF
		if c == nil {
			continue
		}
		if c.FetchURL == "" || c.Pattern == "" || c.Header == "" {
			return nil, fmt.Errorf("identity %q: csrf requires fetch_url, pattern, and header", id.Name)
		}
		pol, err := gateway.NewCSRFPolicy(c.FetchURL, c.Pattern, c.Header, c.Methods)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", id.Name, err)
		}
		if out == nil {
			out = make(map[string]gateway.CSRFPolicy)
		}
		out[id.Name] = pol
	}
	return out, nil
}

func newDaemonCmd() *cobra.Command {
	var cfgPath, socket, gatewayToken, logLevel, auditLog string
	var basePort int
	var refreshInterval time.Duration
	var tls tlsFlags
	cmd := &cobra.Command{
		Use:           "daemon",
		Short:         "Run the headless session authority",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if basePort <= 0 || basePort > 65535 {
				return fmt.Errorf("--base-port must be between 1 and 65535, got %d", basePort)
			}
			lvl, err := parseLogLevel(logLevel)
			if err != nil {
				return err
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
			tls.markChanged(cmd)
			st, recipes, cfg, err := buildStore(cfgPath, tls)
			if err != nil {
				return err
			}
			warnIfInsecure(cmd.ErrOrStderr(), cfg)
			warnIfPlaintextAuth(cmd.ErrOrStderr(), cfg)
			if socket == "" {
				socket, err = defaultSocketPath()
				if err != nil {
					return err
				}
			}
			csrfPolicies, err := buildCSRFPolicies(cfg)
			if err != nil {
				return err
			}
			gwOpts := []gateway.Option{
				gateway.WithTLS(cfg.TLS.ToHTTPX()),
				gateway.WithCSRF(csrfPolicies),
				gateway.WithLogger(logger),
			}
			if auditLog != "" {
				f, err := os.OpenFile(auditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					return err
				}
				defer f.Close()
				auditLogger := slog.New(slog.NewJSONHandler(f, nil))
				gwOpts = append(gwOpts, gateway.WithAudit(auditLogger))
			}
			g, err := gateway.New(st, recipes, cfg.Target, gwOpts...)
			if err != nil {
				return err
			}
			effToken := gatewayToken
			switch gatewayToken {
			case "auto":
				effToken, err = generateGatewayToken()
				if err != nil {
					return fmt.Errorf("generate gateway token: %w", err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "gateway token: %s\n", effToken)
			}
			g.RequireToken = effToken

			// serveErrc carries a serve failure from any listener goroutine so
			// the signal-wait select can surface it instead of losing it. It is
			// buffered for every listener plus the control server so a goroutine
			// never blocks reporting an error after shutdown starts.
			serveErrc := make(chan error, len(st.Identities())+1)

			// The gateway ports are loopback-only. Host + Origin + Sec-Fetch-Site
			// checks block browser DNS-rebinding and modern cross-site requests, but
			// other local users on this host can still reach the ports, and a legacy
			// browser that omits Fetch Metadata could drive a cross-site request.
			// Set --gateway-token to require a shared-secret header and close both.
			if effToken == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "warning: gateway ports are unauthenticated; do not run on an untrusted shared host (see --gateway-token)")
			}

			// One gateway listener per identity, on sequential ports. Bind
			// synchronously first so a failed bind (e.g. port in use) fails loudly
			// before we print a mapping that claims the listener came up.
			port := basePort
			var listeners []net.Listener
			closeAll := func() {
				for _, l := range listeners {
					l.Close()
				}
			}
			for _, id := range st.Identities() {
				addr := fmt.Sprintf("127.0.0.1:%d", port)
				gln, err := net.Listen("tcp", addr)
				if err != nil {
					closeAll()
					return err
				}
				listeners = append(listeners, gln)
				handler := g.Handler(id)
				go func() { serveErrc <- http.Serve(gln, handler) }()
				// Print the actual bound address so an OS remap is reported correctly
				// rather than the requested string.
				fmt.Fprintf(cmd.OutOrStdout(), "identity %s -> http://%s\n", id, gln.Addr().String())
				port++
			}

			// Control server over a Unix socket. Filesystem permissions on the
			// socket are the access boundary, so it must be owner-only. A
			// restrictive umask around the bind closes the window in which the
			// socket would otherwise exist at the process default mode; the
			// explicit Chmod is belt-and-suspenders.
			os.Remove(socket)
			oldMask := syscall.Umask(0o177)
			ln, err := net.Listen("unix", socket)
			syscall.Umask(oldMask)
			if err != nil {
				closeAll()
				return err
			}
			if err := os.Chmod(socket, 0o600); err != nil {
				ln.Close()
				closeAll()
				return err
			}
			listeners = append(listeners, ln)
			go func() { serveErrc <- http.Serve(ln, control.NewServer(st)) }()
			fmt.Fprintf(cmd.OutOrStdout(), "control socket: %s\n", socket)

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Proactive refresh loop: renew any identity whose session expires within
			// 2x the interval, before a request needs it. Sessions with unknown expiry
			// keep relying on the gateway's reactive logout-signal path. Refresh is
			// rate-limited and single-flight, so this cannot hammer the auth endpoint.
			if refreshInterval > 0 {
				go proactiveRefresh(ctx, st, g, refreshInterval)
			}

			var serveErr error
			select {
			case <-ctx.Done():
			case serveErr = <-serveErrc:
			}
			closeAll()
			return serveErr
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "claviger.yaml", "path to config file")
	cmd.Flags().StringVar(&socket, "socket", "", "control Unix socket path (default: $XDG_RUNTIME_DIR/claviger.sock or ~/.claviger/claviger.sock)")
	cmd.Flags().IntVar(&basePort, "base-port", 8888, "first gateway listener port")
	cmd.Flags().StringVar(&gatewayToken, "gateway-token", "",
		"require this value in an X-Claviger-Token header on every gateway request; \"auto\" generates and prints a random token")
	cmd.Flags().DurationVar(&refreshInterval, "refresh-interval", 30*time.Second, "how often to proactively refresh sessions near expiry (0 disables)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log verbosity: error, warn, info, or debug")
	cmd.Flags().StringVar(&auditLog, "audit-log", "", "append one JSON audit record per gateway request to this file (identity, method, path, status; never secrets)")
	registerTLSFlags(cmd, &tls)
	return cmd
}
