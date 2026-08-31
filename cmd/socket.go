package cmd

import (
	"context"
	"io"

	"github.com/Su1ph3r/claviger/internal/control"
	"github.com/Su1ph3r/claviger/internal/replay"
	"github.com/Su1ph3r/claviger/internal/session"
)

// resolveSocket returns the control-socket path to use: the flag value if set,
// otherwise the default path (without creating anything).
func resolveSocket(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return socketPath()
}

// attachClient returns a control client when a daemon is live at the resolved
// socket path. ok is false (with a nil client) when no daemon is running, so the
// caller can fall back to logging in standalone.
func attachClient(socketFlag string) (client *control.Client, path string, ok bool, err error) {
	path, err = resolveSocket(socketFlag)
	if err != nil {
		return nil, "", false, err
	}
	if control.SocketExists(path) {
		return control.NewClient(path), path, true, nil
	}
	return nil, path, false, nil
}

// sessionFor returns a live session for id: from a running daemon's warm session if
// one is up, else via a standalone login built from the config. The TLS flags apply
// only to the standalone path; a daemon-attached session used the daemon's own TLS.
func sessionFor(ctx context.Context, socketFlag, cfgPath, id string, tls tlsFlags, warnW io.Writer) (*session.Session, error) {
	client, _, ok, err := attachClient(socketFlag)
	if err != nil {
		return nil, err
	}
	if ok {
		return client.Creds(ctx, id)
	}
	st, _, cfg, err := buildStore(cfgPath, tls)
	if err != nil {
		return nil, err
	}
	warnIfInsecure(warnW, cfg)
	warnIfPlaintextAuth(warnW, cfg)
	return st.Get(ctx, id)
}

// replaySource returns a session source for replay: the daemon client if a daemon
// is running (reusing warm, single-flighted sessions), else a standalone store.
func replaySource(socketFlag, cfgPath string, tls tlsFlags) (replay.SessionSource, error) {
	client, _, ok, err := attachClient(socketFlag)
	if err != nil {
		return nil, err
	}
	if ok {
		return client, nil
	}
	st, _, _, err := buildStore(cfgPath, tls)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// identityNames lists identities: from the daemon's /status if running, else from
// the config.
func identityNames(ctx context.Context, socketFlag, cfgPath string, tls tlsFlags, warnW io.Writer) ([]string, error) {
	client, _, ok, err := attachClient(socketFlag)
	if err != nil {
		return nil, err
	}
	if ok {
		st, err := client.Status(ctx)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(st.Identities))
		for _, s := range st.Identities {
			names = append(names, s.Name)
		}
		return names, nil
	}
	store, _, cfg, err := buildStore(cfgPath, tls)
	if err != nil {
		return nil, err
	}
	warnIfInsecure(warnW, cfg)
	warnIfPlaintextAuth(warnW, cfg)
	return store.Identities(), nil
}
