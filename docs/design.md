# Claviger: design

_Date: 2026-08-30_

Claviger is a local session authority for penetration testers. It owns the login
lifecycle for a set of test identities, keeps every one of them authenticated, and
presents current credentials to the whole toolbox (ffuf, sqlmap, nuclei, curl,
custom scripts, and optionally Burp) so nothing falls out of auth mid-run. The
name is Latin for "key-bearer": the one who holds your keys and hands them over on
demand.

This document describes the built system. Key shape decisions worth stating up
front:

- **Reverse proxy, not a forward `HTTP_PROXY`.** Claviger runs one identity-scoped
  reverse-proxy listener per identity on `127.0.0.1:<port>`. Point a tool's target
  URL at `http://127.0.0.1:<port>/<path>`; do not set `HTTP_PROXY`. A forward proxy
  with CONNECT/TLS interception is not built (see "Not built").
- **Config is plaintext, not encrypted at rest.** Credentials live in
  `claviger.yaml` and in memory. Inline `password` values expand `${ENV}`
  references, and `password_file` / `password_command` source the secret indirectly
  so it need not sit in the file, but there is no keychain integration. Protect the
  file with filesystem permissions. Do not commit it.
- **Refresh is both proactive and reactive.** A background loop
  (`--refresh-interval`, default 30s) refreshes sessions near expiry; a session is
  also refreshed on access when expired (`Store.Get`) and reactively when the
  gateway sees a logout signal. Setting the interval to 0 disables the proactive
  loop.
- **Backoff is a hard per-window ceiling** (default 10 refreshes / 60s per
  identity, overridable via the `backoff` config block), not
  exponential-with-jitter. It returns an error once exceeded.
- **Gateway hardening.** Host + Origin + Sec-Fetch-Site checks block browser
  DNS-rebinding and modern cross-site requests. `--gateway-token` optionally
  requires an `X-Claviger-Token` header to also close the residual legacy-browser
  path and gate other local users; it is off by default to keep CLI use transparent,
  and the daemon warns at startup when it is off. `--gateway-token auto` generates
  and prints a random token.

## The problem

Authenticated app testing means pointing a fleet of tools at one target, and every
tool has to carry the same session. The de facto protocol for sharing that session
is copy-paste-the-cookie: log in, open devtools, copy the `Authorization` header or
session cookie, paste it into ffuf's `-H`, sqlmap's `--cookie`, a script's headers.

Two things then go wrong constantly:

1. **Tokens expire mid-run.** Short-lived access tokens (5 to 15 minutes) die
   partway through a scan. The whole fleet silently starts eating 401s. ffuf reports
   "everything's 302/401," and you burn twenty minutes assuming your wordlist or the
   routes are wrong when the real cause is a dead token. Misreading a dead session as
   a result is a data-quality bug in your own engagement.

2. **Refresh flows hide the death.** An SPA silently refreshes via an httpOnly
   cookie, so the browser stays logged in while your copied bearer token is dead. The
   evidence in front of you lies about the state.

OAuth solved how services share auth. Password managers solved holding creds. CI
secret stores solved injecting creds into tools. There is no equivalent for the
pentester's live session state across their own toolbox. Everyone reinvents
cookie-paste every engagement.

## What Claviger is (and is not)

Claviger owns the authentication lifecycle for N named identities and exposes each
one's current session to any tool, through interfaces those tools already speak. It
establishes a session, detects when one has died, transparently re-authenticates,
and the consuming tool never notices.

**In scope:**

- Login recipes that establish and refresh a session for an identity: `form`,
  `oauth`, `multistep`, and browser-driven (`browser`) for SPA / SSO / MFA.
- A warm per-identity session store with proactive and reactive refresh.
- An injecting, auto-reauth reverse proxy: point any tool at an identity's local
  gateway port and it stays authenticated through token expiry.
- A credential source for tools that do not proxy cleanly: `claviger header <id>`
  and a small local `GET /creds/<id>` endpoint.
- A thin authz primitive: `claviger replay --as <id> [--as <id> ...]` fires one
  request, or a whole corpus, under each live identity and returns a bare
  status/size table (single request) or a request-by-identity matrix (corpus). No
  verdicts.

**Not built (explicit non-goals):**

- **No authz verdict engine.** No oracle, no "Bypassed!/Enforced!" judgment, no
  structural response diff. `replay` reports status facts and a `DIFFERS` marker
  when a corpus row's identities do not all return the same status; it does not
  decide whether a difference is a vulnerability. Burp's AuthMatrix and Autorize
  already own that ground; rebuilding it is the adjacent-not-novel trap. The novel
  thing Claviger provides is live, non-stale identities on tap; the analysis is left
  to the operator's own eyes or tools. The `replay` primitive gives most of the
  authz-testing value because the hard part was never the diff, it was having three
  valid sessions at once.
- **No forward proxy (MITM interception).** The gateway is a per-identity reverse
  proxy; there is no `HTTP_PROXY`-style CONNECT / TLS-intercepting mode.
- **No interception/inspection UI.** Claviger does not replace Burp's proxy history.
  It does not exist for a human to browse through and read traffic.
- **No request capture by browsing.** A proxy you browse through that logs your
  requests is Burp's identity; Claviger does not recreate it.
- **No Windows support.** Claviger targets Unix-like hosts (control socket, runtime
  directory, `sh -c` password commands).

## Positioning and prior art

The closest prior art lives inside Burp: Autorize (vertical authz replay), AuthMatrix
(role-by-request grid), Auto-Repeater (request repeating with swaps). All three are
real and mature, and all three share two structural limits Claviger is built around:

1. **They do not own the session lifecycle.** You paste a cookie; it goes stale; they
   keep "testing" with a dead identity and can silently report false results. Claviger's
   session authority (live login recipes with real refresh for N identities) closes
   this hole. This is the one thing they structurally cannot do.
2. **They are Burp-jailed.** None keep your ffuf/sqlmap/nuclei/CLI fleet authenticated.
   The moment a request originates from a CLI tool or a script, the Burp plugin
   ecosystem cannot reach it, and that is most of a real engagement.

Claviger's thesis: **the session-authority layer for the CLI-native pentester.** One
job, done completely: keep your test identities live across your entire toolbox, and
make swapping between them a one-flag operation.

## Architecture

One spine, attached surfaces. A headless daemon owns all state; everything else is a
client of it.

```
  recipes / config
        |
        v
  +--------------------------------------------------+
  |  claviger daemon (headless, long-running)        |
  |                                                  |
  |  recipe engine  ->  session store  ->  refresh   |
  |                        |     ^          loop      |
  |                        v     |                    |
  |                  auth gateway (proxy)             |
  |                  replay engine                    |
  |                                                  |
  |  local control socket / API                      |
  +--------------------------------------------------+
     ^              ^                 ^            ^
     |              |                 |            |
  proxy port   header/creds CLI   replay CLI    watch TUI
  (fleet)      (scripts)          (authz)       (session health)
```

The daemon stays up on its own because the fleet depends on the proxy being live
whether or not a human is watching. It can run on a jump box with clients attaching
over the local socket, or fully headless in CI.

## Components

Each unit has one purpose and a defined interface, so it can be understood and tested
on its own.

### 1. Recipe engine (auth strategies)

Turns an identity's configured login method into a live session, and knows how to
recognize a dead one and recover it. A recipe declares three things:

- **Establish:** how to log in from nothing. Four recipe types ship: `form`
  (submit credentials, capture the resulting cookie), `oauth` (OAuth2 password
  grant, hold the access token), `multistep` (a scripted sequence of requests with
  `{{password}}` / `{{extracted}}` templating and a `capture` block for CSRF and
  bearer values, for logins that need a CSRF fetch or an intermediate token), and
  `browser` (a real headless Chrome driven by CSS selectors, for SPA / SSO / MFA;
  `headful` opens a visible window for an interactive MFA prompt).
- **Logged-out signature:** how to recognize an expired session in a response. A
  status code (401/403), a redirect target (`Location: /login`), a body marker, or a
  JSON error shape. Declared per recipe; see hard problems below.
- **Recover:** how to get a fresh session. Either re-run establish, or hit a refresh
  endpoint with the held refresh token.

Interface: `establish(identity) -> Session`, `isExpired(response) -> bool`,
`refresh(session) -> Session`.

### 2. Session store

Holds current state per identity: cookies, bearer/refresh tokens, CSRF values,
expiry timestamps, and any pinned headers or device fingerprint. Owns concurrency:

- **Single-flight refresh:** when many tools hit 401 at once, exactly one refresh
  runs and the rest wait on it. Forty concurrent 401s trigger one re-login, not forty
  (forty parallel logins also look exactly like credential stuffing).
- **Lockout backoff:** a ceiling on re-auths per minute and exponential backoff, so
  aggressive recovery does not trip account lockout or bot defenses.

Interface: `get(identity) -> Session`, `refresh(identity) -> Session` (single-flight),
`set(identity, Session)`.

### 3. Auth gateway (the proxy): capability A

A reverse proxy, one loopback listener per identity on `127.0.0.1:<port>`. For each
outbound request it injects the identity's current auth (cookie, bearer, and a fresh
anti-CSRF token when the identity's `csrf` block is set). For each response it checks
the recipe's logged-out signature; on a hit it triggers a single-flight refresh and,
if the method is safe to retry, replays the original request so the tool never sees
the 401.

- **Retry policy:** idempotent methods are auto-retried after refresh.
  Non-idempotent methods (POST) are re-authed but the retry is surfaced rather than
  performed blindly, so a token dying mid-flight never causes a double "delete user."
- **Honest passthrough:** an `anon` route injects nothing, so you can still test
  unauthenticated behavior.
- **Hardening.** Listeners are loopback-only; Host, Origin, and Sec-Fetch-Site
  checks reject browser-originated cross-site and DNS-rebinding requests before any
  credential is injected. `--gateway-token` optionally requires an `X-Claviger-Token`
  header. That token and the internal `X-Claviger-Identity` routing header are
  stripped before forwarding and never reach the target; hop-by-hop headers are
  stripped in both directions.

Can be chained downstream of Burp so Burp's own Repeater/Intruder ride the live
sessions too.

Interface: one loopback port per identity; point a tool's target URL at it.

### 4. Credential source: capability A

For tools that do not proxy cleanly. `claviger header <id>` prints a live
`Authorization`/`Cookie` header for shell interpolation; `GET /creds/<id>` on the
local control socket returns the current cookies/tokens as JSON so a script fetches
fresh creds at runtime instead of hardcoding a value that will be dead in ten minutes.

### 5. Replay primitive: the thin authz capability

`claviger replay --as admin --as user-a --as anon --path /...` sends the same
request under each named live identity and returns a bare table (identity, status,
size, timing). It does not judge. The operator does the analysis, by eye or piped
into their own diff. It builds on the one novel thing (live, auto-refreshed
identities) without recreating anyone's verdict engine.

Beyond the single-request `--path` mode, `--corpus <file>` replays a whole request
set (`--format requests|har|openapi`, auto-detected by extension) across the
identities and prints a request-by-identity matrix, marking each row `DIFFERS` when
the identities did not all return the same status. `DIFFERS` is a fact (status
inequality), not a verdict. `--include-unsafe` opts state-changing methods back into
an OpenAPI corpus, which by default contributes only safe methods; requests and HAR
corpora replay every method they contain. HAR corpora have their captured
identity headers (`Cookie`, `Authorization`, `Proxy-Authorization`, `X-CSRF-Token`)
stripped on load so each identity replays under its own injected session, not the one
that captured the HAR. For horizontal/IDOR testing every request is sent verbatim
under each identity, so object references are preserved while only the session
changes.

### 6. Control plane

A local-only control socket (Unix domain socket, or loopback with a token) that
clients use to read session state, trigger refreshes, and drive replay. This is the
attach point for the `claviger watch` TUI and for scripting.

## Observability

The daemon emits structured logs at `--log-level` (`error`, `warn`, `info`,
`debug`). With `--audit-log <file>`, it appends one JSON record per gateway request
carrying only identity, method, path, and status: never the query string (which can
carry secrets), headers, cookies, tokens, or bodies. This gives an engagement log
without leaking the traffic it summarizes.

## Not built

- **Forward proxy (MITM interception).** No `HTTP_PROXY`-style CONNECT / TLS
  interception; the gateway is a per-identity reverse proxy.
- **Verdict / judgement engine.** `replay` reports facts (`DIFFERS`), not a bypass
  decision.
- **Browse-and-capture UI.** No proxy history to read; not a Burp replacement.
- **Windows support.** Unix-like hosts only.

## Hard problems and decisions

- **Reliable logged-out detection.** The failure signature varies (401, 403,
  302-to-login, 200-with-login-body, JSON error). v1: the recipe declares it
  explicitly. A later ease-of-use layer can learn it by diffing a known logged-in
  versus logged-out response. Getting this wrong means either missing dead sessions or
  thrashing in a re-login loop, so it is declared, not guessed, in v1.
- **Retry idempotency.** Decided above: auto-retry safe methods, surface (do not
  blindly replay) non-idempotent ones.
- **Concurrency.** Single-flight refresh in the session store; the gateway and replay
  engine both go through it.
- **Rate/lockout.** Backoff and a per-minute re-auth ceiling in the store.
- **Not masking the bug.** Honest `anon`/passthrough plus recording of what was
  injected, so a gateway that keeps you authed never hides an auth-enforcement flaw or
  contaminates evidence.
- **Secret handling.** Claviger holds live creds and tokens, local-only and never
  written to the logs (the audit log records only identity/method/path/status).
  Secrets can be sourced indirectly (`password_file`, `password_command`, `${ENV}`)
  so they need not sit in the config, but the config is plaintext, not encrypted at
  rest. It only ever authenticates against the configured target. TLS trust and
  client-auth for reaching that target are set by the global and per-identity `tls`
  blocks (and matching CLI flags); disabling verification warns on stderr.

## Shipped scope

1. Recipe engine: `form`, `oauth`, `multistep`, and `browser` recipes, each with a
   declared logged-out signature and recover step.
2. Session store: warm per-identity state, single-flight refresh, and a hard
   per-window backoff ceiling.
3. Auth gateway: identity-scoped reverse proxy with inject + reauth-retry + honest
   `anon` passthrough + optional per-identity CSRF injection, behind loopback and
   Host/Origin/Sec-Fetch guards.
4. Credential source: `claviger header <id>` and `GET /creds/<id>`.
5. Replay primitive: single-request (`--path`) and corpus (`--corpus`,
   requests/HAR/OpenAPI) fan-out with a bare status table / matrix.
6. Headless daemon + local control socket; `claviger daemon`, `claviger identities`,
   `claviger status`, `claviger header`, `claviger replay`, `claviger version`
   subcommands.
7. TLS trust/client-auth policy, secret sourcing, structured logging, and an audit
   log.

## CLI surface

```
claviger daemon                       # start the headless authority
claviger identities                   # list configured identities
claviger status                       # per-identity session health
claviger header <id>                  # print a live auth header
claviger replay --as <id> [--as <id>] (--path /p | --corpus file)
claviger version                      # print the built version
```

Config declares identities and their recipes (target, login method, credential
source, logged-out signature, refresh method). Single static Go binary, one
subcommand per surface, matching the existing tool line's distribution pattern
(`make build` stamps the version; goreleaser builds tagged releases).

## Technology

Standalone Go daemon, single static binary, subcommand CLI. Chosen to match the
existing tool line (vercelsior, caminus, the custos tools) and its single-binary,
brew/scoop distribution. A mitmproxy addon would prototype the proxy faster but ties
the tool to Python and mitmproxy's model; a native Go proxy keeps it self-contained
and distributable.

## Testing approach

- Recipe engine and session store are pure units, tested against a local mock auth
  server that issues short-lived tokens and a refresh endpoint, so expiry and
  single-flight refresh are exercised deterministically.
- Gateway tested end to end: run a real CLI tool (curl/ffuf) through the proxy against
  the mock server with a sub-minute token, assert the fleet stays authed across at
  least one expiry.
- Replay tested for verbatim object-reference preservation across identities.
- Retry-idempotency tested explicitly: a POST whose token dies mid-flight must not be
  double-submitted.

## Resolved decisions

- **Config format:** a declarative YAML file (`claviger.yaml`), not a recorded flow.
- **Control plane:** a Unix domain socket by default (owner-only, in a private
  per-user directory).
- **Replay input:** both a single request (`--path`) and a batch corpus
  (`--corpus`, requests/HAR/OpenAPI).
