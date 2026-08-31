#!/usr/bin/env bash
#
# Claviger end-to-end acceptance harness.
#
# Orchestrates the real binary against a self-signed HTTPS target and drives it
# with real tooling (curl, ffuf, nuclei, sqlmap, headless Chrome, and the built-in
# corpus replay). Every step prints PASS/FAIL and tallies; the run exits non-zero
# if any required assertion fails or if fewer than one scanner (nuclei/sqlmap)
# actually runs. A trap kills the daemon and target and removes the socket and the
# rendered config on any exit, so a re-run is always clean.
set -euo pipefail

# Resolve the repo root from this script's location so every path is absolute and
# the harness works regardless of the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$SCRIPT_DIR/.run"
mkdir -p "$RUN_DIR"

BIN="$REPO_ROOT/claviger"
TARGET_BIN="$SCRIPT_DIR/target/target"
TMPL="$SCRIPT_DIR/claviger.e2e.yaml.tmpl"
RENDERED="$SCRIPT_DIR/claviger.e2e.yaml"
SOCKET="$SCRIPT_DIR/clv.sock"
CORPUS="$SCRIPT_DIR/corpus.har"
PATHS="$SCRIPT_DIR/paths.txt"

# Token time-to-live on the target. Long enough that a headless-Chrome establish
# comfortably beats expiry, short enough that the reauth-across-expiry curl step
# observes a real expiry window (it sleeps past this value).
TTL_SECS=8
TTL="${TTL_SECS}s"

DAEMON_PID=""
TARGET_PID=""

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "$TARGET_PID" ] && kill "$TARGET_PID" 2>/dev/null || true
  # Belt-and-suspenders: the target is a plain binary, kill any stragglers.
  pkill -f "$TARGET_BIN" 2>/dev/null || true
  rm -f "$SOCKET" "$RENDERED" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Tally + reporting.
# ---------------------------------------------------------------------------
declare -a STEP_NAMES=()
declare -a STEP_STATES=()
FAIL_REQUIRED=0
TOOLS_RAN=()

record() { # name state(PASS|FAIL|SKIP) required(req|opt)
  local name="$1" state="$2" req="$3"
  STEP_NAMES+=("$name")
  STEP_STATES+=("$state")
  case "$state" in
    PASS) printf '  [ PASS ] %s\n' "$name" ;;
    FAIL) printf '  [ FAIL ] %s\n' "$name" ; if [ "$req" = req ]; then FAIL_REQUIRED=1; fi ;;
    SKIP) printf '  [ SKIP ] %s\n' "$name" ;;
  esac
}

# assert_code label expected actual required
assert_code() {
  local label="$1" want="$2" got="$3" req="$4"
  if [ "$got" = "$want" ]; then
    record "$label (got $got)" PASS "$req"
  else
    record "$label (want $want, got $got)" FAIL "$req"
  fi
}

# Portable timeout wrapper (macOS has no coreutils `timeout`). Runs "$@" in the
# background, kills it after N seconds, and returns its exit code (124 on kill).
# Redirections on the caller's invocation are inherited by the child.
with_timeout() {
  local secs="$1"; shift
  "$@" &
  local pid=$! waited=0 rc=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" || rc=$?
  return "$rc"
}

free_port() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "e2e: python3 is required to pick a free port" >&2
    return 1
  fi
  python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

http_code() { # url [extra curl args...]
  local url="$1"; shift
  curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$@" "$url" 2>/dev/null || echo 000
}

echo "== Claviger e2e acceptance harness =="
echo "   repo: $REPO_ROOT"
echo

# ---------------------------------------------------------------------------
# Step 1: build the versioned binary and the target binary.
# ---------------------------------------------------------------------------
echo "-- step 1: build"
if make -C "$REPO_ROOT" build >"$RUN_DIR/build.log" 2>&1 \
   && go build -o "$TARGET_BIN" "$REPO_ROOT/e2e/target" >>"$RUN_DIR/build.log" 2>&1; then
  record "build claviger + target" PASS req
else
  record "build claviger + target" FAIL req
  cat "$RUN_DIR/build.log"
  echo "PASSED 0/1 (build failed)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: start the self-signed HTTPS target; parse TARGET + CACERT.
# ---------------------------------------------------------------------------
echo "-- step 2: start target"
export BOB_PASSWORD=pw
"$TARGET_BIN" -addr 127.0.0.1:0 -ttl "$TTL" >"$RUN_DIR/target.out" 2>&1 &
TARGET_PID=$!
TARGET=""
CACERT=""
for _ in $(seq 1 50); do
  TARGET="$( (grep -m1 '^LISTENING ' "$RUN_DIR/target.out" 2>/dev/null || true) | awk '{print $2}')"
  CACERT="$( (grep -m1 '^CERT ' "$RUN_DIR/target.out" 2>/dev/null || true) | awk '{print $2}')"
  [ -n "$TARGET" ] && [ -n "$CACERT" ] && break
  sleep 0.2
done
if [ -n "$TARGET" ] && [ -n "$CACERT" ] && kill -0 "$TARGET_PID" 2>/dev/null; then
  record "target listening ($TARGET)" PASS req
else
  record "target listening" FAIL req
  cat "$RUN_DIR/target.out"
  echo "PASSED 1/2 (target failed to start)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: render the config template with the real target base URL.
# ---------------------------------------------------------------------------
echo "-- step 3: render config"
if sed "s|__TARGET__|$TARGET|g" "$TMPL" >"$RENDERED"; then
  record "render config" PASS req
else
  record "render config" FAIL req
  echo "PASSED 2/3 (render failed)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: start the daemon; parse gateway token + identity->port map; wait for
# the control socket. Retry on a base-port collision with a fresh free port.
# ---------------------------------------------------------------------------
echo "-- step 4: start daemon"
TOKEN=""
daemon_up=0
for attempt in 1 2 3; do
  BASE_PORT="$(free_port)"
  "$BIN" daemon \
    --config "$RENDERED" \
    --socket "$SOCKET" \
    --base-port "$BASE_PORT" \
    --insecure \
    --gateway-token auto \
    --refresh-interval 1s \
    >"$RUN_DIR/daemon.out" 2>"$RUN_DIR/daemon.err" &
  DAEMON_PID=$!
  for _ in $(seq 1 50); do
    if [ -S "$SOCKET" ]; then break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then break; fi
    sleep 0.2
  done
  if [ -S "$SOCKET" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    daemon_up=1
    break
  fi
  # This attempt failed (likely a port collision); reap and retry.
  kill "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
  rm -f "$SOCKET" 2>/dev/null || true
  echo "   daemon start attempt $attempt failed on base-port $BASE_PORT, retrying"
done

# identity_port NAME reads the port the daemon bound for exactly that identity.
# The trailing " ->" in the match keeps "alice" from also matching "alice_sso".
identity_port() {
  ( grep -m1 "^identity $1 -> " "$RUN_DIR/daemon.out" || true ) \
    | sed -E 's|.*127\.0\.0\.1:([0-9]+).*|\1|'
}

if [ "$daemon_up" = 1 ]; then
  TOKEN="$( (grep -m1 'gateway token:' "$RUN_DIR/daemon.out" || true) | awk '{print $3}')"
  ID_COUNT="$(grep -cE '^identity [^ ]+ -> http://127\.0\.0\.1:[0-9]+' "$RUN_DIR/daemon.out" || true)"
  ALICE_PORT="$(identity_port alice)"
  SSO_PORT="$(identity_port alice_sso)"
  if [ -n "$TOKEN" ] && [ -n "$ALICE_PORT" ] && [ -n "$SSO_PORT" ]; then
    record "daemon up (token + $ID_COUNT identity ports)" PASS req
  else
    record "daemon up (token/port parse)" FAIL req
    cat "$RUN_DIR/daemon.out"; cat "$RUN_DIR/daemon.err"
    echo "PASSED 3/4 (daemon parse failed)"
    exit 1
  fi
else
  record "daemon up" FAIL req
  cat "$RUN_DIR/daemon.out"; cat "$RUN_DIR/daemon.err"
  echo "PASSED 3/4 (daemon failed to start)"
  exit 1
fi

AUTH=(-H "X-Claviger-Token: $TOKEN")

# ---------------------------------------------------------------------------
# Step 5: curl through the gateway (TLS + reauth + token gate).
# ---------------------------------------------------------------------------
echo "-- step 5: curl through gateway (TLS + reauth + token gate)"
step5_ok=1
code="$(http_code "http://127.0.0.1:$ALICE_PORT/whoami" "${AUTH[@]}")"
assert_code "curl alice /whoami" 200 "$code" req
[ "$code" = 200 ] || step5_ok=0
body="$(curl -s --max-time 30 "${AUTH[@]}" "http://127.0.0.1:$ALICE_PORT/whoami" 2>/dev/null || true)"
if printf '%s' "$body" | grep -q 'alice'; then
  record "curl body names alice" PASS req
else
  record "curl body names alice (got: $body)" FAIL req
  step5_ok=0
fi
echo "   sleeping ${TTL_SECS}s + 2 to cross the token ttl..."
sleep $((TTL_SECS + 2))
code="$(http_code "http://127.0.0.1:$ALICE_PORT/whoami" "${AUTH[@]}")"
assert_code "curl alice /whoami after ttl (reauth)" 200 "$code" req
[ "$code" = 200 ] || step5_ok=0
code="$(http_code "http://127.0.0.1:$ALICE_PORT/whoami")"
assert_code "curl no-token gate" 403 "$code" req
[ "$code" = 403 ] || step5_ok=0
CURL_OK="$step5_ok"

# ---------------------------------------------------------------------------
# Step 6: ffuf keep-alive across the authenticated path set.
# ---------------------------------------------------------------------------
echo "-- step 6: ffuf keep-alive"
FFUF_OK=0
if command -v ffuf >/dev/null 2>&1; then
  TOOLS_RAN+=(ffuf)
  rm -f "$RUN_DIR/ffuf.json"
  if with_timeout 60 ffuf -w "$PATHS" -u "http://127.0.0.1:$ALICE_PORT/FUZZ" \
       "${AUTH[@]}" -mc 200 -of json -o "$RUN_DIR/ffuf.json" -s \
       >"$RUN_DIR/ffuf.log" 2>&1; then
    hits="$(jq '[.results[] | select(.status==200)] | length' "$RUN_DIR/ffuf.json" 2>/dev/null || echo 0)"
    want="$(grep -cve '^[[:space:]]*$' "$PATHS" || true)"
    if [ "$hits" = "$want" ] && [ "$hits" -gt 0 ]; then
      record "ffuf keep-alive ($hits/$want paths 200)" PASS req
      FFUF_OK=1
    else
      record "ffuf keep-alive ($hits/$want paths 200)" FAIL req
    fi
  else
    record "ffuf keep-alive (ffuf failed)" FAIL req
  fi
else
  record "ffuf keep-alive (ffuf not installed; required)" FAIL req
fi

# ---------------------------------------------------------------------------
# Step 7: nuclei through the gateway against the local target.
# ---------------------------------------------------------------------------
echo "-- step 7: nuclei"
NUCLEI_OK=0
if command -v nuclei >/dev/null 2>&1; then
  NUCLEI_TPL="$(find "$HOME/nuclei-templates" -name 'tech-detect.yaml' 2>/dev/null | head -1)"
  nuclei_args=(-u "http://127.0.0.1:$ALICE_PORT/whoami" "${AUTH[@]}" -silent -disable-update-check -nc)
  if [ -n "$NUCLEI_TPL" ]; then
    nuclei_args+=(-t "$NUCLEI_TPL")
  else
    nuclei_args+=(-tags tech)
  fi
  TOOLS_RAN+=(nuclei)
  if with_timeout 120 nuclei "${nuclei_args[@]}" >"$RUN_DIR/nuclei.log" 2>&1; then
    record "nuclei ran through gateway (exit 0)" PASS opt
    NUCLEI_OK=1
  else
    record "nuclei ran through gateway (non-zero exit)" FAIL opt
    tail -3 "$RUN_DIR/nuclei.log" || true
  fi
else
  record "nuclei (not installed)" SKIP opt
fi

# ---------------------------------------------------------------------------
# Step 8: sqlmap through the gateway against the local reflected /search param.
# ---------------------------------------------------------------------------
echo "-- step 8: sqlmap"
SQLMAP_OK=0
if command -v sqlmap >/dev/null 2>&1; then
  TOOLS_RAN+=(sqlmap)
  if with_timeout 150 sqlmap -u "http://127.0.0.1:$ALICE_PORT/search?q=1" \
       --batch --level=1 --risk=1 --crawl=0 --technique=B --smart \
       "${AUTH[@]}" >"$RUN_DIR/sqlmap.log" 2>&1; then
    if grep -q 'ending @' "$RUN_DIR/sqlmap.log"; then
      record "sqlmap ran to completion through gateway" PASS opt
      SQLMAP_OK=1
    else
      record "sqlmap completed but no end marker" FAIL opt
    fi
  else
    record "sqlmap (non-zero exit / timeout)" FAIL opt
    tail -3 "$RUN_DIR/sqlmap.log" || true
  fi
else
  record "sqlmap (not installed)" SKIP opt
fi

# At-least-one-scanner gate.
SCANNER_OK=0
if [ "$NUCLEI_OK" = 1 ] || [ "$SQLMAP_OK" = 1 ]; then
  SCANNER_OK=1
  record "at least one scanner (nuclei|sqlmap) ran" PASS req
else
  record "at least one scanner (nuclei|sqlmap) ran" FAIL req
fi

# ---------------------------------------------------------------------------
# Step 9: headless-Chrome browser recipe -> gateway session.
# The daemon establishes alice_sso via chromedp on first request; give it room.
# ---------------------------------------------------------------------------
echo "-- step 9: headless Chrome (browser recipe)"
CHROME_OK=0
if [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] || command -v google-chrome chromium >/dev/null 2>&1; then
  TOOLS_RAN+=(chrome)
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 90 "${AUTH[@]}" "http://127.0.0.1:$SSO_PORT/whoami" 2>/dev/null || echo 000)"
  assert_code "browser alice_sso /whoami (chromedp login)" 200 "$code" req
  if [ "$code" = 200 ]; then CHROME_OK=1; fi
else
  record "headless Chrome (not installed; required)" FAIL req
fi

# ---------------------------------------------------------------------------
# Step 10: replay corpus matrix (authz split + DIFFERS + captured-cookie is inert).
# ---------------------------------------------------------------------------
echo "-- step 10: replay corpus matrix"
REPLAY_OK=1
if "$BIN" replay --config "$RENDERED" --socket "$SOCKET" --corpus "$CORPUS" \
     --as alice --as bob --as anon --insecure \
     >"$RUN_DIR/replay.out" 2>"$RUN_DIR/replay.err"; then
  # Rows for the corpus endpoints.
  for ep in "/records/alice" "/records/bob" "/idor/alice" "/whoami"; do
    if grep -q "GET $ep" "$RUN_DIR/replay.out"; then
      record "replay row $ep present" PASS req
    else
      record "replay row $ep missing" FAIL req
      REPLAY_OK=0
    fi
  done
  # A DIFFERS marker proves the per-identity authz/IDOR split is observed.
  if grep -q 'DIFFERS' "$RUN_DIR/replay.out"; then
    record "replay DIFFERS marker present" PASS req
  else
    record "replay DIFFERS marker absent" FAIL req
    REPLAY_OK=0
  fi
  # /records/alice must show alice 200, bob 403, anon 401 (the captured Cookie
  # session=CAPTURED is stripped, so anon is genuinely unauthenticated -> 401).
  records_alice="$(awk '/GET \/records\/alice/{f=1;next} /^GET /{f=0} f' "$RUN_DIR/replay.out")"
  if printf '%s\n' "$records_alice" | grep -Eq 'alice[[:space:]]+200' \
     && printf '%s\n' "$records_alice" | grep -Eq 'bob[[:space:]]+403' \
     && printf '%s\n' "$records_alice" | grep -Eq 'anon[[:space:]]+401'; then
    record "replay /records/alice authz split (alice200/bob403/anon401)" PASS req
  else
    record "replay /records/alice authz split" FAIL req
    printf '%s\n' "$records_alice"
    REPLAY_OK=0
  fi
  # Anon must be 401 on /records/bob too, proving the captured cookie never authed.
  records_bob="$(awk '/GET \/records\/bob/{f=1;next} /^GET /{f=0} f' "$RUN_DIR/replay.out")"
  if printf '%s\n' "$records_bob" | grep -Eq 'anon[[:space:]]+401'; then
    record "replay anon 401 on /records/bob (captured cookie inert)" PASS req
  else
    record "replay anon authz on /records/bob" FAIL req
    REPLAY_OK=0
  fi
else
  record "replay corpus (command failed)" FAIL req
  cat "$RUN_DIR/replay.err" || true
  REPLAY_OK=0
fi

# ---------------------------------------------------------------------------
# Step 11: status lists the identities live.
# ---------------------------------------------------------------------------
echo "-- step 11: status"
if "$BIN" status --socket "$SOCKET" --no-color >"$RUN_DIR/status.out" 2>&1; then
  ok=1
  for id in alice bob alice_sso; do
    grep -qE "^$id[[:space:]]" "$RUN_DIR/status.out" || ok=0
  done
  # alice was driven, so it must be established (live/expiring), not no-session.
  if grep -qE '^alice[[:space:]]+(live|expiring)' "$RUN_DIR/status.out" && [ "$ok" = 1 ]; then
    record "status lists identities live" PASS req
  else
    record "status lists identities live" FAIL req
    cat "$RUN_DIR/status.out"
  fi
else
  record "status (command failed)" FAIL req
  cat "$RUN_DIR/status.out" || true
fi

# ---------------------------------------------------------------------------
# Step 12: summary.
# ---------------------------------------------------------------------------
echo
echo "== summary =="
passed=0
total=0
for i in "${!STEP_NAMES[@]}"; do
  state="${STEP_STATES[$i]}"
  if [ "$state" = SKIP ]; then continue; fi
  total=$((total + 1))
  if [ "$state" = PASS ]; then passed=$((passed + 1)); fi
done

if [ "${#TOOLS_RAN[@]}" -gt 0 ]; then
  tools_line="$( (printf '%s+' "${TOOLS_RAN[@]}" || true) | sed 's/+$//')"
else
  tools_line="none"
fi

# The run is a hard failure if any required assertion failed, or if the core
# real-tool coverage (curl + ffuf + a scanner + chrome + replay) did not all run.
gate_fail=0
if [ "$FAIL_REQUIRED" = 1 ]; then gate_fail=1; fi
[ "${CURL_OK:-0}" = 1 ] || gate_fail=1
[ "$FFUF_OK" = 1 ] || gate_fail=1
[ "$SCANNER_OK" = 1 ] || gate_fail=1
[ "$CHROME_OK" = 1 ] || gate_fail=1
[ "$REPLAY_OK" = 1 ] || gate_fail=1

if [ "$gate_fail" = 0 ]; then
  echo "PASSED $passed/$total, tools: replay+$tools_line"
  echo "RESULT: OK"
  exit 0
else
  echo "FAILED ($passed/$total assertions passed), tools: replay+$tools_line"
  echo "RESULT: FAIL"
  exit 1
fi
