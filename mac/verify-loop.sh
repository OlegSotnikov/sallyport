#!/usr/bin/env bash
#
# Run the legacy cross-process integration loop against a local HTTP server.
#
# The script checks that the debug app signs a grant with the Secure Enclave,
# the daemon verifies it, the local server receives an injected test credential,
# and the audit chain verifies. It does not call an external API.
#
# SALLYPORT_DEV_AUTOAPPROVE is available only in debug builds. This script builds
# into build-loop/ and does not replace build/Sallyport.app.
#
# Home isolation:
#   The app's control-socket path is fixed at $HOME/.sallyport/sallyport.sock via
#   NSHomeDirectory. Secure Enclave key creation also needs the real home. The
#   script moves any existing ~/.sallyport aside and restores it on exit.
#
# Usage: ./verify-loop.sh
#        KEEP_HOME=1 ./verify-loop.sh   # leave the test home in place
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
CORE="$(cd "$ROOT/.." && pwd)/core"
APP_BIN="$ROOT/build-loop/Sallyport.app/Contents/MacOS/Sallyport"
SP="$CORE/bin/sp"
PORT=8799
SP_HOME="$HOME/.sallyport"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sallyport-loop.XXXXXX")"
AUTHFILE="$WORK/authorization.txt"
APP_LOG="$WORK/app.log"
DAEMON_LOG="$WORK/daemon.log"
SERVER_LOG="$WORK/server.log"
MCP_OUT="$WORK/mcp-response.jsonl"

APP_PID="" ; DAEMON_PID="" ; SERVER_PID="" ; HOME_BACKUP=""
FAILS=0

c()   { printf '\033[%sm%s\033[0m' "$1" "$2"; }
info() { printf '%s %s\n' "$(c '36' '==>')" "$*"; }
pass() { printf '%s %s\n' "$(c '32' 'pass')" "$*"; }
fail() { printf '%s %s\n' "$(c '31' 'fail')" "$*"; FAILS=$((FAILS+1)); }
hr()   { printf '%s\n' "------------------------------------------------------------"; }

cleanup() {
  hr; info "cleanup"
  [ -n "$APP_PID" ]    && kill "$APP_PID"    2>/dev/null
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  pkill -f 'build-loop/Sallyport.app' 2>/dev/null
  sleep 0.3
  if [ "${KEEP_HOME:-0}" != "1" ]; then
    rm -rf "$SP_HOME"
    if [ -n "$HOME_BACKUP" ] && [ -e "$HOME_BACKUP" ]; then
      mv "$HOME_BACKUP" "$SP_HOME"
      info "restored your original ~/.sallyport"
    fi
  else
    info "KEEP_HOME=1: leaving ~/.sallyport in place"
  fi
  info "logs: $WORK"
}
trap cleanup EXIT

# Local target that records the Authorization header it receives.
write_echo_server() {
  cat > "$WORK/echo_server.py" <<'PY'
import sys, http.server, socketserver
port = int(sys.argv[1]); authfile = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def handle_one(self):
        auth = self.headers.get('Authorization', '')
        open(authfile, 'w').write(auth)
        n = int(self.headers.get('Content-Length', 0) or 0)
        if n: self.rfile.read(n)
        body = ('{"ok":true,"authorization_seen":%r}' % auth).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = handle_one
    do_GET  = handle_one
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('127.0.0.1', port), H) as s:
    s.serve_forever()
PY
}

hr
info "legacy cross-process loop with Secure Enclave signing"
hr

# Build the daemon and CLI.
info "a. build core (sallyportd + sp)"
( cd "$CORE" && go build -o bin/sallyportd ./cmd/sallyportd && go build -o bin/sp ./cmd/sp ) \
  || { fail "core build"; exit 1; }
pass "built $CORE/bin/{sallyportd,sp}"

# Build the debug app used for automatic approval.
info "   build signed debug app in build-loop/"
( cd "$ROOT" && CONFIG=debug OUT_DIR="$ROOT/build-loop" ./build-app.sh ) >"$WORK/build-app.log" 2>&1 \
  || { fail "debug app build/sign (see $WORK/build-app.log)"; exit 1; }
[ -x "$APP_BIN" ] || { fail "app binary missing at $APP_BIN"; exit 1; }
pass "signed debug app: $APP_BIN"

# Start the local HTTP target.
info "b. start local echo server on 127.0.0.1:$PORT"
write_echo_server
python3 "$WORK/echo_server.py" "$PORT" "$AUTHFILE" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  { exec 3<>"/dev/tcp/127.0.0.1/$PORT"; } 2>/dev/null && { exec 3>&-; break; }
  sleep 0.1
done
kill -0 "$SERVER_PID" 2>/dev/null || { fail "echo server did not start"; exit 1; }
pass "echo server started (pid $SERVER_PID, authfile=$AUTHFILE)"

# Initialize the default home and bind the test credential.
info "c. prepare ~/.sallyport (default home; app socket path is fixed there)"
if [ -e "$SP_HOME" ]; then
  HOME_BACKUP="$SP_HOME.verifyloop-bak.$(date +%s)"
  mv "$SP_HOME" "$HOME_BACKUP"
  info "   moved existing ~/.sallyport to $HOME_BACKUP; it will be restored on exit"
fi
"$SP" init >"$WORK/init.log" 2>&1 || { fail "sp init"; exit 1; }
# Bind to hostname 127.0.0.1 because the HTTP executor drops the port during
# credential lookup. The default policy already sends POST requests for approval.
printf 'testtoken' | "$SP" secret set loopcred --kind bearer --bind 127.0.0.1 \
  --format 'Bearer {secret}' >"$WORK/secret.log" 2>&1 || { fail "sp secret set"; exit 1; }
pass "home initialized + loopcred bound to 127.0.0.1 ($("$SP" secret ls | tail -n +2 | tr -s ' ' | cut -d' ' -f1,4))"

# Start the daemon in the default home.
info "d. start sallyportd"
"$SP" daemon >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$SP_HOME/sallyport.sock" ] && break; sleep 0.1; done
[ -S "$SP_HOME/sallyport.sock" ] || { fail "daemon socket never appeared"; cat "$DAEMON_LOG"; exit 1; }
pass "daemon started (pid $DAEMON_PID, socket $SP_HOME/sallyport.sock)"

# Launch the signed app and wait for its subscription.
info "e. launch signed app with SALLYPORT_DEV_AUTOAPPROVE=1"
SALLYPORT_DEV_AUTOAPPROVE=1 "$APP_BIN" >"$APP_LOG" 2>&1 &
APP_PID=$!
for _ in $(seq 1 100); do grep -q 'connected; hello + subscribe sent' "$APP_LOG" && break; sleep 0.1; done
if ! grep -q 'connected; hello + subscribe sent' "$APP_LOG"; then
  fail "app never connected/subscribed"; sed 's/^/    app| /' "$APP_LOG"; exit 1
fi
SIGNER_LINE="$(grep -m1 'signer=' "$APP_LOG")"
pass "app connected and subscribed [$SIGNER_LINE]"

# Send a mutating JSON-RPC request through `sp mcp`.
info "f. send http.request POST to 127.0.0.1:$PORT"
INIT='{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}'
CALL='{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"http.request","arguments":{"method":"POST","url":"http://127.0.0.1:'"$PORT"'/apply","body":"{\"change\":\"loop\"}"}}}'
printf '%s\n%s\n' "$INIT" "$CALL" | "$SP" mcp >"$MCP_OUT" 2>>"$WORK/mcp.err"
pass "tools/call returned"

hr
info "results"
hr

# 1. The app signs with the Secure Enclave.
if grep -q 'signer=secure-enclave' "$APP_LOG" \
   && grep -q 'signed grant .* with secure-enclave' "$APP_LOG"; then
  pass "1. app signed with the Secure Enclave (K-sign, DER ECDSA-P256)"
  grep -m1 'signed grant' "$APP_LOG" | sed 's/^/       app| /'
else
  fail "1. app did not sign with the Secure Enclave"; grep -E 'signer=|signing failed' "$APP_LOG" | sed 's/^/       app| /'
fi

# 2. The daemon verifies the signature and executes the request.
# types.Result uses lowercase JSON keys: ok, decision, output, and status.
DECISION="$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
 l=l.strip()
 if not l: continue
 m=json.loads(l)
 if m.get("id")==1:
  print(json.loads(m["result"]["content"][0]["text"]).get("decision"))' "$MCP_OUT")"
STATUS="$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
 l=l.strip()
 if not l: continue
 m=json.loads(l)
 if m.get("id")==1:
  print((json.loads(m["result"]["content"][0]["text"]).get("output") or {}).get("status"))' "$MCP_OUT")"
if [ "$DECISION" = "ask→approved" ] && [ "$STATUS" = "200" ]; then
  pass "2. daemon verified the signature and executed (decision=$DECISION, HTTP status=$STATUS)"
  pass "   an invalid grant would return SALLYPORT_DENIED"
else
  fail "2. daemon did not approve and execute (decision=$DECISION, status=$STATUS)"; cat "$MCP_OUT"
fi

# 3. The local server receives the injected credential.
SEEN="$(cat "$AUTHFILE" 2>/dev/null || true)"
if [ "$SEEN" = "Bearer testtoken" ]; then
  pass "3. local server received the injected credential: Authorization: $SEEN"
else
  fail "3. local server did not see the injected token (got: '${SEEN:-<none>}')"
fi

# 4. The audit row exists and the chain verifies.
AUDIT_ROW="$("$SP" audit tail -n 10 2>/dev/null | grep -m1 'ask.*approved' || true)"
AUDIT_VERIFY="$("$SP" audit verify 2>&1)"
if [ -n "$AUDIT_ROW" ] && printf '%s' "$AUDIT_VERIFY" | grep -q 'chain intact'; then
  pass "4. audit row written and hash chain verified ($AUDIT_VERIFY)"
  printf '%s' "$AUDIT_ROW" | python3 -c 'import json,sys; r=json.load(sys.stdin); print("       audit|",{k:r[k] for k in ("identity","tool","target","decision","rule","grant_id") if k in r})' 2>/dev/null \
    || printf '       audit| %s\n' "$AUDIT_ROW"
else
  fail "4. audit row/verify failed"; printf '%s\n' "$AUDIT_VERIFY"; "$SP" audit tail -n 10
fi

hr
if [ "$FAILS" -eq 0 ]; then
  printf '%s\n' "$(c '32' 'verify-loop: passed with a Secure Enclave signature')"
  exit 0
else
  printf '%s\n' "$(c '31' "verify-loop: failed ($FAILS checks failed)")"
  exit 1
fi
