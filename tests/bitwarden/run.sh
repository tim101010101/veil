#!/bin/sh
# The Bitwarden compatibility suite (compatibility suite): pinned official clients against a real veild
# behind TLS. Exits non-zero on the first failed check.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
. "$here/versions.env"
home=${COMPAT_HOME:-$HOME/.cache/veil-compat}
VEILD=${VEILD:-$root/target/debug/veild}
VEIL=${VEIL:-$root/target/debug/veil}
BW=${BW:-$home/npm/bin/bw}
CADDY=${CADDY:-$(command -v caddy || echo "$home/caddy")}
export PLAYWRIGHT_DIR=${PLAYWRIGHT_DIR:-$home/pw}
export EXTENSION_DIR=${EXTENSION_DIR:-$home/ext-$EXTENSION_VERSION}
port=${COMPAT_PORT:-18080}
tls_port=${COMPAT_TLS_PORT:-18443}

work=${COMPAT_WORK:-$(mktemp -d)}
mkdir -p "$work"
pids=""
cleanup() { for pid in $pids; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

# JSON without jq: python3 is in every CI image. `jget EXPR` prints EXPR over the parsed stdin
# as `d`; `jset STATEMENTS` applies assignments to `d` and prints it back.
jget() { python3 -c 'import sys, json; d = json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
jset() { python3 -c 'import sys, json; d = json.load(sys.stdin); exec(sys.argv[1]); print(json.dumps(d))' "$1"; }

pass() { echo "PASS $*"; }
fail() {
    echo "FAIL $*" >&2
    for service in veild caddy; do
        if [ -f "$work/$service.log" ]; then
            echo "--- $service log" >&2
            tail -40 "$work/$service.log" >&2
        fi
    done
    exit 1
}
check() { [ "$1" = "$2" ] || fail "$3: expected [$2], got [$1]"; pass "$3"; }

echo "bw $("$BW" --version) (pinned $BW_VERSION), extension $EXTENSION_VERSION"
[ "$("$BW" --version)" = "$BW_VERSION" ] || fail "bw is not the pinned version"

VEIL_BIND=127.0.0.1:$port VEIL_DB=$work/veil.db VEIL_LOG=info,veil_daemon=debug "$VEILD" >"$work/veild.log" 2>&1 &
pids="$pids $!"
COMPAT_TLS_PORT=$tls_port COMPAT_UPSTREAM=127.0.0.1:$port XDG_DATA_HOME=$work/caddy-data \
    "$CADDY" run --config "$here/Caddyfile" --adapter caddyfile >"$work/caddy.log" 2>&1 &
pids="$pids $!"
server="https://localhost:$tls_port"
export NODE_EXTRA_CA_CERTS=$work/caddy-data/caddy/pki/authorities/local/root.crt
for _ in $(seq 1 50); do
    if [ -f "$NODE_EXTRA_CA_CERTS" ] && curl -fsS --connect-timeout 1 --max-time 2 \
        --cacert "$NODE_EXTRA_CA_CERTS" "$server/api/config" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
curl -fsS --connect-timeout 1 --max-time 2 --cacert "$NODE_EXTRA_CA_CERTS" "$server/api/config" >/dev/null \
    || fail "veild is not reachable over TLS"

export VEIL_HOME=$work/veil VEIL_SERVER=http://127.0.0.1:$port VEIL_EMAIL=compat@veil.test
export VEIL_PASSWORD='correct horse battery staple' VEIL_LOG=error
"$VEIL" login --create >/dev/null
"$VEIL" vault create web >/dev/null
"$VEIL" vault create example >/dev/null
"$VEIL" set veil://web/demo-service/username --value example-bot >/dev/null
"$VEIL" set veil://web/demo-service/password --value 'demo-123:ABC' >/dev/null
"$VEIL" set veil://web/demo-service/uri --value https://api.example.com >/dev/null
"$VEIL" set veil://example/admin-token/password --value never-in-the-browser >/dev/null
"$VEIL" bitwarden enable --vault web >/dev/null

export BITWARDENCLI_APPDATA_DIR=$work/bw
"$BW" config server "$server" >/dev/null

# 1. bw logs in to a v2 account created by veil.
BW_SESSION=$("$BW" login "$VEIL_EMAIL" "$VEIL_PASSWORD" --raw 2>"$work/bw-login.err") || true
[ -n "$BW_SESSION" ] || fail "1 bw login: $(cat "$work/bw-login.err")"
export BW_SESSION
pass "1 bw logs in to a v2 account created by veil"

# 2. bw reads an Item written by veil, and sees only the enabled Vault.
"$BW" sync >/dev/null
items=$("$BW" list items)
check "$(echo "$items" | jget "next(i['login']['password'] for i in d if i['name'] == 'demo-service')")" 'demo-123:ABC' "2 bw reads the password veil wrote"
check "$(echo "$items" | jget "next(i['login']['username'] for i in d if i['name'] == 'demo-service')")" 'example-bot' "2 bw reads the username veil wrote"
check "$(echo "$items" | jget "next(i['login']['uris'][0]['uri'] for i in d if i['name'] == 'demo-service')")" 'https://api.example.com' "2 bw reads the URI veil wrote"
check "$(echo "$items" | jget "len([i for i in d if i['name'] == 'admin-token'])")" '0' "2 bw sees nothing from another Vault"

# 3. bw creates and edits Items; veil reads the new values.
folder=$("$BW" get template folder | jset "d['name'] = 'Example'" | "$BW" encode | "$BW" create folder | jget "d['id']")
"$BW" get template item | FOLDER=$folder jset "import os; d.update(name='Example application', folderId=os.environ['FOLDER'], notes=None, login={'username': 'admin', 'password': 'example-pw', 'uris': [{'uri': 'https://app.example.com'}]})" \
    | "$BW" encode | "$BW" create item >/dev/null
id=$("$BW" list items --search demo-service | jget "d[0]['id']")
"$BW" get item "$id" | jset "d['login']['password'] = 'demo-rotated'" | "$BW" encode | "$BW" edit item "$id" >/dev/null
check "$("$VEIL" get veil://web/demo-service/password --yes)" 'demo-rotated' "3 veil reads a password bw edited"
check "$("$VEIL" get 'veil://web/Example application/password' --yes)" 'example-pw' "3 veil reads an Item bw created"
check "$("$VEIL" get 'veil://web/Example application/username' --yes)" 'admin' "3 veil reads its username"
"$BW" delete item "$id" >/dev/null
"$VEIL" get veil://web/demo-service/password --yes >/dev/null 2>&1 && fail "3 a trashed Item must not resolve"
pass "3 bw trashes an Item and veil stops resolving it"
"$BW" restore item "$id" >/dev/null
check "$("$VEIL" get veil://web/demo-service/password --yes)" 'demo-rotated' "3 bw restores it"
"$BW" sync >/dev/null
check "$("$BW" get item "Example application" | jget "d['folderId']")" "$folder" "3 the folder survives a sync"

# 4. The extension logs in and lists the Items.
runner=""
[ -n "${DISPLAY:-}" ] || runner="xvfb-run -a"
SHOTS_DIR=$work/shots $runner node "$here/ext-test.mjs" "$server" "$VEIL_EMAIL" "$VEIL_PASSWORD" \
    demo-service "Example application" --absent admin-token \
    || fail "4 extension (screenshots in $work/shots)"
pass "4 the extension logs in and lists the Items"

# Optional: the extension writes an Item and autofills it (compatibility suite asks for these by hand;
# they run here when the UI cooperates). Not part of the gate.
if [ "${COMPAT_EXTENDED:-}" = 1 ]; then
    mkdir -p "$work/site"
    cat >"$work/site/login.html" <<'HTML'
<!doctype html><title>Login</title>
<form><label>Username <input id="username" name="username" autocomplete="username"></label>
<label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form>
HTML
    (cd "$work/site" && python3 -m http.server 18099 --bind 127.0.0.1 >/dev/null 2>&1) &
    pids="$pids $!"
    sleep 1
    status=0
    SHOTS_DIR=$work/shots-extended $runner node "$here/ext-extended.mjs" "$server" "$VEIL_EMAIL" "$VEIL_PASSWORD" \
        "http://localhost:18099/login.html" || status=$?
    case $status in
        0) echo "EXTENDED PASS the extension autofilled the test page" ;;
        2) echo "EXTENDED autofill not confirmed under automation; check it by hand (screenshots in $work/shots-extended)" ;;
        *) echo "EXTENDED the extension could not write an Item (screenshots in $work/shots-extended)" ;;
    esac
    written=$("$VEIL" get 'veil://web/Extension written/password' --yes 2>/dev/null || true)
    [ "$written" = ext-written-pw ] && echo "EXTENDED PASS veil reads an Item the extension wrote" \
        || echo "EXTENDED FAIL veil does not see the Item the extension wrote"
fi

# 5. With two-step login on, bw needs an authenticator code as well as the password.
totp() { python3 -c 'import base64, hashlib, hmac, struct, sys, time; k = base64.b32decode(sys.argv[1]); s = int(time.time()) // 30 + int(sys.argv[2]); h = hmac.new(k, struct.pack(">Q", s), hashlib.sha1).digest(); o = h[-1] & 15; print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000))' "$@"; }
secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
"$VEIL" bitwarden two-step enable --secret "$secret" --code "$(totp "$secret" 0)" >/dev/null \
    || fail "5 veil turns two-step login on"
"$BW" logout >/dev/null 2>&1 || true
# Without --nointeraction bw would wait for the code on stdin and exit 0 at EOF.
refused=$("$BW" login "$VEIL_EMAIL" "$VEIL_PASSWORD" --raw --nointeraction </dev/null 2>"$work/bw-2fa.err") \
    && fail "5 bw must not log in with the password alone"
[ -z "$refused" ] || fail "5 bw printed a session without a code"
check "$("$BW" status | jget "d['status']")" 'unauthenticated' "5 bw is refused without a code"
# The enabling code is spent; the next step's code is within the allowed drift.
BW_SESSION=$("$BW" login "$VEIL_EMAIL" "$VEIL_PASSWORD" --method 0 --code "$(totp "$secret" 1)" --raw 2>"$work/bw-2fa.err") || true
[ -n "$BW_SESSION" ] || fail "5 bw two-step login: $(cat "$work/bw-2fa.err")"
export BW_SESSION
"$BW" sync >/dev/null
check "$("$BW" get item "Example application" | jget "d['login']['password']")" 'example-pw' "5 bw logs in with a code and reads the Vault"

# 6. bw imports an Apple Passwords export (safaricsv) and a Bitwarden JSON export with a
#    folder through /api/ciphers/import; veil reads what was imported.
cat > "$work/apple-passwords.csv" <<'CSV'
Title,URL,Username,Password,Notes,OTPAuth
Apple Imported,https://apple.example,apple-user,apple-pw-1,from Passwords,otpauth://totp/Apple?secret=JBSWY3DPEHPK3PXP
Second Apple,https://second.example,second-user,apple-pw-2,,
CSV
"$BW" import safaricsv "$work/apple-passwords.csv" >"$work/bw-import.out" 2>&1 \
    || fail "6 bw import safaricsv: $(cat "$work/bw-import.out")"
check "$("$VEIL" get 'veil://web/Apple Imported/password' --yes)" 'apple-pw-1' "6 veil reads an Item imported from Apple Passwords"
check "$("$VEIL" get 'veil://web/Second Apple/username' --yes)" 'second-user' "6 veil reads its username"
cat > "$work/bitwarden-export.json" <<'JSON'
{"encrypted": false,
 "folders": [{"id": "6f0d5e8e-0000-4000-8000-000000000001", "name": "Imported folder"}],
 "items": [{"type": 1, "name": "JSON Imported", "folderId": "6f0d5e8e-0000-4000-8000-000000000001",
            "favorite": false, "notes": null,
            "login": {"username": "json-user", "password": "json-pw", "uris": [{"uri": "https://json.example"}]}}]}
JSON
"$BW" import bitwardenjson "$work/bitwarden-export.json" >"$work/bw-import.out" 2>&1 \
    || fail "6 bw import bitwardenjson: $(cat "$work/bw-import.out")"
"$BW" sync >/dev/null
folder=$("$BW" list folders | jget "next(f['id'] for f in d if f['name'] == 'Imported folder')")
check "$("$BW" get item "JSON Imported" | jget "d['folderId']")" "$folder" "6 an imported Item keeps its folder"
check "$("$VEIL" get 'veil://web/JSON Imported/password' --yes)" 'json-pw' "6 veil reads an Item imported from Bitwarden JSON"

echo "compatibility suite passed"
