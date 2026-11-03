#!/bin/sh
# Safe upgrades (docs/release-1.0.md, M2): the previous release's server
# fills a database (users, projects, analyses, triage, gates, profiles,
# tokens), the server built from this checkout takes it over, and everything
# is still there and served. CI runs it on every pull request.
#
#   scripts/check-upgrade.sh OLD_SERVER NEW_SERVER OLD_SONDA
#
# Needs DATABASE_URL, an empty PostgreSQL database, and jq.
set -eu

[ $# -eq 3 ] || { echo "usage: scripts/check-upgrade.sh OLD_SERVER NEW_SERVER OLD_SONDA" >&2; exit 2; }
old_server=$1
new_server=$2
old_cli=$3
: "${DATABASE_URL:?set DATABASE_URL}"
port=${SONDA_UPGRADE_PORT:-9101}
url=http://127.0.0.1:$port
admin_password=upgrade-check-password-123

work=$(mktemp -d)
pid=
stop() { [ -z "$pid" ] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; pid=; }; }
trap 'stop; rm -rf "$work"' EXIT

start() {
  SONDA_ADMIN_PASSWORD=$admin_password SONDA_LISTEN=127.0.0.1:$port "$1" > "$work/server.log" 2>&1 &
  pid=$!
  i=0
  until curl -fsS "$url/api/health" > /dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ] || ! kill -0 "$pid" 2>/dev/null; then
      echo "check-upgrade: the server didn't come up" >&2
      cat "$work/server.log" >&2
      exit 1
    fi
    sleep 1
  done
}

# Fails with the server's answer, which curl -f would hide.
call() { # METHOD PATH [JSON]
  method=$1; path=$2
  set -- -sS -X "$method" -o "$work/body" -w '%{http_code}' -H "Cookie: $cookie" -H 'sonda-csrf: 1' "$url$path"
  [ -z "${body:-}" ] || set -- "$@" -H 'Content-Type: application/json' -d "$body"
  code=$(curl "$@")
  case $code in 2??) ;; *) echo "check-upgrade: $method $path -> $code" >&2; cat "$work/body" >&2; exit 1 ;; esac
}

sign_in() {
  curl -sS -D "$work/headers" -o /dev/null -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$admin_password\"}" "$url/api/session"
  cookie=$(sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "$work/headers" | head -n 1)
  [ -n "$cookie" ] || { echo "check-upgrade: signing in failed" >&2; cat "$work/headers" >&2; exit 1; }
}

# What a person sees, normalized so two runs compare.
snapshot() { # NAME
  for what in analyses issues gates rule-profiles users me/tokens projects; do
    call GET "/api/$what"
    jq -S . "$work/body" > "$work/$1.$(echo "$what" | tr / _)"
  done
  call GET /api/analyses/1
  jq -S . "$work/body" > "$work/$1.analysis1"
}

mkdir "$work/project"
cat > "$work/project/app.js" <<'JS'
function f(a) {
  if (a == null) { return 1; }
  eval(a);
  return 2;
}
function g(b) { return eval(b); }
JS

echo "check-upgrade: filling a database with $("$old_server" --version)"
start "$old_server"
sign_in
body='{"username":"alice","displayName":"Alice","role":"member","password":"alice-password-123"}' call POST /api/users
body='{"name":"strict","conditions":[{"metric":"new_vulnerabilities","op":"gt","threshold":0}]}' call POST /api/quality-gates
body='{"name":"ours"}' call POST /api/rule-profiles
body='{"name":"ci","type":"global_analysis","expiresInDays":null}' call POST /api/me/tokens
token=$(jq -r '.token // .secret // empty' "$work/body")
[ -n "$token" ] || { echo "check-upgrade: no token in the answer: $(cat "$work/body")" >&2; exit 1; }

upload() {
  SONDA_TOKEN=$token env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME -u GITHUB_EVENT_PATH -u GITHUB_REF \
    "$old_cli" scan "$work/project" --no-gate --upload --server "$url" \
    --project payments --branch main --commit "$1" > /dev/null
}
upload 0123456789abcdef0123456789abcdef01234567
# The second analysis fixes one issue and leaves the other.
sed -i.bak '/function g/d' "$work/project/app.js"
upload 1123456789abcdef0123456789abcdef01234567

call GET '/api/issues?project=payments'
id=$(jq -r '[.issues[]? // .items[]? // .[]?][0].id' "$work/body")
case $id in
  "" | null) echo "check-upgrade: no issue to triage: $(cat "$work/body")" >&2; exit 1 ;;
esac
body='{"status":"accepted","reason":"known","assignee":"alice"}' call PATCH "/api/issues/$id"

snapshot before
# Guards the comparison below: it proves nothing if what was filled isn't in
# the snapshot to begin with.
present() { # FILE JQ-FILTER WHAT
  jq -e "$2" "$work/before.$1" > /dev/null || { echo "check-upgrade: the old server's data lacks $3" >&2; exit 1; }
}
present users 'tostring | contains("alice")' "the user"
present gates 'tostring | contains("strict")' "the gate"
present rule-profiles 'tostring | contains("ours")' "the profile"
present issues 'tostring | contains("accepted")' "the triaged issue"
present me_tokens 'tostring | contains("ci")' "the token"
present analyses 'tostring | contains("payments")' "the analyses"
stop

echo "check-upgrade: upgrading to $("$new_server" --version)"
start "$new_server"
# The same session still works: it was kept in the database.
snapshot after

for f in "$work"/before.*; do
  name=${f##*/before.}
  if ! diff -u "$f" "$work/after.$name" > "$work/diff"; then
    echo "check-upgrade: $name changed in the upgrade" >&2
    cat "$work/diff" >&2
    exit 1
  fi
done
echo "check-upgrade: everything the old server stored is still there and served"
