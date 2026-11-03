#!/bin/sh
# The compatibility window (docs/stability.md): a CLI from the previous
# release uploads to the server built from this checkout. CI runs it on every
# pull request, with the last published release's binary.
#
#   scripts/check-compat.sh OLD_SONDA SERVER_BIN
#
# Needs DATABASE_URL, an empty PostgreSQL database the server may migrate.
set -eu

[ $# -eq 2 ] || { echo "usage: scripts/check-compat.sh OLD_SONDA SERVER_BIN" >&2; exit 2; }
old=$1
server=$2
: "${DATABASE_URL:?set DATABASE_URL}"
port=${SONDA_COMPAT_PORT:-9100}
url=http://127.0.0.1:$port

work=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null; rm -rf "$work"' EXIT

# A project with a finding, so the upload carries an issue and a source.
mkdir "$work/project"
cat > "$work/project/app.js" <<'JS'
function f(a) {
  if (a == null) { return 1; }
  eval(a);
  return 2;
}
JS

# At least 32 characters; the loopback address means no sign-in is needed to read.
token=compat-check-token-0123456789abcdef0123456789
SONDA_TOKEN=$token SONDA_LISTEN=127.0.0.1:$port "$server" > "$work/server.log" 2>&1 &
pid=$!

i=0
until curl -fsS "$url/api/projects" > /dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "check-compat: the server didn't come up" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  sleep 1
done

echo "check-compat: uploading with $("$old" --version)"
# --no-gate: only the upload is under test, not the gate's verdict.
# Not as a GitHub Actions pull request, which the CLI would otherwise detect
# from the environment and upload as one.
SONDA_TOKEN=$token env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME -u GITHUB_EVENT_PATH -u GITHUB_REF "$old" scan "$work/project" --no-gate --upload --server "$url" \
  --project compat --branch main --commit 0123456789abcdef0123456789abcdef01234567

# It was stored and is served, with its issues.
curl -fsS --fail-with-body "$url/api/analyses/1" > "$work/analysis.json"
curl -fsS --fail-with-body "$url/api/projects/compat" > /dev/null
echo "check-compat: the previous release's upload was accepted and is served"
