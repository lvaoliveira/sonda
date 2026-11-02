#!/bin/sh
# Starts the sonda server with Docker Compose (docs/server.md): creates the
# secrets it needs, then builds this checkout and starts it. Safe to rerun:
# secrets and settings are kept, so `git pull && scripts/setup-server.sh`
# upgrades it.
#
# Settings are saved in .env, so later runs need no options:
#   --port PORT              publish on 127.0.0.1:PORT instead of 9000
#   --github-app ID KEY.pem  decorate pull requests with this GitHub App
#   --https IP[:PORT]        also serve HTTPS on this LAN address, port
#                            9443 by default, with Caddy's own certificate
#   --public-url URL         the server's address in those decorations
#                            (default the HTTPS address, else
#                            http://localhost:PORT)
set -eu
cd "$(dirname "$0")/.."

usage() {
  echo "usage: scripts/setup-server.sh [--port PORT] [--github-app ID KEY.pem] [--https IP[:PORT]] [--public-url URL]" >&2
  exit 2
}
die() {
  echo "setup-server: $*" >&2
  exit 1
}
is_number() {
  case $1 in '' | *[!0-9]*) return 1 ;; esac
}

port='' app_id='' app_key='' https='' public_url=''
while [ $# -gt 0 ]; do
  case $1 in
    --port) [ $# -ge 2 ] || usage; port=$2; shift 2 ;;
    --github-app) [ $# -ge 3 ] || usage; app_id=$2; app_key=$3; shift 3 ;;
    --https) [ $# -ge 2 ] || usage; https=$2; shift 2 ;;
    --public-url) [ $# -ge 2 ] || usage; public_url=$2; shift 2 ;;
    *) usage ;;
  esac
done
if [ -n "$port" ]; then
  if ! is_number "$port" || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    die "--port must be a port number"
  fi
fi
https_host=${https%%:*}
https_port=9443
case $https in *:*) https_port=${https#*:} ;; esac
if [ -n "$https" ]; then
  is_ipv4() {
    case $1 in *[!0-9.]* | *..* | .* | *.) return 1 ;; esac
    [ "$(echo "$1" | tr -cd . | wc -c)" -eq 3 ]
  }
  is_ipv4 "$https_host" || die "--https takes an IPv4 address of this machine, such as 192.168.1.10"
  if ! is_number "$https_port" || [ "$https_port" -lt 1 ] || [ "$https_port" -gt 65535 ]; then
    die "--https's port must be a port number"
  fi
fi
if [ -n "$app_id" ]; then
  is_number "$app_id" || die "--github-app's id is a number, from the App's settings page"
  grep -qs 'PRIVATE KEY-----' "$app_key" ||
    die "$app_key is not a private key (*.private-key.pem, as GitHub downloads it)"
fi
command -v docker >/dev/null || die "needs Docker, with Compose"
command -v openssl >/dev/null || die "needs openssl, to generate the secrets"

# Settings in .env, which Docker Compose reads; other lines are kept.
touch .env
get() { sed -n "s/^$1=//p" .env | tail -n 1; }
set_() {
  grep -v "^$1=" .env > .env.new || true
  printf '%s=%s\n' "$1" "$2" >> .env.new
  mv .env.new .env
}

# Secrets, created once. The directory's mode keeps other users out; the
# files are readable because the containers read them as non-root users.
mkdir -p secrets
chmod 700 secrets
first_start=false
[ -s secrets/admin_password ] || first_start=true
[ -s secrets/db_password ] || openssl rand -hex 32 > secrets/db_password
[ -s secrets/sonda_token ] || openssl rand -hex 32 > secrets/sonda_token
[ -s secrets/admin_password ] || openssl rand -base64 18 > secrets/admin_password
if [ -n "$app_id" ]; then
  cp "$app_key" secrets/github_app_key.pem
  set_ SONDA_GITHUB_APP_ID "$app_id"
fi
chmod 644 secrets/*

[ -z "$port" ] || set_ SONDA_PORT "$port"
[ -z "$public_url" ] || set_ SONDA_PUBLIC_URL "$public_url"
if [ -n "$https" ]; then
  set_ SONDA_HTTPS_HOST "$https_host"
  set_ SONDA_HTTPS_PORT "$https_port"
fi

# Which compose files: the GitHub App's and HTTPS's only once they're set
# up, and a local compose.override.yaml, which COMPOSE_FILE would otherwise
# leave out.
files=compose.yaml
if [ -n "$(get SONDA_GITHUB_APP_ID)" ]; then
  [ -s secrets/github_app_key.pem ] ||
    die "secrets/github_app_key.pem is missing: rerun with --github-app ID KEY.pem"
  files=$files:compose.github.yaml
fi
[ -z "$(get SONDA_HTTPS_HOST)" ] || files=$files:compose.https.yaml
[ ! -f compose.override.yaml ] || files=$files:compose.override.yaml
set_ COMPOSE_FILE "$files"

docker compose up -d --build --wait

url="http://127.0.0.1:$(get SONDA_PORT | grep . || echo 9000)"
echo
echo "sonda is running at $url"
if [ -n "$(get SONDA_HTTPS_HOST)" ]; then
  # Caddy creates its local authority on first start; devices need its root.
  root=/data/caddy/pki/authorities/local/root.crt
  tries=0
  until docker compose exec -T caddy test -f "$root" 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 30 ] || die "Caddy made no certificate: see docker compose logs caddy"
    sleep 1
  done
  docker compose cp "caddy:$root" caddy-root.crt
  echo "and at https://$(get SONDA_HTTPS_HOST):$(get SONDA_HTTPS_PORT) once a device trusts"
  echo "caddy-root.crt (docs/server.md, \"HTTPS on a LAN address\")."
fi
if [ "$first_start" = true ]; then
  echo "Sign in as admin, with the password in secrets/admin_password."
fi
if [ -n "$(get SONDA_GITHUB_APP_ID)" ]; then
  echo "GitHub App $(get SONDA_GITHUB_APP_ID): link each project to its repository in its Settings."
fi
