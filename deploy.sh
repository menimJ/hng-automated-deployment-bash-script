#!/usr/bin/env bash
# deploy.sh — One-shot, idempotent Docker + Nginx remote deployer (with cleanup)
# Requires: bash, git, ssh, rsync, curl on your local machine.
#
# QUICK START (replace <>):
# ./deploy.sh \
#   --repo https://github.com/<ORG>/<REPO>.git \
#   --pat <PAT_or_x_for_public> \
#   --branch main \
#   --ssh-user <USER> \
#   --ssh-host <IP_or_DNS> \
#   --ssh-key ~/.ssh/<KEYFILE> \
#   --port <APP_INTERNAL_PORT>
#
# CLEANUP:
# ./deploy.sh --cleanup \
#   --ssh-user <USER> --ssh-host <IP_or_DNS> --ssh-key ~/.ssh/<KEYFILE> \
#   --app-name <APP_NAME_optional_if_repo_used_before>

set -Eeuo pipefail
IFS=$'\n\t'

# ---------- Defaults ----------
BRANCH="main"
APP_PORT=""
REPO_URL=""
PAT=""                      # optional for public repos
SSH_USER=""
SSH_HOST=""
SSH_KEY=""
APP_NAME=""
REMOTE_DIR=""
NON_INTERACTIVE="0"
CLEANUP_ONLY="0"

LOG_DIR="./logs"
DATE_STAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/deploy_${DATE_STAMP}.log"

# Exit codes per stage
E_INPUT=10; E_GIT=20; E_SSH=30; E_INSTALL=40; E_DEPLOY=50; E_NGINX=60; E_VALIDATE=70; E_CLEANUP=80

# ---------- Logging ----------
mkdir -p "$LOG_DIR"
# Write both to console and file
exec > >(tee -a "$LOG_FILE") 2>&1

ts() { date +"[%Y-%m-%d %H:%M:%S]"; }
info() { printf "%s [INFO] %s\n" "$(ts)" "$*"; }
warn() { printf "%s [WARN] %s\n" "$(ts)" "$*" >&2; }
err()  { printf "%s [ERR ] %s\n"  "$(ts)" "$*" >&2; }

on_error() { err "Unexpected error near line ${LINENO}. Check the log: $LOG_FILE"; }
on_exit()  { info "Done. Log saved at: $LOG_FILE"; }
trap on_error ERR
trap on_exit EXIT

usage() {
  cat <<USAGE
Usage: $0 [options]

Required (prompted if omitted unless --non-interactive):
  --repo <URL>            Git HTTPS URL e.g., https://github.com/org/repo.git
  --pat <TOKEN>           GitHub Personal Access Token (optional for public repos; pass 'x')
  --ssh-user <USER>       SSH username on remote (e.g., ubuntu)
  --ssh-host <IP_or_DNS>  SSH host
  --ssh-key <PATH>        SSH private key path
  --port <N>              App internal port (1-65535)

Optional:
  --branch <NAME>         Git branch (default: main)
  --app-name <NAME>       App name (defaults to repo basename)
  --remote-dir <PATH>     Remote folder (default: /opt/<app-name>)
  --non-interactive       Fail if something is missing (no prompts)
  --cleanup               Remove deployed containers, Nginx site, and remote dir
  -h | --help             Show this help

Examples:
  $0
  $0 --repo https://github.com/acme/app.git --pat ghp_xxx --ssh-user ubuntu --ssh-host 1.2.3.4 --ssh-key ~/.ssh/id_rsa --port 8080
  $0 --cleanup --ssh-user ubuntu --ssh-host 1.2.3.4 --ssh-key ~/.ssh/id_rsa --app-name app
USAGE
}

# ---------- Parse args ----------
while [ "${1-}" != "" ]; do
  case "$1" in
    --repo) REPO_URL="${2-}"; shift 2 ;;
    --pat) PAT="${2-}"; shift 2 ;;
    --branch) BRANCH="${2-}"; shift 2 ;;
    --ssh-user) SSH_USER="${2-}"; shift 2 ;;
    --ssh-host) SSH_HOST="${2-}"; shift 2 ;;
    --ssh-key) SSH_KEY="${2-}"; shift 2 ;;
    --port) APP_PORT="${2-}"; shift 2 ;;
    --app-name) APP_NAME="${2-}"; shift 2 ;;
    --remote-dir) REMOTE_DIR="${2-}"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE="1"; shift ;;
    --cleanup) CLEANUP_ONLY="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown option: $1"; usage; exit $E_INPUT ;;
  esac
done

# ---------- Requirements ----------
require_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit $E_INPUT; }; }
require_cmd git
require_cmd ssh
require_cmd rsync
require_cmd curl
require_cmd sed

# ---------- Interactive prompts ----------
prompt_if_empty() {
  var_name="$1"; prompt="$2"; secret="${3-0}"
  eval "val=\${$var_name-}"
  if [ -z "${val-}" ] && [ "$NON_INTERACTIVE" = "0" ]; then
    if [ "$secret" = "1" ]; then
      printf "%s: " "$prompt" >&2; stty -echo; IFS= read -r val; stty echo; printf "\n" >&2
    else
      printf "%s: " "$prompt" >&2; IFS= read -r val
    fi
    eval "$var_name=\"\$val\""
  fi
}

prompt_if_empty REPO_URL "Git repository URL (HTTPS, e.g., https://github.com/org/repo.git)"
prompt_if_empty PAT      "GitHub Personal Access Token (or 'x' for public repos)" 1
prompt_if_empty BRANCH   "Branch name [main]"; BRANCH="${BRANCH:-main}"
prompt_if_empty SSH_USER "SSH username (e.g., ubuntu)"
prompt_if_empty SSH_HOST "Server IP / Hostname"
prompt_if_empty SSH_KEY  "SSH private key path (e.g., ~/.ssh/id_rsa)"
prompt_if_empty APP_PORT "App internal port (1-65535)"

# ---------- Derive names/paths ----------
if [ -z "${APP_NAME-}" ] && [ -n "${REPO_URL-}" ]; then
  base="${REPO_URL%/}"; base="${base%.git}"
  APP_NAME="$(basename "$base" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')"
fi
APP_NAME="${APP_NAME:-app}"
REMOTE_DIR="${REMOTE_DIR:-/opt/$APP_NAME}"

# ---------- Validation ----------
validate_ip() {
  ip="$1"
  echo "$ip" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' >/dev/null 2>&1 || return 1
  OIFS=$IFS; IFS=.; set -- $ip; IFS=$OIFS
  for o in "$@"; do [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1; done
  return 0
}

[ -n "${REPO_URL-}" ] || { err "Repo URL is required"; [ "$NON_INTERACTIVE" = "1" ] && exit $E_INPUT; }
echo "$REPO_URL" | grep -Ei '^https?://.+' >/dev/null 2>&1 || { err "Repo must be HTTPS"; exit $E_INPUT; }
[ -n "${SSH_USER-}" ] || { err "SSH user is required"; exit $E_INPUT; }
[ -n "${SSH_HOST-}" ] || { err "SSH host/IP is required"; exit $E_INPUT; }
validate_ip "$SSH_HOST" || info "Note: '$SSH_HOST' is not a plain IPv4 (assuming DNS ok)."
[ -n "${SSH_KEY-}" ] || { err "SSH key path is required"; exit $E_INPUT; }
[ -f "$SSH_KEY" ] || { err "SSH key '$SSH_KEY' not found"; exit $E_INPUT; }
[ -n "${APP_PORT-}" ] || { err "App port is required"; exit $E_INPUT; }
echo "$APP_PORT" | grep -E '^[0-9]+$' >/dev/null 2>&1 && [ "$APP_PORT" -ge 1 ] && [ "$APP_PORT" -le 65535 ] || { err "Invalid port: $APP_PORT"; exit $E_INPUT; }

# ---------- SSH helpers (no bash arrays for portability) ----------
SSH_BASE="ssh -i \"$SSH_KEY\" -o BatchMode=yes -o StrictHostKeyChecking=accept-new ${SSH_USER}@${SSH_HOST}"
SCP_BASE="scp -i \"$SSH_KEY\" -o StrictHostKeyChecking=accept-new"

# ---------- Cleanup mode ----------
if [ "$CLEANUP_ONLY" = "1" ]; then
  info "Cleanup on ${SSH_USER}@${SSH_HOST} (app='$APP_NAME', dir='$REMOTE_DIR')..."
  eval "$SSH_BASE \"APP_NAME='$APP_NAME' REMOTE_DIR='$REMOTE_DIR' bash -se\"" <<'EOSSH' || { err "Cleanup failed"; exit $E_CLEANUP; }
set -Eeuo pipefail
SUDO="sudo"; [ "$(id -u)" -eq 0 ] && SUDO=""
if command -v docker >/dev/null 2>&1; then
  $SUDO docker rm -f "$APP_NAME" >/dev/null 2>&1 || true
  $SUDO docker images --format '{{.Repository}}:{{.Tag}}' | grep -E "^${APP_NAME}:latest$" >/dev/null 2>&1 && $SUDO docker rmi -f "$APP_NAME:latest" || true
fi
if command -v nginx >/dev/null 2>&1; then
  $SUDO rm -f "/etc/nginx/sites-enabled/${APP_NAME}.conf" || true
  $SUDO rm -f "/etc/nginx/sites-available/${APP_NAME}.conf" || true
  $SUDO nginx -t && $SUDO systemctl reload nginx || true
fi
$SUDO rm -rf "$REMOTE_DIR" || true
echo "Cleanup complete."
EOSSH
  exit 0
fi

# ---------- Stage 1: SSH connectivity ----------
info "Checking SSH connectivity to ${SSH_USER}@${SSH_HOST} ..."
if ! eval "$SSH_BASE true" ; then err "SSH connection failed"; exit $E_SSH; fi
info "SSH connectivity OK."

# ---------- Stage 2: Git clone / update (local) ----------
MASKED_REPO="$(echo "$REPO_URL" | sed 's#^\(https\?://\).*#\1<REDACTED>#')"
info "Preparing source from $MASKED_REPO (branch: $BRANCH) ..."
repo_base="${REPO_URL%/}"; repo_base="${repo_base%.git}"
LOCAL_DIR="$(basename "$repo_base")"

# Build auth URL only if PAT is not empty and not 'x'
AUTH_URL="$REPO_URL"
if [ -n "${PAT-}" ] && [ "$PAT" != "x" ]; then
  tmp="${REPO_URL#http://}"; tmp="${tmp#https://}"
  AUTH_URL="https://${PAT}@${tmp}"
fi

if [ ! -d "$LOCAL_DIR/.git" ]; then
  info "Cloning into $LOCAL_DIR ..."
  # Avoid echoing PAT; send output to log quietly
  git clone --branch "$BRANCH" --single-branch "$AUTH_URL" "$LOCAL_DIR" >/dev/null 2>&1 || { err "git clone failed"; exit $E_GIT; }
else
  info "Repository exists. Updating..."
  ( cd "$LOCAL_DIR" && git fetch --all --quiet && git checkout "$BRANCH" --quiet && git pull --ff-only --quiet ) || { err "git update failed"; exit $E_GIT; }
fi

cd "$LOCAL_DIR"
if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ]; then
  info "Found docker-compose file."
elif [ -f Dockerfile ]; then
  info "Found Dockerfile."
else
  err "Neither Dockerfile nor docker-compose.yml found."; exit $E_GIT
fi

# Ensure APP_NAME/REMOTE_DIR consistent if user didn't pass them before
APP_NAME="${APP_NAME:-$(basename "$PWD")}"
REMOTE_DIR="${REMOTE_DIR:-/opt/$APP_NAME}"

# ---------- Stage 3: Prepare remote environment ----------
info "Preparing remote packages (Docker, Compose, Nginx, rsync, curl)..."
eval "$SSH_BASE \"APP_NAME='$APP_NAME' APP_PORT='$APP_PORT' bash -se\"" <<'EOSSH' || { err "Remote prepare failed"; exit $E_INSTALL; }
set -Eeuo pipefail
SUDO="sudo"; [ "$(id -u)" -eq 0 ] && SUDO=""
if command -v apt-get >/dev/null 2>&1; then
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl gnupg lsb-release rsync git nginx
  command -v docker >/dev/null 2>&1 || $SUDO apt-get install -y docker.io
  if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
    $SUDO apt-get install -y docker-compose-plugin || true
    command -v docker-compose >/dev/null 2>&1 || true
  fi
elif command -v dnf >/dev/null 2>&1; then
  $SUDO dnf -y install rsync git nginx curl
  command -v docker >/dev/null 2>&1 || $SUDO dnf -y install docker
  $SUDO systemctl enable --now docker || true
  command -v docker-compose >/dev/null 2>&1 || $SUDO dnf -y install docker-compose || true
elif command -v yum >/dev/null 2>&1; then
  $SUDO yum -y install rsync git nginx curl
  command -v docker >/dev/null 2>&1 || $SUDO yum -y install docker
  $SUDO systemctl enable --now docker || true
  command -v docker-compose >/dev/null 2>&1 || $SUDO yum -y install docker-compose || true
else
  echo "Unsupported distro (need apt/dnf/yum)"; exit 1
fi

# Add current user to docker group if not member (optional; requires re-login to take effect)
if command -v docker >/dev/null 2>&1; then
  if ! id -nG "$USER" | grep -qw docker; then
    $SUDO usermod -aG docker "$USER" || true
  fi
fi

$SUDO systemctl enable --now docker || true
$SUDO systemctl enable --now nginx || true

echo "Versions:"
docker --version || true
(docker compose version || true) >/dev/null 2>&1 && docker compose version || true
command -v docker-compose >/dev/null 2>&1 && docker-compose --version || true
nginx -v || true
EOSSH

# ---------- Stage 4: Prepare target dir & sync project ----------
info "Creating remote dir and syncing to ${SSH_HOST}:${REMOTE_DIR} ..."
eval "$SSH_BASE \"bash -se\"" <<EOSSH
set -Eeuo pipefail
SUDO="sudo"; [ "\$(id -u)" -eq 0 ] && SUDO=""
\$SUDO mkdir -p "$REMOTE_DIR"
\$SUDO chown -R "$SSH_USER":"$SSH_USER" "$REMOTE_DIR"
EOSSH

# rsync (delete removed files for idempotency)
RSYNC_SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new"
rsync -az --delete -e "$RSYNC_SSH" ./ "${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}/"

# ---------- Stage 5: Build & Run containers ----------
info "Deploying on remote (Compose or Dockerfile path)..."
HAS_COMPOSE_FILE="0"; [ -f docker-compose.yml ] || [ -f docker-compose.yaml ] && HAS_COMPOSE_FILE="1"

eval "$SSH_BASE \"APP_NAME='$APP_NAME' APP_PORT='$APP_PORT' REMOTE_DIR='$REMOTE_DIR' HAS_COMPOSE_FILE='$HAS_COMPOSE_FILE' bash -se\"" <<'EOSSH' || { err "Remote deploy failed"; exit $E_DEPLOY; }
set -Eeuo pipefail
SUDO="sudo"; [ "$(id -u)" -eq 0 ] && SUDO=""
cd "$REMOTE_DIR"

compose_cmd=""
if docker compose version >/dev/null 2>&1; then
  compose_cmd="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  compose_cmd="docker-compose"
fi

if [ "$HAS_COMPOSE_FILE" = "1" ] && [ -n "$compose_cmd" ]; then
  $SUDO $compose_cmd down --remove-orphans || true
  $SUDO $compose_cmd pull || true
  $SUDO $compose_cmd build || true
  $SUDO $compose_cmd up -d
else
  if [ -f Dockerfile ]; then
    $SUDO docker rm -f "$APP_NAME" >/dev/null 2>&1 || true
    $SUDO docker build -t "$APP_NAME:latest" .
    # Bind to localhost for security; Nginx will expose 80 publicly
    $SUDO docker run -d --name "$APP_NAME" -p 127.0.0.1:"$APP_PORT":"$APP_PORT" "$APP_NAME:latest"
  else
    echo "No compose or Dockerfile found on remote."; exit 1
  fi
fi

$SUDO docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
EOSSH

# ---------- Stage 6: Nginx reverse proxy ----------
info "Configuring Nginx (80 → 127.0.0.1:${APP_PORT}) ..."
eval "$SSH_BASE \"APP_NAME='$APP_NAME' APP_PORT='$APP_PORT' bash -se\"" <<'EOSSH' || { err "Nginx config failed"; exit $E_NGINX; }
set -Eeuo pipefail
SUDO="sudo"; [ "$(id -u)" -eq 0 ] && SUDO=""
SITE_AVAIL="/etc/nginx/sites-available/${APP_NAME}.conf"
SITE_EN="/etc/nginx/sites-enabled/${APP_NAME}.conf"

TMP="$(mktemp)"
cat >"$TMP" <<CFG
server {
    listen 80;
    server_name _;
    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
    # TLS ready: add Certbot later for HTTPS (listen 443 ssl; ...)
}
CFG

$SUDO mv "$TMP" "$SITE_AVAIL"
$SUDO ln -sf "$SITE_AVAIL" "$SITE_EN"
$SUDO nginx -t
$SUDO systemctl reload nginx
EOSSH

# ---------- Stage 7: Validation ----------
info "Validating service (remote curl + public curl)..."
eval "$SSH_BASE \"APP_PORT='$APP_PORT' bash -se\"" <<'EOSSH' || { err "Remote validation failed"; exit $E_VALIDATE; }
set -Eeuo pipefail
curl -fsS --max-time 10 "http://127.0.0.1:${APP_PORT}" >/dev/null || echo "WARN: direct app port check failed (path/healthcheck may differ)"
curl -fsS --max-time 10 "http://localhost" >/dev/null || { echo "Nginx frontend check failed"; exit 1; }
echo "Remote HTTP checks OK."
EOSSH

if curl -fsS --max-time 10 "http://${SSH_HOST}/" >/dev/null 2>&1; then
  info "Public endpoint reachable via Nginx ✅"
else
  warn "Public endpoint check failed from here. Firewall/DNS may block HTTP."
fi

info "Deployment complete. Visit: http://${SSH_HOST}/"
