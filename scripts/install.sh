#!/usr/bin/env bash
# Norinth one-command installer.
#
#   curl -fsSL https://github.com/revenant-research/norinth/releases/latest/download/install.sh | bash
#
# What it does, in order:
#   1. Checks for Docker (offers to install it on Ubuntu/Debian), curl, openssl.
#   2. Creates ./norinth (or $NORINTH_DIR) and fetches docker-compose.yml.
#   3. Generates every secret into .env: PostgreSQL password, NORINTH_SECRET_KEY,
#      a random administrator password. The platform therefore never boots with
#      development defaults.
#   4. Pulls the image from GHCR and, if cosign is installed, verifies its
#      keyless signature before running it (or builds from source with --source).
#   5. Starts PostgreSQL and Norinth, waits for /health, prints the URL and the
#      administrator login. The first visit opens the setup wizard.
#
# Flags:  --dir PATH  --port N  --version TAG  --resolve-only  --source  --no-pull  --no-verify  --upgrade  --uninstall  --yes
# Re-running is safe: an existing .env is never overwritten.
#
# Uninstall deletes the database volume. --yes does NOT authorize that deletion;
# a non-interactive uninstall additionally requires NORINTH_DELETE_DATA=1.
set -euo pipefail

REPO_RAW="${NORINTH_REPO_RAW:-}"
IMAGE="${NORINTH_IMAGE:-}"
VERSION="${NORINTH_VERSION:-latest}"
RELEASE_MODE=""
RELEASE_SHA=""
RELEASE_CHANNEL=""
RELEASE_DIGEST=""
MANIFEST_FILE=""
COMPOSE_SHA=""
BACKUP_SHA=""
RESTORE_SHA=""
# Keyless-signing identity for verification: the release workflow in this repo.
COSIGN_IDENTITY_RE="${NORINTH_COSIGN_IDENTITY_RE:-^https://github.com/revenant-research/norinth/}"
COSIGN_ISSUER="${NORINTH_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
DIR="${NORINTH_DIR:-$PWD/norinth}"
PORT="${NORINTH_PORT:-8001}"
PORT_EXPLICIT=0
MODE="install"
FROM_SOURCE=0
NO_PULL=0
NO_VERIFY=0
ASSUME_YES=0

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="$2"; shift 2 ;;
    --port) PORT="$2"; PORT_EXPLICIT=1; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --resolve-only) MODE="resolve"; shift ;;
    --source) FROM_SOURCE=1; shift ;;
    --no-pull) NO_PULL=1; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    --upgrade) MODE="upgrade"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

# an existing install keeps the port it was installed on. without this an
# upgrade of anything not on the default port polls 8001, times out, and reports
# a failure for an upgrade that worked
if [ "$PORT_EXPLICIT" = 0 ] && [ -f "$DIR/.env" ]; then
  existing_port=$(sed -n 's/^NORINTH_PORT=//p' "$DIR/.env" | head -1)
  [ -n "$existing_port" ] && PORT="$existing_port"
fi

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required. $2"; }

resolve_release() {
  [ "$FROM_SOURCE" = 1 ] && { RELEASE_MODE="source"; IMAGE="norinth-platform:source"; return; }
  if [ -n "${NORINTH_IMAGE:-}" ] || [ -n "${NORINTH_REPO_RAW:-}" ]; then
    [ -n "${NORINTH_IMAGE:-}" ] && [ -n "${NORINTH_REPO_RAW:-}" ] ||
      die "Set NORINTH_IMAGE and NORINTH_REPO_RAW together for a custom install. A single override could mix releases."
    RELEASE_MODE="custom"
    return
  fi
  need python3 "Python 3 is needed to validate the release manifest."
  local manifest_url fields_file
  if [ -n "${NORINTH_RELEASE_MANIFEST_URL:-}" ]; then
    manifest_url="$NORINTH_RELEASE_MANIFEST_URL"
  elif [ "$VERSION" = latest ]; then
    manifest_url="https://github.com/revenant-research/norinth/releases/latest/download/release-manifest.json"
  else
    [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || die "Invalid release version: $VERSION"
    manifest_url="https://github.com/revenant-research/norinth/releases/download/$VERSION/release-manifest.json"
  fi
  MANIFEST_FILE=$(mktemp)
  trap 'rm -f "${MANIFEST_FILE:-}"' EXIT
  fields_file=$(mktemp)
  if ! curl -fsSL "$manifest_url" -o "$MANIFEST_FILE"; then
    rm -f "$MANIFEST_FILE" "$fields_file"
    die "No release manifest at $manifest_url. Use a release that publishes one, or set both custom overrides for an older install."
  fi
  if ! python3 - "$MANIFEST_FILE" "$VERSION" > "$fields_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    m = json.load(handle)
requested = sys.argv[2]
if m.get("schema") != 1 or m.get("channel") != "stable":
    raise SystemExit("Unsupported release manifest schema or channel")
version, sha, digest = m.get("version"), m.get("source_sha"), m.get("image_digest")
if not isinstance(version, str) or not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
    raise SystemExit("Invalid release version")
if requested != "latest" and version != requested:
    raise SystemExit("Release manifest version does not match the requested tag")
if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
    raise SystemExit("Invalid source SHA")
if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("Invalid image digest")
image = f"ghcr.io/revenant-research/norinth@{digest}"
if m.get("image") != image:
    raise SystemExit("Image does not match the digest")
files = m.get("files")
expected = ("docker-compose.yml", "scripts/backup.sh", "scripts/restore.sh")
if not isinstance(files, dict) or set(files) != set(expected):
    raise SystemExit("Unexpected support file list")
if any(not isinstance(files[name], str) or not re.fullmatch(r"[0-9a-f]{64}", files[name]) for name in expected):
    raise SystemExit("Invalid support file checksum")
for value in (version, sha, digest, *[files[name] for name in expected]):
    print(value)
PY
  then
    rm -f "$MANIFEST_FILE" "$fields_file"
    die "Release manifest is invalid. Refusing to mix an image with unverified support files."
  fi
  release_fields=()
  while IFS= read -r field; do release_fields+=("$field"); done < "$fields_file"
  rm -f "$fields_file"
  VERSION="${release_fields[0]}"
  RELEASE_SHA="${release_fields[1]}"
  RELEASE_DIGEST="${release_fields[2]}"
  COMPOSE_SHA="${release_fields[3]}"
  BACKUP_SHA="${release_fields[4]}"
  RESTORE_SHA="${release_fields[5]}"
  RELEASE_CHANNEL="stable"
  RELEASE_MODE="manifest"
  REPO_RAW="https://raw.githubusercontent.com/revenant-research/norinth/$RELEASE_SHA"
  IMAGE="ghcr.io/revenant-research/norinth@$RELEASE_DIGEST"
  info "Resolved $VERSION ($RELEASE_CHANNEL) at source $RELEASE_SHA and image $RELEASE_DIGEST."
}

# set to "plugin" (docker compose) or "standalone" (docker-compose) by ensure_docker
COMPOSE_KIND=""

detect_compose() {
  command -v docker >/dev/null 2>&1 || return 1
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_KIND="plugin"
    return 0
  fi
  # older installs, and some desktop setups, only have the standalone binary
  if command -v docker-compose >/dev/null 2>&1 && docker-compose version >/dev/null 2>&1; then
    COMPOSE_KIND="standalone"
    return 0
  fi
  return 1
}

as_root() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# Installs Docker Engine from Docker's own apt repository. apt verifies every
# package against Docker's GPG key, and nothing downloaded is ever executed.
install_docker_apt() {
  local repo_os codename
  # shellcheck disable=SC1091
  repo_os=$(. /etc/os-release; case " ${ID_LIKE:-} ${ID:-} " in (*ubuntu*) echo ubuntu ;; (*debian*) echo debian ;; esac)
  # shellcheck disable=SC1091
  codename=$(. /etc/os-release; echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")
  { [ -n "$repo_os" ] && [ -n "$codename" ]; } || die "Could not identify this distribution. Install Docker from https://docs.docker.com/get-docker/ and re-run."
  as_root apt-get update
  as_root apt-get install -y ca-certificates curl
  as_root install -m 0755 -d /etc/apt/keyrings
  as_root curl -fsSL "https://download.docker.com/linux/${repo_os}/gpg" -o /etc/apt/keyrings/docker.asc
  as_root chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$repo_os" "$codename" | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
  as_root apt-get update
  as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

ensure_docker() {
  if detect_compose; then
    docker info >/dev/null 2>&1 || die "Docker is installed but the daemon is not running (or you lack permission). Start Docker and re-run."
    return
  fi
  if [ -f /etc/os-release ] && grep -qiE 'ubuntu|debian' /etc/os-release; then
    say "Docker is not installed."
    if [ "$ASSUME_YES" = 1 ] || { [ -t 0 ] && read -r -p "  Install Docker Engine from Docker's official apt repository? [y/N] " a && [ "${a:-n}" = y ]; }; then
      [ "$(id -u)" = 0 ] || need sudo "Docker installation needs root. Install sudo or re-run as root."
      install_docker_apt
      detect_compose || die "Docker installation failed."
      return
    fi
  fi
  die "Docker with Compose is required (either 'docker compose' or 'docker-compose'). Install it from https://docs.docker.com/get-docker/ and re-run."
}

compose() {
  if [ "$COMPOSE_KIND" = "standalone" ]; then
    (cd "$DIR" && docker-compose "$@")
  else
    (cd "$DIR" && docker compose "$@")
  fi
}

random_secret() { openssl rand -base64 32 | tr -d '\n=+/' | cut -c1-40; }

update_image_env() {
  local env_tmp
  env_tmp=$(mktemp "$DIR/.env.XXXXXX")
  chmod 600 "$env_tmp"
  if ! awk -v image="$IMAGE" '
    /^NORINTH_IMAGE=/ { print "NORINTH_IMAGE=" image; found=1; next }
    { print }
    END { if (!found) exit 1 }
  ' "$DIR/.env" > "$env_tmp"; then
    rm -f "$env_tmp"
    die "The existing .env has no NORINTH_IMAGE entry. Refusing an ambiguous upgrade."
  fi
  mv "$env_tmp" "$DIR/.env"
}

write_release_metadata() {
  [ "$RELEASE_MODE" = manifest ] || return 0
  cp "$MANIFEST_FILE" "$DIR/installed-release.json"
  chmod 644 "$DIR/installed-release.json"
  info "Installed: $VERSION ($RELEASE_CHANNEL), source $RELEASE_SHA, image $RELEASE_DIGEST"
  info "Release record: $DIR/installed-release.json"
}

write_env() {
  if [ -f "$DIR/.env" ]; then
    info "Keeping existing $DIR/.env secrets (never regenerated)."
    [ "$FROM_SOURCE" = 1 ] || update_image_env
    return
  fi
  local pg_pw admin_pw secret_key
  pg_pw="$(random_secret)"; admin_pw="$(random_secret | cut -c1-20)"; secret_key="$(openssl rand -base64 32 | tr -d '\n')"
  umask 077
  cat > "$DIR/.env" <<ENV
# Generated by scripts/install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Keep this file private.
NORINTH_IMAGE=${IMAGE}
NORINTH_PORT=${PORT}
POSTGRES_PASSWORD=${pg_pw}
NORINTH_SECRET_KEY=${secret_key}
NORINTH_SUPER_ADMIN_EMAIL=admin@norinth.local
NORINTH_SUPER_ADMIN_PASSWORD=${admin_pw}
# Set to your public URL (https://norinth.example.com) when behind TLS/ingress,
# then set NORINTH_COOKIE_SECURE=1 and NORINTH_TRUST_PROXY=1.
NORINTH_PUBLIC_BASE_URL=http://localhost:${PORT}
NORINTH_COOKIE_SECURE=0
NORINTH_TRUST_PROXY=0
ENV
  info "Wrote $DIR/.env with generated secrets."
}

fetch_compose() {
  if [ "$FROM_SOURCE" = 1 ]; then
    need git "Install git to build from source."
    if [ -f "$DIR/apps/platform/Dockerfile" ]; then
      info "Using the existing source checkout at $DIR."
    else
      git clone --depth 1 https://github.com/revenant-research/norinth "$DIR"
    fi
  elif [ "$RELEASE_MODE" = manifest ]; then
    local staging name expected actual
    mkdir -p "$DIR/scripts"
    staging=$(mktemp -d "$DIR/.release-files.XXXXXX")
    for name in docker-compose.yml scripts/backup.sh scripts/restore.sh; do
      case "$name" in
        docker-compose.yml) expected="$COMPOSE_SHA" ;;
        scripts/backup.sh) expected="$BACKUP_SHA" ;;
        scripts/restore.sh) expected="$RESTORE_SHA" ;;
      esac
      mkdir -p "$staging/$(dirname "$name")"
      if ! curl -fsSL "$REPO_RAW/$name" -o "$staging/$name"; then
        rm -rf "$staging"
        die "Could not fetch $name from release source $RELEASE_SHA."
      fi
      actual=$(openssl dgst -sha256 "$staging/$name" | awk '{print $NF}')
      if [ "$actual" != "$expected" ]; then
        rm -rf "$staging"
        die "$name does not match the published release checksum. Existing files were kept."
      fi
    done
    mv "$staging/docker-compose.yml" "$DIR/docker-compose.yml"
    for name in backup.sh restore.sh; do
      mv "$staging/scripts/$name" "$DIR/scripts/$name"
      chmod +x "$DIR/scripts/$name"
    done
    rm -rf "$staging"
  else
    mkdir -p "$DIR"
    curl -fsSL "$REPO_RAW/docker-compose.yml" -o "$DIR/docker-compose.yml"
    mkdir -p "$DIR/scripts"
    for f in backup.sh restore.sh; do curl -fsSL "$REPO_RAW/scripts/$f" -o "$DIR/scripts/$f" && chmod +x "$DIR/scripts/$f"; done
  fi
}

wait_healthy() {
  local _attempt
  for _attempt in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  compose logs --tail 50 norinth || true
  die "Norinth did not become healthy within two minutes. Logs above."
}

verify_image() {
  # Building from source produces no signed image to verify.
  [ "$FROM_SOURCE" = 1 ] && return 0
  if [ "$NO_VERIFY" = 1 ]; then
    info "Signature verification skipped (--no-verify)."
    return 0
  fi
  if command -v cosign >/dev/null 2>&1; then
    say "Verifying image signature with cosign"
    if cosign verify \
        --certificate-identity-regexp "$COSIGN_IDENTITY_RE" \
        --certificate-oidc-issuer "$COSIGN_ISSUER" \
        "$IMAGE" >/dev/null 2>&1; then
      info "Signature verified (keyless, GitHub Actions OIDC)."
    else
      die "cosign could not verify $IMAGE. Refusing to run an unverified image. Pin a trusted digest via NORINTH_IMAGE, or pass --no-verify to skip (not recommended)."
    fi
  else
    info "cosign not installed; skipping signature verification of $IMAGE."
    info "Install cosign (https://docs.sigstore.dev) to verify, or use --source to build locally."
  fi
}

case "$MODE" in
  resolve)
    need curl "Install curl and re-run."
    resolve_release
    [ "$RELEASE_MODE" = manifest ] || die "A source or custom install has no stable release to resolve."
    exit 0 ;;
  uninstall)
    [ -d "$DIR" ] || die "Nothing to uninstall at $DIR."
    say "This stops Norinth and DELETES its database volume at $DIR."
    # --yes deliberately does NOT authorize data deletion; non-interactively,
    # deleting the database requires the explicit NORINTH_DELETE_DATA=1, so a
    # stray --yes in a script can never destroy a database
    confirmed=0
    if [ -t 0 ]; then
      read -r -p "  Type 'delete' to confirm: " a && [ "$a" = delete ] && confirmed=1
    elif [ "${NORINTH_DELETE_DATA:-0}" = 1 ]; then
      confirmed=1
    else
      die "Refusing to delete the database non-interactively. Re-run with NORINTH_DELETE_DATA=1 to confirm."
    fi
    if [ "$confirmed" = 1 ]; then
      compose down -v
      info "Containers and data removed. $DIR/.env left in place; delete it yourself."
    else
      info "Aborted."
    fi
    exit 0 ;;
  upgrade)
    [ -f "$DIR/.env" ] || die "No install found at $DIR. Run without --upgrade first."
    need curl "Install curl and re-run."
    need openssl "Install openssl and re-run."
    resolve_release
    ensure_docker
    say "Upgrading Norinth at $DIR"
    fetch_compose
    [ "$FROM_SOURCE" = 1 ] || update_image_env
    if [ "$FROM_SOURCE" = 1 ]; then compose build; else compose pull; fi
    verify_image
    compose up -d
    wait_healthy
    write_release_metadata
    say "Upgraded. Migrations ran on boot; check Console → Overview → Schema."
    exit 0 ;;
esac

say "Installing Norinth into $DIR"
need curl "Install curl and re-run."
need openssl "Install openssl and re-run."
resolve_release
ensure_docker
fetch_compose
write_env
say "Starting PostgreSQL and Norinth"
if [ "$FROM_SOURCE" = 1 ]; then compose build; elif [ "$NO_PULL" = 0 ]; then compose pull; fi
verify_image
compose up -d
wait_healthy
write_release_metadata

env_value() { sed -n "s/^$1=//p" "$DIR/.env" | head -1; }
say "Norinth is running."
info "URL:            http://localhost:${PORT}"
info "Administrator:  $(env_value NORINTH_SUPER_ADMIN_EMAIL)"
info "Password:       $(env_value NORINTH_SUPER_ADMIN_PASSWORD)   (also in $DIR/.env)"
info ""
info "Next: open the URL. The setup wizard walks you through naming your organization,"
info "creating an ingestion key, and instrumenting your first application."
info ""
compose_cmd() { [ "$COMPOSE_KIND" = "standalone" ] && printf 'docker-compose' || printf 'docker compose'; }
info "Manage:  cd $DIR && $(compose_cmd) logs -f | $(compose_cmd) down | scripts/backup.sh"
info "Upgrade: curl -fsSL https://github.com/revenant-research/norinth/releases/latest/download/install.sh | bash -s -- --upgrade --dir $DIR"
