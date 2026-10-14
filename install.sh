#!/usr/bin/env bash
#
# rano installer
#
# One-liner install (with cache buster):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh?$(date +%s)" | bash
#
# Or without cache buster:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash
#
# Options:
#   --version vX.Y.Z   Install specific version (default: latest)
#   --dest DIR         Install to DIR (default: ~/.local/bin)
#   --system           Install to /usr/local/bin (requires sudo)
#   --easy-mode        Auto-update PATH in shell rc files
#   --verify           Run self-test after install
#   --from-source      Build from source instead of downloading binary
#   --quiet            Suppress non-error output
#   --no-gum           Disable gum formatting even if available
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

VERSION="${VERSION:-}"
SOURCE_REF="${SOURCE_REF:-}"
OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-rano}"
DEST_DEFAULT="$HOME/.local/bin"
DEST="${DEST:-$DEST_DEFAULT}"
EASY=0
QUIET=0
VERIFY=0
FROM_SOURCE=0
CHECKSUM="${CHECKSUM:-}"
CHECKSUM_URL="${CHECKSUM_URL:-}"
ARTIFACT_URL="${ARTIFACT_URL:-}"
NO_GUM=0
USER_AGENT="OpenAI File Downloader, XaiImageApiFetch/1.0"

download() {
  curl -fsSL --user-agent "$USER_AGENT" --connect-timeout 10 --max-time 120 "$@"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  else
    err "No SHA256 tool found: install sha256sum or shasum; refusing unverified installation"
    return 1
  fi
}

require_value() {
  if [ -z "${2:-}" ] || [[ "$2" == --* ]]; then
    err "$1 requires a value"
    exit 2
  fi
}

# Detect gum for fancy output (https://github.com/charmbracelet/gum)
HAS_GUM=0
if command -v gum &> /dev/null && [ -t 1 ]; then
  HAS_GUM=1
fi

# Logging functions with optional gum formatting
log() { [ "$QUIET" -eq 1 ] && return 0; echo -e "$@"; }

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 39 "→ $*"
  else
    echo -e "\033[0;34m→\033[0m $*"
  fi
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 "✓ $*"
  else
    echo -e "\033[0;32m✓\033[0m $*"
  fi
}

warn() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 "⚠ $*"
  else
    echo -e "\033[1;33m⚠\033[0m $*"
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 "✗ $*" >&2
  else
    echo -e "\033[0;31m✗\033[0m $*" >&2
  fi
}

# Spinner wrapper for long operations
run_with_spinner() {
  local title="$1"
  shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    info "$title"
    "$@"
  fi
}

resolve_version() {
  if [ -n "$VERSION" ]; then return 0; fi
  if [ "$FROM_SOURCE" -eq 1 ] && [ -n "$SOURCE_REF" ]; then return 0; fi

  info "Resolving latest version..."
  local latest_url="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  local tag
  if ! tag=$(download -H "Accept: application/vnd.github.v3+json" --url "$latest_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
    tag=""
  fi

  if [ -n "$tag" ]; then
    VERSION="$tag"
    info "Resolved latest version: $VERSION"
  else
    # Try redirect-based resolution as fallback
    local redirect_url="https://github.com/${OWNER}/${REPO}/releases/latest"
    if tag=$(download -o /dev/null -w '%{url_effective}' --url "$redirect_url" | sed -E 's|.*/tag/||'); then
      # Validate: tag must be non-empty, start with 'v' + digit, and not contain URL chars
      if [ -n "$tag" ] && [[ "$tag" =~ ^v[0-9] ]] && [[ "$tag" != *"/"* ]]; then
        VERSION="$tag"
        info "Resolved latest version via redirect: $VERSION"
        return 0
      fi
    fi
    err "Could not resolve an existing release; choose --version vX.Y.Z or --from-source --ref REF"
    exit 1
  fi
}

maybe_add_path() {
  case ":$PATH:" in
    *:"$DEST":*) return 0;;
    *)
      if [ "$EASY" -eq 1 ]; then
        UPDATED=0
        for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
          if [ -e "$rc" ] && [ -w "$rc" ]; then
            if ! grep -F "$DEST" "$rc" >/dev/null 2>&1; then
              local quoted_dest
              printf -v quoted_dest '%q' "$DEST"
              printf "export PATH=%s:\"\$PATH\"\n" "$quoted_dest" >> "$rc"
            fi
            UPDATED=1
          fi
        done
        if [ "$UPDATED" -eq 1 ]; then
          warn "PATH updated in ~/.zshrc/.bashrc; restart shell to use rano"
        else
          warn "Add $DEST to PATH to use rano"
        fi
      else
        warn "Add $DEST to PATH to use rano"
      fi
    ;;
  esac
}

ensure_rust() {
  if [ "${RUSTUP_INIT_SKIP:-0}" != "0" ]; then
    info "Skipping rustup install (RUSTUP_INIT_SKIP set)"
    return 0
  fi
  if command -v cargo >/dev/null 2>&1; then return 0; fi
  if [ "$EASY" -ne 1 ]; then
    if [ -t 0 ]; then
      echo -n "Install Rust via rustup? (y/N): "
      read -r ans
      case "$ans" in y|Y) :;; *) warn "Skipping rustup install"; return 0;; esac
    fi
  fi
  info "Installing rustup (stable)"
  local rustup_script
  rustup_script=$(mktemp)
  download --url https://sh.rustup.rs -o "$rustup_script"
  sh "$rustup_script" -y --default-toolchain stable --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
  rustup component add rustfmt clippy || true
}

usage() {
  cat <<EOFU
Usage: install.sh [--version vX.Y.Z] [--dest DIR] [--system] [--easy-mode] [--verify] \\
                  [--from-source] [--ref REF] [--artifact-url URL] [--checksum HEX] \\
                  [--checksum-url URL] [--quiet] [--no-gum]

Options:
  --version vX.Y.Z   Install specific version (default: latest)
  --dest DIR         Install to DIR (default: ~/.local/bin)
  --system           Install to /usr/local/bin (requires sudo)
  --easy-mode        Auto-update PATH in shell rc files
  --verify           Run self-test after install
  --from-source      Build from source instead of downloading binary
  --ref REF          Exact source branch/tag/ref/SHA (requires --from-source; excludes --version)
  --artifact-url URL Install the selected version from a checksum-verified explicit archive URL
  --checksum HEX     Expected archive SHA256 (otherwise fetch its sidecar)
  --checksum-url URL Explicit checksum sidecar URL
  --quiet            Suppress non-error output
  --no-gum           Disable gum formatting even if available
EOFU
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) require_value "$1" "${2:-}"; VERSION="$2"; shift 2;;
    --ref) require_value "$1" "${2:-}"; SOURCE_REF="$2"; shift 2;;
    --dest) require_value "$1" "${2:-}"; DEST="$2"; shift 2;;
    --system) DEST="/usr/local/bin"; shift;;
    --easy-mode) EASY=1; shift;;
    --verify) VERIFY=1; shift;;
    --artifact-url) require_value "$1" "${2:-}"; ARTIFACT_URL="$2"; shift 2;;
    --checksum) require_value "$1" "${2:-}"; CHECKSUM="$2"; shift 2;;
    --checksum-url) require_value "$1" "${2:-}"; CHECKSUM_URL="$2"; shift 2;;
    --from-source) FROM_SOURCE=1; shift;;
    --quiet|-q) QUIET=1; shift;;
    --no-gum) NO_GUM=1; shift;;
    -h|--help) usage; exit 0;;
    *) err "Unknown option: $1"; exit 2;;
  esac
done

if ! [[ "$OWNER" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ && "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  err "Invalid OWNER/REPO: use GitHub account and repository names"; exit 2
fi
if [ -n "$SOURCE_REF" ] && { [ "$FROM_SOURCE" -ne 1 ] || [ -n "$VERSION" ]; }; then
  err "--ref requires --from-source and cannot combine with --version"; exit 2
fi
if [ "$FROM_SOURCE" -eq 1 ] && [ -n "$ARTIFACT_URL" ]; then
  err "--from-source cannot combine with --artifact-url"; exit 2
fi

# Show fancy header
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border normal \
      --border-foreground 39 \
      --padding "0 1" \
      --margin "1 0" \
      "$(gum style --foreground 42 --bold 'rano installer')" \
      "$(gum style --foreground 245 'Observes AI CLI network activity')"
  else
    echo ""
    echo -e "\033[1;32mrano installer\033[0m"
    echo -e "\033[0;90mObserves AI CLI network activity\033[0m"
    echo ""
  fi
fi

resolve_version

if [ -n "$VERSION" ]; then
  if ! [[ "$VERSION" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$ ]]; then
    err "Invalid version: expected a release version such as v0.2.0"; exit 2
  fi
  VERSION="v${VERSION#v}"
fi

mkdir -p "$DEST"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) warn "Unknown arch $ARCH, using as-is" ;;
esac

TARGET=""
case "${OS}-${ARCH}" in
  linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  linux-aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
  darwin-x86_64) TARGET="x86_64-apple-darwin" ;;
  darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
  *) :;;
esac

# Prefer prebuilt artifact when we know the target or the caller supplied a direct URL.
TAR=""
URL=""
if [ "$FROM_SOURCE" -eq 0 ]; then
  if [ -n "$ARTIFACT_URL" ]; then
    TAR="rano-artifact.tar"
    URL="$ARTIFACT_URL"
  elif [ -n "$TARGET" ]; then
    TAR="rano-${TARGET}.tar.xz"
    URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${TAR}"
  else
    err "No prebuilt artifact for ${OS}/${ARCH}; choose --from-source with an exact --version or --ref"; exit 1
  fi
fi

# Cross-platform locking using mkdir (atomic on all POSIX systems including macOS)
TMP=$(mktemp -d)
LOCK_DIR="${DEST}/.rano-install.lock"
LOCKED=0
cleanup() {
  if [[ "$LOCKED" -eq 1 && "$(cat "$LOCK_DIR/pid" 2>/dev/null || true)" == "$$" ]]; then
    mv "$LOCK_DIR" "$TMP/completed-install.lock"
  fi
  info "Installer files retained at $TMP"
}
trap cleanup EXIT
if mkdir "$LOCK_DIR" 2>/dev/null; then
  LOCKED=1
  echo $$ > "$LOCK_DIR/pid"
else
  # Check if existing lock is stale (process no longer running)
  if [ -f "$LOCK_DIR/pid" ]; then
    OLD_PID=$(cat "$LOCK_DIR/pid" 2>/dev/null || echo "")
    if [[ "$OLD_PID" =~ ^[1-9][0-9]*$ ]] && ! kill -0 "$OLD_PID" 2>/dev/null; then
      mv "$LOCK_DIR" "$TMP/stale-install.lock"
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        LOCKED=1
        echo $$ > "$LOCK_DIR/pid"
      fi
    fi
  fi
  if [ "$LOCKED" -eq 0 ]; then
    err "Another installer is running (lock $LOCK_DIR)"
    exit 1
  fi
fi

if [ "$FROM_SOURCE" -eq 0 ]; then
  info "Downloading $URL"
  if ! download --url "$URL" -o "$TMP/$TAR"; then
    err "Artifact download failed for $VERSION; use explicit --from-source --version $VERSION to build that release"; exit 1
  fi
fi

if [ "$FROM_SOURCE" -eq 1 ]; then
  info "Building from source (requires git and rust toolchain)"
  ensure_rust
  command -v git >/dev/null || { err "Source install requires git"; exit 1; }
  command -v python3 >/dev/null || { err "Source install requires python3 to read Cargo artifact metadata"; exit 1; }
  if [ -n "$VERSION" ]; then
    SOURCE_REF="refs/tags/$VERSION"
  elif ! [[ "$SOURCE_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
    case "$SOURCE_REF" in refs/*) :;; *) SOURCE_REF="refs/heads/$SOURCE_REF";; esac
  fi
  if ! [[ "$SOURCE_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
    git check-ref-format "$SOURCE_REF" || { err "Invalid source ref: $SOURCE_REF"; exit 2; }
  fi
  git init --quiet "$TMP/src"
  git -C "$TMP/src" remote add origin "https://github.com/${OWNER}/${REPO}.git"
  git -c http.userAgent="$USER_AGENT" -C "$TMP/src" fetch --depth 1 origin "$SOURCE_REF"
  SOURCE_COMMIT=$(git -C "$TMP/src" rev-parse FETCH_HEAD)
  git -C "$TMP/src" checkout --quiet --detach "$SOURCE_COMMIT"
  info "Source ref $SOURCE_REF resolved to $SOURCE_COMMIT"
  (cd "$TMP/src" && CARGO_HTTP_USER_AGENT="$USER_AGENT" cargo build --locked --release --message-format=json-render-diagnostics) > "$TMP/build.jsonl"
  BIN=$(python3 - "$TMP/build.jsonl" <<'PY'
import json,sys
artifacts=[row['executable'] for row in map(json.loads,open(sys.argv[1])) if row.get('reason')=='compiler-artifact' and row.get('target',{}).get('name')=='rano' and 'bin' in row.get('target',{}).get('kind',[]) and row.get('executable')]
if len(artifacts)!=1:raise SystemExit('Expected exactly one rano executable in Cargo artifact metadata')
print(artifacts[0])
PY
  )
  [ -x "$BIN" ] || { err "Build failed"; exit 1; }
  VERSION_OUTPUT=$("$BIN" --version) || { err "Source binary --version failed"; exit 1; }
  if [ -n "$VERSION" ] && [ "$VERSION_OUTPUT" != "rano ${VERSION#v}" ]; then
    err "Source binary version '$VERSION_OUTPUT' does not match $VERSION"; exit 1
  fi
  BINARY_SHA256=$(sha256_file "$BIN")
  if [ "$VERIFY" -eq 1 ]; then "$BIN" --help >/dev/null || { err "Source self-test failed"; exit 1; }; fi
  if [ -e "$DEST/rano" ]; then cp -p "$DEST/rano" "$TMP/previous-rano"; fi
  install -m 0755 "$BIN" "$DEST/rano"
  ok "Installed to $DEST/rano (source $SOURCE_COMMIT; $VERSION_OUTPUT; sha256=$BINARY_SHA256)"
  maybe_add_path
  if [ "$VERIFY" -eq 1 ]; then
    INSTALLED_VERSION=$("$DEST/rano" --version) || { err "Installed source binary self-test failed"; exit 1; }
    [ "$INSTALLED_VERSION" = "$VERSION_OUTPUT" ] || { err "Installed source version changed"; exit 1; }
    ok "Self-test complete"
  fi
  ok "Done. Binary at: $DEST/rano"
  exit 0
fi

if [ -z "$CHECKSUM" ]; then
  [ -z "$CHECKSUM_URL" ] && CHECKSUM_URL="${URL}.sha256"
  info "Fetching checksum from ${CHECKSUM_URL}"
  CHECKSUM_FILE="$TMP/checksum.sha256"
  if ! download --url "$CHECKSUM_URL" -o "$CHECKSUM_FILE"; then
    err "Checksum required and could not be fetched"; exit 1;
  fi
  CHECKSUM=$(awk 'NF {count++; value=tolower($1)} END {if(count!=1) exit 1; print value}' "$CHECKSUM_FILE") || { err "Checksum sidecar must contain exactly one checksum"; exit 1; }
fi

if ! [[ "$CHECKSUM" =~ ^[[:xdigit:]]{64}$ ]]; then err "Malformed SHA256 checksum"; exit 1; fi
CHECKSUM=$(printf '%s' "$CHECKSUM" | tr '[:upper:]' '[:lower:]')
ACTUAL_CHECKSUM=$(sha256_file "$TMP/$TAR")
[ "$CHECKSUM" = "$ACTUAL_CHECKSUM" ] || { err "Checksum mismatch"; exit 1; }
ok "Checksum verified"

info "Extracting"
tar -tf "$TMP/$TAR" > "$TMP/archive-members.txt" || { err "Cannot read archive"; exit 1; }
while IFS= read -r member; do
  case "$member" in
    /*|..|../*|*/../*|*/..) err "Unsafe archive member path: $member"; exit 1;;
  esac
done < "$TMP/archive-members.txt"
tar -tvf "$TMP/$TAR" > "$TMP/archive-types.txt"
if awk 'substr($0,1,1)=="l" || substr($0,1,1)=="h" || / -> / || / link to / {found=1} END {exit !found}' "$TMP/archive-types.txt"; then
  err "Archive links are unsupported; refusing extraction"; exit 1
fi
mkdir "$TMP/unpack"
tar -xf "$TMP/$TAR" -C "$TMP/unpack"
BIN="$TMP/unpack/rano"
if [ ! -x "$BIN" ] && [ -n "$TARGET" ]; then
  BIN="$TMP/unpack/rano-${TARGET}/rano"
fi

[ -f "$BIN" ] && [ -x "$BIN" ] || { err "Binary not found in supported archive layout"; exit 1; }
VERSION_OUTPUT=$("$BIN" --version) || { err "Downloaded binary --version failed"; exit 1; }
[ "$VERSION_OUTPUT" = "rano ${VERSION#v}" ] || { err "Downloaded binary version '$VERSION_OUTPUT' does not match $VERSION"; exit 1; }
if [ "$VERIFY" -eq 1 ]; then "$BIN" --help >/dev/null || { err "Downloaded binary self-test failed"; exit 1; }; fi
BINARY_SHA256=$(sha256_file "$BIN")
if [ -e "$DEST/rano" ]; then cp -p "$DEST/rano" "$TMP/previous-rano"; fi
install -m 0755 "$BIN" "$DEST/rano"
ok "Installed to $DEST/rano ($VERSION_OUTPUT; archive sha256=$ACTUAL_CHECKSUM; binary sha256=$BINARY_SHA256)"
maybe_add_path

if [ "$VERIFY" -eq 1 ]; then
  INSTALLED_VERSION=$("$DEST/rano" --version) || { err "Installed binary self-test failed"; exit 1; }
  [ "$INSTALLED_VERSION" = "$VERSION_OUTPUT" ] || { err "Installed binary version changed"; exit 1; }
  ok "Self-test complete"
fi

ok "Done. Binary at: $DEST/rano"
if [ "$QUIET" -eq 0 ]; then
  echo ""
  info "Try it:"
  echo "  $DEST/rano --pattern claude --pattern codex --pattern gemini --stats-interval-ms 5000"
fi
