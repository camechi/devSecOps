#!/usr/bin/env bash
# DevSecOps Tool Installer by CAmechi
# Installs/updates: trivy, gitleaks, trufflehog, tfsec, checkov
# Features: OS/arch detection, idempotency, verification, error handling, getopts, arrays, functions
# Flags: -h (help), -d (dry-run), -u (update-only), -v (verbose)

set -euo pipefail

# -----------------------------
# Globals and configuration
# -----------------------------

DRY_RUN=false
UPDATE_ONLY=false
VERBOSE=false

PREFIX="$HOME/.local/bin"
[[ ":$PATH:" != *":$PREFIX:"* ]] && echo "Warning: Add $PREFIX to your PATH: export PATH=\"\$PATH:$PREFIX\""

declare -A REPOS=(
  [trivy]="aquasecurity/trivy"
  [gitleaks]="gitleaks/gitleaks"
  [trufflehog]="trufflesecurity/trufflehog"
  [tfsec]="aquasecurity/tfsec"
  [checkov]="bridgecrewio/checkov"
)

declare -A VERIFY_CMD=(
  [trivy]="trivy --version"
  [gitleaks]="gitleaks version"
  [trufflehog]="trufflehog --version"
  [tfsec]="tfsec --version"
  [checkov]="checkov --version"
)

declare -A VERSION_REGEX=(
  [trivy]="^Version: ([0-9][^ ]+)"
  [gitleaks]="^v?([0-9][^ ]+)"
  [trufflehog]="^v?([0-9][^ ]+)"
  [tfsec]="^v?([0-9][^ ]+)"
  [checkov]="^([0-9][^ ]+)"
)

# -----------------------------
# Logging
# -----------------------------

log() {
  local level="$1"; shift
  local msg="$*"
  case "$level" in
    INFO)  [[ "$VERBOSE" == true ]] && printf "[INFO] %s\n" "$msg" ;;
    WARN)  printf "[WARN] %s\n" "$msg" ;;
    ERROR) printf "[ERROR] %s\n" "$msg" ;;
    DEBUG) [[ "$VERBOSE" == true ]] && printf "[DEBUG] %s\n" "$msg" >&2 ;;
    *)     printf "[LOG] %s\n" "$msg" ;;
  esac
}

die() { log ERROR "$*"; exit 1; }

run() {
  local cmd="$*"
  if [[ "$DRY_RUN" == true ]]; then
    printf "[DRY-RUN] %s\n" "$cmd"
  else
    eval "$cmd"
  fi
}

# -----------------------------
# OS and architecture detection
# -----------------------------

OS=""
ARCH=""

detect_os_arch() {
  case "$(uname -s)" in
    Linux) OS="linux" ;;
    Darwin) OS="darwin" ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
  log INFO "Detected OS=$OS ARCH=$ARCH"
}

# -----------------------------
# Tool requirements
# -----------------------------

require_tools() {
  for t in curl jq; do
    command -v "$t" >/dev/null 2>&1 || die "$t is required but not installed."
  done
}

require_tar()  { command -v tar   >/dev/null 2>&1 || die "tar is required."; }
require_unzip(){ command -v unzip >/dev/null 2>&1 || die "unzip is required."; }

sha256_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    echo "shasum -a 256"
  else
    echo ""
  fi
}

# -----------------------------
# Networking helpers
# -----------------------------

download_asset() {
  local url="$1" dst="$2"
  log INFO "Downloading: $url"
  run curl --retry 3 --retry-delay 5 -fsSL "$url" -o "$dst"
}

verify_checksum() {
  local file="$1" url="$2"
  local sum_url="${url}.sha256"
  local sha_cmd
  sha_cmd="$(sha256_cmd)"
  [[ -z "$sha_cmd" ]] && log WARN "No sha256 tool available; skipping checksum." && return 0

  if curl --head --silent --fail "$sum_url" >/dev/null; then
    local expected actual
    expected="$(curl -fsSL "$sum_url" | awk '{print $1}' | head -n1)"
    actual="$(eval "$sha_cmd \"$file\" | awk '{print $1}'")"
    [[ -n "$expected" && -n "$actual" && "$expected" == "$actual" ]] || die "Checksum mismatch for $file"
    log INFO "Checksum verified for $file"
  else
    log DEBUG "No checksum found at $sum_url; skipping."
  fi
}

# -----------------------------
# GitHub release resolution
# -----------------------------

get_latest_tag() {
  local repo="$1"
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl -fsSL -H "Authorization: token $GITHUB_TOKEN" \
      "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name'
  else
    curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name'
  fi
}

resolve_asset() {
  local app="$1" repo="${REPOS[$app]}"
  local json
  json="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest")"

  local pattern type_hint
  case "$app" in
    trivy)
      [[ "$OS" == "linux" && "$ARCH" == "amd64" ]] && pattern="Linux-64bit.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "linux" && "$ARCH" == "arm64" ]] && pattern="Linux-ARM64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "amd64" ]] && pattern="macOS-64bit.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "arm64" ]] && pattern="macOS-ARM64.tar.gz" && type_hint="tar.gz"
      ;;
    gitleaks)
      [[ "$OS" == "linux" && "$ARCH" == "amd64" ]] && pattern="linux_x64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "linux" && "$ARCH" == "arm64" ]] && pattern="linux_arm64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "amd64" ]] && pattern="darwin_x64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "arm64" ]] && pattern="darwin_arm64.tar.gz" && type_hint="tar.gz"
      ;;
    trufflehog)
      [[ "$OS" == "linux" && "$ARCH" == "amd64" ]] && pattern="linux_amd64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "linux" && "$ARCH" == "arm64" ]] && pattern="linux_arm64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "amd64" ]] && pattern="darwin_amd64.tar.gz" && type_hint="tar.gz"
      [[ "$OS" == "darwin" && "$ARCH" == "arm64" ]] && pattern="darwin_arm64.tar.gz" && type_hint="tar.gz"
      ;;
    tfsec)
      if [[ "$OS" == "linux" && "$ARCH" == "amd64" ]]; then pattern="^tfsec-linux-amd64$"; type_hint="binary"; fi
      if [[ "$OS" == "linux" && "$ARCH" == "arm64" ]]; then pattern="^tfsec-linux-arm64$"; type_hint="binary"; fi
      if [[ "$OS" == "darwin" && "$ARCH" == "amd64" ]]; then pattern="^tfsec-darwin-amd64$"; type_hint="binary"; fi
      if [[ "$OS" == "darwin" && "$ARCH" == "arm64" ]]; then pattern="^tfsec-darwin-arm64$"; type_hint="binary"; fi
      ;;
    checkov)
      [[ "$OS" == "linux" && "$ARCH" == "amd64" ]] && pattern="linux-amd64.zip" && type_hint="zip"
      [[ "$OS" == "linux" && "$ARCH" == "arm64" ]] && pattern="linux-arm64.zip" && type_hint="zip"
      [[ "$OS" == "darwin" && "$ARCH" == "amd64" ]] && pattern="darwin-amd64.zip" && type_hint="zip"
      [[ "$OS" == "darwin" && "$ARCH" == "arm64" ]] && pattern="darwin-arm64.zip" && type_hint="zip"
      ;;
    *) die "Unknown app: $app" ;;
  esac

  local url
  url="$(echo "$json" | jq -r --arg pat "$pattern" '.assets[] | select(.name | test($pat)) | .browser_download_url' | head -n1)"
  [[ -z "$url" ]] && echo "" && echo "" && return 0
  log DEBUG "Resolved $app asset: $url ($type_hint)"
  echo "$url $type_hint"
}

# -----------------------------
# Idempotency and verification
# -----------------------------

is_installed() { command -v "$1" >/dev/null 2>&1; }

current_version() {
  local app="$1" cmd="${VERIFY_CMD[$app]}"
  if ! is_installed "$app"; then echo ""; return; fi
  local out
  out="$($cmd 2>/dev/null | head -n1 || true)"
  local regex="${VERSION_REGEX[$app]:-}"
  if [[ -n "$regex" && "$out" =~ $regex ]]; then
    echo "${BASH_REMATCH[1]}"; return
  fi
  echo "$out" | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1
}

# -----------------------------
# Installers
# -----------------------------

install_tarball() {
  local tarball="$1" app="$2"
  require_tar
  local tmpdir; tmpdir="$(mktemp -d)"
  run "tar -xzf '$tarball' -C '$tmpdir'"
  local binpath
  binpath="$(find "$tmpdir" -type f -name "$app" -perm -u+x | head -n1)"
  if [[ -z "$binpath" ]]; then
    binpath="$(find "$tmpdir" -type f -perm -u+x -printf '%f %p\n' 2>/dev/null | awk -v a="$app" '$1==a {print $2; exit}')"
  fi
  [[ -z "$binpath" ]] && die "Binary '$app' not found in tarball."
  run "install -m 0755 '$binpath' '$PREFIX/$app'"
}

install_zip() {
  local zipfile="$1" app="$2"
  require_unzip
  local tmpdir; tmpdir="$(mktemp -d)"
  run "unzip -q '$zipfile' -d '$tmpdir'"
  local binpath
  binpath="$(find "$tmpdir" -type f -name "$app" -perm -u+x | head -n1)"
  [[ -z "$binpath" ]] && die "Binary '$app' not found in zip."
  run "install -m 0755 '$binpath' '$PREFIX/$app'"
}

install_binary() {
  local url="$1" app="$2"
  local tmpfile; tmpfile="$(mktemp)"
  download_asset "$url" "$tmpfile"
  verify_checksum "$tmpfile" "$url"
  run "install -m 0755 '$tmpfile' '$PREFIX/$app'"
}

# -----------------------------
# Main install/update workflow
# -----------------------------

process_app() {
  local app="$1"
  [[ -z "$OS" || -z "$ARCH" ]] && die "OS/arch not detected. Call detect_os_arch first."
  local repo="${REPOS[$app]}"; [[ -z "$repo" ]] && die "Repository not configured for $app."

  local cur_ver latest_tag asset_url asset_type tmpfile
  cur_ver="$(current_version "$app")"
  latest_tag="$(get_latest_tag "$repo")"
  [[ -z "$latest_tag" ]] && die "Failed to fetch latest tag for $app."

  log INFO "$app current_version='${cur_ver:-none}' latest_tag='$latest_tag'"

  if [[ -n "$cur_ver" ]]; then
    if [[ "$cur_ver" == "${latest_tag#v}" || "$cur_ver" == "$latest_tag" ]]; then
      log INFO "$app is up-to-date ($cur_ver). Skipping."
      return 0
    fi
  else
    [[ "$UPDATE_ONLY" == true ]] && { log WARN "$app not installed; update-only set. Skipping."; return 0; }
  fi

  # Special handling for Checkov: try binary else pip
if [[ "$app" == "checkov" ]]; then
  read -r asset_url asset_type <<<"$(resolve_asset "$app")"
  if [[ -z "${asset_url:-}" || -z "${asset_type:-}" ]]; then
    log WARN "No binary asset found for Checkov; falling back to pipx."
    if [[ "$DRY_RUN" == true ]]; then
      printf "[DRY-RUN] pipx install checkov || pipx upgrade checkov\n"
    else
      if pipx list | grep -q checkov; then
        run "pipx upgrade checkov"
      else
        run "pipx install checkov"
      fi
    fi
    return 0
  fi
fi

  tmpfile="$(mktemp)"
  download_asset "$asset_url" "$tmpfile"
  verify_checksum "$tmpfile" "$asset_url"

  case "$asset_type" in
    tar.gz) install_tarball "$tmpfile" "$app" ;;
    zip)    install_zip "$tmpfile" "$app" ;;
    binary) install_binary "$asset_url" "$app" ;;
    *)      die "Unknown asset type '$asset_type' for $app." ;;
  esac

  if [[ "$DRY_RUN" == false ]]; then
    local post_ver; post_ver="$(current_version "$app")"
    [[ -z "$post_ver" ]] && die "Verification failed: '$app' did not report version after install."
    log WARN "$app installed/updated to version: $post_ver"
  fi
}

# -----------------------------
# CLI parsing
# -----------------------------

print_help() {
  cat <<EOF
Usage: $(basename "$0") [options] [apps...]

Installs/updates by default: trivy, gitleaks, trufflehog, tfsec, checkov

Options:
  -h   Show help and exit
  -d   Dry-run (print actions without executing)
  -u   Update only (do not install missing apps)
  -v   Verbose logging

Examples:
  $(basename "$0") -v
  $(basename "$0") -u trivy tfsec
  $(basename "$0") -d checkov
EOF
}

parse_args() {
  while getopts ":hduv" opt; do
    case "$opt" in
      h) print_help; exit 0 ;;
      d) DRY_RUN=true ;;
      u) UPDATE_ONLY=true ;;
      v) VERBOSE=true ;;
      \?) die "Invalid option: -$OPTARG (use -h for help)" ;;
    esac
  done
  shift $((OPTIND - 1))
  if [[ $# -gt 0 ]]; then
    APPS=("$@")
  else
    APPS=(trivy gitleaks trufflehog tfsec checkov)
  fi
}

# -----------------------------
# Pre-flight checks
# -----------------------------

ensure_prefix_writable() {
  if [[ "$DRY_RUN" == false ]]; then
    if [[ ! -d "$PREFIX" ]]; then
      run "mkdir -p '$PREFIX'"
    fi
    if [[ ! -w "$PREFIX" ]]; then
      die "Install prefix '$PREFIX' is not writable. Try running with sudo or set PREFIX to a writable path."
    fi
  fi
}

preflight() {
  detect_os_arch
  require_tools
  ensure_prefix_writable
}

# -----------------------------
# Entry point
# -----------------------------

main() {
  parse_args "$@"
  preflight

  local failures=()
  for app in "${APPS[@]}"; do
    log WARN "Processing: $app"
    if ! process_app "$app"; then
      log ERROR "Failed to process $app, continuing."
      failures+=("$app")
    fi
  done

  if [[ "${#failures[@]}" -gt 0 ]]; then
    log ERROR "Completed with failures: ${failures[*]}"
    exit 1
  fi

  log WARN "All done."
}

main "$@"