#!/usr/bin/env bash
#
# Softnix Log Agent — one-line remote installer (Linux)
#
#   curl -fsSL https://raw.githubusercontent.com/SoftnixTech/softnix-log-agent/main/packaging/install.sh | sudo bash
#
# Downloads the latest GitHub release for this host's architecture and hands
# off to install-linux.sh, which is bundled INSIDE that release's tarball (not
# fetched separately) — so the installer a given release runs is always the
# one built and tested against that exact release, never a newer or older
# copy from `main`. See install-linux.sh for what actually gets installed.
#
set -euo pipefail

REPO="SoftnixTech/softnix-log-agent"

if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; GRN=""; BLD=""; RST=""
fi
info() { echo "${GRN}[ok]${RST}    $*"; }
step() { echo "${BLD}==>${RST} $*"; }
fail() { echo "${RED}[error]${RST} $*" >&2; exit 1; }

step "Checking environment"
[ "$(id -u)" -eq 0 ] || fail "must run as root: curl -fsSL <url> | sudo bash"
[ "$(uname -s)" = "Linux" ] || fail "this installer is for Linux; see docs/INSTALL-WINDOWS.md for Windows"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar  >/dev/null 2>&1 || fail "tar is required"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ASSET_ARCH="x86_64" ;;
  *) fail "no prebuilt release for architecture ${ARCH} yet — build from source instead: https://github.com/${REPO}#quick-start-development" ;;
esac
info "architecture: ${ARCH}"

step "Fetching latest release"
API_RESPONSE="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")" \
  || fail "could not reach the GitHub releases API"
URL="$(printf '%s' "$API_RESPONSE" \
  | grep -oE '"browser_download_url": *"[^"]*linux-'"${ASSET_ARCH}"'\.tar\.gz"' \
  | grep -oE 'https://[^"]*')"
[ -n "$URL" ] || fail "no linux-${ASSET_ARCH} release asset found — check https://github.com/${REPO}/releases"
info "found: ${URL}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

step "Downloading"
curl -fsSL "$URL" -o "${WORKDIR}/release.tar.gz" || fail "download failed"
tar xzf "${WORKDIR}/release.tar.gz" -C "$WORKDIR"

EXTRACTED="$(find "$WORKDIR" -mindepth 1 -maxdepth 1 -type d -name 'softnix-log-agent-*')"
[ -n "$EXTRACTED" ] || fail "unexpected archive layout — the release asset may have changed shape"
[ -f "${EXTRACTED}/install-linux.sh" ] || fail "install-linux.sh missing from the release archive"
[ -f "${EXTRACTED}/softnix-log-agent" ] || fail "softnix-log-agent binary missing from the release archive"

step "Handing off to install-linux.sh"
exec bash "${EXTRACTED}/install-linux.sh" --binary "${EXTRACTED}/softnix-log-agent" --yes "$@"
