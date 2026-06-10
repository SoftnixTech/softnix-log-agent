#!/usr/bin/env bash
#
# Build the Windows MSI installer from Linux/macOS.
#
# Requirements:
#   - msitools  (brew install msitools | apt install msitools)  -> provides wixl
#   - a cross-compiled softnix-log-agent.exe, e.g.:
#       rustup target add x86_64-pc-windows-gnu
#       CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
#         cargo build --release --target x86_64-pc-windows-gnu
#
# Output: dist/softnix-log-agent-<version>-x64.msi
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXE="${1:-${REPO_DIR}/target/x86_64-pc-windows-gnu/release/softnix-log-agent.exe}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "${REPO_DIR}/Cargo.toml" | head -1)"
OUT_DIR="${REPO_DIR}/dist"
OUT="${OUT_DIR}/softnix-log-agent-${VERSION}-x64.msi"

command -v wixl >/dev/null 2>&1 || { echo "error: wixl not found (install msitools)"; exit 1; }
[ -f "$EXE" ] || { echo "error: Windows exe not found: $EXE"; exit 1; }

# Stage payload so the .wxs Source paths resolve.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "${STAGE}/packaging/windows"
cp "$EXE" "${STAGE}/softnix-log-agent.exe"
cp "${SCRIPT_DIR}/agent-default.yaml" "${STAGE}/packaging/windows/agent-default.yaml"

mkdir -p "$OUT_DIR"
wixl -D SourceDir="$STAGE" -o "$OUT" "${SCRIPT_DIR}/softnix-log-agent.wxs"

echo "built: $OUT"
ls -lh "$OUT"
