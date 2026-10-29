#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

DRY_RUN=0
MODE=check
TARGET_OVERRIDE=""
USE_CROSS=0
for arg in "$@"; do
  case "$arg" in
    --help | -h)
      repro_usage "$0" " [--target=<triple>] [--cross]" "the stripped rageterm release binary"
      exit 0
      ;;
    --dry-run) DRY_RUN=1 ;;
    --double-build) MODE=double ;;
    --update-expected) MODE=update ;;
    --target=*) TARGET_OVERRIDE="${arg#--target=}" ;;
    --cross) USE_CROSS=1 ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXPECTED_FILE="$REPO_ROOT/scripts/repro/EXPECTED_HASHES.txt"
if [[ -n "$TARGET_OVERRIDE" ]]; then
  TARGET_TRIPLE="$TARGET_OVERRIDE"
else
  TARGET_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2}' || true)"
  if [[ -z "${TARGET_TRIPLE:-}" ]]; then
    echo "error: could not determine the host triple ('rustc -vV' gave no host: line)" >&2
    echo "       Is rustc on PATH? Enter the devshell that ships it, or pass --target=<triple>:" >&2
    echo "           nix develop <path-to-nixos-config>#ragewarden" >&2
    exit 2
  fi
fi
BINARY_NAME="rageterm"
if [[ "$TARGET_TRIPLE" == *windows* ]]; then
  BINARY_NAME="rageterm.exe"
fi

echo "rageterm reproducible-build verifier"
echo "  repo root:    $REPO_ROOT"
echo "  host triple:  $TARGET_TRIPLE"
echo "  expected:     $EXPECTED_FILE"

if ((DRY_RUN)); then
  echo "dry-run: skipping cargo build + b3sum"
  exit 0
fi

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found in PATH (cargo install b3sum)" >&2
  exit 2
fi

build_tool=cargo
((USE_CROSS)) && build_tool=cross

build_rageterm() {
  local root="$1"
  (
    cd "$root"
    RUSTFLAGS="$(repro_rustflags "$root")" CARGO_TARGET_DIR="$root/target" \
      "$build_tool" build --locked --release -p rageterm --target "$TARGET_TRIPLE" \
      --config 'profile.release.lto="fat"' \
      --config 'profile.release.strip="symbols"'
  ) >&2
  b3sum --no-names "$root/target/$TARGET_TRIPLE/release/$BINARY_NAME"
}

repro_verify "rageterm $TARGET_TRIPLE" build_rageterm "$MODE"
