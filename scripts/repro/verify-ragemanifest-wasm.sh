#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

DRY_RUN=0
MODE=check
for arg in "$@"; do
  case "$arg" in
    --help | -h)
      repro_usage "$0" "" "ragemanifest/pkg/ragemanifest_bg.wasm"
      exit 0
      ;;
    --dry-run) DRY_RUN=1 ;;
    --double-build) MODE=double ;;
    --update-expected) MODE=update ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXPECTED_FILE="$REPO_ROOT/scripts/repro/EXPECTED_HASHES.txt"

echo "ragemanifest WASM reproducible-build verifier"
echo "  repo root: $REPO_ROOT"
echo "  expected:  $EXPECTED_FILE"

if ((DRY_RUN)); then
  echo "dry-run: skipping wasm-pack build + b3sum"
  exit 0
fi

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found in PATH (cargo install b3sum)" >&2
  exit 2
fi
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack not found in PATH" >&2
  echo "       install via https://rustwasm.github.io/wasm-pack/installer/" >&2
  exit 2
fi

build_wasm() {
  local root="$1"
  (
    cd "$root"
    RUSTFLAGS="$(repro_rustflags "$root")" CARGO_TARGET_DIR="$root/target" \
      wasm-pack build --target web --release ragemanifest
  ) >&2
  b3sum --no-names "$root/ragemanifest/pkg/ragemanifest_bg.wasm"
}

repro_verify "ragemanifest_bg.wasm wasm32-unknown-unknown" build_wasm "$MODE"
