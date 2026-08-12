#!/usr/bin/env bash
# verify-ragemanifest-wasm.sh -- reproducible-build sanity for the WASM core.
#
# Runs `wasm-pack build --target web ragemanifest`, hashes
# `pkg/ragemanifest_bg.wasm` with `b3sum`, and compares against the
# entry in `EXPECTED_HASHES.txt`. The hash covers only the WASM
# bytecode -- the JS glue is regenerated from the same source on every
# run and isn't reproducible across wasm-bindgen patch versions.
#
# A missing row exits 1, same as a mismatch. "No recorded hash" means
# this build is unverified, which is a gate failure, not a pass -- an
# earlier version exited 0 and made the whole reproducible-build job
# green against an empty table.
#
# Usage:
#   scripts/repro/verify-ragemanifest-wasm.sh
#   scripts/repro/verify-ragemanifest-wasm.sh --update-expected
#   scripts/repro/verify-ragemanifest-wasm.sh --dry-run
#   scripts/repro/verify-ragemanifest-wasm.sh --help
#
# Reproducible build invocation:
#
#   wasm-pack build --target web --release ragemanifest
#
# Pin `wasm-bindgen` and `wasm-pack` to fixed versions in the release
# workflow; differing minor versions of wasm-bindgen produce different
# bytecode, and the hash mismatch is by-design loud.

set -euo pipefail

print_help() {
    sed -n '2,27p' "$0"
}

DRY_RUN=0
UPDATE=0
for arg in "$@"; do
    case "$arg" in
        --help|-h) print_help; exit 0 ;;
        --dry-run) DRY_RUN=1 ;;
        --update-expected) UPDATE=1 ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXPECTED_FILE="$REPO_ROOT/scripts/repro/EXPECTED_HASHES.txt"
WASM_PATH="$REPO_ROOT/ragemanifest/pkg/ragemanifest_bg.wasm"

echo "ragemanifest WASM reproducible-build verifier"
echo "  repo root: $REPO_ROOT"
echo "  wasm path: $WASM_PATH"
echo "  expected:  $EXPECTED_FILE"

if (( DRY_RUN )); then
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

(
    cd "$REPO_ROOT"
    wasm-pack build --target web --release ragemanifest
)

ACTUAL_HASH="$(b3sum --no-names "$WASM_PATH")"
echo "actual hash: $ACTUAL_HASH"

if (( UPDATE )); then
    tmp="$(mktemp)"
    grep -v '^ragemanifest_bg.wasm wasm32-unknown-unknown ' "$EXPECTED_FILE" > "$tmp" || true
    echo "ragemanifest_bg.wasm wasm32-unknown-unknown $ACTUAL_HASH" >> "$tmp"
    mv "$tmp" "$EXPECTED_FILE"
    echo "updated $EXPECTED_FILE"
    exit 0
fi

EXPECTED_HASH="$(grep '^ragemanifest_bg.wasm wasm32-unknown-unknown ' "$EXPECTED_FILE" 2>/dev/null | awk '{print $3}' || true)"
if [[ -z "${EXPECTED_HASH:-}" ]]; then
    # Fail closed -- see the same block in verify-rageterm.sh. An unseeded table
    # used to exit 0 here, so the reproducible-build gate passed by verifying
    # nothing.
    echo "error: no expected hash recorded for 'ragemanifest_bg.wasm wasm32-unknown-unknown'" >&2
    echo "       $EXPECTED_FILE has no row for this artifact, so there is" >&2
    echo "       nothing to verify against and this WASM is UNVERIFIED." >&2
    echo "       Seed the table from a build you have independently established" >&2
    echo "       is the one you intend to publish:" >&2
    echo "           scripts/repro/verify-ragemanifest-wasm.sh --update-expected" >&2
    echo "       That row becomes the reference every later build is judged by," >&2
    echo "       so do not run it just to make this message go away." >&2
    exit 1
fi

if [[ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]]; then
    echo "MISMATCH" >&2
    echo "  expected: $EXPECTED_HASH" >&2
    echo "  actual:   $ACTUAL_HASH" >&2
    exit 1
fi

echo "OK: hash matches"
