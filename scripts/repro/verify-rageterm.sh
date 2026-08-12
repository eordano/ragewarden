#!/usr/bin/env bash
# verify-rageterm.sh -- reproducible-build sanity for the rageterm CLI binary.
#
# Builds rageterm in release mode for the current host triple, hashes the
# resulting binary with `b3sum`, and compares the hash against the entry in
# `EXPECTED_HASHES.txt`. On mismatch the script exits 1 and prints the actual
# vs. expected pair so the operator can investigate.
#
# A MISSING row also exits 1. "No recorded hash" means this build is
# unverified, which is a gate failure, not a pass -- an earlier version exited 0
# and made the whole reproducible-build job green against an empty table.
#
# Usage:
#   scripts/repro/verify-rageterm.sh             # build + verify
#   scripts/repro/verify-rageterm.sh --update-expected
#                                                  # update EXPECTED_HASHES.txt
#                                                  # in place (release-cut path)
#   scripts/repro/verify-rageterm.sh --dry-run     # parse args, print plan, exit 0
#   scripts/repro/verify-rageterm.sh --help        # print this header
#
# Reproducible build invocation:
#
#   cargo build --release -p rageterm --target "$TARGET_TRIPLE" \
#       --config 'profile.release.codegen-units=1' \
#       --config 'profile.release.lto="fat"' \
#       --config 'profile.release.strip="symbols"'
#
# The workspace `Cargo.toml` already pins those settings; we re-pass them on
# the command line so a future workspace edit doesn't silently change the hash
# without a corresponding `--update-expected` cycle.
#
# `--target` is not decoration. The release workflow builds every artifact it
# publishes as `cargo build --release -p rageterm --target <triple>`, which
# lands in `target/<triple>/release/rageterm`. This script used to omit
# `--target` and hash `target/release/rageterm` -- a different cargo layout
# (host and target artifacts share a directory, build scripts and proc-macros
# are built with the same flags as the binary) and, more to the point, a file
# that no release ever shipped. It could have gone green on a byte sequence
# nobody downloaded. Building the way the publisher builds is the whole claim
# the hash is making.

set -euo pipefail

print_help() {
  # Everything from the second line to the first line that is not a comment.
  # A fixed line range silently truncated (or overran) the header every time
  # someone edited it.
  sed -n '2,${/^#/!q;p;}' "$0"
}

DRY_RUN=0
UPDATE=0
TARGET_OVERRIDE=""
USE_CROSS=0
for arg in "$@"; do
  case "$arg" in
    --help | -h)
      print_help
      exit 0
      ;;
    --dry-run) DRY_RUN=1 ;;
    --update-expected) UPDATE=1 ;;
    # Verify a triple other than the host's -- the release CI matrix builds
    # five, and this lets each matrix leg check its own. `--cross` uses
    # `cross build` (as the release does for aarch64-linux) instead of cargo.
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
    # This used to default to the string "unknown", which then went into the
    # expected-hashes lookup key and would have recorded a row named after a
    # triple that does not exist. The triple is now load-bearing for the build
    # too, so there is nothing sensible to guess.
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
BINARY_PATH="$REPO_ROOT/target/$TARGET_TRIPLE/release/$BINARY_NAME"

echo "rageterm reproducible-build verifier"
echo "  repo root:    $REPO_ROOT"
echo "  host triple:  $TARGET_TRIPLE"
echo "  binary path:  $BINARY_PATH"
echo "  expected:     $EXPECTED_FILE"

if ((DRY_RUN)); then
  echo "dry-run: skipping cargo build + b3sum"
  exit 0
fi

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found in PATH (cargo install b3sum)" >&2
  exit 2
fi

(
  cd "$REPO_ROOT"
  # cargo, or `cross` when --cross is passed -- the release builds aarch64-linux
  # with cross, so its hash is only reproducible with cross. The --config flags
  # are redundant with Cargo.toml's [profile.release] (same values), kept so a
  # future profile edit can't silently change what this verifier builds.
  build_tool=cargo
  ((USE_CROSS)) && build_tool=cross
  "$build_tool" build --release -p rageterm --target "$TARGET_TRIPLE" \
    --config 'profile.release.codegen-units=1' \
    --config 'profile.release.lto="fat"' \
    --config 'profile.release.strip="symbols"'
)

if [[ ! -f "$BINARY_PATH" ]]; then
  # Exit 2, not 1: "the build did not produce the file" is an environment
  # problem, and 1 is reserved for a verification verdict.
  echo "error: build succeeded but $BINARY_PATH does not exist" >&2
  exit 2
fi

ACTUAL_HASH="$(b3sum --no-names "$BINARY_PATH")"
echo "actual hash: $ACTUAL_HASH"

if ((UPDATE)); then
  tmp="$(mktemp)"
  grep -v "^rageterm $TARGET_TRIPLE " "$EXPECTED_FILE" >"$tmp" || true
  echo "rageterm $TARGET_TRIPLE $ACTUAL_HASH" >>"$tmp"
  mv "$tmp" "$EXPECTED_FILE"
  echo "updated $EXPECTED_FILE"
  exit 0
fi

EXPECTED_HASH="$(grep "^rageterm $TARGET_TRIPLE " "$EXPECTED_FILE" 2>/dev/null | awk '{print $3}' || true)"
if [[ -z "${EXPECTED_HASH:-}" ]]; then
  # Fail closed. A missing row is indistinguishable from "nobody ever seeded
  # the table", and this used to exit 0 -- with EXPECTED_HASHES.txt holding
  # zero non-comment rows, that made the entire reproducible-build gate green
  # while verifying nothing at all.
  #
  # Note the single quotes below. The old warning wrapped the artifact name in
  # backticks inside a double-quoted echo, which command-substitutes: bash
  # actually tried to run "rageterm x86_64-unknown-linux-gnu" and printed an
  # empty artifact name. Never use backticks for emphasis in a shell string.
  echo "error: no expected hash recorded for 'rageterm $TARGET_TRIPLE'" >&2
  echo "       $EXPECTED_FILE has no row for this artifact and triple, so" >&2
  echo "       there is nothing to verify against and this build is UNVERIFIED." >&2
  echo "       Seed the table from a build you have independently established" >&2
  echo "       is the one you intend to publish:" >&2
  echo "           scripts/repro/verify-rageterm.sh --update-expected" >&2
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
