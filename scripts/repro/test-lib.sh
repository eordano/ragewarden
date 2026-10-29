#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
REPO_ROOT="$work/repo"
mkdir -p "$REPO_ROOT"
echo "fn main() {}" >"$REPO_ROOT/main.rs"
EXPECTED_FILE="$work/EXPECTED_HASHES.txt"
: >"$EXPECTED_FILE"

steady() { b3sum --no-names "$1/main.rs"; }
drifting() { date +%s%N | b3sum --no-names; }
fail() { echo "FAIL: $*" >&2; exit 1; }

repro_verify "demo x" steady check >/dev/null || fail "a steady build must pass the double build"
repro_verify "demo x" drifting check >/dev/null 2>&1 && fail "a drifting build must fail the double build"
[[ -z "$(repro_expected "demo x")" ]] || fail "check mode must not write a row"

repro_verify "demo x" drifting update >/dev/null 2>&1 && fail "update must refuse a drifting build"
[[ -z "$(repro_expected "demo x")" ]] || fail "a refused update must not write a row"

repro_verify "demo x" steady update >/dev/null || fail "update of a steady build"
[[ "$(repro_expected "demo x")" == "$(steady "$REPO_ROOT")" ]] || fail "update must record the hash"
repro_verify "demo x" steady check >/dev/null || fail "a build matching its row must pass"

echo "fn main() { changed() }" >"$REPO_ROOT/main.rs"
repro_verify "demo x" steady check >/dev/null 2>&1 && fail "a build differing from its row must fail"
echo "repro lib: ok"
