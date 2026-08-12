#!/usr/bin/env bash
# verify-ragedroid.sh -- reproducible-build sanity for the ragedroid APK.
#
# Runs `:app:assembleStandardRelease` (with either the operator's release-signing
# config or `-PunsignedBuild=true`), hashes the APK contents, and compares
# against the entry in `EXPECTED_HASHES.txt`.
#
# A missing row exits 1, same as a mismatch. "No recorded hash" means this
# build is unverified, which is a gate failure, not a pass -- an earlier version
# exited 0 and made the whole reproducible-build job green against an empty
# table.
#
# The hash is computed over a normalized copy of the APK:
#   1. APK signing block stripped (so v2/v3 signatures don't contaminate the hash --
#      a reproducible build is reproducible *up to* the per-build signature).
#   2. ZIP entries are re-emitted in deterministic alphabetical order with
#      timestamps zeroed.
#
# Both are done by `normalize_apk` below, with python3's `zipfile`: it reads the
# entries and writes a fresh archive, which drops the APK Signing Block (that
# block is not a zip entry, it sits between the last entry and the central
# directory, so re-emitting the entries cannot carry it over) and replaces every
# per-entry timestamp with a constant. If python3 is unavailable we fall back to
# hashing the APK as-is and warn loudly.
#
# This used to be prose only: the header named `apksigner --strip` and
# `zipalign --force --normalize`, neither of which is a real invocation of
# either tool, and the body hashed the raw APK. That is fine while the table is
# empty and every run fails closed, but the moment a row is seeded the gate
# would have gone red on any zip-ordering or timestamp difference between two
# runners and stayed red -- and the documented cure for a red gate is
# `--update-expected`, i.e. exactly the reflex the table's own header forbids.
#
# Usage:
#   scripts/repro/verify-ragedroid.sh
#   scripts/repro/verify-ragedroid.sh --update-expected
#   scripts/repro/verify-ragedroid.sh --dry-run
#   scripts/repro/verify-ragedroid.sh --help
#
# Reproducible build invocation (assumes JAVA_HOME / ANDROID_HOME / NDK set):
#
#   ./gradlew :app:assembleStandardRelease -PunsignedBuild=true
#
# ...except that `./gradlew` is not guaranteed to exist. ragedroid/.gitignore
# excludes gradlew, gradlew.bat and gradle-wrapper.jar (only
# gradle-wrapper.properties is committed), so a fresh checkout has no wrapper
# and this script exited 127 before reaching any verification logic. CI runs
# `gradle wrapper` first so it never noticed; nobody could run this locally at
# all. We now prefer ./gradlew when it is there -- it pins the Gradle version
# via gradle-wrapper.properties, which is the reproducibility-relevant part --
# and fall back to whatever `gradle` is on PATH (the #android devshell supplies
# one) after checking that it is the same version the wrapper names.
#
# Gradle version. There are exactly two ways this APK gets built and they have
# to agree on the version. release.yml (both the `ragedroid` job and the
# `repro-build` job that runs this script) seds the version out of
# gradle-wrapper.properties, runs `gradle wrapper --gradle-version "$version"`
# and then ./gradlew -- so CI builds with whatever that file names. Here, with no
# wrapper in a fresh checkout, the build uses nixpkgs' `gradle` from the #android
# devshell. Those were 8.14.5 and 8.14.4 respectively, and different Gradle
# versions can emit different bytes: a hash produced here was not comparable
# with one produced in CI, and the documented cure for that red gate is
# `--update-expected`, i.e. the one reflex EXPECTED_HASHES.txt forbids. The
# wrapper now names 8.14.4 -- the devshell's version -- because
# gradle-wrapper.properties is a file this repo owns and the devshell is not;
# the reasoning and the AGP floor that bounds it are recorded in that file.
# The skew check below is therefore a hard failure rather than a warning: an
# uncomparable hash is worse than no hash, because someone will compare it.
#
# Version metadata is pinned, not passed through. Commit 6ea1487b made
# ragedroid/app/build.gradle.kts read versionCode/versionName from
# RAGEDROID_VERSION_CODE / RAGEDROID_VERSION_NAME, and both land in the APK's
# binary manifest -- so both are part of this hash. This script runs Gradle under
# `env -u` for both names: the build always uses build.gradle.kts's own defaults
# no matter what the caller has exported, and those defaults are echoed beside
# the hash so a row is self-describing.
#
# Pinning rather than requiring them, even though release.yml's repro-build job
# does export the tag's values to this script, because a recorded hash may only
# depend on what is in the tree. RAGEDROID_VERSION_* are not: a row that
# depended on them could be reproduced only by someone who also knew which tag
# it came from, and anyone with them exported for an unrelated reason would get
# a mismatch curable only by `--update-expected`. Pinned, `git checkout <tag> &&
# scripts/repro/verify-ragedroid.sh` reproduces the recorded hash from the tree
# alone, which is what a third party auditing a release actually has.
#
# The cost, stated plainly because whoever seeds a row needs to know it: the APK
# hashed here is not byte-identical to the published one. It is unsigned
# (-PunsignedBuild=true) and it claims versionCode/versionName defaults rather
# than the tag's. This gate proves that the source in this tree builds to these
# bytes; that the published APK claims the right version is attested by the
# `version` job in release.yml and by aapt2 against the artifact, not by this
# hash. release.yml still exports both variables to the repro-build step -- they
# are inert now, and that env block can go the next time that file is touched.
#
# Known remaining skew, not fixed here: release.yml builds under zulu JDK 17
# while the #android devshell currently runs JDK 21. build.gradle.kts pins
# sourceCompatibility/targetCompatibility/jvmTarget at 17, which fixes the
# bytecode level, but that is not a proof that two JDKs emit identical class
# files. If a seeded row ever goes red across exactly those two hosts and
# nothing else changed, suspect this before reaching for --update-expected.

set -euo pipefail

print_help() {
    # Everything from the second line to the first line that is not a comment.
    # A fixed line range silently truncated (or overran) the header every time
    # someone edited it.
    sed -n '2,${/^#/!q;p;}' "$0"
}

# Re-emit the APK's entries into a fresh archive: sorted by name, timestamps
# constant, signing block gone. See the header for why this is what gets hashed.
normalize_apk() {
    python3 - "$1" "$2" <<'PY'
import sys, zipfile

src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
    for name in sorted(zin.namelist()):
        info = zin.getinfo(name)
        out = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
        out.compress_type = info.compress_type
        out.external_attr = info.external_attr
        out.internal_attr = info.internal_attr
        out.create_system = 3
        zout.writestr(out, zin.read(name))
PY
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

echo "ragedroid APK reproducible-build verifier (standard + fdroid flavors)"
echo "  repo root:      $REPO_ROOT"
echo "  expected hashes: $EXPECTED_FILE"

if (( DRY_RUN )); then
    echo "dry-run: skipping gradle assemble{Standard,Fdroid}Release + b3sum"
    exit 0
fi

if ! command -v b3sum >/dev/null 2>&1; then
    echo "error: b3sum not found in PATH (cargo install b3sum)" >&2
    exit 2
fi

# The version gradle-wrapper.properties names, parsed exactly as release.yml
# parses it. It is the version CI builds with (it generates the wrapper from
# this file), so it is also the version a recorded row belongs to.
WRAPPER_VERSION="$(sed -n 's|.*/gradle-\(.*\)-bin\.zip|\1|p' \
    "$REPO_ROOT/ragedroid/gradle/wrapper/gradle-wrapper.properties" 2>/dev/null || true)"

# Prefer the wrapper (it pins the Gradle version), else a PATH gradle, else say
# which shell provides one. See the header for why the wrapper may be absent.
if [[ -x "$REPO_ROOT/ragedroid/gradlew" ]]; then
    GRADLE_CMD="$REPO_ROOT/ragedroid/gradlew"
    GRADLE_VERSION="$WRAPPER_VERSION"
    echo "gradle: $GRADLE_CMD (wrapper, ${WRAPPER_VERSION:-unknown version})"
elif command -v gradle >/dev/null 2>&1; then
    GRADLE_CMD="$(command -v gradle)"
    GRADLE_VERSION="$("$GRADLE_CMD" --version 2>/dev/null | awk '/^Gradle /{print $2; exit}')"
    echo "gradle: $GRADLE_CMD (${GRADLE_VERSION:-unknown version}; no ./gradlew wrapper present)"
    if [[ -n "$WRAPPER_VERSION" && -n "$GRADLE_VERSION" && "$WRAPPER_VERSION" != "$GRADLE_VERSION" ]]; then
        # Refused, not warned about: the release workflow builds with the version
        # gradle-wrapper.properties names, so a hash produced by a different
        # Gradle cannot be compared with a recorded row in either direction -- and
        # a warning on stderr in the middle of a Gradle build is a warning nobody
        # reads before pasting the hash into the table.
        echo "error: gradle-wrapper.properties pins Gradle $WRAPPER_VERSION but this" >&2
        echo "       build would use $GRADLE_VERSION. A hash produced here is not" >&2
        echo "       comparable with one produced by the wrapper, and the release" >&2
        echo "       workflow uses the wrapper, so refusing to produce one at all." >&2
        echo "       Either generate the wrapper this file names:" >&2
        echo "           (cd ragedroid && gradle wrapper --gradle-version $WRAPPER_VERSION)" >&2
        echo "       or reconcile the two versions -- see the comment at the top of" >&2
        echo "       ragedroid/gradle/wrapper/gradle-wrapper.properties, which is the" >&2
        echo "       only place a Gradle version is allowed to be written down." >&2
        exit 2
    fi
    if [[ -z "$WRAPPER_VERSION" || -z "$GRADLE_VERSION" ]]; then
        echo "warning: could not determine the wrapper version (${WRAPPER_VERSION:-?}) or the" >&2
        echo "         gradle version (${GRADLE_VERSION:-?}), so the two are unchecked. The" >&2
        echo "         hash below may have been built by a Gradle no row was recorded with." >&2
    fi
else
    echo "error: neither $REPO_ROOT/ragedroid/gradlew nor a 'gradle' on PATH." >&2
    echo "       gradlew is gitignored and generated, so a fresh checkout has none." >&2
    echo "       Either enter the devshell that ships gradle:" >&2
    echo "           nix develop <path-to-nixos-config>#android" >&2
    echo "       or generate the wrapper first:" >&2
    echo "           (cd ragedroid && gradle wrapper)" >&2
    exit 2
fi

# The two version variables are read out of build.gradle.kts rather than
# repeated here, so this line cannot drift from the values the build actually
# uses when someone bumps the defaults.
BUILD_GRADLE="$REPO_ROOT/ragedroid/app/build.gradle.kts"
PINNED_VERSION_CODE="$(sed -n 's/^val defaultVersionCode = \([0-9][0-9]*\).*/\1/p' "$BUILD_GRADLE" | head -n 1)"
PINNED_VERSION_NAME="$(sed -n 's/^val defaultVersionName = "\([^"]*\)".*/\1/p' "$BUILD_GRADLE" | head -n 1)"

# Say so out loud when they were exported. The whole point of the pin is that
# the hash does not move with them, but someone who set them on purpose (CI
# does, per release.yml's repro-build job) is owed an explanation of why the APK
# does not claim the version they asked for.
for _var in RAGEDROID_VERSION_CODE RAGEDROID_VERSION_NAME; do
    if [[ -n "${!_var:-}" ]]; then
        echo "note: $_var=${!_var} is set and is being IGNORED for this build."
        echo "      The APK is always built with build.gradle.kts's defaults so the hash"
        echo "      depends only on the tree; see the header."
    fi
done
echo "version metadata: versionCode=${PINNED_VERSION_CODE:-<unparsed>} versionName=${PINNED_VERSION_NAME:-<unparsed>} (build.gradle.kts defaults, pinned)"

# Assemble one flavor's release APK, normalize+hash it, and update or compare
# against its EXPECTED_HASHES.txt row. Release publishes BOTH the standard and
# the F-Droid APK, so both are verified -- hashing only `standard` shipped the
# F-Droid build with no reproducibility check at all.
verify_flavor() {
    local flavor="$1" task="$2" subdir="$3" row="$4"
    local apk_glob="$REPO_ROOT/ragedroid/app/build/outputs/apk/$subdir/release/*.apk"
    echo
    echo "=== flavor: $flavor ($task) -> row 'ragedroid-app $row' ==="
    (
        cd "$REPO_ROOT/ragedroid"
        # `env -u` both names: the build must see build.gradle.kts's defaults
        # whatever the caller exported, or the hash stops being a function of the
        # tree alone (header, "Version metadata is pinned").
        #
        # --no-daemon for the same reason and it is not optional: a Gradle daemon
        # keeps the environment it was started with, so a daemon left behind by a
        # build that *did* have RAGEDROID_VERSION_* set can put those values back
        # under `env -u`, and the pin would hold only until someone had built an
        # actual release on the same machine.
        env -u RAGEDROID_VERSION_CODE -u RAGEDROID_VERSION_NAME \
            "$GRADLE_CMD" --no-daemon ":app:$task" -PunsignedBuild=true
    )

    local apk_path
    apk_path="$(ls -1 $apk_glob 2>/dev/null | head -n 1)"
    if [[ -z "${apk_path:-}" ]]; then
        echo "error: no APK found matching $apk_glob" >&2
        exit 2
    fi
    echo "apk path: $apk_path"

    local actual_hash
    if command -v python3 >/dev/null 2>&1; then
        local work_dir
        work_dir="$(mktemp -d)"
        normalize_apk "$apk_path" "$work_dir/normalized.apk"
        actual_hash="$(b3sum --no-names "$work_dir/normalized.apk")"
        rm -rf "$work_dir"
        echo "actual hash: $actual_hash (normalized: entries sorted, timestamps zeroed, signing block dropped)"
    else
        echo "warning: python3 not found, so the APK could NOT be normalized." >&2
        echo "         The hash below is of the raw APK: entry order, per-entry" >&2
        echo "         timestamps and any signing block all contaminate it, and it" >&2
        echo "         is not comparable with a row recorded on a host that had" >&2
        echo "         python3. Install python3 before trusting or seeding this." >&2
        actual_hash="$(b3sum --no-names "$apk_path")"
        echo "actual hash: $actual_hash (raw APK; NOT normalized)"
    fi

    # Everything a row depends on, printed next to the hash for a seeder to paste
    # into a commit message.
    echo "hash provenance: gradle=${GRADLE_VERSION:-unknown} versionCode=${PINNED_VERSION_CODE:-<unparsed>} versionName=${PINNED_VERSION_NAME:-<unparsed>} unsigned=true"

    if (( UPDATE )); then
        local tmp
        tmp="$(mktemp)"
        grep -v "^ragedroid-app $row " "$EXPECTED_FILE" > "$tmp" || true
        echo "ragedroid-app $row $actual_hash" >> "$tmp"
        mv "$tmp" "$EXPECTED_FILE"
        echo "updated $EXPECTED_FILE ($row)"
        return 0
    fi

    local expected_hash
    expected_hash="$(grep "^ragedroid-app $row " "$EXPECTED_FILE" 2>/dev/null | awk '{print $3}' || true)"
    if [[ -z "${expected_hash:-}" ]]; then
        # Fail closed -- see the same block in verify-rageterm.sh. An unseeded
        # table used to exit 0 here, so the gate passed by verifying nothing.
        echo "error: no expected hash recorded for 'ragedroid-app $row'" >&2
        echo "       $EXPECTED_FILE has no row for this artifact, so there is" >&2
        echo "       nothing to verify against and this APK is UNVERIFIED." >&2
        echo "       Seed the table from a build you have independently established" >&2
        echo "       is the one you intend to publish:" >&2
        echo "           scripts/repro/verify-ragedroid.sh --update-expected" >&2
        echo "       That row becomes the reference every later build is judged by," >&2
        echo "       so do not run it just to make this message go away." >&2
        exit 1
    fi

    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo "MISMATCH ($row)" >&2
        echo "  expected: $expected_hash" >&2
        echo "  actual:   $actual_hash" >&2
        exit 1
    fi

    echo "OK: $row hash matches"
}

verify_flavor standard assembleStandardRelease standard standardRelease
verify_flavor fdroid assembleFdroidRelease fdroid fdroidRelease
