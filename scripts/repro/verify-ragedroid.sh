#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

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
MODE=check
for arg in "$@"; do
  case "$arg" in
    --help | -h)
      repro_usage "$0" "" "the unsigned standard and fdroid release APKs (normalized)"
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

echo "ragedroid APK reproducible-build verifier (standard + fdroid flavors)"
echo "  repo root:      $REPO_ROOT"
echo "  expected hashes: $EXPECTED_FILE"

if ((DRY_RUN)); then
  echo "dry-run: skipping gradle assemble{Standard,Fdroid}Release + b3sum"
  exit 0
fi

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found in PATH (cargo install b3sum)" >&2
  exit 2
fi

WRAPPER_VERSION="$(sed -n 's|.*/gradle-\(.*\)-bin\.zip|\1|p' \
  "$REPO_ROOT/ragedroid/gradle/wrapper/gradle-wrapper.properties" 2>/dev/null || true)"
WRAPPER_SHA256="$(sed -n 's|^distributionSha256Sum=||p' \
  "$REPO_ROOT/ragedroid/gradle/wrapper/gradle-wrapper.properties" 2>/dev/null || true)"

if [[ -x "$REPO_ROOT/ragedroid/gradlew" ]]; then
  GRADLE_CMD="$REPO_ROOT/ragedroid/gradlew"
  GRADLE_VERSION="$WRAPPER_VERSION"
  echo "gradle: $GRADLE_CMD (wrapper, ${WRAPPER_VERSION:-unknown version})"
elif command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD="$(command -v gradle)"
  GRADLE_VERSION="$("$GRADLE_CMD" --version 2>/dev/null | awk '/^Gradle /{print $2; exit}')"
  echo "gradle: $GRADLE_CMD (${GRADLE_VERSION:-unknown version}; no ./gradlew wrapper present)"
  if [[ -n "$WRAPPER_VERSION" && -n "$GRADLE_VERSION" && "$WRAPPER_VERSION" != "$GRADLE_VERSION" ]]; then
    echo "error: gradle-wrapper.properties pins Gradle $WRAPPER_VERSION but this" >&2
    echo "       build would use $GRADLE_VERSION. A hash produced here is not" >&2
    echo "       comparable with one produced by the wrapper, and the release" >&2
    echo "       workflow uses the wrapper, so refusing to produce one at all." >&2
    echo "       Either generate the wrapper this file names:" >&2
    echo "           (cd ragedroid && gradle wrapper --gradle-version $WRAPPER_VERSION \\" >&2
    echo "              --gradle-distribution-sha256-sum $WRAPPER_SHA256)" >&2
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
  echo "           (cd ragedroid && gradle wrapper --gradle-version $WRAPPER_VERSION \\" >&2
  echo "              --gradle-distribution-sha256-sum $WRAPPER_SHA256)" >&2
  exit 2
fi

BUILD_GRADLE="$REPO_ROOT/ragedroid/app/build.gradle.kts"
PINNED_VERSION_CODE="$(sed -n 's/^val defaultVersionCode = \([0-9][0-9]*\).*/\1/p' "$BUILD_GRADLE" | head -n 1)"
PINNED_VERSION_NAME="$(sed -n 's/^val defaultVersionName = "\([^"]*\)".*/\1/p' "$BUILD_GRADLE" | head -n 1)"

for _var in RAGEDROID_VERSION_CODE RAGEDROID_VERSION_NAME; do
  if [[ -n "${!_var:-}" ]]; then
    echo "note: $_var=${!_var} is set and is being IGNORED for this build."
    echo "      The APK is always built with build.gradle.kts's defaults so the hash"
    echo "      depends only on the tree; see the header."
  fi
done
echo "version metadata: versionCode=${PINNED_VERSION_CODE:-<unparsed>} versionName=${PINNED_VERSION_NAME:-<unparsed>} (build.gradle.kts defaults, pinned)"

build_flavor() {
  local root="$1" task="$2" subdir="$3" apk_path work_dir hash
  (
    cd "$root/ragedroid"
    env -u RAGEDROID_VERSION_CODE -u RAGEDROID_VERSION_NAME \
      RUSTFLAGS="$(repro_rustflags "$root")" \
      "$GRADLE_CMD" --no-daemon --project-dir "$root/ragedroid" ":app:$task" -PunsignedBuild=true
  ) >&2
  apk_path="$(ls -1 "$root"/ragedroid/app/build/outputs/apk/"$subdir"/release/*.apk 2>/dev/null | head -n 1)"
  if [[ -z "${apk_path:-}" ]]; then
    echo "error: no $subdir release APK under $root/ragedroid/app/build/outputs" >&2
    exit 2
  fi
  work_dir="$(mktemp -d)"
  normalize_apk "$apk_path" "$work_dir/normalized.apk"
  hash="$(b3sum --no-names "$work_dir/normalized.apk")"
  rm -rf "$work_dir"
  printf '%s\n' "$hash"
}

build_standard() { build_flavor "$1" assembleStandardRelease standard; }
build_fdroid() { build_flavor "$1" assembleFdroidRelease fdroid; }

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is needed to normalize the APK (entry order, timestamps, signing block)" >&2
  exit 2
fi
echo "hash provenance: gradle=${GRADLE_VERSION:-unknown} versionCode=${PINNED_VERSION_CODE:-<unparsed>} versionName=${PINNED_VERSION_NAME:-<unparsed>} unsigned=true normalized=true"

status=0
repro_verify "ragedroid-app standardRelease" build_standard "$MODE" || status=1
repro_verify "ragedroid-app fdroidRelease" build_fdroid "$MODE" || status=1
exit "$status"
