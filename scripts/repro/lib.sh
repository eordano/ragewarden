# shellcheck shell=bash

repro_fresh_tree() {
  local root="$1" label="$2" dir prefix
  dir="$(mktemp -d "${TMPDIR:-/tmp}/ragewarden-repro-$label.XXXXXX")"
  if git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
    prefix="$(git -C "$root" rev-parse --show-prefix)"
    git -C "$root" archive --format=tar "HEAD:$prefix" | tar -x -C "$dir"
  else
    tar -C "$root" --exclude=./.git --exclude=./target --exclude='./*/target' \
      --exclude='*/node_modules' --exclude=./ragemanifest/pkg --exclude='*/build' \
      --exclude='*/.gradle' -cf - . | tar -x -C "$dir"
  fi
  printf '%s\n' "$dir"
}

repro_rustflags() {
  printf '%s --remap-path-prefix=%s=/ragewarden' "${RUSTFLAGS:-}" "$1"
}

repro_expected() {
  local key="$1"
  grep "^$key " "$EXPECTED_FILE" 2>/dev/null | awk '{print $NF}' || true
}

repro_set_expected() {
  local key="$1" hash="$2" tmp
  tmp="$(mktemp)"
  grep -v "^$key " "$EXPECTED_FILE" >"$tmp" || true
  echo "$key $hash" >>"$tmp"
  mv "$tmp" "$EXPECTED_FILE"
  echo "updated $EXPECTED_FILE ($key)"
}

repro_verify() {
  local key="$1" build_fn="$2" mode="$3" expected a b ha hb
  expected="$(repro_expected "$key")"
  if [[ "$mode" == check && -n "$expected" ]]; then
    a="$(repro_fresh_tree "$REPO_ROOT" a)"
    ha="$("$build_fn" "$a")"
    rm -rf "$a"
    echo "built:    $ha"
    echo "expected: $expected"
    if [[ "$ha" != "$expected" ]]; then
      echo "MISMATCH ($key)" >&2
      return 1
    fi
    echo "OK: $key matches the recorded release hash"
    return 0
  fi

  a="$(repro_fresh_tree "$REPO_ROOT" a)"
  b="$(repro_fresh_tree "$REPO_ROOT" b)"
  ha="$("$build_fn" "$a")"
  hb="$("$build_fn" "$b")"
  rm -rf "$a" "$b"
  echo "build 1 ($a): $ha"
  echo "build 2 ($b): $hb"
  if [[ "$ha" != "$hb" ]]; then
    echo "NOT REPRODUCIBLE ($key): two builds of the same tree at different paths differ" >&2
    return 1
  fi
  if [[ -n "$expected" && "$ha" != "$expected" ]]; then
    echo "reproducible, but differs from the recorded release hash $expected ($key)" >&2
    [[ "$mode" == update ]] || return 1
  fi
  if [[ "$mode" == update ]]; then
    repro_set_expected "$key" "$ha"
  elif [[ -z "$expected" ]]; then
    echo "OK: $key is reproducible ($ha); no release hash is recorded yet --"
    echo "    run with --update-expected on the release tag to record it"
  else
    echo "OK: $key is reproducible and matches the recorded release hash"
  fi
}

repro_usage() {
  cat <<USAGE
usage: $1 [--double-build] [--update-expected] [--dry-run]$2

Builds $3 from the committed tree (HEAD) in a fresh directory and compares its
BLAKE3 hash with the row in scripts/repro/EXPECTED_HASHES.txt. Without a row,
or with --double-build, it builds twice from two fresh trees at different paths
and requires both hashes to agree. --update-expected records the hash after
such a double build; run it on the release tag.
USAGE
}
