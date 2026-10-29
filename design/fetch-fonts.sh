#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION=5.3.0
URL="https://registry.npmjs.org/@fontsource-variable/source-serif-4/-/source-serif-4-$VERSION.tgz"
WANT=4a19d3a6fda1a977f15a0ee1e60e5f53df2e6ae77f46f1ed54c7fc52d015e85a
TGZ=fonts/.source-serif-4-$VERSION.tgz

mkdir -p fonts
if [ ! -f "$TGZ" ] || [ "$(sha256sum <"$TGZ" | cut -d' ' -f1)" != "$WANT" ]; then
  curl -fsSL --retry 3 -o "$TGZ.tmp" "$URL"
  got=$(sha256sum <"$TGZ.tmp" | cut -d' ' -f1)
  [ "$got" = "$WANT" ] || { rm -f "$TGZ.tmp"; echo "sha256 $got != $WANT" >&2; exit 1; }
  mv -f "$TGZ.tmp" "$TGZ"
fi
for subset in latin latin-ext cyrillic cyrillic-ext greek vietnamese; do
  tar -xzf "$TGZ" -O "package/files/source-serif-4-$subset-wght-normal.woff2" > "fonts/SourceSerif4-Roman-$subset.woff2"
  tar -xzf "$TGZ" -O "package/files/source-serif-4-$subset-wght-italic.woff2" > "fonts/SourceSerif4-Italic-$subset.woff2"
done
ls fonts/*.woff2
