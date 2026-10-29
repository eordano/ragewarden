#!/usr/bin/env bash
# Build the Safari app (host + web extension) from dist/safari on macOS.
# Unsigned unless SAFARI_TEAM_ID is set; nothing is uploaded or notarized.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
dist="${SAFARI_DIST:-$root/dist/safari}"
out="${SAFARI_BUILD_DIR:-$here/build}"
bundle_id="${SAFARI_BUNDLE_ID:-com.ragewarden.safari}"

[ "$(uname -s)" = Darwin ] || { echo "safari-host-app/build.sh: needs macOS with Xcode" >&2; exit 1; }
[ -f "$dist/manifest.json" ] || { echo "no $dist/manifest.json -- run node build.mjs safari first" >&2; exit 1; }
[ -f "$dist/wasm/ragemanifest_bg.wasm" ] || { echo "$dist has no wasm -- wasm-pack build first" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"
xcrun safari-web-extension-converter "$dist" \
    --project-location "$out" \
    --app-name Ragewarden \
    --bundle-identifier "$bundle_id" \
    --swift --macos-only --copy-resources --no-prompt --no-open --force

project="$out/Ragewarden/Ragewarden.xcodeproj"
[ -d "$project" ] || { echo "converter produced no $project" >&2; exit 1; }
# The converter names the app <org>.<AppName>; the extension must be prefixed by it.
BUNDLE_ID="$bundle_id" perl -pi -e \
    's/PRODUCT_BUNDLE_IDENTIFIER = [A-Za-z0-9.-]*\.Ragewarden;/PRODUCT_BUNDLE_IDENTIFIER = $ENV{BUNDLE_ID};/' \
    "$project/project.pbxproj"

# The extension's native messages go to rageterm through our handler.
cp "$here/Extension/SafariWebExtensionHandler.swift" \
    "$out/Ragewarden/Ragewarden Extension/SafariWebExtensionHandler.swift"
ext_entitlements=$(find "$out/Ragewarden/Ragewarden Extension" -name '*.entitlements' | head -n 1)
if [ -n "$ext_entitlements" ]; then
    pb=/usr/libexec/PlistBuddy
    "$pb" -c "Add :com.apple.security.smartcard bool true" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.device.usb bool true" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.home-relative-path.read-only array" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.home-relative-path.read-only:0 string /.config/ragewarden/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.home-relative-path.read-only:1 string /.nix-profile/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only array" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only:0 string /opt/homebrew/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only:1 string /usr/local/bin/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only:2 string /nix/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only:3 string /etc/profiles/" "$ext_entitlements" 2>/dev/null || true
    "$pb" -c "Add :com.apple.security.temporary-exception.files.absolute-path.read-only:4 string /run/current-system/" "$ext_entitlements" 2>/dev/null || true
fi

signing=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=)
if [ -n "${SAFARI_TEAM_ID:-}" ]; then
    signing=(DEVELOPMENT_TEAM="$SAFARI_TEAM_ID" CODE_SIGN_STYLE=Automatic)
fi

# The converter targets macOS 10.14; the relay handler needs Safari's macOS 11+
# messaging API, and Package.swift already requires macOS 13.
xcodebuild -project "$project" -scheme Ragewarden -configuration Release \
    -derivedDataPath "$out/DerivedData" MACOSX_DEPLOYMENT_TARGET=13.0 "${signing[@]}" build

app="$out/DerivedData/Build/Products/Release/Ragewarden.app"
appex="$app/Contents/PlugIns/Ragewarden Extension.appex"
[ -d "$appex" ] || { echo "no extension bundle inside $app" >&2; exit 1; }
[ -f "$appex/Contents/Resources/manifest.json" ] || { echo "the extension bundle carries no manifest.json" >&2; exit 1; }
# RAGETERM_BIN (a macOS rageterm) is bundled next to the handler, which prefers it.
# It runs inside the extension's sandbox; on a signed build it is signed to inherit
# that sandbox and the extension and app are re-sealed around it.
if [ -n "${RAGETERM_BIN:-}" ]; then
    install -m 0755 "$RAGETERM_BIN" "$appex/Contents/MacOS/rageterm"
    if [ -n "${SAFARI_TEAM_ID:-}" ]; then
        identity=$(codesign -dvv "$appex" 2>&1 | sed -n 's/^Authority=//p' | head -n 1)
        [ -n "$identity" ] || { echo "cannot read the identity Xcode signed $appex with" >&2; exit 1; }
        inherit="$out/rageterm-inherit.entitlements"
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
            '<plist version="1.0"><dict>' \
            '<key>com.apple.security.app-sandbox</key><true/>' \
            '<key>com.apple.security.inherit</key><true/>' \
            '</dict></plist>' >"$inherit"
        codesign --force --options runtime --entitlements "$inherit" --sign "$identity" \
            "$appex/Contents/MacOS/rageterm"
        for bundle in "$appex" "$app"; do
            codesign --force --options runtime --preserve-metadata=entitlements,identifier,flags \
                --sign "$identity" "$bundle"
        done
        codesign --verify --deep --strict "$app"
    fi
fi
grep -q 'native-host' "$appex/Contents/MacOS/Ragewarden Extension" \
    || { echo "the extension binary does not carry the rageterm relay handler" >&2; exit 1; }
cmp -s "$appex/Contents/Resources/wasm/ragemanifest_bg.wasm" "$dist/wasm/ragemanifest_bg.wasm" \
    || { echo "the bundled wasm is not the one in $dist" >&2; exit 1; }
echo "$app"
