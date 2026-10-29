# Ragewarden for Safari -- host app

Safari ships web extensions inside a macOS app. `build.sh` builds that app from the
extension in `../dist/safari`:

```sh
wasm-pack build --target web ..        # or from ragewarden/: wasm-pack build --target web ragemanifest
node ../build.mjs safari
./build.sh                             # prints the path of Ragewarden.app
```

It runs `xcrun safari-web-extension-converter` (macOS-only, Swift) into `build/`, gives the
app the bundle id `com.ragewarden.safari` (override with `SAFARI_BUNDLE_ID`) so the
extension `com.ragewarden.safari.Extension` embeds under it, builds Release with
`xcodebuild`, and checks that the `.appex` carries the manifest and the very wasm in
`dist/safari`. The build is unsigned; set `SAFARI_TEAM_ID` to sign with your team.
`Package.swift` / `Sources/RagewardenHost/main.swift` are the host's own launcher (it opens
Safari's extension settings when the extension is off) and build with `swift build`.

CI builds both on `macos-latest` (`.github/workflows/ci.yml`, job `safari`).

## Running it

Open `Ragewarden.app`, then enable Ragewarden in Safari -> Settings -> Extensions. An
unsigned build needs Safari -> Develop -> Allow Unsigned Extensions.

## Distribution

| channel | what it takes |
|---|---|
| Direct download | Developer ID signing (`SAFARI_TEAM_ID`), `xcrun notarytool`, a `.dmg` |
| Mac App Store | Apple Developer Program and App Store Connect review |

## PIV and FIDO2 keys

Safari has no native-messaging host manifests. The extension's
`runtime.sendNativeMessage` goes to this app's extension handler
(`Extension/SafariWebExtensionHandler.swift`, copied over the converter's), which
relays the same length-prefixed request to `rageterm native-host` and returns its reply.
Set `RAGETERM_BIN` to a macOS rageterm and `build.sh` bundles it next to the handler,
which prefers it; otherwise the handler runs an installed rageterm (Homebrew, Nix
profile). For the sandboxed extension `build.sh` adds the smart-card and USB entitlements
and read access to `~/.config/ragewarden` and those install locations; the handler runs
rageterm with the user's real HOME. A signed build signs the bundled rageterm to inherit
the extension's sandbox and re-seals the extension and app around it. `swift test` runs
the handler against stand-in rageterms (framing, native-host mode, HOME, no reply, a
rageterm that exits early, an oversized reply).
