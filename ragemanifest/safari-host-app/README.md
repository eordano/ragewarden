# RagewardenHost -- Safari host app

Minimal macOS host application that ships the Ragewarden Safari Web Extension. Apple's
extension model requires every Safari Web Extension to be packaged inside a host app: this
folder is that shell.

## Why this exists

Safari Web Extensions cannot be sideloaded the way Chromium / Firefox extensions can. They
are bundled into a `.app`, signed with an Apple Developer ID, optionally notarized, and
distributed through the App Store (or, for development builds, sideloaded by enabling the
"Allow Unsigned Extensions" toggle in Safari -> Develop). The host app's only job is to
present a settings/about window and ensure the bundled extension shows up in
Safari -> Settings -> Extensions.

The actual extension logic -- popup, content script, background page, WASM -- lives in
`../ext/` and is staged into the Xcode project at build time by `xcrun
safari-web-extension-converter`.

## Repository layout

```
safari-host-app/
+-- README.md         # this file
+-- Package.swift     # Swift Package -- minimal target so the Swift code stays compilable
|                     # without an Xcode project; the real `.app` is produced by Xcode
|                     # via the converter (below).
+-- Sources/
    +-- RagewardenHost/
        +-- main.swift
```

The `Package.swift` produces a CLI binary; the actual macOS `.app` is produced by Xcode.
We keep both because:

- `swift build` runs in CI on Linux runners (the file compiles, the AppKit/SafariServices
  blocks are gated behind `#if canImport(...)`), so a regression in the host-app source
  blocks merge.
- The Xcode project is intentionally not committed here -- Xcode project files are noisy
  XML diffs that don't survive automated edits well. A human developer regenerates them
  with `xcrun safari-web-extension-converter`.

## Generating the Xcode project

From the repo root, after building the extension into `dist/safari/`:

```bash
node ragemanifest/build.mjs safari --with-wasm
xcrun safari-web-extension-converter \
    ragemanifest/dist/safari \
    --project-location ragemanifest/safari-host-app/build \
    --bundle-identifier com.ragewarden.safari \
    --app-name "Ragewarden" \
    --no-prompt --no-open
```

The converter writes `build/Ragewarden/Ragewarden.xcodeproj`. The host-app target it
generates is conventional Swift + AppKit + SafariServices code. The `main.swift` here
mirrors the pattern Apple's template uses, so when the converter overwrites the target
sources at upgrade time the diff stays small.

## Distribution channels

| channel | requirements |
|---|---|
| Local development | Xcode -> "Run" -- sideloads the extension into the running Safari. Toggle Safari -> Develop -> "Allow Unsigned Extensions" to enable. |
| Direct download (`.dmg`) | Apple Developer Program membership ($99/year). Sign with `codesign`, notarize with `xcrun notarytool`. Stamp the ticket onto the `.dmg`. |
| Mac App Store | Apple Developer Program membership ($99/year) + App Store Connect submission. Apple's reviewer runs the host app in their environment; expect feedback on the host-app UI specifically (Apple expects more than a stub window). |

The Mac App Store is the canonical channel for end users; direct download is the escape
hatch for users who don't want to use the App Store. Both share the same signed binary.

## Native messaging caveat

Safari Web Extensions cannot use `chrome.runtime.connectNative`. The PIV-via-rageterm
path that lights up in Chromium and Firefox is **post-MVP on Safari** and requires the
host app to bridge via `NSExtensionContext` + a separate XPC service -- design work
captured in `ragemanifest/DESIGN.md` §5 and §6.

## Source of truth

- Extension code: `ragemanifest/ext/`
- Extension-to-Safari converter: `xcrun safari-web-extension-converter` (Apple)
- Distribution checklists: `../../SECURITY.md` (release-gate ceremonies)
- Apple Developer ID setup, App Store submission: external Apple developer docs
