import Foundation
#if canImport(AppKit)
import AppKit
#endif
#if canImport(SafariServices)
import SafariServices
#endif

#if canImport(AppKit) && canImport(SafariServices)
final class RagewardenHostAppDelegate: NSObject, NSApplicationDelegate {
    private let extensionBundleIdentifier = "com.ragewarden.safari.extension"

    func applicationDidFinishLaunching(_ notification: Notification) {
        SFSafariExtensionManager.getStateOfSafariExtension(withIdentifier: extensionBundleIdentifier) { state, error in
            DispatchQueue.main.async {
                if let error = error {
                    FileHandle.standardError.write(Data("ragewarden host: extension state lookup failed: \(error)\n".utf8))
                    return
                }
                guard let state = state else { return }
                if !state.isEnabled {
                    SFSafariApplication.showPreferencesForExtension(withIdentifier: self.extensionBundleIdentifier) { err in
                        if let err = err {
                            FileHandle.standardError.write(Data("ragewarden host: openPreferences failed: \(err)\n".utf8))
                        }
                    }
                }
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = RagewardenHostAppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
#else
print("RagewardenHost: this binary only runs on macOS with AppKit + SafariServices.")
#endif
