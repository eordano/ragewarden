import Foundation
import SafariServices

/// Relays the extension's native messages (browser.runtime.sendNativeMessage) to
/// `rageterm native-host`: one length-prefixed JSON request in, one reply out,
/// exactly the frames Chromium and Firefox exchange with it. The rageterm the
/// app bundles is preferred; otherwise the usual install locations are tried.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey]
        let reply: Any
        if let message = message, JSONSerialization.isValidJSONObject(message) {
            reply = Self.relay(message)
        } else {
            reply = ["ok": false, "error": "the extension sent no JSON message"]
        }
        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: reply]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    static let maxReply = 1 << 20

    /// The user's home, not the sandbox container NSHomeDirectory() returns.
    static func realHome() -> String {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return NSHomeDirectory() }
        return String(cString: dir)
    }

    static func ragetermURL() -> URL? {
        if let bundled = Bundle.main.url(forAuxiliaryExecutable: "rageterm") {
            return bundled
        }
        let candidates = [
            "/opt/homebrew/bin/rageterm",
            "/usr/local/bin/rageterm",
            realHome() + "/.nix-profile/bin/rageterm",
            "/etc/profiles/per-user/" + NSUserName() + "/bin/rageterm",
            "/run/current-system/sw/bin/rageterm",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }

    static func relay(_ message: Any, executable: URL? = ragetermURL(), home: String = realHome()) -> Any {
        guard let exe = executable else {
            return ["ok": false, "error": "rageterm is not installed where the Safari app can run it"]
        }
        // A rageterm that exits before reading must fail the request, not kill the extension.
        signal(SIGPIPE, SIG_IGN)
        do {
            let payload = try JSONSerialization.data(withJSONObject: message)
            let process = Process()
            process.executableURL = exe
            process.arguments = ["native-host"]
            // A sandboxed process's HOME is its container; rageterm's identities
            // live under the user's ~/.config/ragewarden.
            var env = ProcessInfo.processInfo.environment
            env["HOME"] = home
            if env["RAGEWARDEN_CONFIG_DIR"] == nil {
                env["RAGEWARDEN_CONFIG_DIR"] = home + "/.config/ragewarden"
            }
            process.environment = env
            let input = Pipe()
            let output = Pipe()
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            try process.run()

            var length = UInt32(payload.count).littleEndian
            try input.fileHandleForWriting.write(contentsOf: Data(bytes: &length, count: 4) + payload)
            try input.fileHandleForWriting.close()

            let header = output.fileHandleForReading.readData(ofLength: 4)
            guard header.count == 4 else {
                process.terminate()
                return ["ok": false, "error": "rageterm closed without a reply"]
            }
            let size = Int(UInt32(littleEndian: header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }))
            guard size <= maxReply else {
                process.terminate()
                return ["ok": false, "error": "rageterm's reply is larger than \(maxReply) bytes"]
            }
            let body = output.fileHandleForReading.readData(ofLength: size)
            process.waitUntilExit()
            return try JSONSerialization.jsonObject(with: body)
        } catch {
            return ["ok": false, "error": "relay to rageterm failed: \(error.localizedDescription)"]
        }
    }
}
