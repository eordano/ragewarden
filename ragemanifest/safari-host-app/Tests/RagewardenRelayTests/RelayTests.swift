import Foundation
import XCTest

@testable import RagewardenRelay

/// The relay against stand-in rageterms: small perl scripts speaking the
/// native-messaging framing (4-byte little-endian length, then JSON).
final class RelayTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("relay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func fakeRageterm(_ body: String) throws -> URL {
        let url = dir.appendingPathComponent("rageterm")
        let script = "#!/usr/bin/perl\nbinmode STDIN; binmode STDOUT;\n" + body + "\n"
        try script.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url
    }

    private static let readFrame = """
        read(STDIN, my $h, 4) == 4 or exit 1;
        my $n = unpack('V', $h);
        read(STDIN, my $body, $n) == $n or exit 1;
        """

    func testOneFramedRequestGoesToNativeHostModeAndTheFramedReplyComesBack() throws {
        let exe = try fakeRageterm(Self.readFrame + """

            my $r = '{"ok":true,"arg":"' . $ARGV[0] . '","home":"' . $ENV{HOME} . '","config":"'
                . $ENV{RAGEWARDEN_CONFIG_DIR} . '","got":' . $body . '}';
            print pack('V', length $r), $r;
            """)
        let reply = SafariWebExtensionHandler.relay(
            ["method": "unwrap_stanza", "challenge": "Y2hhbA=="], executable: exe, home: "/tmp/fake-home")
        let r = try XCTUnwrap(reply as? [String: Any])
        XCTAssertEqual(r["ok"] as? Bool, true)
        XCTAssertEqual(r["arg"] as? String, "native-host")
        XCTAssertEqual(r["home"] as? String, "/tmp/fake-home")
        if ProcessInfo.processInfo.environment["RAGEWARDEN_CONFIG_DIR"] == nil {
            XCTAssertEqual(r["config"] as? String, "/tmp/fake-home/.config/ragewarden")
        }
        let got = try XCTUnwrap(r["got"] as? [String: Any])
        XCTAssertEqual(got["method"] as? String, "unwrap_stanza")
        XCTAssertEqual(got["challenge"] as? String, "Y2hhbA==")
    }

    func testARagetermThatAnswersNothingIsAnError() throws {
        let exe = try fakeRageterm(Self.readFrame + "\nexit 0;")
        let r = try XCTUnwrap(SafariWebExtensionHandler.relay(["method": "probe"], executable: exe) as? [String: Any])
        XCTAssertEqual(r["ok"] as? Bool, false)
        XCTAssertEqual(r["error"] as? String, "rageterm closed without a reply")
    }

    func testARagetermThatExitsBeforeReadingIsAnErrorNotACrash() throws {
        let exe = try fakeRageterm("exit 3;")
        let r = try XCTUnwrap(SafariWebExtensionHandler.relay(["method": "probe"], executable: exe) as? [String: Any])
        XCTAssertEqual(r["ok"] as? Bool, false)
    }

    func testAnOversizedReplyIsRefused() throws {
        let exe = try fakeRageterm(Self.readFrame + "\nprint pack('V', 0x7fffffff); select(undef, undef, undef, 5);")
        let r = try XCTUnwrap(SafariWebExtensionHandler.relay(["method": "probe"], executable: exe) as? [String: Any])
        XCTAssertEqual(r["ok"] as? Bool, false)
        XCTAssertEqual(r["error"] as? String, "rageterm's reply is larger than \(SafariWebExtensionHandler.maxReply) bytes")
    }

    func testNoRagetermIsAnError() throws {
        let r = try XCTUnwrap(SafariWebExtensionHandler.relay(["method": "probe"], executable: nil) as? [String: Any])
        XCTAssertEqual(r["ok"] as? Bool, false)
        XCTAssertEqual(r["error"] as? String, "rageterm is not installed where the Safari app can run it")
    }
}
