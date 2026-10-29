// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RagewardenHost",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "RagewardenHost", targets: ["RagewardenHost"])
    ],
    targets: [
        .executableTarget(
            name: "RagewardenHost",
            path: "Sources/RagewardenHost"
        ),
        // The Safari extension's native-messaging relay, built here so it has tests;
        // build.sh copies the same file into the converter's extension target.
        .target(
            name: "RagewardenRelay",
            path: "Extension"
        ),
        .testTarget(
            name: "RagewardenRelayTests",
            dependencies: ["RagewardenRelay"],
            path: "Tests/RagewardenRelayTests"
        ),
    ]
)
