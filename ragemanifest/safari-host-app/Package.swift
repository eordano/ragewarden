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
        )
    ]
)
