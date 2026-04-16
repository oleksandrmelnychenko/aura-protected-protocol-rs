// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraProtectedProtocol",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "AuraProtectedProtocol",
            targets: ["AuraProtectedProtocolSwift", "AuraProtectedProtocol"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "AuraProtectedProtocol",
            url: "https://github.com/oleksandrmelnychenko/aura-protected-protocol-rs/releases/download/v2.0.0/aura-protected-protocol.xcframework.zip",
            checksum: "PENDING_V2_0_0_RELEASE"
        ),
        .target(
            name: "AuraProtectedProtocolSwift",
            dependencies: ["AuraProtectedProtocol"],
            path: "swift/Sources/AuraProtectedProtocol"
        )
    ]
)
