// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EcliptixProtectedProtocol",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "EcliptixProtectedProtocol",
            targets: ["EcliptixProtectedProtocolSwift", "EcliptixProtectedProtocol"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixProtectedProtocol",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.2.0/ecliptix-protected-protocol.xcframework.zip",
            checksum: "a98af0a12cca48238ea9af2da495c7b314fd3c084c938c12d82d700be3c4b0e5"
        ),
        .target(
            name: "EcliptixProtectedProtocolSwift",
            dependencies: ["EcliptixProtectedProtocol"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
