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
            path: "dist/apple/AuraProtectedProtocol.xcframework"
        ),
        .target(
            name: "AuraProtectedProtocolSwift",
            dependencies: ["AuraProtectedProtocol"],
            path: "swift/Sources/AuraProtectedProtocol"
        )
    ]
)
