# Ecliptix Protected Protocol v1.0.1

## Summary

- hardened the core protocol defaults and removed implicit legacy permissive paths
- added mandatory authorization for external group join flows
- bound handshake identity material more strictly to close misbinding risk
- enforced group franking policy on receive path, not only sender path
- aligned Rust, C FFI, and Swift wrappers around the same security model
- improved Swift session verification UX with peer identity, binding hash, and verified handshake helpers
- removed stale audit PoCs and dead key-abstraction code

## Swift Package Manager

```swift
.binaryTarget(
    name: "EcliptixProtectedProtocolBinary",
    url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.1/ecliptix-protected-protocol.xcframework.zip",
    checksum: "7d5f43bd4eb899d0837d34754d727db48d2fe52ebe2e2c57071c3097775ace85"
)
```

## Release Artifacts

- archive: `dist/apple/ecliptix-protected-protocol.xcframework.zip`
- sha256: `7d5f43bd4eb899d0837d34754d727db48d2fe52ebe2e2c57071c3097775ace85`

## Notable Breaking Changes

- default group creation now uses a hardened shielded posture
- external join now requires an explicit authorization artifact
- Swift and FFI consumers should verify peers via identity APIs instead of trusting handshake completion alone
- group decrypt FFI result now exposes sealed/franking payload details directly

## Verification Performed

- `cargo fmt`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- local Apple release staticlibs built for:
  - `aarch64-apple-darwin`
  - `aarch64-apple-ios`
  - `aarch64-apple-ios-sim`
  - `x86_64-apple-ios`
- local XCFramework archive and checksum generated from the same build flow as CI
