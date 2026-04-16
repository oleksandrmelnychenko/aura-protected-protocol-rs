# Aura Protected Protocol v2.0.0 — Rebrand Release

**Date:** 2026-04-16
**Status:** Breaking change release

## Summary

Full rename from the previous `ecliptix-protected-protocol` project to **`aura-protected-protocol`**, backing the `auramessenger.ai` product. Every identifier, wire label, symbol, and artifact name has changed — this release is **not wire-compatible** with any prior version.

## Breaking changes

### Crate / package

| Layer | Before | After |
|---|---|---|
| Cargo package | `ecliptix-protocol` | `aura-protected-protocol` |
| Rust lib name | `ecliptix_protocol` | `aura_protected_protocol` |
| Swift Package | `EcliptixProtectedProtocol` | `AuraProtectedProtocol` |
| C framework | `EcliptixProtocolC` | `AuraProtectedProtocolC` |
| C symbol prefix | `epp_*` | `aura_*` |
| Swift type prefix | `Epp*` | `Aura*` |
| xcframework asset | `ecliptix-protected-protocol.xcframework.zip` | `aura-protected-protocol.xcframework.zip` |
| Proto packages | `ecliptix.proto.{protocol,e2e}` | `aura.proto.{protocol,e2e}` |

### Wire-protocol labels (HKDF info / AAD / personalization)

All cryptographic context labels were reworded from `Ecliptix-*` / `ecliptix-*` to `Aura-*` / `aura-*` (e.g. `Ecliptix-X3DH` → `Aura-X3DH`, `Ecliptix-Hybrid-Ratchet` → `Aura-Hybrid-Ratchet`, `ecliptix-identity-ed25519` → `aura-identity-ed25519`). Sessions, envelopes, group commits, and VoIP frames produced by v1.x **will not decrypt** on v2.0.0 clients (by design — separate product).

### Proto schema package

`package ecliptix.proto.protocol;` → `package aura.proto.protocol;`
`package ecliptix.proto.e2e;` → `package aura.proto.e2e;`

Generated Rust modules are now at `OUT_DIR/aura.proto.protocol.rs` and `OUT_DIR/aura.proto.e2e.rs`.

### C headers

Renamed with matching include-guard updates:

- `include/epp_api.h` → `include/aura_api.h`
- `include/epp_export.h` → `include/aura_export.h`
- `include/epp_client_api.h` → `include/aura_client_api.h`
- `include/epp_common_api.h` → `include/aura_common_api.h`

All exported FFI functions renamed `epp_*` → `aura_*`. All error codes renamed `EppError*` → `AuraError*` (ABI values unchanged).

### Swift surface

Source directory `swift/Sources/EcliptixProtectedProtocol/` → `swift/Sources/AuraProtectedProtocol/`. All types (`EppSession` → `AuraSession`, `EppCrypto` → `AuraCrypto`, etc.) and the `import EcliptixProtocolC` → `import AuraProtectedProtocolC` module import have changed.

## Deleted

- `docs/release-v1.0.1.md`, `docs/release-v1.2.0.md`, `docs/release-snapshot.md` — superseded. Old GitHub release assets remain under the prior repository/tag for archival.
- `dist/apple/ecliptix-protected-protocol.xcframework*` — regenerate via build script.
- `dist/frameworks/{ios-arm64,ios-sim,macos-arm64}` — regenerate.

## Migration path

There is no in-place migration. v2.0.0 is a new product. Clients must be rebuilt against the new crate / Package and will generate incompatible session state.

## Verification

After rebuild:

```bash
cargo build --release --features ffi
cargo test --all-features
cargo clippy --all-targets -- -D warnings
```

Then rebuild the xcframework, publish as a GitHub release asset, and update `Package.swift` `checksum:` with the SHA-256 of the uploaded zip.
