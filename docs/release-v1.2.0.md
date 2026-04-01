# Ecliptix Protected Protocol v1.2.0

## Release Summary

This release aligns the Rust crate, C headers, Swift wrapper, tests, and release documentation around the current FFI snapshot.

Highlights:

- public `EPP_ERROR_BUSY = 29` exported across Rust, C, and Swift
- manual time provider is now explicitly forward-only
- low-level VoIP destroy APIs use `**handle`, null the slot, and are safe on repeated destroy
- padding validation tightened for malformed input rejection
- release docs and package metadata refreshed to a single snapshot

## Migration Notes

### C / FFI Integrators

- Treat VoIP destroy functions as pointer-to-pointer lifecycle APIs.
- Do not reuse the same native handle concurrently without external synchronisation.
- Treat backward manual clock updates as `EPP_ERROR_INVALID_INPUT`.

### Swift Integrators

- `EppError.busy` is now part of the public mapping.
- `EppTimeProvider.setNowUnix(_:)` is forward-only.
- Existing high-level VoIP Swift objects already call the updated nulling destroy functions correctly.

## Validation Snapshot

- `cargo fmt --check`
- `cargo test --features ffi --tests --no-run`
- targeted regressions for busy-handle contention, backward clock rejection, VoIP destroy idempotence, and malformed padding rejection
- latest reported full run for this snapshot: `93` integration + `116` FFI + `2` FFI proptest suites passed

## Release Artifacts

- Git tag: `v1.2.0`
- Swift binary target artifact: `ecliptix-protected-protocol.xcframework.zip`
- Release checksum must match the value committed in the root `Package.swift`

See also: `docs/release-snapshot.md`
