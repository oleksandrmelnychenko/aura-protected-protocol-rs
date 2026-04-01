# Current Repository Snapshot

Date: 2026-04-01

This document records the current integration/documentation snapshot for the repository HEAD. It is intentionally short and release-facing: use it to keep README, headers, Swift wrappers, tests, and release notes aligned.

## Contract Snapshot

- Low-level VoIP destroy entry points now take `**handle`, set `*handle = NULL`, and are idempotent on repeated destroy.
- `EPP_ERROR_BUSY = 29` is part of the public C and Swift surface and is returned when the same native handle is used concurrently.
- Manual time providers are forward-only. Calling `set_now` / `setNowUnix(_:)` with an older timestamp now fails with `EPP_ERROR_INVALID_INPUT`.
- Padding validation now explicitly rejects malformed inputs (empty, non-aligned, missing sentinel, non-zero tail after sentinel).

## Validation Snapshot

- `cargo fmt --check`
- `cargo test --features ffi --tests --no-run`
- Targeted regressions added for:
  - backward manual-clock rejection
  - `EPP_ERROR_BUSY` on session/group/VoIP handle contention
  - VoIP destroy nulling + idempotence
  - malformed padding rejection
- Latest full validation run reported for this snapshot:
  - `93` integration tests passed
  - `116` FFI tests passed
  - `2` FFI proptest suites passed

## Release Hygiene

- Rebuild and republish the XCFramework before the next tagged release.
- Update the root `Package.swift` binary-target URL and checksum together with the published artifact.
- Keep `README.md`, `docs/ffi-api.md`, `docs/ffi-swift.md`, C headers, and Swift wrappers in lockstep whenever the FFI contract changes.
