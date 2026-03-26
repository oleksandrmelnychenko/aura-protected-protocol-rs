# Ecliptix Protected Protocol v1.0.1

## Security Hardening Update

This patch release focuses on resource-exhaustion and input-validation hardening.

- Added strict bounds for protocol parsing and encryption inputs (protobuf, envelopes, plaintext buffers).
- Added explicit caps for `PreKeyBundle` one-time pre-key count and in-flight handshake init reservations.
- Standardized Ed25519 verification to strict mode in critical verification paths.
- Removed a redundant relay decode step for group-message validation.
- Expanded regression coverage for size/count limits and validation behavior.

## Limits Added/Enforced

- `MAX_PROTOBUF_MESSAGE_SIZE`: 1 MiB
- `MAX_ENVELOPE_MESSAGE_SIZE`: 1 MiB
- `MAX_BUFFER_SIZE`: 10 MiB
- `MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE`: 4096
- `MAX_INFLIGHT_HANDSHAKE_INITS`: 4096

Important: limits are cumulative. Input can pass one limit and still be rejected by another.

## FFI Impact

Attachment/media FFI APIs were introduced in this release:

- `epp_attachment_generate_id`
- `epp_attachment_generate_file_key`
- `epp_attachment_encrypt_chunk`
- `epp_attachment_decrypt_chunk`
- `epp_attachment_manifest_create`
- `epp_attachment_manifest_validate`
- `epp_attachment_chunk_validate`

Existing C/Swift session/group APIs keep backward-compatible signatures.
- Behavior is stricter: oversized inputs are rejected earlier by existing calls.

## Attachment Contract (transport out of scope)

- EPP now supports attachment envelope encryption primitives and manifest validation.
- External transport (gRPC/HTTP/object storage) remains integrator-owned.
- Relay/storage handles only ciphertext chunks and validated manifests.
- File key exchange must use existing encrypted chat channel path (wrapped file key), not plaintext side channels.

## Migration Notes

### Rust Integrators

- Treat size-related rejects as policy outcomes, not transient transport errors.
- Keep edge limits (HTTP/WebSocket/frame caps) at or below protocol limits.
- Do not retry the same oversized payload unchanged.

### C FFI Integrators

- Add preflight size checks before calling encrypt/decrypt/handshake functions.
- Handle `EPP_ERROR_INVALID_INPUT` as non-retryable unless payload is reduced/fixed.
- Preserve existing memory-management flow (`epp_buffer_release`, `epp_error_free`).

### Swift Integrators

- Add app-side payload size guards before FFI call sites.
- Map invalid-input size rejects to dedicated app errors (`payload_too_large`, `envelope_too_large`).
- Keep telemetry metadata-only (error code/type/size), without logging sensitive payload content.

## Operator Actions

Before production rollout:

1. Enable transport-level request/frame size limits.
2. Enable rate limiting and backpressure for prekey upload/replenish endpoints.
3. Confirm oversized payload paths fail fast and are covered by integration tests.
4. Verify client/server docs are aligned with these hard limits.
