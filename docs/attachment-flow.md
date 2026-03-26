# Attachment Flow (without transport implementation)

This document defines the EPP attachment contract when file upload/download is implemented outside the protocol stack (gRPC, HTTP, object storage, CDN, etc.).

## Scope

- EPP provides cryptography and strict validation for attachment metadata/chunks.
- Integrator transport provides upload/download, storage, authz, and delivery semantics.
- EPP chat messages carry only metadata plus wrapped keys, not raw media bytes.

## Security model

1. Generate random `attachment_id` and random per-file `file_key` (DEK).
2. Encrypt file by chunks using AEAD and deterministic nonce derivation tied to attachment context.
3. Wrap `file_key` with existing chat channel cryptography and include the wrapped key in `AttachmentManifest`.
4. Send `AttachmentManifest` in chat payload.
5. Upload encrypted chunks to external transport/storage keyed by `attachment_id`.
6. Receiver unwraps `file_key` from chat path, validates manifest/chunks, downloads chunks, decrypts locally.

Relay/storage never gets plaintext media or plaintext `file_key`.

## FFI API responsibilities

- `epp_attachment_generate_id`: returns a new 32-byte id.
- `epp_attachment_generate_file_key`: returns a new 32-byte DEK.
- `epp_attachment_encrypt_chunk`: encrypts one plaintext chunk.
- `epp_attachment_decrypt_chunk`: decrypts one encrypted chunk.
- `epp_attachment_manifest_create`: builds protobuf `AttachmentManifest`.
- `epp_attachment_manifest_validate`: validates full manifest.
- `epp_attachment_chunk_validate`: validates encrypted chunk structure against manifest.

`AttachmentManifest` also includes optional `collage_index` for collage Threads ordering.

## Transport contract (integrator responsibilities)

- Enforce authenticated access for upload/download by user/device/group policy.
- Enforce file/chunk size caps and rate limits before storage writes.
- Persist chunks as opaque ciphertext bytes.
- Define chunk ordering policy (`index` based), dedup behavior, and resume behavior.
- Support idempotent retries for upload and chunk fetch.
- Never log plaintext media, unwrapped file keys, or decrypted previews.
- If multiple attachments belong to one collage Threads message, set `collage_index` to preserve display order.

## Recommended sender flow

1. Create `attachment_id` and `file_key`.
2. Split file into chunks under policy max chunk size.
3. Encrypt each chunk with `epp_attachment_encrypt_chunk`.
4. Compute whole-file hash over plaintext (or enforce documented policy consistently).
5. Wrap `file_key` using session/group channel crypto.
6. Create manifest via `epp_attachment_manifest_create`.
7. Send manifest through chat channel.
8. Upload encrypted chunks to transport endpoint.

## Recommended receiver flow

1. Receive manifest from chat channel.
2. Validate manifest via `epp_attachment_manifest_validate`.
3. Unwrap `encrypted_file_key` through channel crypto.
4. Download encrypted chunks from transport by `attachment_id`.
5. For each chunk, run `epp_attachment_chunk_validate`.
6. Decrypt chunk via `epp_attachment_decrypt_chunk`.
7. Reassemble file and verify declared file hash/size.

## Failure handling

- Validation failure: reject attachment and do not persist rollback markers from invalid artifacts.
- Missing chunk: treat as incomplete upload/download state; retry according to transport policy.
- Decrypt failure: treat as tampering/corruption; abort reassembly.
- Hash mismatch: reject final file and quarantine chunk set.
