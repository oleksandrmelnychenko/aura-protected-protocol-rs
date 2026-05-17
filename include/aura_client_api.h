#pragma once
#include "aura_common_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client-side E2E API — Aura Protection Protocol
 *
 * All operations here involve private key material and run entirely on the
 * client device. The relay never calls these functions.
 *
 * OWNERSHIP RULES (apply to every function in this file):
 *   - Parameters named `out_handle` write a newly allocated opaque handle.
 *     The caller owns the handle and MUST destroy it with the matching
 *     _destroy() function when done. The FFI layer does not inspect or free
 *     the previous value stored in the output slot; destroy any previous
 *     handle before passing the same slot to another call.
 *   - Parameters named `out_*` of type AuraBuffer* write a heap-allocated
 *     buffer owned by the caller. Release it with aura_buffer_release().
 *     The FFI layer does not inspect or release previous AuraBuffer contents;
 *     call aura_buffer_release() before reusing the same buffer slot.
 *
 *     CRITICAL #1 — OUTPUT INITIALIZATION: Simple `AuraBuffer*` and
 *     `out_handle` slots are overwritten without reading their prior bytes,
 *     so stack storage does not have to be pre-zeroed before a successful
 *     call.  Compound output structs such as `AuraEncryptedFrame`,
 *     `AuraDecryptedFrame`, `AuraEnvelopeMetadata`, and
 *     `AuraGroupDecryptResult` MUST still be zero-initialized before first
 *     use because their function-specific cleanup paths may inspect nested
 *     fields. In C: `AuraEncryptedFrame f = {0};` NOT
 *     `AuraEncryptedFrame f;`.
 *
 *     CRITICAL #2 — ALLOCATOR OWNERSHIP: `AuraBuffer.data` MUST always be
 *     either NULL or a pointer returned by an aura_* FFI function
 *     (aura_buffer_alloc, or written by an out_* parameter).  NEVER assign
 *     a malloc()/new/Swift-allocated pointer into `.data` — the Rust
 *     allocator uses a different heap and free()ing non-Rust memory is
 *     undefined behavior.  If you need to hand C-allocated data to the
 *     library, copy into a buffer obtained from aura_buffer_alloc() or
 *     pass it as a borrowed `(ptr, len)` slice.
 *   - Parameters named `out_error` receive an optional error detail struct.
 *     If non-NULL and an error occurs the struct is populated; free it with
 *     aura_error_free() after use.  Pass NULL to ignore error details.
 *   - All byte-slice inputs (`const uint8_t* foo, size_t foo_length`) are
 *     borrowed for the duration of the call only; the caller retains ownership.
 *   - Handles are NOT thread-safe. Do not share a single handle across threads
 *     without external synchronisation.
 *
 * ERROR HANDLING:
 *   Every fallible function returns AuraErrorCode. Check for AURA_SUCCESS (0)
 *   before reading any out_* value — they are undefined on failure.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * Opaque handle types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct AuraIdentityHandle          AuraIdentityHandle;
typedef struct AuraSessionHandle           AuraSessionHandle;
typedef struct AuraVoipSessionHandle       AuraVoipSessionHandle;
typedef struct AuraGroupSessionHandle      AuraGroupSessionHandle;
typedef struct AuraKeyPackageSecretsHandle AuraKeyPackageSecretsHandle;
typedef struct AuraHandshakeInitiatorHandle AuraHandshakeInitiatorHandle;
typedef struct AuraHandshakeResponderHandle AuraHandshakeResponderHandle;
typedef struct AuraVoipCallInitiatorHandle AuraVoipCallInitiatorHandle;
typedef struct AuraSealedStateCounterTrackerHandle AuraSealedStateCounterTrackerHandle;
typedef struct AuraSealedStateSlotHandle AuraSealedStateSlotHandle;
typedef struct AuraTimeProviderHandle AuraTimeProviderHandle;

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration structs
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraSessionConfig — tuning parameters for a 1-to-1 Double Ratchet session.
 *
 *   max_messages_per_chain
 *     Maximum number of messages that may be encrypted under a single ratchet
 *     chain key before a forced ratchet step is required.  Use 0 for the
 *     library default (100).  Smaller values improve forward secrecy at the
 *     cost of slightly more frequent key-exchange round-trips.
 */
typedef struct AuraSessionConfig {
    uint32_t max_messages_per_chain;
} AuraSessionConfig;

/*
 * AuraGroupSecurityPolicy — per-group security constraints.
 *
 *   max_messages_per_epoch
 *     Hard cap on sender-key messages before a mandatory Update commit is
 *     required.  0 = library default (1000).
 *
 *   max_skipped_keys_per_sender
 *     Maximum number of out-of-order message keys cached per sender.
 *     Prevents memory exhaustion from artificially skipped messages.
 *     0 = library default (32).
 *
 *   block_external_join
 *     Non-zero: reject ExternalInit commits from outside the group.
 *     Use when all members must be invited via Welcome.
 *
 *   enhanced_key_schedule
 *     Non-zero: enable the extended HKDF domain-separation labels that
 *     provide stronger key isolation between epochs.
 *
 *   mandatory_franking
 *     Non-zero: all outgoing group messages MUST include a franking tag.
 *     Calls to aura_group_encrypt() (non-frankable) will return
 *     AURA_ERROR_INVALID_STATE when this flag is set.
 */
typedef struct AuraGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;
    uint32_t max_skipped_keys_per_sender;
    uint8_t  block_external_join;
    uint8_t  enhanced_key_schedule;
    uint8_t  mandatory_franking;
} AuraGroupSecurityPolicy;

/*
 * aura_sealed_state_counter_tracker_* — managed anti-rollback helper for sealed
 * session/group/VoIP state slots.
 *
 * This tracker persists the two values required to use sealed-state rollback
 * protection correctly:
 *   - max_restored_counter: highest blob counter already accepted on restore.
 *   - latest_issued_counter: highest counter already used for export.
 *
 * Prefer aura_sealed_state_slot_* plus the `*_persisted_state` APIs for new
 * clients. The tracker APIs are the lower-level managed surface when the
 * application still wants to store the sealed blob separately.
 */
AURA_API AuraErrorCode aura_sealed_state_counter_tracker_create(
    AuraSealedStateCounterTrackerHandle** out_handle,
    AuraError*                            out_error);

/*
 * Recreate a tracker from bytes previously returned by
 * aura_sealed_state_counter_tracker_serialize().
 */
AURA_API AuraErrorCode aura_sealed_state_counter_tracker_create_from_serialized(
    const uint8_t*                       data,
    size_t                               data_length,
    AuraSealedStateCounterTrackerHandle** out_handle,
    AuraError*                            out_error);

/*
 * Serialize the tracker so it can be persisted next to the sealed blob for
 * the same slot.
 */
AURA_API AuraErrorCode aura_sealed_state_counter_tracker_serialize(
    AuraSealedStateCounterTrackerHandle* handle,
    AuraBuffer*                          out_state,
    AuraError*                           out_error);

AURA_API AuraErrorCode aura_sealed_state_counter_tracker_get_max_restored_counter(
    AuraSealedStateCounterTrackerHandle* handle,
    uint64_t*                           out_counter,
    AuraError*                           out_error);

AURA_API AuraErrorCode aura_sealed_state_counter_tracker_get_latest_issued_counter(
    AuraSealedStateCounterTrackerHandle* handle,
    uint64_t*                           out_counter,
    AuraError*                           out_error);

AURA_API void aura_sealed_state_counter_tracker_destroy(
    AuraSealedStateCounterTrackerHandle** handle);

/*
 * aura_sealed_state_slot_* — single-record sealed-state persistence helper.
 *
 * A slot bundles the latest sealed blob together with the tracker state in one
 * serializable object. This removes the "blob and tracker stored separately"
 * crash-consistency footgun. Persist the serialized slot as a single record.
 *
 * IMPORTANT: this improves atomicity, not the fundamental rollback model. A
 * storage attacker who can replace the entire slot with an older serialized
 * slot still defeats rollback protection unless the application also relies on
 * trusted monotonic storage outside that slot.
 */
AURA_API AuraErrorCode aura_sealed_state_slot_create(
    AuraSealedStateSlotHandle** out_handle,
    AuraError*                  out_error);

AURA_API AuraErrorCode aura_sealed_state_slot_create_from_serialized(
    const uint8_t*             data,
    size_t                     data_length,
    AuraSealedStateSlotHandle** out_handle,
    AuraError*                  out_error);

AURA_API AuraErrorCode aura_sealed_state_slot_serialize(
    AuraSealedStateSlotHandle* handle,
    AuraBuffer*                out_state,
    AuraError*                 out_error);

AURA_API AuraErrorCode aura_sealed_state_slot_get_max_restored_counter(
    AuraSealedStateSlotHandle* handle,
    uint64_t*                 out_counter,
    AuraError*                 out_error);

AURA_API AuraErrorCode aura_sealed_state_slot_get_latest_issued_counter(
    AuraSealedStateSlotHandle* handle,
    uint64_t*                 out_counter,
    AuraError*                 out_error);

AURA_API void aura_sealed_state_slot_destroy(
    AuraSealedStateSlotHandle** handle);

/*
 * AuraGroupDecryptResult — full metadata returned by aura_group_decrypt_ex().
 *
 *   plaintext
 *     Decrypted message content.  Owned by the caller; release all AuraBuffer
 *     fields inside this struct with aura_group_decrypt_result_free().
 *     Do NOT call aura_buffer_release() on individual fields manually.
 *
 *   sender_leaf_index
 *     Zero-based leaf index of the sending member in the ratchet tree.
 *     Use aura_group_get_member_leaf_indices() to map indices to credentials.
 *
 *   generation
 *     Per-sender message counter within the current epoch (starts at 0).
 *     Together with epoch + sender_leaf_index this uniquely identifies a
 *     message; use aura_group_compute_message_id() to derive the canonical ID.
 *
 *   content_type
 *     Message subtype: 0=normal, 1=sealed, 2=disappearing, 3=frankable,
 *     4=edit, 5=delete.
 *
 *   ttl_seconds
 *     For disappearing messages: time-to-live in seconds from sent_timestamp.
 *     0 for non-disappearing messages.
 *
 *   sent_timestamp
 *     Unix timestamp (seconds) embedded by the sender at encryption time.
 *     Not authenticated by the protocol; treat as informational only.
 *
 *   message_id
 *     Canonical message identifier bytes (32 bytes).
 *
 *   referenced_message_id
 *     For edit/delete messages: the message_id being edited or deleted.
 *     Empty (length == 0) for all other content types.
 *
 *   has_sealed_payload
 *     Non-zero when the message carries a sealed (two-layer) encrypted
 *     payload.  Use aura_group_reveal_sealed() to decrypt the inner layer.
 *
 *   has_franking_data
 *     Non-zero when the message carries a franking tag and franking key
 *     suitable for abuse reporting via aura_group_verify_franking().
 *
 *   sealed_*
 *     Present only when has_sealed_payload != 0.  These buffers provide the
 *     exact inputs required by aura_group_reveal_sealed().
 *
 *   franking_*
 *     Present only when has_franking_data != 0.  These buffers provide the
 *     exact inputs required by aura_group_verify_franking().
 */
typedef struct {
    AuraBuffer plaintext;
    uint32_t  sender_leaf_index;
    uint32_t  generation;
    uint32_t  content_type;
    uint32_t  ttl_seconds;
    uint64_t  sent_timestamp;
    AuraBuffer message_id;
    AuraBuffer referenced_message_id;
    uint8_t   has_sealed_payload;
    uint8_t   has_franking_data;
    AuraBuffer sealed_hint;
    AuraBuffer sealed_encrypted_content;
    AuraBuffer sealed_nonce;
    AuraBuffer sealed_key;
    AuraBuffer franking_tag;
    AuraBuffer franking_key;
    AuraBuffer franking_content;
    AuraBuffer franking_sealed_content;
} AuraGroupDecryptResult;


/* ═══════════════════════════════════════════════════════════════════════════
 * Identity
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_identity_create — generate a fresh identity with random keys.
 *
 * Creates a new long-term identity consisting of:
 *   - X25519 Diffie-Hellman key pair (classic DH for X3DH)
 *   - Ed25519 signing key pair      (signature authentication)
 *   - ML-KEM-768 key pair           (post-quantum KEM; historical API names use "kyber")
 *
 * Parameters:
 *   out_handle  — receives a pointer to the newly allocated identity handle.
 *                 Must be destroyed with aura_identity_destroy() when done.
 *   out_error   — optional; receives error detail on failure.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_identity_create(
    AuraIdentityHandle** out_handle,
    AuraError*           out_error);

/*
 * aura_identity_create_from_seed — derive a deterministic identity from a seed.
 *
 * Derives all key pairs via HKDF from the provided seed bytes.  The same
 * seed always produces the same identity.  Use at least 32 bytes of
 * cryptographically random material as the seed.
 *
 * Parameters:
 *   seed         — pointer to seed bytes (borrowed for the duration of call).
 *   seed_length  — byte length of seed; minimum 16, recommended >= 32.
 *   out_handle   — receives the newly allocated identity handle.
 *   out_error    — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_identity_create_from_seed(
    const uint8_t*      seed,
    size_t              seed_length,
    AuraIdentityHandle** out_handle,
    AuraError*           out_error);

/*
 * aura_identity_create_with_context — derive a deterministic identity bound
 * to a membership context string.
 *
 * Like aura_identity_create_from_seed() but additionally mixes a
 * membership_id string into the key derivation.  This allows the same
 * root seed to produce different identities for different services or
 * group contexts without risk of key reuse.
 *
 * Parameters:
 *   seed                — seed bytes (borrowed).
 *   seed_length         — byte length of seed; minimum 16, recommended >= 32.
 *   membership_id       — arbitrary UTF-8 string identifying the context
 *                         (e.g. "service:v1:user42").  Not required to be
 *                         null-terminated; length is given explicitly.
 *   membership_id_length — byte length of membership_id.
 *   out_handle          — receives the newly allocated identity handle.
 *   out_error           — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_identity_create_with_context(
    const uint8_t*      seed,
    size_t              seed_length,
    const char*         membership_id,
    size_t              membership_id_length,
    AuraIdentityHandle** out_handle,
    AuraError*           out_error);

/*
 * aura_time_provider_manual_create — create a mutable manual clock handle.
 *
 * Manual time providers are intended for tests, deterministic replay, or
 * environments that want to drive time-sensitive protocol checks from an
 * application-managed trusted clock. Identity handles use the system clock by
 * default until aura_identity_set_time_provider() is called.
 */
AURA_API AuraErrorCode aura_time_provider_manual_create(
    uint64_t                initial_now_unix,
    AuraTimeProviderHandle** out_handle,
    AuraError*               out_error);

/*
 * aura_time_provider_manual_set_now_unix — advance a manual clock.
 *
 * Fails if handle is NULL, destroyed, not a manual provider, or `now_unix`
 * would move the clock backwards.
 */
AURA_API AuraErrorCode aura_time_provider_manual_set_now_unix(
    AuraTimeProviderHandle* handle,
    uint64_t               now_unix,
    AuraError*              out_error);

/*
 * aura_identity_set_time_provider — bind an identity handle to a clock.
 *
 * Identity-bound operations such as handshake start/finish, group create/join,
 * ExternalInit join, and VoIP call establishment inherit this provider. Pass
 * NULL as time_provider_handle to reset the identity back to the system clock.
 */
AURA_API AuraErrorCode aura_identity_set_time_provider(
    AuraIdentityHandle*          handle,
    const AuraTimeProviderHandle* time_provider_handle,
    AuraError*                   out_error);

/*
 * aura_identity_get_x25519_public — copy the X25519 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle (not NULL, not destroyed).
 *   out_key         — caller-allocated buffer to receive the 32-byte key.
 *   out_key_length  — size of out_key in bytes; must be >= 32.
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_BUFFER_TOO_SMALL.
 */
AURA_API AuraErrorCode aura_identity_get_x25519_public(
    const AuraIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    AuraError*                out_error);

/*
 * aura_identity_get_ed25519_public — copy the Ed25519 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle.
 *   out_key         — caller-allocated buffer; must be >= 32 bytes.
 *   out_key_length  — size of out_key in bytes.
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_BUFFER_TOO_SMALL.
 */
AURA_API AuraErrorCode aura_identity_get_ed25519_public(
    const AuraIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    AuraError*                out_error);

/*
 * aura_identity_get_kyber_public — copy the ML-KEM-768 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle.
 *   out_key         — caller-allocated buffer; must be >= 1184 bytes (ML-KEM-768
 *                     public key size).
 *   out_key_length  — size of out_key in bytes.
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_BUFFER_TOO_SMALL.
 */
AURA_API AuraErrorCode aura_identity_get_kyber_public(
    const AuraIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    AuraError*                out_error);

/*
 * aura_identity_destroy — free an identity handle and securely wipe
 * all private key material.
 *
 * Sets *handle to NULL after freeing.  Safe to call with *handle == NULL
 * (no-op).  Do not use the handle after this call.
 *
 * Parameters:
 *   handle — pointer-to-pointer returned by an aura_identity_create* call.
 */
AURA_API void aura_identity_destroy(AuraIdentityHandle** handle);

/*
 * aura_time_provider_destroy — free a manual time provider handle. Safe to call
 * with NULL.
 */
AURA_API void aura_time_provider_destroy(AuraTimeProviderHandle** handle_ptr);


/* ═══════════════════════════════════════════════════════════════════════════
 * Prekey bundle
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraSessionPeerIdentity — fixed-size struct carrying a session participant's
 * public keys.  No heap allocation; safe to copy on the stack.
 * Populated by aura_session_get_peer_identity() and
 * aura_session_get_local_identity().
 *
 *   ed25519_public — 32-byte Ed25519 public key (signature verification).
 *   x25519_public  — 32-byte X25519 public key (Diffie-Hellman).
 */
typedef struct {
    uint8_t ed25519_public[32];
    uint8_t x25519_public[32];
} AuraSessionPeerIdentity;

/*
 * AuraEnvelopeMetadata — parsed metadata from a 1-to-1 session decrypt call.
 *
 * Obtained by passing the raw out_metadata buffer from aura_session_decrypt()
 * into aura_envelope_metadata_parse().  Free its heap contents with
 * aura_envelope_metadata_free() when done.  Do NOT free the struct itself —
 * it is caller-allocated (typically on the stack).
 *
 * MUST be zero-initialized on first use (`AuraEnvelopeMetadata m = {0};`).
 * On subsequent `aura_envelope_metadata_parse()` calls the previous
 * `correlation_id` heap allocation is freed before the new value is
 * written, so reusing the same struct across calls is allowed; passing
 * uninitialized stack memory is undefined behavior.
 *
 *   envelope_type          — semantic type of the message.
 *   envelope_id            — request/response correlation number chosen by
 *                            the sender; 0 when unused.
 *   message_index          — monotonic per-chain message counter embedded by
 *                            the ratchet (useful for detecting gaps).
 *   correlation_id         — optional null-terminated application tracing
 *                            string; NULL when the sender did not set one.
 *                            Heap-allocated; freed by aura_envelope_metadata_free().
 *   correlation_id_length  — byte length of correlation_id (excluding NUL);
 *                            0 when correlation_id is NULL.
 */
typedef struct {
    AuraEnvelopeType envelope_type;
    uint32_t        envelope_id;
    uint64_t        message_index;
    char*           correlation_id;
    size_t          correlation_id_length;
} AuraEnvelopeMetadata;

/*
 * aura_prekey_bundle_create — serialise the identity's public keys into a
 * prekey bundle suitable for upload to a key server.
 *
 * The bundle contains: identity public keys (X25519 + Ed25519 + ML-KEM-768),
 * signed one-time prekeys, and a signature over all fields.  Peers fetch
 * this bundle before initiating a handshake.
 *
 * Parameters:
 *   identity_keys — valid identity handle whose public keys are exported.
 *                   The handle is NOT consumed; it remains valid after the call.
 *   out_bundle    — receives a heap-allocated protobuf-encoded bundle.
 *                   Release with aura_buffer_release() when done.
 *   out_error     — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_ENCODE, or AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_prekey_bundle_create(
    const AuraIdentityHandle* identity_keys,
    AuraBuffer*               out_bundle,
    AuraError*                out_error);

/*
 * aura_prekey_bundle_replenish — generate fresh one-time prekeys and add them
 * to the identity's local pool.
 *
 * Each successful X3DH handshake consumes one OTK from the responder's
 * published bundle.  When the key server reports that supply is low, call
 * this function to generate new OTKs, then upload the returned bytes to the
 * server.
 *
 * The returned buffer is a partial PreKeyBundle protobuf with only the
 * one_time_pre_keys field populated (same schema as aura_prekey_bundle_create
 * output).  The server merges these into the existing bundle for that identity.
 *
 * Parameters:
 *   identity_handle — valid identity handle (not consumed).  The new OTKs are
 *                     stored in the handle's internal pool so future responder
 *                     handshakes can use them automatically.
 *   count           — number of new OTKs to generate; must be > 0.
 *                     Recommended: AURA_DEFAULT_ONE_TIME_KEY_COUNT (100).
 *   out_keys        — receives the serialised partial PreKeyBundle containing
 *                     only the new OTKs' public keys and IDs
 *                     (release with aura_buffer_release()).
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_prekey_bundle_replenish(
    AuraIdentityHandle*  identity_handle,
    uint32_t            count,
    AuraBuffer*          out_keys,
    AuraError*           out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Handshake — hybrid X3DH + ML-KEM-768
 *
 * The handshake establishes a shared session key between two parties
 * (initiator and responder) using a hybrid post-quantum X3DH protocol.
 *
 * Flow:
 *   Initiator                          Responder
 *   ─────────────────────────────────────────────
 *   aura_handshake_initiator_start()
 *     → out_handshake_init  ──────────────────────►
 *                                aura_handshake_responder_start()
 *                                  → out_handshake_ack
 *                  ◄──────────────────────────────
 *   aura_handshake_initiator_finish()               aura_handshake_responder_finish()
 *     → AuraSessionHandle                            → AuraSessionHandle
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_handshake_initiator_start — begin a handshake as the initiating party.
 *
 * Fetches the peer's prekey bundle, generates ephemeral keys, performs the
 * hybrid X3DH+ML-KEM KEM, and produces the initial handshake message.
 *
 * Parameters:
 *   identity_keys          — caller's long-term identity (not consumed).
 *   peer_prekey_bundle     — serialised prekey bundle of the remote peer
 *                            (obtained from the key server, borrowed).
 *   peer_prekey_bundle_length — byte length of peer_prekey_bundle.
 *   config                 — session configuration; may be NULL to use
 *                            library defaults.
 *   out_handle             — receives the in-progress initiator state.
 *                            Keep alive until aura_handshake_initiator_finish().
 *                            Destroy with aura_handshake_initiator_destroy()
 *                            if the handshake is abandoned.
 *   out_handshake_init     — receives the serialised init message to send to
 *                            the peer (release with aura_buffer_release()).
 *   out_error              — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, AURA_ERROR_HANDSHAKE, or
 *          AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_handshake_initiator_start(
    AuraIdentityHandle*          identity_keys,
    const uint8_t*              peer_prekey_bundle,
    size_t                      peer_prekey_bundle_length,
    const AuraSessionConfig*     config,
    AuraHandshakeInitiatorHandle** out_handle,
    AuraBuffer*                  out_handshake_init,
    AuraError*                   out_error);

/*
 * aura_handshake_initiator_finish — complete the handshake after receiving the
 * responder's acknowledgement message.
 *
 * Verifies the responder's contribution and derives the final session key.
 * Consumes and frees the initiator handle internally on success; do NOT call
 * aura_handshake_initiator_destroy() afterwards.
 * On failure the handle remains valid and must be destroyed by the caller.
 *
 * Parameters:
 *   handle            — initiator handle from aura_handshake_initiator_start().
 *   handshake_ack     — acknowledgement bytes received from the responder
 *                       (borrowed).
 *   handshake_ack_length — byte length of handshake_ack.
 *   out_session       — receives the established AuraSessionHandle.
 *                       Destroy with aura_session_destroy() when done.
 *   out_error         — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_HANDSHAKE, AURA_ERROR_DECODE, or
 *          AURA_ERROR_CRYPTO_FAILURE.
 */
AURA_API AuraErrorCode aura_handshake_initiator_finish(
    AuraHandshakeInitiatorHandle* handle,
    const uint8_t*               handshake_ack,
    size_t                       handshake_ack_length,
    AuraSessionHandle**           out_session,
    AuraError*                    out_error);

/*
 * aura_handshake_initiator_destroy — discard an in-progress initiator state.
 *
 * Call only when abandoning a handshake before finish.  Sets *handle to NULL.
 * Safe to call with *handle == NULL (no-op).
 */
AURA_API void aura_handshake_initiator_destroy(AuraHandshakeInitiatorHandle** handle);

/*
 * aura_handshake_responder_start — process the initiator's message and produce
 * an acknowledgement.
 *
 * Verifies the incoming handshake, uses the local prekey bundle's private
 * keys to complete the KEM, and derives the shared session key.
 *
 * Parameters:
 *   identity_keys              — caller's long-term identity (not consumed).
 *   local_prekey_bundle        — the caller's own prekey bundle bytes
 *                                (same bytes that were uploaded to the key
 *                                server and fetched by the initiator). Borrowed.
 *   local_prekey_bundle_length — byte length of local_prekey_bundle.
 *   handshake_init             — init message bytes received from the
 *                                initiator (borrowed).
 *   handshake_init_length      — byte length of handshake_init.
 *   config                     — session configuration; may be NULL for
 *                                library defaults.
 *   out_handle                 — receives the in-progress responder state.
 *                                Keep alive until aura_handshake_responder_finish().
 *   out_handshake_ack          — receives the serialised ack message to send
 *                                back to the initiator (release with
 *                                aura_buffer_release()).
 *   out_error                  — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_HANDSHAKE, AURA_ERROR_DECODE, or
 *          AURA_ERROR_INVALID_INPUT.
 */
AURA_API AuraErrorCode aura_handshake_responder_start(
    AuraIdentityHandle*           identity_keys,
    const uint8_t*               local_prekey_bundle,
    size_t                       local_prekey_bundle_length,
    const uint8_t*               handshake_init,
    size_t                       handshake_init_length,
    const AuraSessionConfig*      config,
    AuraHandshakeResponderHandle** out_handle,
    AuraBuffer*                   out_handshake_ack,
    AuraError*                    out_error);

/*
 * aura_handshake_responder_finish — finalise the responder side and obtain
 * the established session.
 *
 * Consumes the responder handle internally on success; do NOT call
 * aura_handshake_responder_destroy() afterwards.
 * On failure the handle remains valid.
 *
 * Parameters:
 *   handle      — responder handle from aura_handshake_responder_start().
 *   out_session — receives the established AuraSessionHandle.
 *                 Destroy with aura_session_destroy() when done.
 *   out_error   — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_HANDSHAKE.
 */
AURA_API AuraErrorCode aura_handshake_responder_finish(
    AuraHandshakeResponderHandle* handle,
    AuraSessionHandle**           out_session,
    AuraError*                    out_error);

/*
 * aura_handshake_responder_destroy — discard an in-progress responder state.
 *
 * Call only when abandoning a handshake before finish.  Sets *handle to NULL.
 * Safe to call with *handle == NULL (no-op).
 */
AURA_API void aura_handshake_responder_destroy(AuraHandshakeResponderHandle** handle);


/* ═══════════════════════════════════════════════════════════════════════════
 * 1-to-1 session — hybrid Double Ratchet
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_session_encrypt — encrypt a plaintext message within a 1-to-1 session.
 *
 * Advances the sending ratchet and produces a serialised Envelope protobuf
 * that includes the ciphertext, ratchet header, and envelope metadata.
 *
 * Parameters:
 *   handle                  — active session handle.
 *   plaintext               — message bytes to encrypt (borrowed).
 *   plaintext_length        — byte length of plaintext.
 *   envelope_type           — semantic type tag embedded in the envelope
 *                             (e.g. AURA_ENVELOPE_REQUEST).  Used by the
 *                             application layer for routing; not a security
 *                             parameter.
 *   envelope_id             — monotonically increasing request/response ID
 *                             chosen by the caller.  Used to match responses
 *                             to requests; 0 is valid.
 *   correlation_id          — optional arbitrary UTF-8 string for
 *                             application-level tracing (NOT null-terminated;
 *                             length given explicitly).  Pass NULL + 0 to omit.
 *   correlation_id_length   — byte length of correlation_id.
 *   out_encrypted_envelope  — receives the serialised encrypted envelope
 *                             (release with aura_buffer_release()).
 *   out_error               — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_ENCRYPTION, or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_encrypt(
    AuraSessionHandle*   handle,
    const uint8_t*      plaintext,
    size_t              plaintext_length,
    AuraEnvelopeType     envelope_type,
    uint32_t            envelope_id,
    const char*         correlation_id,
    size_t              correlation_id_length,
    AuraBuffer*          out_encrypted_envelope,
    AuraError*           out_error);

/*
 * aura_session_decrypt — decrypt a received Envelope.
 *
 * Advances the receiving ratchet as needed, handles out-of-order messages
 * within the allowed skip window, and verifies the AEAD MAC.
 *
 * Parameters:
 *   handle                   — active session handle.
 *   encrypted_envelope       — serialised Envelope bytes received from peer
 *                              (borrowed).
 *   encrypted_envelope_length — byte length of encrypted_envelope.
 *   out_plaintext            — receives the decrypted message bytes
 *                              (release with aura_buffer_release()).
 *   out_metadata             — receives the serialised EnvelopeMetadata
 *                              protobuf (envelope_type, envelope_id,
 *                              correlation_id).  Release with
 *                              aura_buffer_release().  May be NULL if
 *                              metadata is not needed.
 *   out_error                — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_DECRYPTION, AURA_ERROR_DECODE,
 *          AURA_ERROR_REPLAY_ATTACK, or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_decrypt(
    AuraSessionHandle*   handle,
    const uint8_t*      encrypted_envelope,
    size_t              encrypted_envelope_length,
    AuraBuffer*          out_plaintext,
    AuraBuffer*          out_metadata,
    AuraError*           out_error);

/*
 * aura_session_serialize_sealed — persist the session state to an encrypted
 * blob for storage (e.g. on-disk or in a secure enclave).
 *
 * LOW-LEVEL API: the state is encrypted with AES-256-GCM using the provided
 * key, and an external_counter is mixed into the AAD to prevent rollback
 * attacks. New clients should prefer
 * aura_session_export_persisted_state() when they can store one serialized slot
 * record, or otherwise
 * aura_session_serialize_sealed_with_tracker().
 *
 * To use raw sealed-state APIs safely, persist two values per storage slot:
 *   - max_restored_counter: highest counter already accepted on restore.
 *   - latest_issued_counter: highest counter already used for export.
 *
 * The external_counter passed here must be latest_issued_counter + 1.
 *
 * Parameters:
 *   handle           — active session handle (not consumed; remains usable).
 *   key              — 32-byte AES-256 encryption key (borrowed).
 *   key_length       — must be exactly 32.
 *   external_counter — next export counter for this slot
 *                      (latest_issued_counter + 1).
 *   out_state        — receives the sealed blob (release with
 *                      aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_ENCRYPTION.
 */
AURA_API AuraErrorCode aura_session_serialize_sealed(
    AuraSessionHandle*   handle,
    const uint8_t*      key,
    size_t              key_length,
    uint64_t            external_counter,
    AuraBuffer*          out_state,
    AuraError*           out_error);

/*
 * aura_session_serialize_sealed_with_tracker — managed sealed-state export.
 *
 * Uses the supplied tracker to allocate the next export counter and advances
 * the tracker only after a successful export. Persist the resulting sealed
 * blob and serialized tracker together for the same storage slot.
 */
AURA_API AuraErrorCode aura_session_serialize_sealed_with_tracker(
    AuraSessionHandle*                    handle,
    const uint8_t*                       key,
    size_t                               key_length,
    AuraSealedStateCounterTrackerHandle*  tracker_handle,
    AuraBuffer*                           out_state,
    AuraError*                            out_error);

/*
 * aura_session_export_persisted_state — export session state into a managed
 * sealed-state slot.
 *
 * The slot is mutated in place: it allocates the next export counter, stores
 * the new sealed blob, and updates the tracker in one in-memory object. Persist
 * slot_handle via aura_sealed_state_slot_serialize() as a single record.
 */
AURA_API AuraErrorCode aura_session_export_persisted_state(
    AuraSessionHandle*          handle,
    const uint8_t*             key,
    size_t                     key_length,
    AuraSealedStateSlotHandle*  slot_handle,
    AuraError*                  out_error);

/*
 * aura_session_deserialize_sealed — restore a session from a sealed blob.
 *
 * LOW-LEVEL API: decrypts and validates the blob. Rejects it when the stored
 * counter is lower than min_external_counter; equality is allowed for
 * idempotent re-restore of the same blob. New clients should
 * prefer aura_session_restore_persisted_state() when restoring from one
 * serialized slot record, or otherwise
 * aura_session_deserialize_sealed_with_tracker().
 *
 * Parameters:
 *   state_bytes          — sealed blob bytes (borrowed).
 *   state_length         — byte length of state_bytes.
 *   key                  — 32-byte AES-256 decryption key (borrowed).
 *   key_length           — must be exactly 32.
 *   min_external_counter — minimum accepted restore watermark for this slot.
 *   out_external_counter — receives the counter embedded in the blob.
 *                          After a successful restore, persist it as the new
 *                          max_restored_counter and raise
 *                          latest_issued_counter to at least this value.
 *   out_handle           — receives the restored AuraSessionHandle.
 *                          Destroy with aura_session_destroy() when done.
 *   out_error            — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_DECRYPTION, AURA_ERROR_DECODE,
 *          AURA_ERROR_INVALID_INPUT, or AURA_ERROR_REPLAY_ATTACK.
 */
AURA_API AuraErrorCode aura_session_deserialize_sealed(
    const uint8_t*      state_bytes,
    size_t              state_length,
    const uint8_t*      key,
    size_t              key_length,
    uint64_t            min_external_counter,
    uint64_t*           out_external_counter,
    AuraSessionHandle**  out_handle,
    AuraError*           out_error);

/*
 * aura_session_deserialize_sealed_with_time_provider — same as
 * aura_session_deserialize_sealed(), but the restored session uses the supplied
 * time provider for TTL / expiry checks. Pass NULL to use the system clock.
 */
AURA_API AuraErrorCode aura_session_deserialize_sealed_with_time_provider(
    const uint8_t*             state_bytes,
    size_t                     state_length,
    const uint8_t*             key,
    size_t                     key_length,
    uint64_t                   min_external_counter,
    const AuraTimeProviderHandle* time_provider_handle,
    uint64_t*                  out_external_counter,
    AuraSessionHandle**         out_handle,
    AuraError*                  out_error);

/*
 * aura_session_deserialize_sealed_with_tracker — managed sealed-state restore.
 *
 * Uses tracker_handle->max_restored_counter as the restore watermark and
 * advances the tracker only after a successful restore. The embedded blob
 * counter is not returned separately; inspect the tracker if the caller needs
 * the updated values.
 */
AURA_API AuraErrorCode aura_session_deserialize_sealed_with_tracker(
    const uint8_t*                       state_bytes,
    size_t                               state_length,
    const uint8_t*                       key,
    size_t                               key_length,
    AuraSealedStateCounterTrackerHandle*  tracker_handle,
    AuraSessionHandle**                   out_handle,
    AuraError*                            out_error);

/*
 * aura_session_deserialize_sealed_with_tracker_and_time_provider — managed
 * session restore using tracker_handle plus an optional explicit time provider.
 * Pass NULL to use the system clock.
 */
AURA_API AuraErrorCode aura_session_deserialize_sealed_with_tracker_and_time_provider(
    const uint8_t*                       state_bytes,
    size_t                               state_length,
    const uint8_t*                       key,
    size_t                               key_length,
    AuraSealedStateCounterTrackerHandle*  tracker_handle,
    const AuraTimeProviderHandle*         time_provider_handle,
    AuraSessionHandle**                   out_handle,
    AuraError*                            out_error);

/*
 * aura_session_restore_persisted_state — restore a session from a managed slot.
 *
 * The slot supplies the sealed blob plus restore watermark and is updated in
 * place on success. After restore, re-serialize and persist the slot so the
 * restore watermark advances inside the same record.
 */
AURA_API AuraErrorCode aura_session_restore_persisted_state(
    AuraSealedStateSlotHandle*  slot_handle,
    const uint8_t*             key,
    size_t                     key_length,
    AuraSessionHandle**         out_handle,
    AuraError*                  out_error);

/*
 * aura_session_restore_persisted_state_with_time_provider — restore a session
 * from a managed slot and bind the restored session to the supplied clock.
 * Pass NULL to use the system clock.
 */
AURA_API AuraErrorCode aura_session_restore_persisted_state_with_time_provider(
    AuraSealedStateSlotHandle*   slot_handle,
    const uint8_t*              key,
    size_t                      key_length,
    const AuraTimeProviderHandle* time_provider_handle,
    AuraSessionHandle**          out_handle,
    AuraError*                   out_error);

/*
 * aura_session_nonce_remaining — query how many more messages can be encrypted
 * under the current chain key before a ratchet step is forced.
 *
 * Parameters:
 *   handle        — active session handle.
 *   out_remaining — receives the remaining nonce budget.
 *   out_error     — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_nonce_remaining(
    AuraSessionHandle*   handle,
    uint64_t*           out_remaining,
    AuraError*           out_error);

/*
 * aura_session_destroy — free a session handle and securely wipe all
 * ratchet key material.
 *
 * Sets *handle to NULL.  Safe to call with *handle == NULL (no-op).
 */
AURA_API void aura_session_destroy(AuraSessionHandle** handle);

/*
 * aura_session_get_id — retrieve the session's stable 16-byte identifier.
 *
 * The session ID is derived during the handshake from both parties' key
 * material and is identical on both sides.  Use it to correlate an
 * AuraSessionHandle with a stored contact record without exposing private keys.
 *
 * Parameters:
 *   handle         — active session handle.
 *   out_session_id — receives the 16-byte session ID
 *                    (release with aura_buffer_release()).
 *   out_error      — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_get_id(
    AuraSessionHandle*   handle,
    AuraBuffer*          out_session_id,
    AuraError*           out_error);

/*
 * aura_session_get_identity_binding_hash — retrieve the 32-byte authenticated
 * identity-binding hash for the current session.
 *
 * This hash is computed by the native protocol from the established local and
 * peer identity keys.  Applications can use it for TOFU, pinning, or audit
 * logging without reimplementing the transcript rules.
 */
AURA_API AuraErrorCode aura_session_get_identity_binding_hash(
    AuraSessionHandle*   handle,
    AuraBuffer*          out_binding_hash,
    AuraError*           out_error);

/*
 * aura_session_get_peer_identity — retrieve the remote peer's public keys.
 *
 * Returns the Ed25519 and X25519 public keys that the peer presented during
 * the handshake.  Use these to look up the peer in your contact store or to
 * verify out-of-band fingerprints.
 *
 * Parameters:
 *   handle       — active session handle.
 *   out_identity — caller-allocated AuraSessionPeerIdentity to fill.
 *                  Stack allocation is sufficient (no pointers inside).
 *   out_error    — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_get_peer_identity(
    AuraSessionHandle*        handle,
    AuraSessionPeerIdentity*  out_identity,
    AuraError*                out_error);

/*
 * aura_session_get_local_identity — retrieve the local device's public keys
 * as seen by this session.
 *
 * Mirrors aura_session_get_peer_identity() but returns the local party's
 * Ed25519 and X25519 public keys baked into the session state.
 *
 * Parameters:
 *   handle       — active session handle.
 *   out_identity — caller-allocated AuraSessionPeerIdentity to fill.
 *   out_error    — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_session_get_local_identity(
    AuraSessionHandle*        handle,
    AuraSessionPeerIdentity*  out_identity,
    AuraError*                out_error);

/*
 * aura_envelope_metadata_parse — parse the raw metadata buffer returned by
 * aura_session_decrypt() into a structured AuraEnvelopeMetadata.
 *
 * aura_session_decrypt() writes an opaque protobuf blob into out_metadata.
 * Call this function on that blob to get individual fields without embedding
 * proto parsing in the client app.
 *
 * Parameters:
 *   metadata_bytes   — the raw metadata buffer from aura_session_decrypt()
 *                      (out_metadata.data, out_metadata.length). Borrowed.
 *   metadata_length  — byte length of metadata_bytes.
 *   out_meta         — caller-allocated AuraEnvelopeMetadata to fill.
 *                      Must be zero-initialized before first use; reusing the
 *                      same struct across calls is supported after that.
 *                      correlation_id inside will be heap-allocated if present;
 *                      free it with aura_envelope_metadata_free().
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_DECODE.
 */
AURA_API AuraErrorCode aura_envelope_metadata_parse(
    const uint8_t*       metadata_bytes,
    size_t               metadata_length,
    AuraEnvelopeMetadata* out_meta,
    AuraError*            out_error);

/*
 * aura_envelope_metadata_free — release heap memory inside an
 * AuraEnvelopeMetadata.
 *
 * Frees correlation_id if non-NULL and zeroes the pointer.  Does NOT free
 * the out_meta struct itself (caller-allocated).  Safe to call on a zeroed
 * struct (no-op).
 *
 * Parameters:
 *   meta — pointer to the AuraEnvelopeMetadata to clean up.
 */
AURA_API void aura_envelope_metadata_free(AuraEnvelopeMetadata* meta);


/* ═══════════════════════════════════════════════════════════════════════════
 * VoIP calling
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraEncryptedFrame — encrypted media/control frame produced by
 * aura_voip_encrypt_frame() or aura_voip_encrypt_call_control().
 *
 * Release every AuraBuffer field with aura_buffer_release() when done.
 * The struct itself is caller-allocated and must not be freed.
 * MUST be zero-initialized on first use (`AuraEncryptedFrame frame = {0};`).
 * The library may release prior FFI-owned buffers when reusing the same
 * frame struct across calls, so passing uninitialized frame memory is
 * undefined behavior.
 */
typedef struct {
    AuraBuffer call_id;
    uint32_t  ssrc;
    uint64_t  frame_counter;
    uint32_t  ratchet_generation;
    AuraBuffer encrypted_payload;
    AuraBuffer nonce;
    AuraBuffer encrypted_header;
} AuraEncryptedFrame;

/*
 * AuraDecryptedFrame — decrypted frame returned by aura_voip_decrypt_frame().
 *
 * Release payload with aura_buffer_release() when done.  All scalar fields are
 * plain metadata copied from the authenticated RTP-like header.
 * MUST be zero-initialized on first use (`AuraDecryptedFrame frame = {0};`).
 * The library may release prior FFI-owned buffers when reusing the same
 * frame struct across calls, so passing uninitialized frame memory is
 * undefined behavior.
 */
typedef struct {
    AuraBuffer payload;
    uint8_t   payload_type;
    uint32_t  ssrc;
    uint32_t  timestamp;
    uint16_t  sequence_number;
    uint64_t  frame_counter;
    uint32_t  ratchet_generation;
} AuraDecryptedFrame;

/*
 * AuraCallStatistics — point-in-time call counters for a VoIP session.
 */
typedef struct {
    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t frames_dropped;
    uint32_t rekey_count;
    uint32_t ratchet_generation;
    uint64_t call_duration_secs;
} AuraCallStatistics;

/*
 * AuraVoipCallControlTypeCode — values accepted by aura_voip_encrypt_call_control().
 *
 * For AURA_VOIP_CALL_CONTROL_DTMF, pass the ASCII digit / symbol in dtmf_digit
 * (for example '5', '*', or '#').
 */
typedef enum {
    AURA_VOIP_CALL_CONTROL_MUTE = 1,
    AURA_VOIP_CALL_CONTROL_UNMUTE = 2,
    AURA_VOIP_CALL_CONTROL_HOLD = 3,
    AURA_VOIP_CALL_CONTROL_UNHOLD = 4,
    AURA_VOIP_CALL_CONTROL_DTMF = 5
} AuraVoipCallControlTypeCode;

/*
 * aura_voip_call_init — begin an outbound call and create an initiator handle.
 *
 * This is the base API used by aura_voip_call_init_start(); both functions
 * have identical behavior and outputs. `out_init_bytes` and `out_initiator`
 * are required.
 */
AURA_API AuraErrorCode aura_voip_call_init(
    const AuraIdentityHandle*      identity_handle,
    const uint8_t*                peer_kyber_public,
    size_t                        peer_kyber_public_len,
    uint8_t                       shield_mode,
    uint32_t                      ratchet_interval_frames,
    uint32_t                      pq_rekey_interval_secs,
    AuraBuffer*                    out_init_bytes,
    AuraVoipCallInitiatorHandle**  out_initiator,
    AuraError*                     out_error);

/*
 * aura_voip_call_init_start — alias of aura_voip_call_init().
 */
AURA_API AuraErrorCode aura_voip_call_init_start(
    const AuraIdentityHandle*      identity_handle,
    const uint8_t*                peer_kyber_public,
    size_t                        peer_kyber_public_len,
    uint8_t                       shield_mode,
    uint32_t                      ratchet_interval_frames,
    uint32_t                      pq_rekey_interval_secs,
    AuraBuffer*                    out_init_bytes,
    AuraVoipCallInitiatorHandle**  out_initiator,
    AuraError*                     out_error);

/*
 * aura_voip_call_init_complete — finish the caller side after receiving
 * CallAccept bytes from the callee.
 *
 * On success writes a new VoIP session handle and consumes the initiator
 * handle. `out_session` is required. On failure the initiator remains valid
 * and must be destroyed by the caller.
 */
AURA_API AuraErrorCode aura_voip_call_init_complete(
    AuraVoipCallInitiatorHandle*  initiator_handle,
    const AuraIdentityHandle*     identity_handle,
    const uint8_t*               accept_bytes,
    size_t                       accept_len,
    AuraVoipSessionHandle**       out_session,
    AuraError*                    out_error);

/*
 * aura_voip_call_initiator_destroy — discard an in-progress outbound call
 * initiator state.
 *
 * Sets *handle to NULL. Safe to call with `handle == NULL` or `*handle == NULL`.
 */
AURA_API void aura_voip_call_initiator_destroy(AuraVoipCallInitiatorHandle** handle);

/*
 * aura_voip_accept_call — process CallInit bytes as the callee, returning the
 * CallAccept bytes to send back plus the active VoIP session handle.
 * `out_accept_bytes` and `out_session` are required.
 */
AURA_API AuraErrorCode aura_voip_accept_call(
    const AuraIdentityHandle*  identity_handle,
    const uint8_t*            call_init_bytes,
    size_t                    call_init_len,
    const uint8_t*            peer_kyber_public,
    size_t                    peer_kyber_public_len,
    AuraBuffer*                out_accept_bytes,
    AuraVoipSessionHandle**    out_session,
    AuraError*                 out_error);

/*
 * aura_voip_encrypt_frame — encrypt one media frame.
 *
 * `out_frame` is required and MUST be zero-initialized before the first
 * call (`AuraEncryptedFrame f = {0};` in C).  On every subsequent call the
 * library inspects any FFI-owned contents to release/zeroize them before
 * writing the new ciphertext, so reusing the same struct across calls is
 * allowed and allocation-efficient.  Passing uninitialized stack memory is
 * undefined behavior — the library cannot distinguish garbage from a
 * previously-written valid allocation.
 */
AURA_API AuraErrorCode aura_voip_encrypt_frame(
    const AuraVoipSessionHandle*  handle,
    uint8_t                      payload_type,
    uint32_t                     ssrc,
    uint32_t                     timestamp,
    uint16_t                     sequence_number,
    const uint8_t*               payload,
    size_t                       payload_len,
    AuraEncryptedFrame*           out_frame,
    AuraError*                    out_error);

/*
 * aura_voip_decrypt_frame — decrypt one received media/control frame.
 *
 * `out_frame` is required and MUST be zero-initialized on first use
 * (`AuraDecryptedFrame f = {0};`).  Same reuse semantics as
 * aura_voip_encrypt_frame — see that comment.
 */
AURA_API AuraErrorCode aura_voip_decrypt_frame(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               call_id,
    size_t                       call_id_len,
    uint32_t                     ssrc,
    uint64_t                     frame_counter,
    uint32_t                     ratchet_generation,
    const uint8_t*               encrypted_payload,
    size_t                       encrypted_payload_len,
    const uint8_t*               nonce,
    size_t                       nonce_len,
    const uint8_t*               encrypted_header,
    size_t                       encrypted_header_len,
    AuraDecryptedFrame*           out_frame,
    AuraError*                    out_error);

/*
 * aura_voip_call_id — return the session's authenticated call identifier.
 */
AURA_API AuraErrorCode aura_voip_call_id(
    const AuraVoipSessionHandle*  handle,
    AuraBuffer*                   out_buf,
    AuraError*                    out_error);

/*
 * aura_voip_ssrc — return the local SSRC.  On failure returns 0 and populates
 * out_error when non-NULL.
 */
AURA_API uint32_t aura_voip_ssrc(
    const AuraVoipSessionHandle*  handle,
    AuraError*                    out_error);

/*
 * aura_voip_is_shield_mode — return 1 when the call was negotiated in shield
 * mode, else 0.  On failure returns 0 and populates out_error when non-NULL.
 */
AURA_API uint8_t aura_voip_is_shield_mode(
    const AuraVoipSessionHandle*  handle,
    AuraError*                    out_error);

/*
 * aura_voip_end_call — locally mark the call as ended.  After success, frame
 * encryption/decryption APIs reject further traffic on this handle.
 */
AURA_API AuraErrorCode aura_voip_end_call(
    const AuraVoipSessionHandle*  handle,
    AuraError*                    out_error);

/*
 * aura_voip_generate_call_end_hmac — build the authenticated CallEnd HMAC for
 * application-supplied device_id and timestamp values.
 */
AURA_API AuraErrorCode aura_voip_generate_call_end_hmac(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               device_id,
    size_t                       device_id_len,
    uint64_t                     timestamp,
    AuraBuffer*                   out_hmac,
    AuraError*                    out_error);

/*
 * aura_voip_verify_call_end_hmac — verify a previously generated CallEnd HMAC.
 *
 * Writes 1 to out_valid when valid, else 0.
 */
AURA_API AuraErrorCode aura_voip_verify_call_end_hmac(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               device_id,
    size_t                       device_id_len,
    uint64_t                     timestamp,
    const uint8_t*               hmac_value,
    size_t                       hmac_value_len,
    uint8_t*                     out_valid,
    AuraError*                    out_error);

/*
 * aura_voip_build_call_end — serialize an authenticated CallEnd signal.
 */
AURA_API AuraErrorCode aura_voip_build_call_end(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               device_id,
    size_t                       device_id_len,
    uint64_t                     timestamp,
    AuraBuffer*                   out_buf,
    AuraError*                    out_error);

/*
 * aura_voip_process_call_end — verify and apply a serialized CallEnd signal.
 */
AURA_API AuraErrorCode aura_voip_process_call_end(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               call_end_bytes,
    size_t                       call_end_len,
    AuraError*                    out_error);

/*
 * aura_voip_encrypt_call_control — encode and encrypt one call-control frame.
 *
 * `out_frame` is required and has the same zero-initialization/reuse
 * semantics as aura_voip_encrypt_frame.
 */
AURA_API AuraErrorCode aura_voip_encrypt_call_control(
    const AuraVoipSessionHandle*  handle,
    uint8_t                      control_type,
    uint8_t                      dtmf_digit,
    AuraEncryptedFrame*           out_frame,
    AuraError*                    out_error);

/*
 * aura_voip_export_sealed_state — serialize encrypted VoIP session state for
 * persistence. LOW-LEVEL API: use external_counter as
 * latest_issued_counter + 1 for this slot. state_key must be exactly 32 bytes.
 * New clients should prefer aura_voip_export_persisted_state() when they can
 * store one serialized slot record, or otherwise
 * aura_voip_export_sealed_state_with_tracker().
 */
AURA_API AuraErrorCode aura_voip_export_sealed_state(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               state_key,
    size_t                       state_key_len,
    uint64_t                     external_counter,
    AuraBuffer*                   out_buf,
    AuraError*                    out_error);

/*
 * aura_voip_export_sealed_state_with_tracker — managed VoIP sealed-state
 * export. Allocates the next export counter from tracker_handle and advances
 * the tracker only after a successful export.
 */
AURA_API AuraErrorCode aura_voip_export_sealed_state_with_tracker(
    const AuraVoipSessionHandle*         handle,
    const uint8_t*                      state_key,
    size_t                              state_key_len,
    AuraSealedStateCounterTrackerHandle* tracker_handle,
    AuraBuffer*                          out_buf,
    AuraError*                           out_error);

/*
 * aura_voip_export_persisted_state — export VoIP state into a managed slot.
 *
 * The slot is mutated in place: it allocates the next export counter, stores
 * the new sealed blob, and updates the tracker inside one in-memory object.
 * Persist slot_handle via aura_sealed_state_slot_serialize().
 */
AURA_API AuraErrorCode aura_voip_export_persisted_state(
    const AuraVoipSessionHandle* handle,
    const uint8_t*              state_key,
    size_t                      state_key_len,
    AuraSealedStateSlotHandle*   slot_handle,
    AuraError*                   out_error);

/*
 * aura_voip_initiate_rekey — begin a PQ rekey for an active call.
 */
AURA_API AuraErrorCode aura_voip_initiate_rekey(
    const AuraVoipSessionHandle*  handle,
    const AuraIdentityHandle*     identity_handle,
    const uint8_t*               peer_kyber_public,
    size_t                       peer_kyber_public_len,
    AuraBuffer*                   out_rekey_bytes,
    AuraError*                    out_error);

/*
 * aura_voip_process_rekey — process a peer rekey and return the rekey-ack
 * bytes to send back.
 */
AURA_API AuraErrorCode aura_voip_process_rekey(
    const AuraVoipSessionHandle*  handle,
    const AuraIdentityHandle*     identity_handle,
    const uint8_t*               peer_ed25519_public,
    size_t                       peer_ed25519_public_len,
    const uint8_t*               rekey_bytes,
    size_t                       rekey_len,
    const uint8_t*               peer_kyber_public,
    size_t                       peer_kyber_public_len,
    AuraBuffer*                   out_ack_bytes,
    AuraError*                    out_error);

/*
 * aura_voip_process_rekey_ack — process the final ack for a previously
 * initiated rekey.
 */
AURA_API AuraErrorCode aura_voip_process_rekey_ack(
    const AuraVoipSessionHandle*  handle,
    const AuraIdentityHandle*     identity_handle,
    const uint8_t*               peer_ed25519_public,
    size_t                       peer_ed25519_public_len,
    const uint8_t*               ack_bytes,
    size_t                       ack_len,
    AuraError*                    out_error);

/*
 * aura_voip_import_sealed_state — restore a VoIP session from a sealed blob.
 *
 * LOW-LEVEL API: pass max_restored_counter as min_external_counter, then after
 * success persist the returned blob counter as the new restore watermark.
 * `out_session` is required. New clients should prefer
 * aura_voip_restore_persisted_state() when restoring from one serialized slot
 * record, or otherwise aura_voip_import_sealed_state_with_tracker().
 */
AURA_API AuraErrorCode aura_voip_import_sealed_state(
    const uint8_t*             data,
    size_t                     data_len,
    const uint8_t*             state_key,
    size_t                     state_key_len,
    uint64_t                   min_external_counter,
    AuraVoipSessionHandle**     out_session,
    AuraError*                  out_error);

/*
 * aura_voip_import_sealed_state_with_time_provider — same as
 * aura_voip_import_sealed_state(), but binds the restored session to an
 * optional explicit clock. Pass NULL to use the system clock.
 */
AURA_API AuraErrorCode aura_voip_import_sealed_state_with_time_provider(
    const uint8_t*              data,
    size_t                      data_len,
    const uint8_t*              state_key,
    size_t                      state_key_len,
    uint64_t                    min_external_counter,
    const AuraTimeProviderHandle* time_provider_handle,
    AuraVoipSessionHandle**      out_session,
    AuraError*                   out_error);

/*
 * aura_voip_import_sealed_state_with_tracker — managed VoIP sealed-state
 * restore. Uses tracker_handle->max_restored_counter as the restore
 * watermark and advances the tracker only after a successful restore.
 */
AURA_API AuraErrorCode aura_voip_import_sealed_state_with_tracker(
    const uint8_t*                      data,
    size_t                              data_len,
    const uint8_t*                      state_key,
    size_t                              state_key_len,
    AuraSealedStateCounterTrackerHandle* tracker_handle,
    AuraVoipSessionHandle**              out_session,
    AuraError*                           out_error);

/*
 * aura_voip_import_sealed_state_with_tracker_and_time_provider — managed VoIP
 * restore using tracker_handle plus an optional explicit clock. Pass NULL to
 * use the system clock.
 */
AURA_API AuraErrorCode aura_voip_import_sealed_state_with_tracker_and_time_provider(
    const uint8_t*                      data,
    size_t                              data_len,
    const uint8_t*                      state_key,
    size_t                              state_key_len,
    AuraSealedStateCounterTrackerHandle* tracker_handle,
    const AuraTimeProviderHandle*        time_provider_handle,
    AuraVoipSessionHandle**              out_session,
    AuraError*                           out_error);

/*
 * aura_voip_restore_persisted_state — restore VoIP state from a managed slot.
 *
 * The slot supplies the sealed blob plus restore watermark and is updated in
 * place on success. After restore, re-serialize and persist the slot so the
 * restore watermark advances inside the same record.
 */
AURA_API AuraErrorCode aura_voip_restore_persisted_state(
    AuraSealedStateSlotHandle*  slot_handle,
    const uint8_t*             state_key,
    size_t                     state_key_len,
    AuraVoipSessionHandle**     out_session,
    AuraError*                  out_error);

/*
 * aura_voip_restore_persisted_state_with_time_provider — restore VoIP state
 * from a managed slot and bind it to an optional explicit clock. Pass NULL to
 * use the system clock.
 */
AURA_API AuraErrorCode aura_voip_restore_persisted_state_with_time_provider(
    AuraSealedStateSlotHandle*   slot_handle,
    const uint8_t*              state_key,
    size_t                      state_key_len,
    const AuraTimeProviderHandle* time_provider_handle,
    AuraVoipSessionHandle**      out_session,
    AuraError*                   out_error);

/*
 * aura_voip_sealed_state_external_counter — read the anti-rollback counter
 * from a sealed VoIP state blob without decrypting it.
 */
AURA_API AuraErrorCode aura_voip_sealed_state_external_counter(
    const uint8_t*  data,
    size_t          data_len,
    uint64_t*       out_external_counter,
    AuraError*       out_error);

/*
 * aura_voip_session_destroy — free a VoIP session handle.
 *
 * Sets *handle to NULL. Safe to call with `handle == NULL` or `*handle == NULL`.
 */
AURA_API void aura_voip_session_destroy(AuraVoipSessionHandle** handle);

/*
 * aura_voip_set_screen_share_meta — attach optional screen-share metadata to
 * the local session state. codec_hint is optional UTF-8.
 */
AURA_API AuraErrorCode aura_voip_set_screen_share_meta(
    const AuraVoipSessionHandle*  handle,
    uint32_t                     width,
    uint32_t                     height,
    uint32_t                     frame_rate,
    const uint8_t*               codec_hint,
    size_t                       codec_hint_length,
    AuraError*                    out_error);

/*
 * aura_voip_get_screen_share_meta — fetch the currently stored screen-share
 * metadata. When absent, width/height/frame_rate are written as 0 and
 * out_codec_hint receives an empty buffer.
 */
AURA_API AuraErrorCode aura_voip_get_screen_share_meta(
    const AuraVoipSessionHandle*  handle,
    uint32_t*                    out_width,
    uint32_t*                    out_height,
    uint32_t*                    out_frame_rate,
    AuraBuffer*                   out_codec_hint,
    AuraError*                    out_error);

/*
 * aura_voip_clear_screen_share_meta — remove stored screen-share metadata.
 */
AURA_API AuraErrorCode aura_voip_clear_screen_share_meta(
    const AuraVoipSessionHandle*  handle,
    AuraError*                    out_error);

/*
 * aura_voip_get_call_statistics — fetch current counters for a VoIP session.
 */
AURA_API AuraErrorCode aura_voip_get_call_statistics(
    const AuraVoipSessionHandle*  handle,
    AuraCallStatistics*           out_stats,
    AuraError*                    out_error);

/*
 * aura_voip_set_recording_consent — set the local user's recording-consent
 * value. Accepted values are protocol-defined integers (currently 0 or 1).
 */
AURA_API AuraErrorCode aura_voip_set_recording_consent(
    const AuraVoipSessionHandle*  handle,
    int32_t                      consent,
    AuraError*                    out_error);

/*
 * aura_voip_get_local_recording_consent — return the local consent value, or
 * -1 on failure.
 */
AURA_API int32_t aura_voip_get_local_recording_consent(
    const AuraVoipSessionHandle*  handle);

/*
 * aura_voip_set_remote_recording_consent — legacy API retained for ABI
 * compatibility. New code must not use this: remote consent is only valid
 * when updated via a signed RecordingConsentMessage.
 */
AURA_API AuraErrorCode aura_voip_set_remote_recording_consent(
    const AuraVoipSessionHandle*  handle,
    int32_t                      consent,
    AuraError*                    out_error);

/*
 * aura_voip_get_remote_recording_consent — return the last authenticated
 * remote consent value, or -1 on failure.
 */
AURA_API int32_t aura_voip_get_remote_recording_consent(
    const AuraVoipSessionHandle*  handle);

/*
 * aura_voip_both_consented_to_recording — return true only when both local and
 * authenticated remote consent values allow recording.
 */
AURA_API bool aura_voip_both_consented_to_recording(
    const AuraVoipSessionHandle*  handle);

/*
 * aura_voip_build_recording_consent_message — create a signed
 * RecordingConsentMessage that can be sent to the peer. On success this also
 * updates the session's local consent state and advances its outbound consent
 * timestamp monotonically.
 */
AURA_API AuraErrorCode aura_voip_build_recording_consent_message(
    const AuraVoipSessionHandle*  handle,
    const AuraIdentityHandle*     identity_handle,
    int32_t                      consent,
    uint64_t                     timestamp_unix,
    AuraBuffer*                   out_message,
    AuraError*                    out_error);

/*
 * aura_voip_process_recording_consent_message — verify and apply a peer's
 * signed RecordingConsentMessage.
 */
AURA_API AuraErrorCode aura_voip_process_recording_consent_message(
    const AuraVoipSessionHandle*  handle,
    const uint8_t*               peer_ed25519_public,
    size_t                       peer_ed25519_public_len,
    const uint8_t*               message_bytes,
    size_t                       message_len,
    AuraError*                    out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Key derivation & secret sharing
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_derive_root_key — derive an application-level key from an established
 * session's opaque shared secret.
 *
 * Use this after handshake to derive e.g. a database encryption key or a
 * file-encryption key that is bound to the session.  The user_context string
 * domain-separates different keys derived from the same session.
 *
 * Parameters:
 *   opaque_session_key        — the session's exportable shared secret
 *                               bytes (obtain by serialising the session and
 *                               extracting the root key field, or via a
 *                               dedicated export API).  Borrowed.
 *   opaque_session_key_length — byte length of opaque_session_key.
 *   user_context              — arbitrary UTF-8 context string to domain-
 *                               separate the derived key (e.g. "v1:db-key").
 *                               Not null-terminated; length given explicitly.
 *   user_context_length       — byte length of user_context.
 *   out_root_key              — caller-allocated buffer to receive the
 *                               derived key bytes.
 *   out_root_key_length       — requested key length in bytes (1–64).
 *   out_error                 — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_DERIVE_KEY.
 */
AURA_API AuraErrorCode aura_derive_root_key(
    const uint8_t*  opaque_session_key,
    size_t          opaque_session_key_length,
    const uint8_t*  user_context,
    size_t          user_context_length,
    uint8_t*        out_root_key,
    size_t          out_root_key_length,
    AuraError*       out_error);

/*
 * aura_shamir_split — split a secret into authenticated Shamir shares.
 *
 * Splits `secret` into `share_count` shares such that any `threshold` of
 * them can reconstruct the original secret.  Each share is authenticated
 * with an HMAC keyed by auth_key to prevent forgery.
 *
 * Parameters:
 *   secret           — secret bytes to split (borrowed).
 *   secret_length    — byte length of secret (1–256 bytes).
 *   threshold        — minimum shares required to reconstruct (2–255).
 *                      Must be <= share_count.
 *   share_count      — total number of shares to generate (2–255).
 *   auth_key         — HMAC key used to authenticate each share (borrowed).
 *                      Recommended: 32 bytes of random material.
 *   auth_key_length  — byte length of auth_key; minimum 16.
 *   out_shares       — receives all shares packed end-to-end into one
 *                      contiguous buffer (total size = share_count *
 *                      *out_share_length).  Release with aura_buffer_release().
 *   out_share_length — receives the byte length of each individual share.
 *                      All shares have the same length.
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_CRYPTO_FAILURE.
 */
AURA_API AuraErrorCode aura_shamir_split(
    const uint8_t*  secret,
    size_t          secret_length,
    uint8_t         threshold,
    uint8_t         share_count,
    const uint8_t*  auth_key,
    size_t          auth_key_length,
    AuraBuffer*      out_shares,
    size_t*         out_share_length,
    AuraError*       out_error);

/*
 * aura_shamir_reconstruct — reconstruct a secret from a subset of shares.
 *
 * Verifies each share's HMAC before interpolation.  Requires exactly
 * `share_count` shares in the `shares` buffer, each of `share_length` bytes,
 * packed contiguously (i.e. total buffer = share_count * share_length bytes).
 *
 * Parameters:
 *   shares          — packed share bytes (borrowed).
 *   shares_length   — total byte length = share_count * share_length.
 *   share_length    — byte length of each individual share (from out_share_length
 *                     returned by aura_shamir_split()).
 *   share_count     — number of shares provided; must be >= threshold.
 *   auth_key        — same HMAC key used during aura_shamir_split() (borrowed).
 *   auth_key_length — byte length of auth_key.
 *   out_secret      — receives the reconstructed secret bytes
 *                     (release with aura_buffer_release()).
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, AURA_ERROR_CRYPTO_FAILURE
 *          (auth failure), or AURA_ERROR_DECODE.
 */
AURA_API AuraErrorCode aura_shamir_reconstruct(
    const uint8_t*  shares,
    size_t          shares_length,
    size_t          share_length,
    size_t          share_count,
    const uint8_t*  auth_key,
    size_t          auth_key_length,
    AuraBuffer*      out_secret,
    AuraError*       out_error);

AURA_API AuraErrorCode aura_attachment_generate_id(
    AuraBuffer* out_attachment_id,
    AuraError*  out_error);

AURA_API AuraErrorCode aura_attachment_generate_file_key(
    AuraBuffer* out_file_key,
    AuraError*  out_error);

AURA_API AuraErrorCode aura_attachment_encrypt_chunk(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_index,
    uint32_t       chunk_count,
    const uint8_t* plaintext,
    size_t         plaintext_length,
    AuraBuffer*     out_nonce,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_decrypt_chunk(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_index,
    uint32_t       chunk_count,
    const uint8_t* nonce,
    size_t         nonce_length,
    const uint8_t* ciphertext,
    size_t         ciphertext_length,
    AuraBuffer*     out_plaintext,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_manifest_create(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const char*    mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_count,
    const uint8_t* file_sha256,
    size_t         file_sha256_length,
    const uint8_t* encrypted_file_key,
    size_t         encrypted_file_key_length,
    AuraBuffer*     out_manifest,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_manifest_validate(
    const uint8_t* manifest_bytes,
    size_t         manifest_length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_chunk_validate(
    const uint8_t* manifest_bytes,
    size_t         manifest_length,
    uint32_t       chunk_index,
    const uint8_t* nonce,
    size_t         nonce_length,
    const uint8_t* ciphertext,
    size_t         ciphertext_length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_encrypt_thumbnail(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const uint8_t* thumbnail_mime_type,
    size_t         thumbnail_mime_type_length,
    const uint8_t* thumbnail_plaintext,
    size_t         thumbnail_plaintext_length,
    AuraBuffer*     out_nonce,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_decrypt_thumbnail(
    const uint8_t* file_key,
    size_t         file_key_length,
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const uint8_t* thumbnail_mime_type,
    size_t         thumbnail_mime_type_length,
    const uint8_t* nonce,
    size_t         nonce_length,
    const uint8_t* ciphertext,
    size_t         ciphertext_length,
    AuraBuffer*     out_plaintext,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_validate_ttl(
    uint64_t  ttl_seconds,
    AuraError* out_error);

AURA_API bool aura_attachment_is_expired(
    uint64_t created_at_unix,
    uint64_t ttl_seconds,
    uint64_t now_unix);

AURA_API AuraErrorCode aura_attachment_progress_create(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    uint32_t       chunk_count,
    AuraBuffer*     out_progress,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_progress_mark_completed(
    const uint8_t* progress_bytes,
    size_t         progress_length,
    uint32_t       chunk_index,
    uint64_t       bytes_transferred,
    uint64_t       now_unix,
    AuraBuffer*     out_updated_progress,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_progress_get_remaining(
    const uint8_t* progress_bytes,
    size_t         progress_length,
    AuraBuffer*     out_remaining,
    uint32_t*      out_remaining_count,
    AuraError*      out_error);

AURA_API bool aura_attachment_progress_is_complete(
    const uint8_t* progress_bytes,
    size_t         progress_length);

AURA_API AuraErrorCode aura_attachment_generate_collage_id(
    AuraBuffer* out_collage_id,
    AuraError*  out_error);

AURA_API AuraErrorCode aura_attachment_collage_create(
    const uint8_t *const * manifest_array,
    const size_t*          manifest_lengths,
    size_t                 manifest_count,
    AuraBuffer*             out_collage,
    AuraError*              out_error);

AURA_API AuraErrorCode aura_attachment_collage_validate(
    const uint8_t* collage_bytes,
    size_t         collage_length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_collage_create_with_metadata(
    const uint8_t *const * manifest_array,
    const size_t*          manifest_lengths,
    size_t                 manifest_count,
    const uint8_t*         name,
    size_t                 name_length,
    const uint8_t*         description,
    size_t                 description_length,
    int32_t                layout,
    AuraBuffer*             out_collage,
    AuraError*              out_error);

typedef struct AuraStreamingEncryptorHandle AuraStreamingEncryptorHandle;
typedef struct AuraStreamingDecryptorHandle AuraStreamingDecryptorHandle;

AURA_API AuraErrorCode aura_attachment_streaming_encryptor_create(
    const uint8_t*              file_key,
    size_t                      file_key_length,
    const uint8_t*              attachment_id,
    size_t                      attachment_id_length,
    const uint8_t*              mime_type,
    size_t                      mime_type_length,
    uint64_t                    total_size,
    uint32_t                    chunk_size,
    uint32_t                    chunk_count,
    AuraStreamingEncryptorHandle** out_handle,
    AuraError*                   out_error);

AURA_API AuraErrorCode aura_attachment_streaming_encryptor_write(
    AuraStreamingEncryptorHandle* handle,
    const uint8_t*               data,
    size_t                       data_length,
    AuraBuffer*                   out_chunks,
    uint32_t*                    out_chunk_count,
    AuraError*                    out_error);

AURA_API AuraErrorCode aura_attachment_streaming_encryptor_finish(
    AuraStreamingEncryptorHandle* handle,
    AuraBuffer*                   out_chunk,
    uint8_t*                     out_has_chunk,
    AuraError*                    out_error);

/**
 * Destroys a streaming encryptor and nulls the caller's handle pointer so a
 * redundant destroy from a different code path becomes a no-op (prevents
 * double-free).  Pass the address of your `AuraStreamingEncryptorHandle*`
 * variable.
 */
AURA_API void aura_attachment_streaming_encryptor_destroy(
    AuraStreamingEncryptorHandle** handle_ptr);

AURA_API AuraErrorCode aura_attachment_streaming_decryptor_create(
    const uint8_t*              file_key,
    size_t                      file_key_length,
    const uint8_t*              attachment_id,
    size_t                      attachment_id_length,
    const uint8_t*              mime_type,
    size_t                      mime_type_length,
    uint64_t                    total_size,
    uint32_t                    chunk_size,
    uint32_t                    chunk_count,
    AuraStreamingDecryptorHandle** out_handle,
    AuraError*                   out_error);

AURA_API AuraErrorCode aura_attachment_streaming_decryptor_write(
    AuraStreamingDecryptorHandle* handle,
    uint32_t                     chunk_index,
    const uint8_t*               nonce,
    size_t                       nonce_length,
    const uint8_t*               ciphertext,
    size_t                       ciphertext_length,
    AuraBuffer*                   out_plaintext,
    AuraError*                    out_error);

AURA_API bool aura_attachment_streaming_decryptor_is_complete(
    AuraStreamingDecryptorHandle* handle);

/**
 * Destroys a streaming decryptor and nulls the caller's handle pointer so a
 * redundant destroy from a different code path becomes a no-op (prevents
 * double-free).  Pass the address of your `AuraStreamingDecryptorHandle*`
 * variable.
 */
AURA_API void aura_attachment_streaming_decryptor_destroy(
    AuraStreamingDecryptorHandle** handle_ptr);

AURA_API AuraErrorCode aura_attachment_manifest_create_v2(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const uint8_t* mime_type,
    size_t         mime_type_length,
    uint64_t       total_size,
    uint32_t       chunk_size,
    uint32_t       chunk_count,
    const uint8_t* file_sha256,
    size_t         file_sha256_length,
    const uint8_t* encrypted_file_key,
    size_t         encrypted_file_key_length,
    int64_t        collage_index,
    const uint8_t* thumbnail_ciphertext,
    size_t         thumbnail_ciphertext_length,
    const uint8_t* thumbnail_nonce,
    size_t         thumbnail_nonce_length,
    const uint8_t* thumbnail_mime_type,
    size_t         thumbnail_mime_type_length,
    uint32_t       thumbnail_original_size,
    uint64_t       ttl_seconds,
    uint64_t       created_at_unix,
    AuraBuffer*     out_manifest,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_encrypt_file_key(
    AuraSessionHandle* handle,
    const uint8_t*    file_key,
    size_t            file_key_length,
    const uint8_t*    attachment_id,
    size_t            attachment_id_length,
    AuraBuffer*        out_encrypted_file_key,
    AuraError*         out_error);

/*
 * Decrypts an attachment file key and verifies that the decrypted envelope is
 * bound to the supplied attachment_id.
 */
AURA_API AuraErrorCode aura_attachment_decrypt_file_key(
    AuraSessionHandle* handle,
    const uint8_t*    encrypted_file_key,
    size_t            encrypted_file_key_length,
    const uint8_t*    attachment_id,
    size_t            attachment_id_length,
    AuraBuffer*        out_file_key,
    AuraError*         out_error);

/*
 * Validates magic bytes for a supported MIME type. Unsupported MIME strings
 * are rejected rather than treated as implicitly valid.
 */
AURA_API AuraErrorCode aura_attachment_validate_magic_bytes(
    const uint8_t* header,
    size_t         header_length,
    const uint8_t* mime_type,
    size_t         mime_type_length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_detect_mime(
    const uint8_t* header,
    size_t         header_length,
    AuraBuffer*     out_mime,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_validate_filename(
    const uint8_t* name,
    size_t         name_length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_sanitize_filename(
    const uint8_t* name,
    size_t         name_length,
    AuraBuffer*     out_sanitized,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_inline_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_inline_create(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    const uint8_t* mime_type,
    size_t         mime_type_length,
    const uint8_t* data,
    size_t         data_length,
    const uint8_t* original_filename,
    size_t         original_filename_length,
    uint8_t        has_content_policy,
    uint8_t        view_once,
    uint8_t        no_forward,
    uint8_t        no_save,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_reference_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_reference_create(
    const uint8_t* attachment_id,
    size_t         attachment_id_length,
    int32_t        reference_type,
    const uint8_t* source_message_id,
    size_t         source_message_id_length,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_voice_meta_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_voice_meta_create(
    const float*   waveform_samples,
    size_t         waveform_count,
    const uint8_t* transcript,
    size_t         transcript_length,
    float          playback_speed_hint,
    uint8_t        has_playback_speed,
    uint8_t        is_listened,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_location_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_location_create(
    double         latitude,
    double         longitude,
    double         accuracy_meters,
    uint8_t        has_accuracy,
    const uint8_t* label,
    size_t         label_length,
    uint64_t       timestamp_unix,
    uint8_t        has_timestamp,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_contact_card_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_contact_card_create(
    const uint8_t* display_name,
    size_t         display_name_length,
    const uint8_t* phone,
    size_t         phone_length,
    const uint8_t* email,
    size_t         email_length,
    const uint8_t* avatar_data,
    size_t         avatar_data_length,
    const uint8_t* organization,
    size_t         organization_length,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_link_preview_validate(
    const uint8_t* bytes,
    size_t         length,
    AuraError*      out_error);

AURA_API AuraErrorCode aura_attachment_link_preview_create(
    const uint8_t* url,
    size_t         url_length,
    const uint8_t* title,
    size_t         title_length,
    const uint8_t* description,
    size_t         description_length,
    const uint8_t* preview_image,
    size_t         preview_image_length,
    const uint8_t* preview_image_mime,
    size_t         preview_image_mime_length,
    const uint8_t* domain,
    size_t         domain_length,
    AuraBuffer*     out_buffer,
    AuraError*      out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group session — hybrid PQ TreeKEM (MLS-inspired)
 *
 * Groups use a left-balanced binary ratchet tree where each leaf holds a
 * hybrid X25519+ML-KEM-768 key pair.  Epoch transitions are driven by Commit
 * messages that update the tree and derive new epoch keys.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_group_generate_key_package — generate a signed key package for group
 * invitation.
 *
 * A KeyPackage is a signed public-key advertisement that a group admin uses
 * to add a new member.  The matching secrets handle holds the private keys
 * and MUST be retained by the invitee until aura_group_join() is called.
 *
 * Parameters:
 *   identity_handle — the invitee's long-term identity (not consumed).
 *   credential      — application-level identity credential bytes (e.g.
 *                     a user ID or certificate); included in the key package
 *                     and visible to all group members.  Borrowed.
 *   credential_length — byte length of credential.
 *   out_key_package — receives the serialised, signed KeyPackage protobuf to
 *                     send to the group admin (release with aura_buffer_release()).
 *   out_secrets     — receives the private secrets handle corresponding to
 *                     this key package.  MUST be kept alive and passed to
 *                     aura_group_join() later.  Destroy with
 *                     aura_group_key_package_secrets_destroy() if the
 *                     invitation is never completed.
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_KEY_GENERATION, or AURA_ERROR_ENCODE.
 */
AURA_API AuraErrorCode aura_group_generate_key_package(
    AuraIdentityHandle*           identity_handle,
    const uint8_t*               credential,
    size_t                       credential_length,
    AuraBuffer*                   out_key_package,
    AuraKeyPackageSecretsHandle** out_secrets,
    AuraError*                    out_error);

/*
 * aura_group_key_package_secrets_destroy — free a key package secrets handle.
 *
 * Call when an invitation was never completed and the secrets are no longer
 * needed.  Sets *handle to NULL.
 */
AURA_API void aura_group_key_package_secrets_destroy(
    AuraKeyPackageSecretsHandle** handle);

/*
 * aura_group_validate_key_package — validate a serialized KeyPackage before
 * trusting identity public keys from it.
 *
 * Checks the protobuf shape, key sizes, X25519/Kyber public-key validity, and
 * the KeyPackage Ed25519 signature using strict verification.
 *
 * Parameters:
 *   key_package_bytes  — serialized GroupKeyPackage protobuf (borrowed).
 *   key_package_length — byte length of key_package_bytes.
 *   out_error          — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, AURA_ERROR_DECODE, or a
 *          protocol validation error.
 */
AURA_API AuraErrorCode aura_group_validate_key_package(
    const uint8_t* key_package_bytes,
    size_t         key_package_length,
    AuraError*     out_error);

/*
 * aura_group_create — create a new group as the sole initial member.
 *
 * The caller becomes leaf index 0.  Use aura_group_add_member() to invite
 * others.  Group uses the hardened shielded policy by default.
 *
 * Parameters:
 *   identity_handle — caller's long-term identity (not consumed).
 *   credential      — caller's application credential embedded in the group
 *                     tree (borrowed).
 *   credential_length — byte length of credential.
 *   out_handle      — receives the AuraGroupSessionHandle.
 *                     Destroy with aura_group_destroy() when done.
 *   out_error       — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_KEY_GENERATION, or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_create(
    AuraIdentityHandle*       identity_handle,
    const uint8_t*           credential,
    size_t                   credential_length,
    AuraGroupSessionHandle**  out_handle,
    AuraError*                out_error);

/*
 * aura_group_create_shielded — create a new group with metadata shielding
 * enabled.
 *
 * Like aura_group_create() but enables enhanced sender-key padding and
 * traffic-analysis resistance features.  All members must support shielded
 * mode; mixing shielded and non-shielded clients in the same group is not
 * supported.
 *
 * Parameters: same as aura_group_create().
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_KEY_GENERATION, or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_create_shielded(
    AuraIdentityHandle*       identity_handle,
    const uint8_t*           credential,
    size_t                   credential_length,
    AuraGroupSessionHandle**  out_handle,
    AuraError*                out_error);

/*
 * aura_group_is_shielded — query whether the group has shielding enabled.
 *
 * Parameters:
 *   handle       — active group session handle.
 *   out_shielded — receives 1 if shielded, 0 otherwise.
 *   out_error    — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_is_shielded(
    AuraGroupSessionHandle*  handle,
    uint8_t*                out_shielded,
    AuraError*               out_error);

/*
 * aura_group_create_with_policy — create a new group with an explicit
 * security policy.
 *
 * Parameters:
 *   identity_handle   — caller's long-term identity (not consumed).
 *   credential        — caller's credential (borrowed).
 *   credential_length — byte length of credential.
 *   policy            — pointer to a populated AuraGroupSecurityPolicy;
 *                       must not be NULL.  The struct is copied internally.
 *   out_handle        — receives the group session handle.
 *   out_error         — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_create_with_policy(
    AuraIdentityHandle*            identity_handle,
    const uint8_t*                credential,
    size_t                        credential_length,
    const AuraGroupSecurityPolicy* policy,
    AuraGroupSessionHandle**       out_handle,
    AuraError*                     out_error);

/*
 * aura_group_get_security_policy — read the active security policy of a group.
 *
 * Parameters:
 *   handle     — active group session handle.
 *   out_policy — caller-allocated AuraGroupSecurityPolicy to fill in.
 *   out_error  — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_get_security_policy(
    AuraGroupSessionHandle*  handle,
    AuraGroupSecurityPolicy* out_policy,
    AuraError*               out_error);

/*
 * aura_group_join — join a group using a Welcome message.
 *
 * Decrypts the Welcome, verifies the tree and confirmation MAC, and
 * establishes the new member's group session at the current epoch.
 *
 * IMPORTANT: After calling this function do NOT also call
 * aura_group_process_commit() for the same commit that generated the Welcome.
 * The Welcome already brings the session to epoch N; processing the commit
 * again would cause an epoch mismatch error.
 *
 * Parameters:
 *   identity_handle   — new member's long-term identity (not consumed).
 *   welcome_bytes     — serialised Welcome protobuf from the group admin
 *                       (borrowed).
 *   welcome_length    — byte length of welcome_bytes.
 *   secrets_handle    — the key package secrets created alongside the
 *                       KeyPackage that was added (consumed and freed
 *                       internally on success; do NOT destroy afterwards).
 *                       On failure the handle remains valid.
 *   out_group_handle  — receives the AuraGroupSessionHandle.
 *                       Destroy with aura_group_destroy() when done.
 *   out_error         — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_WELCOME, AURA_ERROR_DECODE, or
 *          AURA_ERROR_TREE_INTEGRITY.
 */
AURA_API AuraErrorCode aura_group_join(
    AuraIdentityHandle*          identity_handle,
    const uint8_t*              welcome_bytes,
    size_t                      welcome_length,
    AuraKeyPackageSecretsHandle* secrets_handle,
    AuraGroupSessionHandle**     out_group_handle,
    AuraError*                   out_error);

/*
 * aura_group_add_member — add a new member to the group.
 *
 * Creates an Add proposal, wraps it in a Commit, advances the local epoch,
 * and produces a Welcome message for the new member.
 *
 * Only the member who calls this function should send the commit to the
 * group; other existing members call aura_group_process_commit() on receipt.
 * The new member calls aura_group_join() with the welcome bytes.
 *
 * Parameters:
 *   handle             — active group session handle (caller must be a
 *                        current member with committer rights).
 *   key_package_bytes  — serialised KeyPackage from the invitee (borrowed).
 *   key_package_length — byte length of key_package_bytes.
 *   out_commit         — receives the serialised Commit to broadcast to
 *                        existing members (release with aura_buffer_release()).
 *   out_welcome        — receives the serialised Welcome to send to the
 *                        new member (release with aura_buffer_release()).
 *   out_error          — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_GROUP_MEMBERSHIP, AURA_ERROR_GROUP_PROTOCOL,
 *          or AURA_ERROR_ENCODE.
 */
AURA_API AuraErrorCode aura_group_add_member(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          key_package_bytes,
    size_t                  key_package_length,
    AuraBuffer*              out_commit,
    AuraBuffer*              out_welcome,
    AuraError*               out_error);

/*
 * aura_group_remove_member — remove a member from the group.
 *
 * Creates a Remove proposal, wraps it in a Commit, and advances the local
 * epoch.  The removed member loses access to future messages immediately.
 *
 * Parameters:
 *   handle      — active group session handle (caller must be a current member).
 *   leaf_index  — zero-based leaf index of the member to remove.
 *                 Use aura_group_get_member_leaf_indices() to discover indices.
 *                 A member may not remove themselves; use aura_group_update()
 *                 followed by leaving via the application layer instead.
 *   out_commit  — receives the serialised Commit to broadcast
 *                 (release with aura_buffer_release()).
 *   out_error   — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_GROUP_MEMBERSHIP, AURA_ERROR_INVALID_INPUT,
 *          or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_remove_member(
    AuraGroupSessionHandle*  handle,
    uint32_t                leaf_index,
    AuraBuffer*              out_commit,
    AuraError*               out_error);

/*
 * aura_group_update — rotate the caller's leaf keys and advance the epoch.
 *
 * Creates an Update proposal, wraps it in a Commit, and publishes a new
 * UpdatePath so all other members can derive the new epoch keys.  Call
 * periodically for post-compromise security (PCS) or when the policy's
 * max_messages_per_epoch is approaching.
 *
 * Parameters:
 *   handle     — active group session handle.
 *   out_commit — receives the serialised Commit to broadcast
 *                (release with aura_buffer_release()).
 *   out_error  — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_update(
    AuraGroupSessionHandle*  handle,
    AuraBuffer*              out_commit,
    AuraError*               out_error);

/*
 * aura_group_process_commit — apply a Commit received from another member.
 *
 * Validates the Commit (parent hash chain, confirmation MAC, UpdatePath),
 * updates the ratchet tree, and advances the local epoch.  Must be called
 * for every Commit from other members in delivery order.
 *
 * Do NOT call this for a Commit that was generated locally (by add/remove/
 * update), as the local epoch has already been advanced.
 * Do NOT call this for the Commit whose Welcome you used to join the group.
 *
 * Parameters:
 *   handle        — active group session handle.
 *   commit_bytes  — serialised Commit protobuf received from the network
 *                   (borrowed).
 *   commit_length — byte length of commit_bytes.
 *   out_error     — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_GROUP_PROTOCOL, AURA_ERROR_TREE_INTEGRITY,
 *          AURA_ERROR_DECODE, or AURA_ERROR_GROUP_MEMBERSHIP.
 */
AURA_API AuraErrorCode aura_group_process_commit(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          commit_bytes,
    size_t                  commit_length,
    AuraError*               out_error);

/*
 * aura_group_encrypt — encrypt a plaintext message to the group.
 *
 * Uses the current epoch's sender-key ratchet.  The generation counter
 * advances with each call; recipients use the sender leaf index + generation
 * to decrypt out-of-order messages within the epoch.
 *
 * If mandatory_franking is set in the group's security policy this function
 * returns AURA_ERROR_INVALID_STATE; use aura_group_encrypt_frankable() instead.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — message bytes to encrypt (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   out_ciphertext   — receives the serialised GroupMessage protobuf
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_ENCRYPTION, or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_encrypt(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_decrypt — decrypt a group message (basic variant).
 *
 * Suitable when you only need the plaintext and sender identity.  For full
 * metadata (TTL, content type, message ID, franking) use aura_group_decrypt_ex().
 *
 * Parameters:
 *   handle            — active group session handle.
 *   ciphertext        — serialised GroupMessage bytes (borrowed).
 *   ciphertext_length — byte length of ciphertext.
 *   out_plaintext     — receives the decrypted plaintext
 *                       (release with aura_buffer_release()).
 *   out_sender_leaf   — receives the zero-based leaf index of the sender.
 *   out_generation    — receives the per-sender generation counter.
 *   out_error         — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_DECRYPTION, AURA_ERROR_DECODE, or
 *          AURA_ERROR_GROUP_MEMBERSHIP.
 */
AURA_API AuraErrorCode aura_group_decrypt(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    AuraBuffer*              out_plaintext,
    uint32_t*               out_sender_leaf,
    uint32_t*               out_generation,
    AuraError*               out_error);

/*
 * aura_group_decrypt_ex — decrypt a group message with full metadata.
 *
 * Populates an AuraGroupDecryptResult with plaintext, sender, generation,
 * content type, TTL, timestamps, message IDs, and feature flags.
 * Must be freed with aura_group_decrypt_result_free() after use.
 *
 * Parameters:
 *   handle            — active group session handle.
 *   ciphertext        — serialised GroupMessage bytes (borrowed).
 *   ciphertext_length — byte length of ciphertext.
 *   out_result        — caller-allocated AuraGroupDecryptResult to fill.
 *                       All AuraBuffer fields inside are heap-allocated;
 *                       free the entire struct with aura_group_decrypt_result_free().
 *   out_error         — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_DECRYPTION, AURA_ERROR_DECODE,
 *          AURA_ERROR_MESSAGE_EXPIRED, or AURA_ERROR_GROUP_MEMBERSHIP.
 */
AURA_API AuraErrorCode aura_group_decrypt_ex(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    AuraGroupDecryptResult*  out_result,
    AuraError*               out_error);

/*
 * aura_group_decrypt_result_free — release all heap memory inside an
 * AuraGroupDecryptResult previously populated by aura_group_decrypt_ex().
 *
 * Does NOT free the result struct itself (which is caller-allocated).
 * Zeros all AuraBuffer fields after release.  Safe to call on a zeroed struct.
 *
 * Safety:
 *   - Call only after a successful aura_group_decrypt_ex() (AURA_SUCCESS), or on
 *     a zero-initialised struct (AuraGroupDecryptResult result = {0}).
 *   - If aura_group_decrypt_ex() returned an error the struct may be partially
 *     written.  Always zero-initialise before passing to aura_group_decrypt_ex()
 *     so that calling aura_group_decrypt_result_free() after an error is safe.
 *   - Do NOT call aura_buffer_release() on individual fields — use this
 *     function to release the entire result atomically.
 */
AURA_API void aura_group_decrypt_result_free(AuraGroupDecryptResult* result);

/*
 * aura_group_compute_message_id — compute a deterministic message ID from
 * group metadata.
 *
 * Produces a stable, collision-resistant ID that clients can use to track,
 * deduplicate, and reference messages without decrypting them.  The relay
 * uses the same computation (Rust side) for deduplication and ordering.
 *
 * The ID is derived as:
 *   HKDF-Expand(epoch_secret, group_id || epoch || sender_leaf_index ||
 *               generation, 32)
 *
 * Parameters:
 *   group_id            — group identifier bytes (borrowed).
 *   group_id_length     — byte length of group_id.
 *   epoch               — current group epoch at the time the message was sent.
 *   sender_leaf_index   — leaf index of the sending member in the ratchet tree.
 *   generation          — per-member message generation counter at send time.
 *   out_message_id      — receives the 32-byte deterministic message ID
 *                         (release with aura_buffer_release()).
 *   out_error           — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_CRYPTO.
 */
AURA_API AuraErrorCode aura_group_compute_message_id(
    const uint8_t*  group_id,
    size_t          group_id_length,
    uint64_t        epoch,
    uint32_t        sender_leaf_index,
    uint32_t        generation,
    AuraBuffer*      out_message_id,
    AuraError*       out_error);

/*
 * aura_group_get_id — retrieve the group's unique identifier bytes.
 *
 * The group ID is a stable 32-byte random value assigned at creation and
 * preserved across epochs.
 *
 * Parameters:
 *   handle       — active group session handle.
 *   out_group_id — receives a copy of the group ID bytes
 *                  (release with aura_buffer_release()).
 *   out_error    — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_get_id(
    AuraGroupSessionHandle*  handle,
    AuraBuffer*              out_group_id,
    AuraError*               out_error);

/*
 * aura_group_get_epoch — return the current epoch number.
 *
 * The epoch increments with each successfully processed Commit.  Epoch 0
 * is the initial state after group creation.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: current epoch as uint64_t.  No error output; panics on NULL.
 */
AURA_API uint64_t aura_group_get_epoch(AuraGroupSessionHandle* handle);

/*
 * aura_group_get_my_leaf_index — return the caller's leaf index in the tree.
 *
 * Stable for the lifetime of membership; does not change across epochs.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: zero-based leaf index as uint32_t.
 */
AURA_API uint32_t aura_group_get_my_leaf_index(AuraGroupSessionHandle* handle);

/*
 * aura_group_get_member_count — return the current number of active members.
 *
 * Counts only occupied (non-blank) leaf nodes.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: member count as uint32_t.
 */
AURA_API uint32_t aura_group_get_member_count(AuraGroupSessionHandle* handle);

/*
 * aura_group_get_member_leaf_indices — retrieve the leaf indices of all
 * current members as a packed array of uint32_t.
 *
 * The returned buffer contains member_count values, each 4 bytes,
 * in little-endian order.
 *
 * Parameters:
 *   handle      — active group session handle.
 *   out_indices — receives the packed uint32_t array
 *                 (release with aura_buffer_release()).
 *   out_error   — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_get_member_leaf_indices(
    AuraGroupSessionHandle*  handle,
    AuraBuffer*              out_indices,
    AuraError*               out_error);

/*
 * aura_group_serialize — persist the full group session state to an encrypted
 * blob (including private ratchet tree keys).
 *
 * Uses the same sealed-blob format as aura_session_serialize_sealed().
 * LOW-LEVEL API: persist two values per slot:
 *   - max_restored_counter: highest counter already accepted on restore.
 *   - latest_issued_counter: highest counter already used for export.
 * New clients should prefer aura_group_export_persisted_state() when they can
 * store one serialized slot record, or otherwise
 * aura_group_serialize_with_tracker().
 *
 * external_counter here must be latest_issued_counter + 1.
 *
 * Parameters:
 *   handle           — active group session handle (not consumed).
 *   key              — 32-byte AES-256 encryption key (borrowed).
 *   key_length       — must be exactly 32.
 *   external_counter — next export counter for this slot
 *                      (latest_issued_counter + 1).
 *   out_state        — receives the encrypted blob
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_ENCRYPTION.
 */
AURA_API AuraErrorCode aura_group_serialize(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          key,
    size_t                  key_length,
    uint64_t                external_counter,
    AuraBuffer*              out_state,
    AuraError*               out_error);

/*
 * aura_group_serialize_with_tracker — managed group sealed-state export.
 *
 * Uses tracker_handle to allocate the next export counter and advances the
 * tracker only after a successful export.
 */
AURA_API AuraErrorCode aura_group_serialize_with_tracker(
    AuraGroupSessionHandle*               handle,
    const uint8_t*                       key,
    size_t                               key_length,
    AuraSealedStateCounterTrackerHandle*  tracker_handle,
    AuraBuffer*                           out_state,
    AuraError*                            out_error);

/*
 * aura_group_export_persisted_state — export group state into a managed slot.
 *
 * The slot is mutated in place: it allocates the next export counter, stores
 * the new sealed blob, and updates the tracker inside one in-memory object.
 * Persist slot_handle via aura_sealed_state_slot_serialize().
 */
AURA_API AuraErrorCode aura_group_export_persisted_state(
    AuraGroupSessionHandle*      handle,
    const uint8_t*              key,
    size_t                      key_length,
    AuraSealedStateSlotHandle*   slot_handle,
    AuraError*                   out_error);

/*
 * aura_group_deserialize — restore a group session from an encrypted blob.
 * New clients should prefer aura_group_restore_persisted_state() when
 * restoring from one serialized slot record, or otherwise
 * aura_group_deserialize_with_tracker().
 *
 * Parameters:
 *   state_bytes          — sealed blob bytes (borrowed).
 *   state_length         — byte length of state_bytes.
 *   key                  — 32-byte AES-256 decryption key (borrowed).
 *   key_length           — must be exactly 32.
 *   min_external_counter — minimum accepted restore watermark for this slot.
 *   out_external_counter — receives the counter stored in the blob.
 *                          After successful restore, persist it as the new
 *                          max_restored_counter and raise
 *                          latest_issued_counter to at least this value.
 *   identity_handle      — long-term identity to re-attach to the session
 *                          (not consumed; the session borrows it logically
 *                          so keep the identity alive while the session is
 *                          in use). Its Ed25519 identity keypair must match
 *                          the identity embedded in the sealed group state.
 *   out_handle           — receives the restored AuraGroupSessionHandle.
 *                          Destroy with aura_group_destroy(). 
 *   out_error            — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_DECRYPTION, AURA_ERROR_DECODE,
 *          AURA_ERROR_INVALID_INPUT, or AURA_ERROR_REPLAY_ATTACK.
 */
AURA_API AuraErrorCode aura_group_deserialize(
    const uint8_t*          state_bytes,
    size_t                  state_length,
    const uint8_t*          key,
    size_t                  key_length,
    uint64_t                min_external_counter,
    uint64_t*               out_external_counter,
    AuraIdentityHandle*      identity_handle,
    AuraGroupSessionHandle** out_handle,
    AuraError*               out_error);

/*
 * aura_group_deserialize_with_tracker — managed group sealed-state restore.
 *
 * Uses tracker_handle->max_restored_counter as the restore watermark and
 * advances the tracker only after a successful restore.
 */
AURA_API AuraErrorCode aura_group_deserialize_with_tracker(
    const uint8_t*                       state_bytes,
    size_t                               state_length,
    const uint8_t*                       key,
    size_t                               key_length,
    AuraSealedStateCounterTrackerHandle*  tracker_handle,
    AuraIdentityHandle*                   identity_handle,
    AuraGroupSessionHandle**              out_handle,
    AuraError*                            out_error);

/*
 * aura_group_restore_persisted_state — restore a group session from a managed
 * slot.
 *
 * The slot supplies the sealed blob plus restore watermark and is updated in
 * place on success. After restore, re-serialize and persist the slot so the
 * restore watermark advances inside the same record.
 */
AURA_API AuraErrorCode aura_group_restore_persisted_state(
    AuraSealedStateSlotHandle*  slot_handle,
    const uint8_t*             key,
    size_t                     key_length,
    AuraIdentityHandle*         identity_handle,
    AuraGroupSessionHandle**    out_handle,
    AuraError*                  out_error);

/*
 * aura_group_export_public_state — export the group's public state for
 * ExternalInit joins.
 *
 * The exported PublicGroupState contains the ratchet tree public keys,
 * group context, and external init public key.  Upload it to the relay or
 * distribute out-of-band so that prospective members can call
 * aura_group_join_external().
 *
 * Parameters:
 *   handle           — active group session handle.
 *   out_public_state — receives the serialised PublicGroupState protobuf
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_GROUP_PROTOCOL.
 */
AURA_API AuraErrorCode aura_group_export_public_state(
    AuraGroupSessionHandle*  handle,
    AuraBuffer*              out_public_state,
    AuraError*               out_error);

/*
 * aura_group_authorize_external_join — mint an authorization artifact for one
 * specific external joiner.
 *
 * Existing members call this after verifying the joiner's identity out of
 * band.  The returned bytes are bound to group_id + current epoch + joiner
 * identity + joiner credential + an explicit signed auth-format version + the
 * current exported public state (group_context_hash + external init public
 * keys), and must be supplied to aura_group_join_external().  Authorizations
 * are short-lived and joiners reject expired artifacts during bootstrap;
 * existing members validate the resulting ExternalInit Commit against the exact
 * pre-commit group state rather than their local wall clock. During rollout,
 * use ExternalInit only between peers that support the same authorization
 * payload format.
 */
AURA_API AuraErrorCode aura_group_authorize_external_join(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          joiner_identity_ed25519_public,
    size_t                  joiner_identity_ed25519_public_length,
    const uint8_t*          joiner_identity_x25519_public,
    size_t                  joiner_identity_x25519_public_length,
    const uint8_t*          joiner_credential,
    size_t                  joiner_credential_length,
    AuraBuffer*              out_authorization,
    AuraError*               out_error);

/*
 * aura_group_join_external — join a group without a Welcome by performing an
 * ExternalInit.
 *
 * Uses the group's published external init key (inside public_state) plus a
 * member-issued authorization artifact to KEM a new init secret, produce an
 * ExternalInit Commit, and establish the caller as a new leaf.
 *
 * After a successful call the caller broadcasts out_commit to all existing
 * members, who apply it with aura_group_process_commit().
 *
 * Parameters:
 *   identity_handle    — caller's long-term identity (not consumed).
 *   public_state       — PublicGroupState bytes (from aura_group_export_public_state
 *                        of an existing member, or fetched from relay). Borrowed.
 *                        The joiner verifies that authorization is signed by a
 *                        current member and cryptographically bound to this
 *                        exact public_state.
 *   public_state_length — byte length of public_state.
 *   authorization      — authorization bytes from
 *                        aura_group_authorize_external_join(). Borrowed. The
 *                        joiner enforces the authorization freshness window
 *                        here before creating an ExternalInit Commit.
 *   authorization_length — byte length of authorization.
 *   credential         — caller's application credential to embed in the tree
 *                        (borrowed).
 *   credential_length  — byte length of credential.
 *   out_group_handle   — receives the new AuraGroupSessionHandle.
 *                        Destroy with aura_group_destroy() when done.
 *   out_commit         — receives the ExternalInit Commit to broadcast
 *                        (release with aura_buffer_release()).
 *   out_error          — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_GROUP_PROTOCOL, AURA_ERROR_DECODE, or
 *          AURA_ERROR_KEY_GENERATION.
 */
AURA_API AuraErrorCode aura_group_join_external(
    AuraIdentityHandle*      identity_handle,
    const uint8_t*          public_state,
    size_t                  public_state_length,
    const uint8_t*          authorization,
    size_t                  authorization_length,
    const uint8_t*          credential,
    size_t                  credential_length,
    AuraGroupSessionHandle** out_group_handle,
    AuraBuffer*              out_commit,
    AuraError*               out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group messaging features
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_group_encrypt_sealed — encrypt a message with a two-layer sealed payload.
 *
 * The outer layer is a normal group-encrypted envelope.  The inner plaintext
 * is additionally encrypted with a per-message seal_key derived from the
 * message key.  Recipients see that a sealed payload exists (has_sealed_payload
 * in AuraGroupDecryptResult) but cannot read the inner content until the sender
 * calls aura_group_reveal_sealed() and shares the seal_key and nonce.
 *
 * hint is visible to recipients before the reveal and can carry a preview
 * (e.g. "You have a sealed message from Alice").
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — inner plaintext to seal (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   hint             — optional plaintext hint visible before reveal.
 *                      Pass NULL + 0 to omit.  Borrowed.
 *   hint_length      — byte length of hint.
 *   out_ciphertext   — receives the serialised GroupMessage protobuf
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_ENCRYPTION, or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_encrypt_sealed(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    const uint8_t*          hint,
    size_t                  hint_length,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_encrypt_disappearing — encrypt a message with a server-enforced
 * time-to-live.
 *
 * The TTL and sent_timestamp are embedded in the authenticated plaintext.
 * aura_group_decrypt_ex() returns AURA_ERROR_MESSAGE_EXPIRED if the current
 * time exceeds sent_timestamp + ttl_seconds.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — message bytes to encrypt (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   ttl_seconds      — lifetime in seconds after sent_timestamp.
 *                      Must be > 0.
 *   out_ciphertext   — receives the serialised GroupMessage
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_ENCRYPTION.
 */
AURA_API AuraErrorCode aura_group_encrypt_disappearing(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    uint32_t                ttl_seconds,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_encrypt_frankable — encrypt a message with an embedded franking
 * tag for abuse reporting.
 *
 * Generates a (franking_key, franking_tag) pair.  The franking_tag is placed
 * outside the encrypted payload (visible to the relay); the franking_key is
 * inside (E2E encrypted).  A user wishing to report the message shares
 * (franking_tag, franking_key, plaintext) with the relay, which verifies the
 * tag via its Rust-side API (the relay is implemented in Rust and does not use
 * the C interop surface).
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — message bytes to encrypt (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   out_ciphertext   — receives the serialised GroupMessage
 *                      (release with aura_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_ENCRYPTION, or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_encrypt_frankable(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_encrypt_edit — encrypt an edit to a previously sent message.
 *
 * Produces a GroupMessage with content_type=4 (edit) that references the
 * original message by its canonical ID.  Recipients who can decrypt the
 * original should update their local copy of the message.
 *
 * Parameters:
 *   handle                   — active group session handle.
 *   new_content              — replacement message bytes (borrowed).
 *   new_content_length       — byte length of new_content.
 *   target_message_id        — canonical ID of the message being edited
 *                              (32 bytes; from AuraGroupDecryptResult.message_id
 *                              or aura_group_compute_message_id()). Borrowed.
 *   target_message_id_length — byte length of target_message_id; must be 32.
 *   out_ciphertext           — receives the serialised GroupMessage
 *                              (release with aura_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_ENCRYPTION.
 */
AURA_API AuraErrorCode aura_group_encrypt_edit(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          new_content,
    size_t                  new_content_length,
    const uint8_t*          target_message_id,
    size_t                  target_message_id_length,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_encrypt_delete — encrypt a delete request for a previously sent
 * message.
 *
 * Produces a GroupMessage with content_type=5 (delete) referencing the
 * target message ID.  Recipients should remove or hide the referenced
 * message from their UI.  The protocol does not enforce deletion of
 * previously received ciphertext.
 *
 * Parameters:
 *   handle                   — active group session handle.
 *   target_message_id        — canonical ID of the message to delete
 *                              (32 bytes). Borrowed.
 *   target_message_id_length — must be 32.
 *   out_ciphertext           — receives the serialised GroupMessage
 *                              (release with aura_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_ENCRYPTION.
 */
AURA_API AuraErrorCode aura_group_encrypt_delete(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          target_message_id,
    size_t                  target_message_id_length,
    AuraBuffer*              out_ciphertext,
    AuraError*               out_error);

/*
 * aura_group_reveal_sealed — decrypt the inner layer of a sealed message.
 *
 * The caller must supply the hint, encrypted_content, nonce, and seal_key
 * that are embedded in the decrypted GroupMessage payload
 * (available after aura_group_decrypt_ex() when has_sealed_payload == 1).
 * The sender shares seal_key out-of-band when ready to reveal.
 *
 * Parameters:
 *   hint                     — hint bytes from the sealed message (borrowed).
 *   hint_length              — byte length of hint.
 *   encrypted_content        — inner ciphertext from the sealed payload (borrowed).
 *   encrypted_content_length — byte length of encrypted_content.
 *   nonce                    — 12-byte AES-GCM nonce from the sealed payload
 *                              (borrowed).
 *   nonce_length             — must be 12.
 *   seal_key                 — 32-byte seal key shared by the sender (borrowed).
 *   seal_key_length          — must be 32.
 *   out_plaintext            — receives the decrypted inner plaintext
 *                              (release with aura_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT, or AURA_ERROR_DECRYPTION.
 */
AURA_API AuraErrorCode aura_group_reveal_sealed(
    const uint8_t*  hint,
    size_t          hint_length,
    const uint8_t*  encrypted_content,
    size_t          encrypted_content_length,
    const uint8_t*  nonce,
    size_t          nonce_length,
    const uint8_t*  seal_key,
    size_t          seal_key_length,
    AuraBuffer*      out_plaintext,
    AuraError*       out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group management
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * aura_group_set_psk — inject a pre-shared key into the group's key schedule.
 *
 * The PSK is mixed into the next epoch's init_secret via HKDF, binding the
 * epoch to external shared context (e.g. a password or hardware token value).
 * All members must inject the same PSK (identified by psk_id) before the
 * next Commit, otherwise their epoch keys will diverge.
 *
 * Parameters:
 *   handle      — active group session handle.
 *   psk_id      — application-defined PSK identifier bytes; must match
 *                 across all members (borrowed).
 *   psk_id_length — byte length of psk_id; must be >= 1.
 *   psk         — the pre-shared key bytes (borrowed); recommended >= 32 bytes.
 *   psk_length  — byte length of psk.
 *   out_error   — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_INPUT.
 */
AURA_API AuraErrorCode aura_group_set_psk(
    AuraGroupSessionHandle*  handle,
    const uint8_t*          psk_id,
    size_t                  psk_id_length,
    const uint8_t*          psk,
    size_t                  psk_length,
    AuraError*               out_error);

/*
 * aura_group_get_pending_reinit — check whether a ReInit proposal is pending.
 *
 * A ReInit signals that the group should migrate to a new group (new ID,
 * potentially new protocol version).  When this returns AURA_SUCCESS and
 * out_new_group_id.length > 0, the application should initiate the migration
 * flow: create a new group with the given ID and re-add all members.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   out_new_group_id — receives the proposed new group ID bytes, or an
 *                      empty buffer if no reinit is pending
 *                      (release with aura_buffer_release()).
 *   out_new_version  — receives the proposed new protocol version number,
 *                      or 0 if no reinit is pending.
 *   out_error        — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_INVALID_STATE.
 */
AURA_API AuraErrorCode aura_group_get_pending_reinit(
    AuraGroupSessionHandle*  handle,
    AuraBuffer*              out_new_group_id,
    uint32_t*               out_new_version,
    AuraError*               out_error);

/*
 * aura_group_destroy — free a group session handle and securely wipe all
 * private ratchet tree key material.
 *
 * Sets *handle to NULL.  Safe to call with *handle == NULL (no-op).
 */
AURA_API void aura_group_destroy(AuraGroupSessionHandle** handle);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — 1-to-1 session
 *
 * Register a set of C function pointers to receive protocol events from a
 * session.  All callbacks are optional (set to NULL to ignore).
 * The library never calls a NULL slot.
 *
 * THREADING: Callbacks may be invoked from any thread that drives ratchet /
 * session state — NOT necessarily the thread that called
 * aura_session_set_event_handler.  user_data MUST be thread-safe (protected
 * by your own lock, or marshalled to the UI thread inside the callback for
 * Swift `@MainActor` types).  Treating the callback as main-thread-only is
 * a bug that will crash under concurrent session use.
 *
 * LIFETIME: user_data must remain valid until the session is destroyed or a
 * new handler is registered.  The library holds no reference to user_data
 * beyond passing it verbatim to each callback.
 *
 * PANICS / EXCEPTIONS: Your callback must NOT throw a C++ exception or
 * raise a Rust panic across the call boundary.  The library installs
 * `catch_unwind` around the invocation so a Rust-side panic in your
 * callback is contained and the event is silently dropped, but this is a
 * last-ditch safety net — write callbacks that never panic.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraOnHandshakeCompleted — fired once when both sides have completed the
 * X3DH+Kyber handshake and the session is ready for encrypt/decrypt.
 *
 *   session_id     — pointer to the 16-byte session identifier (borrowed for
 *                    the duration of the callback only; do NOT retain).
 *   session_id_len — always 16.
 *   user_data      — the value passed in AuraSessionEventCallbacks.user_data.
 *
 * Use case: store the session ID in your contact database to correlate this
 * AuraSessionHandle with a user record.
 */
typedef void (*AuraOnHandshakeCompleted)(
    const uint8_t* session_id,
    size_t         session_id_len,
    void*          user_data);

/*
 * AuraOnRatchetRotated — fired each time the DH ratchet advances to a new
 * epoch (i.e. a new chain key is derived).
 *
 *   epoch     — monotonically increasing ratchet epoch counter.
 *   user_data — value from AuraSessionEventCallbacks.user_data.
 *
 * Use case: UI indicator showing "forward secrecy refreshed".
 */
typedef void (*AuraOnRatchetRotated)(uint64_t epoch, void* user_data);

/*
 * AuraOnSessionError — fired on a non-fatal internal protocol error.
 *
 *   code      — error category (see AuraErrorCode).
 *   message   — null-terminated human-readable description (borrowed; valid
 *               only for the duration of the callback).
 *   user_data — value from AuraSessionEventCallbacks.user_data.
 *
 * Use case: logging / telemetry.  The session remains usable after this
 * callback; if the error is fatal the next API call will return an error code.
 */
typedef void (*AuraOnSessionError)(
    AuraErrorCode   code,
    const char*    message,
    void*          user_data);

/*
 * AuraOnNonceExhaustionWarning — fired when the current chain's nonce budget
 * drops below ~10 %.  The next outgoing or incoming message will trigger a
 * DH ratchet step automatically, but calling the callback gives the app a
 * chance to schedule a proactive message.
 *
 *   remaining    — nonces left in the current chain.
 *   max_capacity — total nonce budget for a single chain.
 *   user_data    — value from AuraSessionEventCallbacks.user_data.
 */
typedef void (*AuraOnNonceExhaustionWarning)(
    uint64_t remaining,
    uint64_t max_capacity,
    void*    user_data);

/*
 * AuraOnRatchetStallingWarning — fired when many consecutive messages have
 * been sent without a DH ratchet step (the peer appears unresponsive).
 * At this point forward secrecy is degraded; consider sending a ping or
 * triggering a session refresh.
 *
 *   messages_since_ratchet — number of messages sent since the last ratchet.
 *   user_data              — value from AuraSessionEventCallbacks.user_data.
 */
typedef void (*AuraOnRatchetStallingWarning)(
    uint64_t messages_since_ratchet,
    void*    user_data);

/*
 * AuraSessionEventCallbacks — vtable of C callbacks for a 1-to-1 session.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * aura_session_set_event_handler().  The struct is copied by value; you do
 * not need to keep it alive after the call returns.
 *
 * Set any callback field to NULL to ignore that event.
 *
 * user_data is an opaque pointer forwarded verbatim to every callback.
 * Typical use: pass `self` / a context pointer from your application.
 */
typedef struct {
    AuraOnHandshakeCompleted      on_handshake_completed;
    AuraOnRatchetRotated          on_ratchet_rotated;
    AuraOnSessionError            on_error;
    AuraOnNonceExhaustionWarning  on_nonce_exhaustion_warning;
    AuraOnRatchetStallingWarning  on_ratchet_stalling_warning;
    void*                        user_data;
} AuraSessionEventCallbacks;

/*
 * aura_session_set_event_handler — register C callbacks on a 1-to-1 session.
 *
 * The callbacks struct is copied immediately; you can free or reuse it after
 * this call returns.  Calling this function again replaces the previous
 * handler.  Pass a zeroed struct to remove all callbacks.
 *
 * Parameters:
 *   handle    — active session handle.
 *   callbacks — pointer to a populated AuraSessionEventCallbacks (not NULL).
 *               All function-pointer fields may individually be NULL.
 *   out_error — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_NULL_POINTER / AURA_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_ratchet(uint64_t epoch, void* ctx) {
 *       MyApp* app = ctx;
 *       app->last_ratchet_epoch = epoch;
 *   }
 *   AuraSessionEventCallbacks cbs = {0};
 *   cbs.on_ratchet_rotated = on_ratchet;
 *   cbs.user_data = my_app;
 *   aura_session_set_event_handler(session, &cbs, &err);
 */
AURA_API AuraErrorCode aura_session_set_event_handler(
    AuraSessionHandle*              handle,
    const AuraSessionEventCallbacks* callbacks,
    AuraError*                      out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — group session
 *
 * Same threading and lifetime rules as session event callbacks above.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraOnMemberAdded — fired after a Commit that added a new member is applied.
 *
 *   leaf_index           — zero-based leaf position of the new member in the
 *                          ratchet tree.
 *   identity_ed25519     — pointer to the new member's 32-byte Ed25519 public
 *                          key (borrowed; valid only during this callback).
 *   identity_ed25519_len — always 32.
 *   user_data            — value from AuraGroupEventCallbacks.user_data.
 *
 * Use case: update the UI member list; look up the new contact by their key.
 */
typedef void (*AuraOnMemberAdded)(
    uint32_t       leaf_index,
    const uint8_t* identity_ed25519,
    size_t         identity_ed25519_len,
    void*          user_data);

/*
 * AuraOnMemberRemoved — fired after a Commit that removed a member is applied.
 *
 *   leaf_index — leaf position of the removed member (now blank in the tree).
 *   user_data  — value from AuraGroupEventCallbacks.user_data.
 *
 * Use case: remove the member from the UI; revoke any cached sender key.
 */
typedef void (*AuraOnMemberRemoved)(uint32_t leaf_index, void* user_data);

/*
 * AuraOnEpochAdvanced — fired every time a Commit is successfully applied and
 * the epoch number increments.
 *
 *   new_epoch    — epoch number after the commit.
 *   member_count — number of active (non-blank) members after the commit.
 *   user_data    — value from AuraGroupEventCallbacks.user_data.
 *
 * Use case: persist the new epoch to storage; refresh epoch-bound UI state.
 */
typedef void (*AuraOnEpochAdvanced)(
    uint64_t new_epoch,
    uint32_t member_count,
    void*    user_data);

/*
 * AuraOnSenderKeyExhaustionWarning — fired when this member's sender-key
 * generation counter approaches the per-epoch limit set by
 * AuraGroupSecurityPolicy.max_messages_per_epoch.
 *
 *   remaining    — generation slots remaining before a forced Update is needed.
 *   max_capacity — the total per-epoch message budget for this member.
 *   user_data    — value from AuraGroupEventCallbacks.user_data.
 *
 * Use case: prompt the user or automatically call aura_group_update() to
 * rotate keys and start a new epoch before the budget is exhausted.
 */
typedef void (*AuraOnSenderKeyExhaustionWarning)(
    uint32_t remaining,
    uint32_t max_capacity,
    void*    user_data);

/*
 * AuraOnReInitProposed — fired when a Commit that contains a ReInit proposal
 * is successfully applied.  A ReInit signals that the group is deprecated and
 * all members should migrate to a new group.
 *
 *   new_group_id     — pointer to the new group's 32-byte identifier (borrowed;
 *                      valid only for the duration of this callback).
 *   new_group_id_len — always 32.
 *   new_version      — protocol version the new group should use.
 *   user_data        — value from AuraGroupEventCallbacks.user_data.
 *
 * Use case: notify participants, create a fresh group at new_group_id with
 * the indicated protocol version, and stop sending into the old group.
 */
typedef void (*AuraOnReInitProposed)(
    const uint8_t* new_group_id,
    size_t         new_group_id_len,
    uint32_t       new_version,
    void*          user_data);

/*
 * AuraGroupEventCallbacks — vtable of C callbacks for a group session.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * aura_group_set_event_handler().  Copied by value; struct need not outlive
 * the call.  Set any field to NULL to ignore that event.
 */
typedef struct {
    AuraOnMemberAdded                on_member_added;
    AuraOnMemberRemoved              on_member_removed;
    AuraOnEpochAdvanced              on_epoch_advanced;
    AuraOnSenderKeyExhaustionWarning on_sender_key_exhaustion_warning;
    AuraOnReInitProposed             on_reinit_proposed;
    void*                           user_data;
} AuraGroupEventCallbacks;

/*
 * aura_group_set_event_handler — register C callbacks on a group session.
 *
 * The callbacks struct is copied immediately; free or reuse it after return.
 * Calling again replaces the previous handler; pass a zeroed struct to remove.
 *
 * Parameters:
 *   handle    — active group session handle.
 *   callbacks — pointer to a populated AuraGroupEventCallbacks (not NULL).
 *   out_error — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_NULL_POINTER / AURA_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_epoch(uint64_t epoch, uint32_t members, void* ctx) {
 *       persist_epoch(ctx, epoch, members);
 *   }
 *   AuraGroupEventCallbacks cbs = {0};
 *   cbs.on_epoch_advanced = on_epoch;
 *   cbs.user_data = my_db;
 *   aura_group_set_event_handler(group, &cbs, &err);
 */
AURA_API AuraErrorCode aura_group_set_event_handler(
    AuraGroupSessionHandle*          handle,
    const AuraGroupEventCallbacks*   callbacks,
    AuraError*                       out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — identity
 *
 * Identity-level events are not tied to a single session or group.
 * Register once per identity handle.  Same threading and lifetime rules
 * as session and group callbacks above.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * AuraOnOtkExhaustionWarning — fired after an OTK (One-Time Prekey) is
 * consumed and the remaining pool has dropped at or below the exhaustion
 * warning threshold (default: ≤ 10 % of max_capacity).
 *
 * A depleted OTK pool prevents new contacts from initiating a handshake with
 * this identity.  Upload fresh OTKs immediately by calling
 * aura_prekey_bundle_replenish() and sending the result to the key server.
 *
 *   remaining    — OTKs remaining in the local pool after this consumption.
 *   max_capacity — the default pool size (DEFAULT_ONE_TIME_KEY_COUNT = 100).
 *   user_data    — value from AuraIdentityEventCallbacks.user_data.
 *
 * Use case: trigger background replenishment so the pool never hits zero.
 */
typedef void (*AuraOnOtkExhaustionWarning)(
    uint32_t remaining,
    uint32_t max_capacity,
    void*    user_data);

/*
 * AuraIdentityEventCallbacks — vtable of C callbacks for an identity handle.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * aura_identity_set_event_handler().  Copied by value; struct need not outlive
 * the call.  Set any field to NULL to ignore that event.
 */
typedef struct {
    AuraOnOtkExhaustionWarning on_otk_exhaustion_warning;
    void*                     user_data;
} AuraIdentityEventCallbacks;

/*
 * aura_identity_set_event_handler — register C callbacks on an identity handle.
 *
 * The callbacks struct is copied immediately; free or reuse it after return.
 * Calling again replaces the previous handler; pass a zeroed struct to remove.
 *
 * Parameters:
 *   handle    — active identity handle (not NULL).
 *   callbacks — pointer to a populated AuraIdentityEventCallbacks (not NULL).
 *               All function-pointer fields may individually be NULL.
 *   out_error — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_NULL_POINTER / AURA_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_otk_low(uint32_t remaining, uint32_t max, void* ctx) {
 *       MyApp* app = ctx;
 *       aura_prekey_bundle_replenish(app->identity, 50, app->out_buf, NULL);
 *       upload_otks_to_key_server(app->out_buf);
 *   }
 *   AuraIdentityEventCallbacks cbs = {0};
 *   cbs.on_otk_exhaustion_warning = on_otk_low;
 *   cbs.user_data = my_app;
 *   aura_identity_set_event_handler(identity, &cbs, &err);
 */
AURA_API AuraErrorCode aura_identity_set_event_handler(
    AuraIdentityHandle*                handle,
    const AuraIdentityEventCallbacks*  callbacks,
    AuraError*                         out_error);

/* ============================================================================
 * Channel encryption (broadcast E2E for channel posts)
 *
 * Stateless API. Channel keys are managed externally by the calling layer.
 *
 * Buffer sizes:
 *   - channel_key:           32 bytes (AES-256-GCM-SIV symmetric key)
 *   - channel_id:            16 bytes (UUID)
 *   - channel_key_id:        16 bytes (UUID)
 *   - device X25519 public:  32 bytes
 *   - device Kyber public:   1184 bytes
 *   - sender Ed25519 secret: 32 bytes (seed)
 *   - sender Ed25519 public: 32 bytes
 *   - nonce:                 12 bytes (AES-GCM-SIV)
 *   - signature:             64 bytes (Ed25519)
 *   - wrapped key blob:      1180 bytes
 *       (32 ephemeral X25519 + 1088 Kyber CT + 12 nonce + 48 ciphertext)
 *
 * The wire envelope (channel_key_id + generation + nonce + ciphertext + signature)
 * is assembled by the calling layer and sent through the gateway.
 * ========================================================================== */

/*
 * aura_channel_generate_key — generate a fresh symmetric channel key + UUID v4 id.
 *
 * Parameters:
 *   out_key_id  — caller-provided 16-byte buffer; receives the UUID v4 key id.
 *   out_key     — caller-provided 32-byte buffer; receives the AES-256 key.
 *   out_error   — optional error detail.
 *
 * Returns: AURA_SUCCESS or AURA_ERROR_GENERIC.
 */
AURA_API AuraErrorCode aura_channel_generate_key(
    uint8_t*    out_key_id,
    uint8_t*    out_key,
    AuraError*  out_error);

/*
 * aura_channel_wrap_key_for_device — wrap a channel key for one subscriber
 * device using hybrid X25519 ECDH + ML-KEM-768 + HKDF + AES-GCM-SIV.
 *
 * Output blob is exactly 1180 bytes regardless of input. Caller releases
 * out_blob with aura_buffer_release().
 *
 * Parameters:
 *   channel_key          — 32-byte symmetric channel key.
 *   device_x25519_public — 32-byte device X25519 public key.
 *   device_kyber_public  — 1184-byte device Kyber/ML-KEM public key.
 *   out_blob             — receives the 1180-byte wrapped blob.
 *   out_error            — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_NULL_POINTER, AURA_ERROR_GENERIC,
 *          or AURA_ERROR_CRYPTO_FAILURE.
 */
AURA_API AuraErrorCode aura_channel_wrap_key_for_device(
    const uint8_t*  channel_key,
    const uint8_t*  device_x25519_public,
    const uint8_t*  device_kyber_public,
    AuraBuffer*     out_blob,
    AuraError*      out_error);

/*
 * aura_channel_unwrap_key_blob — unwrap a previously wrapped channel key blob
 * using the device identity handle's X25519 and Kyber/ML-KEM secret keys.
 *
 * Parameters:
 *   blob                 — wrapped key blob (must be exactly 1180 bytes).
 *   blob_length          — byte length of blob.
 *   identity_handle      — identity handle for the recipient device.
 *   out_channel_key      — caller-provided 32-byte buffer for the unwrapped key.
 *   out_error            — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT (wrong length),
 *          AURA_ERROR_NULL_POINTER, or AURA_ERROR_DECRYPTION (tampered blob /
 *          wrong recipient identity).
 */
AURA_API AuraErrorCode aura_channel_unwrap_key_blob(
    const uint8_t*  blob,
    size_t          blob_length,
    const AuraIdentityHandle* identity_handle,
    uint8_t*        out_channel_key,
    AuraError*      out_error);

/*
 * aura_channel_encrypt_message — encrypt a channel message and produce the
 * envelope fields (nonce + ciphertext + signature).
 *
 * Computes:
 *   nonce      = random 12 bytes (CSPRNG)
 *   ciphertext = AES-256-GCM-SIV(channel_key, nonce, plaintext, AAD)
 *   signature  = Ed25519(sender_secret, channel_id || generation_be8 || ciphertext)
 *
 * The caller assembles {channel_key_id, generation, nonce, ciphertext, signature}
 * into the wire envelope (e.g. ProtoEncryptedChannelMessage).
 *
 * Parameters:
 *   plaintext             — message bytes (may be empty if length is 0).
 *   plaintext_length      — byte length of plaintext.
 *   channel_key           — 32-byte symmetric channel key.
 *   channel_id            — 16-byte channel UUID.
 *   channel_key_id        — 16-byte UUID identifying the key epoch.
 *   generation            — monotonically increasing per-sender counter.
 *   sender_ed25519_secret — 32-byte Ed25519 seed of the sender's identity key.
 *   out_nonce             — caller-provided 12-byte buffer; receives the nonce.
 *   out_signature         — caller-provided 64-byte buffer; receives the signature.
 *   out_ciphertext        — receives the AES-GCM-SIV ciphertext+tag
 *                           (release with aura_buffer_release()).
 *   out_error             — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT (plaintext too large),
 *          AURA_ERROR_NULL_POINTER, AURA_ERROR_GENERIC, or AURA_ERROR_CRYPTO_FAILURE.
 */
AURA_API AuraErrorCode aura_channel_encrypt_message(
    const uint8_t*  plaintext,
    size_t          plaintext_length,
    const uint8_t*  channel_key,
    const uint8_t*  channel_id,
    const uint8_t*  channel_key_id,
    uint64_t        generation,
    const uint8_t*  sender_ed25519_secret,
    uint8_t*        out_nonce,
    uint8_t*        out_signature,
    AuraBuffer*     out_ciphertext,
    AuraError*      out_error);

/*
 * aura_channel_decrypt_message — verify Ed25519 signature and AES-256-GCM-SIV
 * decrypt a channel message envelope.
 *
 * Parameters:
 *   ciphertext            — AES-GCM-SIV ciphertext+tag (must include 16-byte tag).
 *   ciphertext_length     — byte length of ciphertext.
 *   nonce                 — 12-byte nonce from the envelope.
 *   signature             — 64-byte Ed25519 signature from the envelope.
 *   channel_key_id        — 16-byte key id from the envelope (binds AAD).
 *   generation            — generation counter from the envelope.
 *   channel_key           — 32-byte symmetric channel key (looked up by id).
 *   channel_id            — 16-byte channel UUID.
 *   sender_ed25519_public — 32-byte Ed25519 public key of the claimed sender.
 *   out_plaintext         — receives the decrypted plaintext
 *                           (release with aura_buffer_release()).
 *   out_error             — optional error detail.
 *
 * Returns: AURA_SUCCESS, AURA_ERROR_INVALID_INPUT (length / key format),
 *          AURA_ERROR_NULL_POINTER, AURA_ERROR_DECRYPTION (signature or AEAD
 *          verification failed).
 */
AURA_API AuraErrorCode aura_channel_decrypt_message(
    const uint8_t*  ciphertext,
    size_t          ciphertext_length,
    const uint8_t*  nonce,
    const uint8_t*  signature,
    const uint8_t*  channel_key_id,
    uint64_t        generation,
    const uint8_t*  channel_key,
    const uint8_t*  channel_id,
    const uint8_t*  sender_ed25519_public,
    AuraBuffer*     out_plaintext,
    AuraError*      out_error);

#ifdef __cplusplus
}
#endif
