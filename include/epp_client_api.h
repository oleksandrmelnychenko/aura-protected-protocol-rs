#pragma once
#include "epp_common_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client-side E2E API — Ecliptix Protection Protocol
 *
 * All operations here involve private key material and run entirely on the
 * client device. The relay never calls these functions.
 *
 * OWNERSHIP RULES (apply to every function in this file):
 *   - Parameters named `out_handle` write a newly allocated opaque handle.
 *     The caller owns the handle and MUST destroy it with the matching
 *     _destroy() function when done.
 *   - Parameters named `out_*` of type EppBuffer* write a heap-allocated
 *     buffer owned by the caller. Release it with epp_buffer_release().
 *   - Parameters named `out_error` receive an optional error detail struct.
 *     If non-NULL and an error occurs the struct is populated; free it with
 *     epp_error_free() after use.  Pass NULL to ignore error details.
 *   - All byte-slice inputs (`const uint8_t* foo, size_t foo_length`) are
 *     borrowed for the duration of the call only; the caller retains ownership.
 *   - Handles are NOT thread-safe. Do not share a single handle across threads
 *     without external synchronisation.
 *
 * ERROR HANDLING:
 *   Every fallible function returns EppErrorCode. Check for EPP_SUCCESS (0)
 *   before reading any out_* value — they are undefined on failure.
 */

/* ═══════════════════════════════════════════════════════════════════════════
 * Opaque handle types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct EppIdentityHandle          EppIdentityHandle;
typedef struct EppSessionHandle           EppSessionHandle;
typedef struct EppGroupSessionHandle      EppGroupSessionHandle;
typedef struct EppKeyPackageSecretsHandle EppKeyPackageSecretsHandle;
typedef struct EppHandshakeInitiatorHandle EppHandshakeInitiatorHandle;
typedef struct EppHandshakeResponderHandle EppHandshakeResponderHandle;

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration structs
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * EppSessionConfig — tuning parameters for a 1-to-1 Double Ratchet session.
 *
 *   max_messages_per_chain
 *     Maximum number of messages that may be encrypted under a single ratchet
 *     chain key before a forced ratchet step is required.  Use 0 for the
 *     library default (100).  Smaller values improve forward secrecy at the
 *     cost of slightly more frequent key-exchange round-trips.
 */
typedef struct EppSessionConfig {
    uint32_t max_messages_per_chain;
} EppSessionConfig;

/*
 * EppGroupSecurityPolicy — per-group security constraints.
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
 *     Calls to epp_group_encrypt() (non-frankable) will return
 *     EPP_ERROR_INVALID_STATE when this flag is set.
 */
typedef struct EppGroupSecurityPolicy {
    uint32_t max_messages_per_epoch;
    uint32_t max_skipped_keys_per_sender;
    uint8_t  block_external_join;
    uint8_t  enhanced_key_schedule;
    uint8_t  mandatory_franking;
} EppGroupSecurityPolicy;

/*
 * EppGroupDecryptResult — full metadata returned by epp_group_decrypt_ex().
 *
 *   plaintext
 *     Decrypted message content.  Owned by the caller; release all EppBuffer
 *     fields inside this struct with epp_group_decrypt_result_free().
 *     Do NOT call epp_buffer_release() on individual fields manually.
 *
 *   sender_leaf_index
 *     Zero-based leaf index of the sending member in the ratchet tree.
 *     Use epp_group_get_member_leaf_indices() to map indices to credentials.
 *
 *   generation
 *     Per-sender message counter within the current epoch (starts at 0).
 *     Together with epoch + sender_leaf_index this uniquely identifies a
 *     message; use epp_group_compute_message_id() to derive the canonical ID.
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
 *     payload.  Use epp_group_reveal_sealed() to decrypt the inner layer.
 *
 *   has_franking_data
 *     Non-zero when the message carries a franking tag and franking key
 *     suitable for abuse reporting via epp_group_verify_franking().
 *
 *   sealed_*
 *     Present only when has_sealed_payload != 0.  These buffers provide the
 *     exact inputs required by epp_group_reveal_sealed().
 *
 *   franking_*
 *     Present only when has_franking_data != 0.  These buffers provide the
 *     exact inputs required by epp_group_verify_franking().
 */
typedef struct {
    EppBuffer plaintext;
    uint32_t  sender_leaf_index;
    uint32_t  generation;
    uint32_t  content_type;
    uint32_t  ttl_seconds;
    uint64_t  sent_timestamp;
    EppBuffer message_id;
    EppBuffer referenced_message_id;
    uint8_t   has_sealed_payload;
    uint8_t   has_franking_data;
    EppBuffer sealed_hint;
    EppBuffer sealed_encrypted_content;
    EppBuffer sealed_nonce;
    EppBuffer sealed_key;
    EppBuffer franking_tag;
    EppBuffer franking_key;
    EppBuffer franking_content;
    EppBuffer franking_sealed_content;
} EppGroupDecryptResult;


/* ═══════════════════════════════════════════════════════════════════════════
 * Identity
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_identity_create — generate a fresh identity with random keys.
 *
 * Creates a new long-term identity consisting of:
 *   - X25519 Diffie-Hellman key pair (classic DH for X3DH)
 *   - Ed25519 signing key pair      (signature authentication)
 *   - Kyber-768 key pair            (post-quantum KEM)
 *
 * Parameters:
 *   out_handle  — receives a pointer to the newly allocated identity handle.
 *                 Must be destroyed with epp_identity_destroy() when done.
 *   out_error   — optional; receives error detail on failure.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_identity_create(
    EppIdentityHandle** out_handle,
    EppError*           out_error);

/*
 * epp_identity_create_from_seed — derive a deterministic identity from a seed.
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
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_identity_create_from_seed(
    const uint8_t*      seed,
    size_t              seed_length,
    EppIdentityHandle** out_handle,
    EppError*           out_error);

/*
 * epp_identity_create_with_context — derive a deterministic identity bound
 * to a membership context string.
 *
 * Like epp_identity_create_from_seed() but additionally mixes a
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
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_identity_create_with_context(
    const uint8_t*      seed,
    size_t              seed_length,
    const char*         membership_id,
    size_t              membership_id_length,
    EppIdentityHandle** out_handle,
    EppError*           out_error);

/*
 * epp_identity_get_x25519_public — copy the X25519 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle (not NULL, not destroyed).
 *   out_key         — caller-allocated buffer to receive the 32-byte key.
 *   out_key_length  — size of out_key in bytes; must be >= 32.
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_BUFFER_TOO_SMALL.
 */
EPP_API EppErrorCode epp_identity_get_x25519_public(
    const EppIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    EppError*                out_error);

/*
 * epp_identity_get_ed25519_public — copy the Ed25519 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle.
 *   out_key         — caller-allocated buffer; must be >= 32 bytes.
 *   out_key_length  — size of out_key in bytes.
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_BUFFER_TOO_SMALL.
 */
EPP_API EppErrorCode epp_identity_get_ed25519_public(
    const EppIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    EppError*                out_error);

/*
 * epp_identity_get_kyber_public — copy the Kyber-768 public key into a
 * caller-allocated buffer.
 *
 * Parameters:
 *   handle          — valid identity handle.
 *   out_key         — caller-allocated buffer; must be >= 1184 bytes (Kyber-768
 *                     public key size).
 *   out_key_length  — size of out_key in bytes.
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_BUFFER_TOO_SMALL.
 */
EPP_API EppErrorCode epp_identity_get_kyber_public(
    const EppIdentityHandle* handle,
    uint8_t*                 out_key,
    size_t                   out_key_length,
    EppError*                out_error);

/*
 * epp_identity_destroy — free an identity handle and securely wipe
 * all private key material.
 *
 * Sets *handle to NULL after freeing.  Safe to call with *handle == NULL
 * (no-op).  Do not use the handle after this call.
 *
 * Parameters:
 *   handle — pointer-to-pointer returned by an epp_identity_create* call.
 */
EPP_API void epp_identity_destroy(EppIdentityHandle** handle);


/* ═══════════════════════════════════════════════════════════════════════════
 * Prekey bundle
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * EppSessionPeerIdentity — fixed-size struct carrying a session participant's
 * public keys.  No heap allocation; safe to copy on the stack.
 * Populated by epp_session_get_peer_identity() and
 * epp_session_get_local_identity().
 *
 *   ed25519_public — 32-byte Ed25519 public key (signature verification).
 *   x25519_public  — 32-byte X25519 public key (Diffie-Hellman).
 */
typedef struct {
    uint8_t ed25519_public[32];
    uint8_t x25519_public[32];
} EppSessionPeerIdentity;

/*
 * EppEnvelopeMetadata — parsed metadata from a 1-to-1 session decrypt call.
 *
 * Obtained by passing the raw out_metadata buffer from epp_session_decrypt()
 * into epp_envelope_metadata_parse().  Free its heap contents with
 * epp_envelope_metadata_free() when done.  Do NOT free the struct itself —
 * it is caller-allocated (typically on the stack).
 *
 *   envelope_type          — semantic type of the message.
 *   envelope_id            — request/response correlation number chosen by
 *                            the sender; 0 when unused.
 *   message_index          — monotonic per-chain message counter embedded by
 *                            the ratchet (useful for detecting gaps).
 *   correlation_id         — optional null-terminated application tracing
 *                            string; NULL when the sender did not set one.
 *                            Heap-allocated; freed by epp_envelope_metadata_free().
 *   correlation_id_length  — byte length of correlation_id (excluding NUL);
 *                            0 when correlation_id is NULL.
 */
typedef struct {
    EppEnvelopeType envelope_type;
    uint32_t        envelope_id;
    uint64_t        message_index;
    char*           correlation_id;
    size_t          correlation_id_length;
} EppEnvelopeMetadata;

/*
 * epp_prekey_bundle_create — serialise the identity's public keys into a
 * prekey bundle suitable for upload to a key server.
 *
 * The bundle contains: identity public keys (X25519 + Ed25519 + Kyber-768),
 * signed one-time prekeys, and a signature over all fields.  Peers fetch
 * this bundle before initiating a handshake.
 *
 * Parameters:
 *   identity_keys — valid identity handle whose public keys are exported.
 *                   The handle is NOT consumed; it remains valid after the call.
 *   out_bundle    — receives a heap-allocated protobuf-encoded bundle.
 *                   Release with epp_buffer_release() when done.
 *   out_error     — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_ENCODE, or EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_prekey_bundle_create(
    const EppIdentityHandle* identity_keys,
    EppBuffer*               out_bundle,
    EppError*                out_error);

/*
 * epp_prekey_bundle_replenish — generate fresh one-time prekeys and add them
 * to the identity's local pool.
 *
 * Each successful X3DH handshake consumes one OTK from the responder's
 * published bundle.  When the key server reports that supply is low, call
 * this function to generate new OTKs, then upload the returned bytes to the
 * server.
 *
 * The returned buffer is a partial PreKeyBundle protobuf with only the
 * one_time_pre_keys field populated (same schema as epp_prekey_bundle_create
 * output).  The server merges these into the existing bundle for that identity.
 *
 * Parameters:
 *   identity_handle — valid identity handle (not consumed).  The new OTKs are
 *                     stored in the handle's internal pool so future responder
 *                     handshakes can use them automatically.
 *   count           — number of new OTKs to generate; must be > 0.
 *                     Recommended: EPP_DEFAULT_ONE_TIME_KEY_COUNT (100).
 *   out_keys        — receives the serialised partial PreKeyBundle containing
 *                     only the new OTKs' public keys and IDs
 *                     (release with epp_buffer_release()).
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_prekey_bundle_replenish(
    EppIdentityHandle*  identity_handle,
    uint32_t            count,
    EppBuffer*          out_keys,
    EppError*           out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Handshake — hybrid X3DH + Kyber-768
 *
 * The handshake establishes a shared session key between two parties
 * (initiator and responder) using a hybrid post-quantum X3DH protocol.
 *
 * Flow:
 *   Initiator                          Responder
 *   ─────────────────────────────────────────────
 *   epp_handshake_initiator_start()
 *     → out_handshake_init  ──────────────────────►
 *                                epp_handshake_responder_start()
 *                                  → out_handshake_ack
 *                  ◄──────────────────────────────
 *   epp_handshake_initiator_finish()               epp_handshake_responder_finish()
 *     → EppSessionHandle                            → EppSessionHandle
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_handshake_initiator_start — begin a handshake as the initiating party.
 *
 * Fetches the peer's prekey bundle, generates ephemeral keys, performs the
 * hybrid X3DH+Kyber KEM, and produces the initial handshake message.
 *
 * Parameters:
 *   identity_keys          — caller's long-term identity (not consumed).
 *   peer_prekey_bundle     — serialised prekey bundle of the remote peer
 *                            (obtained from the key server, borrowed).
 *   peer_prekey_bundle_length — byte length of peer_prekey_bundle.
 *   config                 — session configuration; may be NULL to use
 *                            library defaults.
 *   out_handle             — receives the in-progress initiator state.
 *                            Keep alive until epp_handshake_initiator_finish().
 *                            Destroy with epp_handshake_initiator_destroy()
 *                            if the handshake is abandoned.
 *   out_handshake_init     — receives the serialised init message to send to
 *                            the peer (release with epp_buffer_release()).
 *   out_error              — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, EPP_ERROR_HANDSHAKE, or
 *          EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_handshake_initiator_start(
    EppIdentityHandle*          identity_keys,
    const uint8_t*              peer_prekey_bundle,
    size_t                      peer_prekey_bundle_length,
    const EppSessionConfig*     config,
    EppHandshakeInitiatorHandle** out_handle,
    EppBuffer*                  out_handshake_init,
    EppError*                   out_error);

/*
 * epp_handshake_initiator_finish — complete the handshake after receiving the
 * responder's acknowledgement message.
 *
 * Verifies the responder's contribution and derives the final session key.
 * Consumes and frees the initiator handle internally on success; do NOT call
 * epp_handshake_initiator_destroy() afterwards.
 * On failure the handle remains valid and must be destroyed by the caller.
 *
 * Parameters:
 *   handle            — initiator handle from epp_handshake_initiator_start().
 *   handshake_ack     — acknowledgement bytes received from the responder
 *                       (borrowed).
 *   handshake_ack_length — byte length of handshake_ack.
 *   out_session       — receives the established EppSessionHandle.
 *                       Destroy with epp_session_destroy() when done.
 *   out_error         — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_HANDSHAKE, EPP_ERROR_DECODE, or
 *          EPP_ERROR_CRYPTO_FAILURE.
 */
EPP_API EppErrorCode epp_handshake_initiator_finish(
    EppHandshakeInitiatorHandle* handle,
    const uint8_t*               handshake_ack,
    size_t                       handshake_ack_length,
    EppSessionHandle**           out_session,
    EppError*                    out_error);

/*
 * epp_handshake_initiator_destroy — discard an in-progress initiator state.
 *
 * Call only when abandoning a handshake before finish.  Sets *handle to NULL.
 * Safe to call with *handle == NULL (no-op).
 */
EPP_API void epp_handshake_initiator_destroy(EppHandshakeInitiatorHandle** handle);

/*
 * epp_handshake_responder_start — process the initiator's message and produce
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
 *                                Keep alive until epp_handshake_responder_finish().
 *   out_handshake_ack          — receives the serialised ack message to send
 *                                back to the initiator (release with
 *                                epp_buffer_release()).
 *   out_error                  — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_HANDSHAKE, EPP_ERROR_DECODE, or
 *          EPP_ERROR_INVALID_INPUT.
 */
EPP_API EppErrorCode epp_handshake_responder_start(
    EppIdentityHandle*           identity_keys,
    const uint8_t*               local_prekey_bundle,
    size_t                       local_prekey_bundle_length,
    const uint8_t*               handshake_init,
    size_t                       handshake_init_length,
    const EppSessionConfig*      config,
    EppHandshakeResponderHandle** out_handle,
    EppBuffer*                   out_handshake_ack,
    EppError*                    out_error);

/*
 * epp_handshake_responder_finish — finalise the responder side and obtain
 * the established session.
 *
 * Consumes the responder handle internally on success; do NOT call
 * epp_handshake_responder_destroy() afterwards.
 * On failure the handle remains valid.
 *
 * Parameters:
 *   handle      — responder handle from epp_handshake_responder_start().
 *   out_session — receives the established EppSessionHandle.
 *                 Destroy with epp_session_destroy() when done.
 *   out_error   — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_HANDSHAKE.
 */
EPP_API EppErrorCode epp_handshake_responder_finish(
    EppHandshakeResponderHandle* handle,
    EppSessionHandle**           out_session,
    EppError*                    out_error);

/*
 * epp_handshake_responder_destroy — discard an in-progress responder state.
 *
 * Call only when abandoning a handshake before finish.  Sets *handle to NULL.
 * Safe to call with *handle == NULL (no-op).
 */
EPP_API void epp_handshake_responder_destroy(EppHandshakeResponderHandle** handle);


/* ═══════════════════════════════════════════════════════════════════════════
 * 1-to-1 session — hybrid Double Ratchet
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_session_encrypt — encrypt a plaintext message within a 1-to-1 session.
 *
 * Advances the sending ratchet and produces a serialised Envelope protobuf
 * that includes the ciphertext, ratchet header, and envelope metadata.
 *
 * Parameters:
 *   handle                  — active session handle.
 *   plaintext               — message bytes to encrypt (borrowed).
 *   plaintext_length        — byte length of plaintext.
 *   envelope_type           — semantic type tag embedded in the envelope
 *                             (e.g. EPP_ENVELOPE_REQUEST).  Used by the
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
 *                             (release with epp_buffer_release()).
 *   out_error               — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_ENCRYPTION, or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_encrypt(
    EppSessionHandle*   handle,
    const uint8_t*      plaintext,
    size_t              plaintext_length,
    EppEnvelopeType     envelope_type,
    uint32_t            envelope_id,
    const char*         correlation_id,
    size_t              correlation_id_length,
    EppBuffer*          out_encrypted_envelope,
    EppError*           out_error);

/*
 * epp_session_decrypt — decrypt a received Envelope.
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
 *                              (release with epp_buffer_release()).
 *   out_metadata             — receives the serialised EnvelopeMetadata
 *                              protobuf (envelope_type, envelope_id,
 *                              correlation_id).  Release with
 *                              epp_buffer_release().  May be NULL if
 *                              metadata is not needed.
 *   out_error                — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_DECRYPTION, EPP_ERROR_DECODE,
 *          EPP_ERROR_REPLAY_ATTACK, or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_decrypt(
    EppSessionHandle*   handle,
    const uint8_t*      encrypted_envelope,
    size_t              encrypted_envelope_length,
    EppBuffer*          out_plaintext,
    EppBuffer*          out_metadata,
    EppError*           out_error);

/*
 * epp_session_serialize_sealed — persist the session state to an encrypted
 * blob for storage (e.g. on-disk or in a secure enclave).
 *
 * The state is encrypted with AES-256-GCM using the provided key, and an
 * external_counter is mixed into the AAD to prevent rollback attacks.
 * Always increment external_counter before writing the new blob.
 *
 * Parameters:
 *   handle           — active session handle (not consumed; remains usable).
 *   key              — 32-byte AES-256 encryption key (borrowed).
 *   key_length       — must be exactly 32.
 *   external_counter — monotonic counter persisted alongside the blob.
 *                      Increment it on each successful serialisation.
 *   out_state        — receives the sealed blob (release with
 *                      epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_ENCRYPTION.
 */
EPP_API EppErrorCode epp_session_serialize_sealed(
    EppSessionHandle*   handle,
    const uint8_t*      key,
    size_t              key_length,
    uint64_t            external_counter,
    EppBuffer*          out_state,
    EppError*           out_error);

/*
 * epp_session_deserialize_sealed — restore a session from a sealed blob.
 *
 * Decrypts and validates the blob.  Rejects it if the stored counter is
 * less than min_external_counter (rollback protection).
 *
 * Parameters:
 *   state_bytes          — sealed blob bytes (borrowed).
 *   state_length         — byte length of state_bytes.
 *   key                  — 32-byte AES-256 decryption key (borrowed).
 *   key_length           — must be exactly 32.
 *   min_external_counter — minimum acceptable counter value; pass the last
 *                          known good counter to prevent rollback.
 *   out_external_counter — receives the counter embedded in the blob.
 *                          Update your persistent counter to this value.
 *   out_handle           — receives the restored EppSessionHandle.
 *                          Destroy with epp_session_destroy() when done.
 *   out_error            — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_DECRYPTION, EPP_ERROR_DECODE,
 *          EPP_ERROR_INVALID_INPUT, or EPP_ERROR_REPLAY_ATTACK.
 */
EPP_API EppErrorCode epp_session_deserialize_sealed(
    const uint8_t*      state_bytes,
    size_t              state_length,
    const uint8_t*      key,
    size_t              key_length,
    uint64_t            min_external_counter,
    uint64_t*           out_external_counter,
    EppSessionHandle**  out_handle,
    EppError*           out_error);

/*
 * epp_session_nonce_remaining — query how many more messages can be encrypted
 * under the current chain key before a ratchet step is forced.
 *
 * Parameters:
 *   handle        — active session handle.
 *   out_remaining — receives the remaining nonce budget.
 *   out_error     — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_nonce_remaining(
    EppSessionHandle*   handle,
    uint64_t*           out_remaining,
    EppError*           out_error);

/*
 * epp_session_destroy — free a session handle and securely wipe all
 * ratchet key material.
 *
 * Sets *handle to NULL.  Safe to call with *handle == NULL (no-op).
 */
EPP_API void epp_session_destroy(EppSessionHandle** handle);

/*
 * epp_session_get_id — retrieve the session's stable 16-byte identifier.
 *
 * The session ID is derived during the handshake from both parties' key
 * material and is identical on both sides.  Use it to correlate an
 * EppSessionHandle with a stored contact record without exposing private keys.
 *
 * Parameters:
 *   handle         — active session handle.
 *   out_session_id — receives the 16-byte session ID
 *                    (release with epp_buffer_release()).
 *   out_error      — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_get_id(
    EppSessionHandle*   handle,
    EppBuffer*          out_session_id,
    EppError*           out_error);

/*
 * epp_session_get_identity_binding_hash — retrieve the 32-byte authenticated
 * identity-binding hash for the current session.
 *
 * This hash is computed by the native protocol from the established local and
 * peer identity keys.  Applications can use it for TOFU, pinning, or audit
 * logging without reimplementing the transcript rules.
 */
EPP_API EppErrorCode epp_session_get_identity_binding_hash(
    EppSessionHandle*   handle,
    EppBuffer*          out_binding_hash,
    EppError*           out_error);

/*
 * epp_session_get_peer_identity — retrieve the remote peer's public keys.
 *
 * Returns the Ed25519 and X25519 public keys that the peer presented during
 * the handshake.  Use these to look up the peer in your contact store or to
 * verify out-of-band fingerprints.
 *
 * Parameters:
 *   handle       — active session handle.
 *   out_identity — caller-allocated EppSessionPeerIdentity to fill.
 *                  Stack allocation is sufficient (no pointers inside).
 *   out_error    — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_get_peer_identity(
    EppSessionHandle*        handle,
    EppSessionPeerIdentity*  out_identity,
    EppError*                out_error);

/*
 * epp_session_get_local_identity — retrieve the local device's public keys
 * as seen by this session.
 *
 * Mirrors epp_session_get_peer_identity() but returns the local party's
 * Ed25519 and X25519 public keys baked into the session state.
 *
 * Parameters:
 *   handle       — active session handle.
 *   out_identity — caller-allocated EppSessionPeerIdentity to fill.
 *   out_error    — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_session_get_local_identity(
    EppSessionHandle*        handle,
    EppSessionPeerIdentity*  out_identity,
    EppError*                out_error);

/*
 * epp_envelope_metadata_parse — parse the raw metadata buffer returned by
 * epp_session_decrypt() into a structured EppEnvelopeMetadata.
 *
 * epp_session_decrypt() writes an opaque protobuf blob into out_metadata.
 * Call this function on that blob to get individual fields without embedding
 * proto parsing in the client app.
 *
 * Parameters:
 *   metadata_bytes   — the raw metadata buffer from epp_session_decrypt()
 *                      (out_metadata.data, out_metadata.length). Borrowed.
 *   metadata_length  — byte length of metadata_bytes.
 *   out_meta         — caller-allocated EppEnvelopeMetadata to fill.
 *                      correlation_id inside will be heap-allocated if present;
 *                      free it with epp_envelope_metadata_free().
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_DECODE.
 */
EPP_API EppErrorCode epp_envelope_metadata_parse(
    const uint8_t*       metadata_bytes,
    size_t               metadata_length,
    EppEnvelopeMetadata* out_meta,
    EppError*            out_error);

/*
 * epp_envelope_metadata_free — release heap memory inside an
 * EppEnvelopeMetadata.
 *
 * Frees correlation_id if non-NULL and zeroes the pointer.  Does NOT free
 * the out_meta struct itself (caller-allocated).  Safe to call on a zeroed
 * struct (no-op).
 *
 * Parameters:
 *   meta — pointer to the EppEnvelopeMetadata to clean up.
 */
EPP_API void epp_envelope_metadata_free(EppEnvelopeMetadata* meta);


/* ═══════════════════════════════════════════════════════════════════════════
 * Key derivation & secret sharing
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_derive_root_key — derive an application-level key from an established
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
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_DERIVE_KEY.
 */
EPP_API EppErrorCode epp_derive_root_key(
    const uint8_t*  opaque_session_key,
    size_t          opaque_session_key_length,
    const uint8_t*  user_context,
    size_t          user_context_length,
    uint8_t*        out_root_key,
    size_t          out_root_key_length,
    EppError*       out_error);

/*
 * epp_shamir_split — split a secret into authenticated Shamir shares.
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
 *                      *out_share_length).  Release with epp_buffer_release().
 *   out_share_length — receives the byte length of each individual share.
 *                      All shares have the same length.
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_CRYPTO_FAILURE.
 */
EPP_API EppErrorCode epp_shamir_split(
    const uint8_t*  secret,
    size_t          secret_length,
    uint8_t         threshold,
    uint8_t         share_count,
    const uint8_t*  auth_key,
    size_t          auth_key_length,
    EppBuffer*      out_shares,
    size_t*         out_share_length,
    EppError*       out_error);

/*
 * epp_shamir_reconstruct — reconstruct a secret from a subset of shares.
 *
 * Verifies each share's HMAC before interpolation.  Requires exactly
 * `share_count` shares in the `shares` buffer, each of `share_length` bytes,
 * packed contiguously (i.e. total buffer = share_count * share_length bytes).
 *
 * Parameters:
 *   shares          — packed share bytes (borrowed).
 *   shares_length   — total byte length = share_count * share_length.
 *   share_length    — byte length of each individual share (from out_share_length
 *                     returned by epp_shamir_split()).
 *   share_count     — number of shares provided; must be >= threshold.
 *   auth_key        — same HMAC key used during epp_shamir_split() (borrowed).
 *   auth_key_length — byte length of auth_key.
 *   out_secret      — receives the reconstructed secret bytes
 *                     (release with epp_buffer_release()).
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, EPP_ERROR_CRYPTO_FAILURE
 *          (auth failure), or EPP_ERROR_DECODE.
 */
EPP_API EppErrorCode epp_shamir_reconstruct(
    const uint8_t*  shares,
    size_t          shares_length,
    size_t          share_length,
    size_t          share_count,
    const uint8_t*  auth_key,
    size_t          auth_key_length,
    EppBuffer*      out_secret,
    EppError*       out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group session — hybrid PQ TreeKEM (MLS-inspired)
 *
 * Groups use a left-balanced binary ratchet tree where each leaf holds a
 * hybrid X25519+Kyber-768 key pair.  Epoch transitions are driven by Commit
 * messages that update the tree and derive new epoch keys.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_group_generate_key_package — generate a signed key package for group
 * invitation.
 *
 * A KeyPackage is a signed public-key advertisement that a group admin uses
 * to add a new member.  The matching secrets handle holds the private keys
 * and MUST be retained by the invitee until epp_group_join() is called.
 *
 * Parameters:
 *   identity_handle — the invitee's long-term identity (not consumed).
 *   credential      — application-level identity credential bytes (e.g.
 *                     a user ID or certificate); included in the key package
 *                     and visible to all group members.  Borrowed.
 *   credential_length — byte length of credential.
 *   out_key_package — receives the serialised, signed KeyPackage protobuf to
 *                     send to the group admin (release with epp_buffer_release()).
 *   out_secrets     — receives the private secrets handle corresponding to
 *                     this key package.  MUST be kept alive and passed to
 *                     epp_group_join() later.  Destroy with
 *                     epp_group_key_package_secrets_destroy() if the
 *                     invitation is never completed.
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_KEY_GENERATION, or EPP_ERROR_ENCODE.
 */
EPP_API EppErrorCode epp_group_generate_key_package(
    EppIdentityHandle*           identity_handle,
    const uint8_t*               credential,
    size_t                       credential_length,
    EppBuffer*                   out_key_package,
    EppKeyPackageSecretsHandle** out_secrets,
    EppError*                    out_error);

/*
 * epp_group_key_package_secrets_destroy — free a key package secrets handle.
 *
 * Call when an invitation was never completed and the secrets are no longer
 * needed.  Sets *handle to NULL.
 */
EPP_API void epp_group_key_package_secrets_destroy(
    EppKeyPackageSecretsHandle** handle);

/*
 * epp_group_create — create a new group as the sole initial member.
 *
 * The caller becomes leaf index 0.  Use epp_group_add_member() to invite
 * others.  Group uses the hardened shielded policy by default.
 *
 * Parameters:
 *   identity_handle — caller's long-term identity (not consumed).
 *   credential      — caller's application credential embedded in the group
 *                     tree (borrowed).
 *   credential_length — byte length of credential.
 *   out_handle      — receives the EppGroupSessionHandle.
 *                     Destroy with epp_group_destroy() when done.
 *   out_error       — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_KEY_GENERATION, or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_create(
    EppIdentityHandle*       identity_handle,
    const uint8_t*           credential,
    size_t                   credential_length,
    EppGroupSessionHandle**  out_handle,
    EppError*                out_error);

/*
 * epp_group_create_shielded — create a new group with metadata shielding
 * enabled.
 *
 * Like epp_group_create() but enables enhanced sender-key padding and
 * traffic-analysis resistance features.  All members must support shielded
 * mode; mixing shielded and non-shielded clients in the same group is not
 * supported.
 *
 * Parameters: same as epp_group_create().
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_KEY_GENERATION, or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_create_shielded(
    EppIdentityHandle*       identity_handle,
    const uint8_t*           credential,
    size_t                   credential_length,
    EppGroupSessionHandle**  out_handle,
    EppError*                out_error);

/*
 * epp_group_is_shielded — query whether the group has shielding enabled.
 *
 * Parameters:
 *   handle       — active group session handle.
 *   out_shielded — receives 1 if shielded, 0 otherwise.
 *   out_error    — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_is_shielded(
    EppGroupSessionHandle*  handle,
    uint8_t*                out_shielded,
    EppError*               out_error);

/*
 * epp_group_create_with_policy — create a new group with an explicit
 * security policy.
 *
 * Parameters:
 *   identity_handle   — caller's long-term identity (not consumed).
 *   credential        — caller's credential (borrowed).
 *   credential_length — byte length of credential.
 *   policy            — pointer to a populated EppGroupSecurityPolicy;
 *                       must not be NULL.  The struct is copied internally.
 *   out_handle        — receives the group session handle.
 *   out_error         — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_create_with_policy(
    EppIdentityHandle*            identity_handle,
    const uint8_t*                credential,
    size_t                        credential_length,
    const EppGroupSecurityPolicy* policy,
    EppGroupSessionHandle**       out_handle,
    EppError*                     out_error);

/*
 * epp_group_get_security_policy — read the active security policy of a group.
 *
 * Parameters:
 *   handle     — active group session handle.
 *   out_policy — caller-allocated EppGroupSecurityPolicy to fill in.
 *   out_error  — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_get_security_policy(
    EppGroupSessionHandle*  handle,
    EppGroupSecurityPolicy* out_policy,
    EppError*               out_error);

/*
 * epp_group_join — join a group using a Welcome message.
 *
 * Decrypts the Welcome, verifies the tree and confirmation MAC, and
 * establishes the new member's group session at the current epoch.
 *
 * IMPORTANT: After calling this function do NOT also call
 * epp_group_process_commit() for the same commit that generated the Welcome.
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
 *   out_group_handle  — receives the EppGroupSessionHandle.
 *                       Destroy with epp_group_destroy() when done.
 *   out_error         — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_WELCOME, EPP_ERROR_DECODE, or
 *          EPP_ERROR_TREE_INTEGRITY.
 */
EPP_API EppErrorCode epp_group_join(
    EppIdentityHandle*          identity_handle,
    const uint8_t*              welcome_bytes,
    size_t                      welcome_length,
    EppKeyPackageSecretsHandle* secrets_handle,
    EppGroupSessionHandle**     out_group_handle,
    EppError*                   out_error);

/*
 * epp_group_add_member — add a new member to the group.
 *
 * Creates an Add proposal, wraps it in a Commit, advances the local epoch,
 * and produces a Welcome message for the new member.
 *
 * Only the member who calls this function should send the commit to the
 * group; other existing members call epp_group_process_commit() on receipt.
 * The new member calls epp_group_join() with the welcome bytes.
 *
 * Parameters:
 *   handle             — active group session handle (caller must be a
 *                        current member with committer rights).
 *   key_package_bytes  — serialised KeyPackage from the invitee (borrowed).
 *   key_package_length — byte length of key_package_bytes.
 *   out_commit         — receives the serialised Commit to broadcast to
 *                        existing members (release with epp_buffer_release()).
 *   out_welcome        — receives the serialised Welcome to send to the
 *                        new member (release with epp_buffer_release()).
 *   out_error          — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_GROUP_MEMBERSHIP, EPP_ERROR_GROUP_PROTOCOL,
 *          or EPP_ERROR_ENCODE.
 */
EPP_API EppErrorCode epp_group_add_member(
    EppGroupSessionHandle*  handle,
    const uint8_t*          key_package_bytes,
    size_t                  key_package_length,
    EppBuffer*              out_commit,
    EppBuffer*              out_welcome,
    EppError*               out_error);

/*
 * epp_group_remove_member — remove a member from the group.
 *
 * Creates a Remove proposal, wraps it in a Commit, and advances the local
 * epoch.  The removed member loses access to future messages immediately.
 *
 * Parameters:
 *   handle      — active group session handle (caller must be a current member).
 *   leaf_index  — zero-based leaf index of the member to remove.
 *                 Use epp_group_get_member_leaf_indices() to discover indices.
 *                 A member may not remove themselves; use epp_group_update()
 *                 followed by leaving via the application layer instead.
 *   out_commit  — receives the serialised Commit to broadcast
 *                 (release with epp_buffer_release()).
 *   out_error   — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_GROUP_MEMBERSHIP, EPP_ERROR_INVALID_INPUT,
 *          or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_remove_member(
    EppGroupSessionHandle*  handle,
    uint32_t                leaf_index,
    EppBuffer*              out_commit,
    EppError*               out_error);

/*
 * epp_group_update — rotate the caller's leaf keys and advance the epoch.
 *
 * Creates an Update proposal, wraps it in a Commit, and publishes a new
 * UpdatePath so all other members can derive the new epoch keys.  Call
 * periodically for post-compromise security (PCS) or when the policy's
 * max_messages_per_epoch is approaching.
 *
 * Parameters:
 *   handle     — active group session handle.
 *   out_commit — receives the serialised Commit to broadcast
 *                (release with epp_buffer_release()).
 *   out_error  — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_update(
    EppGroupSessionHandle*  handle,
    EppBuffer*              out_commit,
    EppError*               out_error);

/*
 * epp_group_process_commit — apply a Commit received from another member.
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
 * Returns: EPP_SUCCESS, EPP_ERROR_GROUP_PROTOCOL, EPP_ERROR_TREE_INTEGRITY,
 *          EPP_ERROR_DECODE, or EPP_ERROR_GROUP_MEMBERSHIP.
 */
EPP_API EppErrorCode epp_group_process_commit(
    EppGroupSessionHandle*  handle,
    const uint8_t*          commit_bytes,
    size_t                  commit_length,
    EppError*               out_error);

/*
 * epp_group_encrypt — encrypt a plaintext message to the group.
 *
 * Uses the current epoch's sender-key ratchet.  The generation counter
 * advances with each call; recipients use the sender leaf index + generation
 * to decrypt out-of-order messages within the epoch.
 *
 * If mandatory_franking is set in the group's security policy this function
 * returns EPP_ERROR_INVALID_STATE; use epp_group_encrypt_frankable() instead.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — message bytes to encrypt (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   out_ciphertext   — receives the serialised GroupMessage protobuf
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_ENCRYPTION, or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_encrypt(
    EppGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_decrypt — decrypt a group message (basic variant).
 *
 * Suitable when you only need the plaintext and sender identity.  For full
 * metadata (TTL, content type, message ID, franking) use epp_group_decrypt_ex().
 *
 * Parameters:
 *   handle            — active group session handle.
 *   ciphertext        — serialised GroupMessage bytes (borrowed).
 *   ciphertext_length — byte length of ciphertext.
 *   out_plaintext     — receives the decrypted plaintext
 *                       (release with epp_buffer_release()).
 *   out_sender_leaf   — receives the zero-based leaf index of the sender.
 *   out_generation    — receives the per-sender generation counter.
 *   out_error         — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_DECRYPTION, EPP_ERROR_DECODE, or
 *          EPP_ERROR_GROUP_MEMBERSHIP.
 */
EPP_API EppErrorCode epp_group_decrypt(
    EppGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    EppBuffer*              out_plaintext,
    uint32_t*               out_sender_leaf,
    uint32_t*               out_generation,
    EppError*               out_error);

/*
 * epp_group_decrypt_ex — decrypt a group message with full metadata.
 *
 * Populates an EppGroupDecryptResult with plaintext, sender, generation,
 * content type, TTL, timestamps, message IDs, and feature flags.
 * Must be freed with epp_group_decrypt_result_free() after use.
 *
 * Parameters:
 *   handle            — active group session handle.
 *   ciphertext        — serialised GroupMessage bytes (borrowed).
 *   ciphertext_length — byte length of ciphertext.
 *   out_result        — caller-allocated EppGroupDecryptResult to fill.
 *                       All EppBuffer fields inside are heap-allocated;
 *                       free the entire struct with epp_group_decrypt_result_free().
 *   out_error         — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_DECRYPTION, EPP_ERROR_DECODE,
 *          EPP_ERROR_MESSAGE_EXPIRED, or EPP_ERROR_GROUP_MEMBERSHIP.
 */
EPP_API EppErrorCode epp_group_decrypt_ex(
    EppGroupSessionHandle*  handle,
    const uint8_t*          ciphertext,
    size_t                  ciphertext_length,
    EppGroupDecryptResult*  out_result,
    EppError*               out_error);

/*
 * epp_group_decrypt_result_free — release all heap memory inside an
 * EppGroupDecryptResult previously populated by epp_group_decrypt_ex().
 *
 * Does NOT free the result struct itself (which is caller-allocated).
 * Zeros all EppBuffer fields after release.  Safe to call on a zeroed struct.
 *
 * Safety:
 *   - Call only after a successful epp_group_decrypt_ex() (EPP_SUCCESS), or on
 *     a zero-initialised struct (EppGroupDecryptResult result = {0}).
 *   - If epp_group_decrypt_ex() returned an error the struct may be partially
 *     written.  Always zero-initialise before passing to epp_group_decrypt_ex()
 *     so that calling epp_group_decrypt_result_free() after an error is safe.
 *   - Do NOT call epp_buffer_release() on individual fields — use this
 *     function to release the entire result atomically.
 */
EPP_API void epp_group_decrypt_result_free(EppGroupDecryptResult* result);

/*
 * epp_group_compute_message_id — compute a deterministic message ID from
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
 *                         (release with epp_buffer_release()).
 *   out_error           — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_CRYPTO.
 */
EPP_API EppErrorCode epp_group_compute_message_id(
    const uint8_t*  group_id,
    size_t          group_id_length,
    uint64_t        epoch,
    uint32_t        sender_leaf_index,
    uint32_t        generation,
    EppBuffer*      out_message_id,
    EppError*       out_error);

/*
 * epp_group_get_id — retrieve the group's unique identifier bytes.
 *
 * The group ID is a stable 32-byte random value assigned at creation and
 * preserved across epochs.
 *
 * Parameters:
 *   handle       — active group session handle.
 *   out_group_id — receives a copy of the group ID bytes
 *                  (release with epp_buffer_release()).
 *   out_error    — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_get_id(
    EppGroupSessionHandle*  handle,
    EppBuffer*              out_group_id,
    EppError*               out_error);

/*
 * epp_group_get_epoch — return the current epoch number.
 *
 * The epoch increments with each successfully processed Commit.  Epoch 0
 * is the initial state after group creation.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: current epoch as uint64_t.  No error output; panics on NULL.
 */
EPP_API uint64_t epp_group_get_epoch(EppGroupSessionHandle* handle);

/*
 * epp_group_get_my_leaf_index — return the caller's leaf index in the tree.
 *
 * Stable for the lifetime of membership; does not change across epochs.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: zero-based leaf index as uint32_t.
 */
EPP_API uint32_t epp_group_get_my_leaf_index(EppGroupSessionHandle* handle);

/*
 * epp_group_get_member_count — return the current number of active members.
 *
 * Counts only occupied (non-blank) leaf nodes.
 *
 * Parameters:
 *   handle — active group session handle; must not be NULL.
 *
 * Returns: member count as uint32_t.
 */
EPP_API uint32_t epp_group_get_member_count(EppGroupSessionHandle* handle);

/*
 * epp_group_get_member_leaf_indices — retrieve the leaf indices of all
 * current members as a packed array of uint32_t.
 *
 * The returned buffer contains member_count values, each 4 bytes,
 * in little-endian order.
 *
 * Parameters:
 *   handle      — active group session handle.
 *   out_indices — receives the packed uint32_t array
 *                 (release with epp_buffer_release()).
 *   out_error   — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_get_member_leaf_indices(
    EppGroupSessionHandle*  handle,
    EppBuffer*              out_indices,
    EppError*               out_error);

/*
 * epp_group_serialize — persist the full group session state to an encrypted
 * blob (including private ratchet tree keys).
 *
 * Uses the same sealed-blob format as epp_session_serialize_sealed().
 * Always increment external_counter before writing; use the stored counter
 * as min_external_counter on load to prevent rollback.
 *
 * Parameters:
 *   handle           — active group session handle (not consumed).
 *   key              — 32-byte AES-256 encryption key (borrowed).
 *   key_length       — must be exactly 32.
 *   external_counter — monotonic counter embedded in the blob.
 *   out_state        — receives the encrypted blob
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_ENCRYPTION.
 */
EPP_API EppErrorCode epp_group_serialize(
    EppGroupSessionHandle*  handle,
    const uint8_t*          key,
    size_t                  key_length,
    uint64_t                external_counter,
    EppBuffer*              out_state,
    EppError*               out_error);

/*
 * epp_group_deserialize — restore a group session from an encrypted blob.
 *
 * Parameters:
 *   state_bytes          — sealed blob bytes (borrowed).
 *   state_length         — byte length of state_bytes.
 *   key                  — 32-byte AES-256 decryption key (borrowed).
 *   key_length           — must be exactly 32.
 *   min_external_counter — minimum acceptable counter (rollback protection).
 *   out_external_counter — receives the counter stored in the blob.
 *   identity_handle      — long-term identity to re-attach to the session
 *                          (not consumed; the session borrows it logically
 *                          so keep the identity alive while the session is
 *                          in use).
 *   out_handle           — receives the restored EppGroupSessionHandle.
 *                          Destroy with epp_group_destroy().
 *   out_error            — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_DECRYPTION, EPP_ERROR_DECODE,
 *          EPP_ERROR_INVALID_INPUT, or EPP_ERROR_REPLAY_ATTACK.
 */
EPP_API EppErrorCode epp_group_deserialize(
    const uint8_t*          state_bytes,
    size_t                  state_length,
    const uint8_t*          key,
    size_t                  key_length,
    uint64_t                min_external_counter,
    uint64_t*               out_external_counter,
    EppIdentityHandle*      identity_handle,
    EppGroupSessionHandle** out_handle,
    EppError*               out_error);

/*
 * epp_group_export_public_state — export the group's public state for
 * ExternalInit joins.
 *
 * The exported PublicGroupState contains the ratchet tree public keys,
 * group context, and external init public key.  Upload it to the relay or
 * distribute out-of-band so that prospective members can call
 * epp_group_join_external().
 *
 * Parameters:
 *   handle           — active group session handle.
 *   out_public_state — receives the serialised PublicGroupState protobuf
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_GROUP_PROTOCOL.
 */
EPP_API EppErrorCode epp_group_export_public_state(
    EppGroupSessionHandle*  handle,
    EppBuffer*              out_public_state,
    EppError*               out_error);

/*
 * epp_group_authorize_external_join — mint an authorization artifact for one
 * specific external joiner.
 *
 * Existing members call this after verifying the joiner's identity out of
 * band.  The returned bytes are bound to group_id + current epoch + joiner
 * identity + joiner credential, and must be supplied to
 * epp_group_join_external().
 */
EPP_API EppErrorCode epp_group_authorize_external_join(
    EppGroupSessionHandle*  handle,
    const uint8_t*          joiner_identity_ed25519_public,
    size_t                  joiner_identity_ed25519_public_length,
    const uint8_t*          joiner_identity_x25519_public,
    size_t                  joiner_identity_x25519_public_length,
    const uint8_t*          joiner_credential,
    size_t                  joiner_credential_length,
    EppBuffer*              out_authorization,
    EppError*               out_error);

/*
 * epp_group_join_external — join a group without a Welcome by performing an
 * ExternalInit.
 *
 * Uses the group's published external init key (inside public_state) plus a
 * member-issued authorization artifact to KEM a new init secret, produce an
 * ExternalInit Commit, and establish the caller as a new leaf.
 *
 * After a successful call the caller broadcasts out_commit to all existing
 * members, who apply it with epp_group_process_commit().
 *
 * Parameters:
 *   identity_handle    — caller's long-term identity (not consumed).
 *   public_state       — PublicGroupState bytes (from epp_group_export_public_state
 *                        of an existing member, or fetched from relay). Borrowed.
 *   public_state_length — byte length of public_state.
 *   authorization      — authorization bytes from
 *                        epp_group_authorize_external_join(). Borrowed.
 *   authorization_length — byte length of authorization.
 *   credential         — caller's application credential to embed in the tree
 *                        (borrowed).
 *   credential_length  — byte length of credential.
 *   out_group_handle   — receives the new EppGroupSessionHandle.
 *                        Destroy with epp_group_destroy() when done.
 *   out_commit         — receives the ExternalInit Commit to broadcast
 *                        (release with epp_buffer_release()).
 *   out_error          — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_GROUP_PROTOCOL, EPP_ERROR_DECODE, or
 *          EPP_ERROR_KEY_GENERATION.
 */
EPP_API EppErrorCode epp_group_join_external(
    EppIdentityHandle*      identity_handle,
    const uint8_t*          public_state,
    size_t                  public_state_length,
    const uint8_t*          authorization,
    size_t                  authorization_length,
    const uint8_t*          credential,
    size_t                  credential_length,
    EppGroupSessionHandle** out_group_handle,
    EppBuffer*              out_commit,
    EppError*               out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group messaging features
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_group_encrypt_sealed — encrypt a message with a two-layer sealed payload.
 *
 * The outer layer is a normal group-encrypted envelope.  The inner plaintext
 * is additionally encrypted with a per-message seal_key derived from the
 * message key.  Recipients see that a sealed payload exists (has_sealed_payload
 * in EppGroupDecryptResult) but cannot read the inner content until the sender
 * calls epp_group_reveal_sealed() and shares the seal_key and nonce.
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
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_ENCRYPTION, or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_encrypt_sealed(
    EppGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    const uint8_t*          hint,
    size_t                  hint_length,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_encrypt_disappearing — encrypt a message with a server-enforced
 * time-to-live.
 *
 * The TTL and sent_timestamp are embedded in the authenticated plaintext.
 * epp_group_decrypt_ex() returns EPP_ERROR_MESSAGE_EXPIRED if the current
 * time exceeds sent_timestamp + ttl_seconds.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   plaintext        — message bytes to encrypt (borrowed).
 *   plaintext_length — byte length of plaintext.
 *   ttl_seconds      — lifetime in seconds after sent_timestamp.
 *                      Must be > 0.
 *   out_ciphertext   — receives the serialised GroupMessage
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_ENCRYPTION.
 */
EPP_API EppErrorCode epp_group_encrypt_disappearing(
    EppGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    uint32_t                ttl_seconds,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_encrypt_frankable — encrypt a message with an embedded franking
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
 *                      (release with epp_buffer_release()).
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_ENCRYPTION, or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_encrypt_frankable(
    EppGroupSessionHandle*  handle,
    const uint8_t*          plaintext,
    size_t                  plaintext_length,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_encrypt_edit — encrypt an edit to a previously sent message.
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
 *                              (32 bytes; from EppGroupDecryptResult.message_id
 *                              or epp_group_compute_message_id()). Borrowed.
 *   target_message_id_length — byte length of target_message_id; must be 32.
 *   out_ciphertext           — receives the serialised GroupMessage
 *                              (release with epp_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_ENCRYPTION.
 */
EPP_API EppErrorCode epp_group_encrypt_edit(
    EppGroupSessionHandle*  handle,
    const uint8_t*          new_content,
    size_t                  new_content_length,
    const uint8_t*          target_message_id,
    size_t                  target_message_id_length,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_encrypt_delete — encrypt a delete request for a previously sent
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
 *                              (release with epp_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_ENCRYPTION.
 */
EPP_API EppErrorCode epp_group_encrypt_delete(
    EppGroupSessionHandle*  handle,
    const uint8_t*          target_message_id,
    size_t                  target_message_id_length,
    EppBuffer*              out_ciphertext,
    EppError*               out_error);

/*
 * epp_group_reveal_sealed — decrypt the inner layer of a sealed message.
 *
 * The caller must supply the hint, encrypted_content, nonce, and seal_key
 * that are embedded in the decrypted GroupMessage payload
 * (available after epp_group_decrypt_ex() when has_sealed_payload == 1).
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
 *                              (release with epp_buffer_release()).
 *   out_error                — optional error detail.
 *
 * Returns: EPP_SUCCESS, EPP_ERROR_INVALID_INPUT, or EPP_ERROR_DECRYPTION.
 */
EPP_API EppErrorCode epp_group_reveal_sealed(
    const uint8_t*  hint,
    size_t          hint_length,
    const uint8_t*  encrypted_content,
    size_t          encrypted_content_length,
    const uint8_t*  nonce,
    size_t          nonce_length,
    const uint8_t*  seal_key,
    size_t          seal_key_length,
    EppBuffer*      out_plaintext,
    EppError*       out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Group management
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * epp_group_set_psk — inject a pre-shared key into the group's key schedule.
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
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_INPUT.
 */
EPP_API EppErrorCode epp_group_set_psk(
    EppGroupSessionHandle*  handle,
    const uint8_t*          psk_id,
    size_t                  psk_id_length,
    const uint8_t*          psk,
    size_t                  psk_length,
    EppError*               out_error);

/*
 * epp_group_get_pending_reinit — check whether a ReInit proposal is pending.
 *
 * A ReInit signals that the group should migrate to a new group (new ID,
 * potentially new protocol version).  When this returns EPP_SUCCESS and
 * out_new_group_id.length > 0, the application should initiate the migration
 * flow: create a new group with the given ID and re-add all members.
 *
 * Parameters:
 *   handle           — active group session handle.
 *   out_new_group_id — receives the proposed new group ID bytes, or an
 *                      empty buffer if no reinit is pending
 *                      (release with epp_buffer_release()).
 *   out_new_version  — receives the proposed new protocol version number,
 *                      or 0 if no reinit is pending.
 *   out_error        — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_INVALID_STATE.
 */
EPP_API EppErrorCode epp_group_get_pending_reinit(
    EppGroupSessionHandle*  handle,
    EppBuffer*              out_new_group_id,
    uint32_t*               out_new_version,
    EppError*               out_error);

/*
 * epp_group_destroy — free a group session handle and securely wipe all
 * private ratchet tree key material.
 *
 * Sets *handle to NULL.  Safe to call with *handle == NULL (no-op).
 */
EPP_API void epp_group_destroy(EppGroupSessionHandle** handle);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — 1-to-1 session
 *
 * Register a set of C function pointers to receive protocol events from a
 * session.  All callbacks are optional (set to NULL to ignore).
 * The library never calls a NULL slot.
 *
 * THREADING: Callbacks may be invoked from any thread that calls an
 * epp_session_* function.  If your user_data is shared state, protect it
 * with your own lock.
 *
 * LIFETIME: user_data must remain valid until the session is destroyed or a
 * new handler is registered.  The library holds no reference to user_data
 * beyond passing it verbatim to each callback.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * EppOnHandshakeCompleted — fired once when both sides have completed the
 * X3DH+Kyber handshake and the session is ready for encrypt/decrypt.
 *
 *   session_id     — pointer to the 16-byte session identifier (borrowed for
 *                    the duration of the callback only; do NOT retain).
 *   session_id_len — always 16.
 *   user_data      — the value passed in EppSessionEventCallbacks.user_data.
 *
 * Use case: store the session ID in your contact database to correlate this
 * EppSessionHandle with a user record.
 */
typedef void (*EppOnHandshakeCompleted)(
    const uint8_t* session_id,
    size_t         session_id_len,
    void*          user_data);

/*
 * EppOnRatchetRotated — fired each time the DH ratchet advances to a new
 * epoch (i.e. a new chain key is derived).
 *
 *   epoch     — monotonically increasing ratchet epoch counter.
 *   user_data — value from EppSessionEventCallbacks.user_data.
 *
 * Use case: UI indicator showing "forward secrecy refreshed".
 */
typedef void (*EppOnRatchetRotated)(uint64_t epoch, void* user_data);

/*
 * EppOnSessionError — fired on a non-fatal internal protocol error.
 *
 *   code      — error category (see EppErrorCode).
 *   message   — null-terminated human-readable description (borrowed; valid
 *               only for the duration of the callback).
 *   user_data — value from EppSessionEventCallbacks.user_data.
 *
 * Use case: logging / telemetry.  The session remains usable after this
 * callback; if the error is fatal the next API call will return an error code.
 */
typedef void (*EppOnSessionError)(
    EppErrorCode   code,
    const char*    message,
    void*          user_data);

/*
 * EppOnNonceExhaustionWarning — fired when the current chain's nonce budget
 * drops below ~20 %.  The next outgoing or incoming message will trigger a
 * DH ratchet step automatically, but calling the callback gives the app a
 * chance to schedule a proactive message.
 *
 *   remaining    — nonces left in the current chain.
 *   max_capacity — total nonce budget for a single chain.
 *   user_data    — value from EppSessionEventCallbacks.user_data.
 */
typedef void (*EppOnNonceExhaustionWarning)(
    uint64_t remaining,
    uint64_t max_capacity,
    void*    user_data);

/*
 * EppOnRatchetStallingWarning — fired when many consecutive messages have
 * been sent without a DH ratchet step (the peer appears unresponsive).
 * At this point forward secrecy is degraded; consider sending a ping or
 * triggering a session refresh.
 *
 *   messages_since_ratchet — number of messages sent since the last ratchet.
 *   user_data              — value from EppSessionEventCallbacks.user_data.
 */
typedef void (*EppOnRatchetStallingWarning)(
    uint64_t messages_since_ratchet,
    void*    user_data);

/*
 * EppSessionEventCallbacks — vtable of C callbacks for a 1-to-1 session.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * epp_session_set_event_handler().  The struct is copied by value; you do
 * not need to keep it alive after the call returns.
 *
 * Set any callback field to NULL to ignore that event.
 *
 * user_data is an opaque pointer forwarded verbatim to every callback.
 * Typical use: pass `self` / a context pointer from your application.
 */
typedef struct {
    EppOnHandshakeCompleted      on_handshake_completed;
    EppOnRatchetRotated          on_ratchet_rotated;
    EppOnSessionError            on_error;
    EppOnNonceExhaustionWarning  on_nonce_exhaustion_warning;
    EppOnRatchetStallingWarning  on_ratchet_stalling_warning;
    void*                        user_data;
} EppSessionEventCallbacks;

/*
 * epp_session_set_event_handler — register C callbacks on a 1-to-1 session.
 *
 * The callbacks struct is copied immediately; you can free or reuse it after
 * this call returns.  Calling this function again replaces the previous
 * handler.  Pass a zeroed struct to remove all callbacks.
 *
 * Parameters:
 *   handle    — active session handle.
 *   callbacks — pointer to a populated EppSessionEventCallbacks (not NULL).
 *               All function-pointer fields may individually be NULL.
 *   out_error — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_NULL_POINTER / EPP_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_ratchet(uint64_t epoch, void* ctx) {
 *       MyApp* app = ctx;
 *       app->last_ratchet_epoch = epoch;
 *   }
 *   EppSessionEventCallbacks cbs = {0};
 *   cbs.on_ratchet_rotated = on_ratchet;
 *   cbs.user_data = my_app;
 *   epp_session_set_event_handler(session, &cbs, &err);
 */
EPP_API EppErrorCode epp_session_set_event_handler(
    EppSessionHandle*              handle,
    const EppSessionEventCallbacks* callbacks,
    EppError*                      out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — group session
 *
 * Same threading and lifetime rules as session event callbacks above.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * EppOnMemberAdded — fired after a Commit that added a new member is applied.
 *
 *   leaf_index           — zero-based leaf position of the new member in the
 *                          ratchet tree.
 *   identity_ed25519     — pointer to the new member's 32-byte Ed25519 public
 *                          key (borrowed; valid only during this callback).
 *   identity_ed25519_len — always 32.
 *   user_data            — value from EppGroupEventCallbacks.user_data.
 *
 * Use case: update the UI member list; look up the new contact by their key.
 */
typedef void (*EppOnMemberAdded)(
    uint32_t       leaf_index,
    const uint8_t* identity_ed25519,
    size_t         identity_ed25519_len,
    void*          user_data);

/*
 * EppOnMemberRemoved — fired after a Commit that removed a member is applied.
 *
 *   leaf_index — leaf position of the removed member (now blank in the tree).
 *   user_data  — value from EppGroupEventCallbacks.user_data.
 *
 * Use case: remove the member from the UI; revoke any cached sender key.
 */
typedef void (*EppOnMemberRemoved)(uint32_t leaf_index, void* user_data);

/*
 * EppOnEpochAdvanced — fired every time a Commit is successfully applied and
 * the epoch number increments.
 *
 *   new_epoch    — epoch number after the commit.
 *   member_count — number of active (non-blank) members after the commit.
 *   user_data    — value from EppGroupEventCallbacks.user_data.
 *
 * Use case: persist the new epoch to storage; refresh epoch-bound UI state.
 */
typedef void (*EppOnEpochAdvanced)(
    uint64_t new_epoch,
    uint32_t member_count,
    void*    user_data);

/*
 * EppOnSenderKeyExhaustionWarning — fired when this member's sender-key
 * generation counter approaches the per-epoch limit set by
 * EppGroupSecurityPolicy.max_messages_per_epoch.
 *
 *   remaining    — generation slots remaining before a forced Update is needed.
 *   max_capacity — the total per-epoch message budget for this member.
 *   user_data    — value from EppGroupEventCallbacks.user_data.
 *
 * Use case: prompt the user or automatically call epp_group_update() to
 * rotate keys and start a new epoch before the budget is exhausted.
 */
typedef void (*EppOnSenderKeyExhaustionWarning)(
    uint32_t remaining,
    uint32_t max_capacity,
    void*    user_data);

/*
 * EppOnReInitProposed — fired when a Commit that contains a ReInit proposal
 * is successfully applied.  A ReInit signals that the group is deprecated and
 * all members should migrate to a new group.
 *
 *   new_group_id     — pointer to the new group's 32-byte identifier (borrowed;
 *                      valid only for the duration of this callback).
 *   new_group_id_len — always 32.
 *   new_version      — protocol version the new group should use.
 *   user_data        — value from EppGroupEventCallbacks.user_data.
 *
 * Use case: notify participants, create a fresh group at new_group_id with
 * the indicated protocol version, and stop sending into the old group.
 */
typedef void (*EppOnReInitProposed)(
    const uint8_t* new_group_id,
    size_t         new_group_id_len,
    uint32_t       new_version,
    void*          user_data);

/*
 * EppGroupEventCallbacks — vtable of C callbacks for a group session.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * epp_group_set_event_handler().  Copied by value; struct need not outlive
 * the call.  Set any field to NULL to ignore that event.
 */
typedef struct {
    EppOnMemberAdded                on_member_added;
    EppOnMemberRemoved              on_member_removed;
    EppOnEpochAdvanced              on_epoch_advanced;
    EppOnSenderKeyExhaustionWarning on_sender_key_exhaustion_warning;
    EppOnReInitProposed             on_reinit_proposed;
    void*                           user_data;
} EppGroupEventCallbacks;

/*
 * epp_group_set_event_handler — register C callbacks on a group session.
 *
 * The callbacks struct is copied immediately; free or reuse it after return.
 * Calling again replaces the previous handler; pass a zeroed struct to remove.
 *
 * Parameters:
 *   handle    — active group session handle.
 *   callbacks — pointer to a populated EppGroupEventCallbacks (not NULL).
 *   out_error — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_NULL_POINTER / EPP_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_epoch(uint64_t epoch, uint32_t members, void* ctx) {
 *       persist_epoch(ctx, epoch, members);
 *   }
 *   EppGroupEventCallbacks cbs = {0};
 *   cbs.on_epoch_advanced = on_epoch;
 *   cbs.user_data = my_db;
 *   epp_group_set_event_handler(group, &cbs, &err);
 */
EPP_API EppErrorCode epp_group_set_event_handler(
    EppGroupSessionHandle*          handle,
    const EppGroupEventCallbacks*   callbacks,
    EppError*                       out_error);


/* ═══════════════════════════════════════════════════════════════════════════
 * Event callbacks — identity
 *
 * Identity-level events are not tied to a single session or group.
 * Register once per identity handle.  Same threading and lifetime rules
 * as session and group callbacks above.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * EppOnOtkExhaustionWarning — fired after an OTK (One-Time Prekey) is
 * consumed and the remaining pool has dropped at or below the exhaustion
 * warning threshold (default: ≤ 10 % of max_capacity).
 *
 * A depleted OTK pool prevents new contacts from initiating a handshake with
 * this identity.  Upload fresh OTKs immediately by calling
 * epp_prekey_bundle_replenish() and sending the result to the key server.
 *
 *   remaining    — OTKs remaining in the local pool after this consumption.
 *   max_capacity — the default pool size (DEFAULT_ONE_TIME_KEY_COUNT = 100).
 *   user_data    — value from EppIdentityEventCallbacks.user_data.
 *
 * Use case: trigger background replenishment so the pool never hits zero.
 */
typedef void (*EppOnOtkExhaustionWarning)(
    uint32_t remaining,
    uint32_t max_capacity,
    void*    user_data);

/*
 * EppIdentityEventCallbacks — vtable of C callbacks for an identity handle.
 *
 * Pass a pointer to a populated (or zeroed) instance to
 * epp_identity_set_event_handler().  Copied by value; struct need not outlive
 * the call.  Set any field to NULL to ignore that event.
 */
typedef struct {
    EppOnOtkExhaustionWarning on_otk_exhaustion_warning;
    void*                     user_data;
} EppIdentityEventCallbacks;

/*
 * epp_identity_set_event_handler — register C callbacks on an identity handle.
 *
 * The callbacks struct is copied immediately; free or reuse it after return.
 * Calling again replaces the previous handler; pass a zeroed struct to remove.
 *
 * Parameters:
 *   handle    — active identity handle (not NULL).
 *   callbacks — pointer to a populated EppIdentityEventCallbacks (not NULL).
 *               All function-pointer fields may individually be NULL.
 *   out_error — optional error detail.
 *
 * Returns: EPP_SUCCESS or EPP_ERROR_NULL_POINTER / EPP_ERROR_INVALID_STATE.
 *
 * Example:
 *   static void on_otk_low(uint32_t remaining, uint32_t max, void* ctx) {
 *       MyApp* app = ctx;
 *       epp_prekey_bundle_replenish(app->identity, 50, app->out_buf, NULL);
 *       upload_otks_to_key_server(app->out_buf);
 *   }
 *   EppIdentityEventCallbacks cbs = {0};
 *   cbs.on_otk_exhaustion_warning = on_otk_low;
 *   cbs.user_data = my_app;
 *   epp_identity_set_event_handler(identity, &cbs, &err);
 */
EPP_API EppErrorCode epp_identity_set_event_handler(
    EppIdentityHandle*                handle,
    const EppIdentityEventCallbacks*  callbacks,
    EppError*                         out_error);

#ifdef __cplusplus
}
#endif
