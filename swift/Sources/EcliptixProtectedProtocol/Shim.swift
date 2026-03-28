// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT
//
// Shim.swift — @_silgen_name declarations for all EPP C FFI functions.
// These map directly to symbols exported by the Rust static library.
// No module.modulemap or C headers needed at compile time.

import Foundation

// MARK: - Native C struct mirrors (must match Rust #[repr(C)] layout)

internal struct NativeEppBuffer {
    var data: UnsafeMutablePointer<UInt8>?
    var length: Int
}

internal struct NativeEppError {
    var code: UInt32
    var message: UnsafeMutablePointer<CChar>?
}

internal struct NativeEppSessionConfig {
    var max_messages_per_chain: UInt32
}

internal struct NativeEppGroupSecurityPolicy {
    var max_messages_per_epoch: UInt32
    var max_skipped_keys_per_sender: UInt32
    var block_external_join: UInt8
    var enhanced_key_schedule: UInt8
    var mandatory_franking: UInt8
}

internal struct NativeEppGroupDecryptResult {
    var plaintext: NativeEppBuffer
    var sender_leaf_index: UInt32
    var generation: UInt32
    var content_type: UInt32
    var ttl_seconds: UInt32
    var sent_timestamp: UInt64
    var message_id: NativeEppBuffer
    var referenced_message_id: NativeEppBuffer
    var has_sealed_payload: UInt8
    var has_franking_data: UInt8
    var sealed_hint: NativeEppBuffer
    var sealed_encrypted_content: NativeEppBuffer
    var sealed_nonce: NativeEppBuffer
    var sealed_key: NativeEppBuffer
    var franking_tag: NativeEppBuffer
    var franking_key: NativeEppBuffer
    var franking_content: NativeEppBuffer
    var franking_sealed_content: NativeEppBuffer
}

internal struct NativeEppSessionPeerIdentity {
    var ed25519_public: (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
    var x25519_public: (
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8,
        UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8
    )
}

internal struct NativeEppEnvelopeMetadata {
    var envelope_type: UInt32
    var envelope_id: UInt32
    var message_index: UInt64
    var correlation_id: UnsafeMutablePointer<CChar>?
    var correlation_id_length: Int
}

// MARK: - Error code constants

internal let EPP_SUCCESS: UInt32 = 0
internal let EPP_ERROR_GENERIC: UInt32 = 1
internal let EPP_ERROR_INVALID_INPUT: UInt32 = 2
internal let EPP_ERROR_KEY_GENERATION: UInt32 = 3
internal let EPP_ERROR_DERIVE_KEY: UInt32 = 4
internal let EPP_ERROR_HANDSHAKE: UInt32 = 5
internal let EPP_ERROR_ENCRYPTION: UInt32 = 6
internal let EPP_ERROR_DECRYPTION: UInt32 = 7
internal let EPP_ERROR_DECODE: UInt32 = 8
internal let EPP_ERROR_ENCODE: UInt32 = 9
internal let EPP_ERROR_BUFFER_TOO_SMALL: UInt32 = 10
internal let EPP_ERROR_OBJECT_DISPOSED: UInt32 = 11
internal let EPP_ERROR_PREPARE_LOCAL: UInt32 = 12
internal let EPP_ERROR_OUT_OF_MEMORY: UInt32 = 13
internal let EPP_ERROR_CRYPTO_FAILURE: UInt32 = 14
internal let EPP_ERROR_NULL_POINTER: UInt32 = 15
internal let EPP_ERROR_INVALID_STATE: UInt32 = 16
internal let EPP_ERROR_REPLAY_ATTACK: UInt32 = 17
internal let EPP_ERROR_SESSION_EXPIRED: UInt32 = 18
internal let EPP_ERROR_PQ_MISSING: UInt32 = 19
internal let EPP_ERROR_GROUP_PROTOCOL: UInt32 = 20
internal let EPP_ERROR_GROUP_MEMBERSHIP: UInt32 = 21
internal let EPP_ERROR_TREE_INTEGRITY: UInt32 = 22
internal let EPP_ERROR_WELCOME: UInt32 = 23
internal let EPP_ERROR_MESSAGE_EXPIRED: UInt32 = 24
internal let EPP_ERROR_FRANKING: UInt32 = 25
internal let EPP_ERROR_VOIP_CALL: UInt32 = 26
internal let EPP_ERROR_VOIP_MEDIA: UInt32 = 27
internal let EPP_ERROR_VOIP_REKEY: UInt32 = 28

// MARK: - Envelope type constants

internal let EPP_ENVELOPE_REQUEST: UInt32 = 0
internal let EPP_ENVELOPE_RESPONSE: UInt32 = 1
internal let EPP_ENVELOPE_NOTIFICATION: UInt32 = 2
internal let EPP_ENVELOPE_HEARTBEAT: UInt32 = 3
internal let EPP_ENVELOPE_ERROR_RESPONSE: UInt32 = 4

// MARK: - Init / Shutdown

@_silgen_name("epp_version")
internal func native_epp_version() -> UnsafePointer<CChar>?

@_silgen_name("epp_init")
internal func native_epp_init() -> UInt32

@_silgen_name("epp_shutdown")
internal func native_epp_shutdown()

// MARK: - Identity

@_silgen_name("epp_identity_create")
internal func native_epp_identity_create(
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_create_from_seed")
internal func native_epp_identity_create_from_seed(
    _ seed: UnsafePointer<UInt8>?,
    _ seed_length: Int,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_create_with_context")
internal func native_epp_identity_create_with_context(
    _ seed: UnsafePointer<UInt8>?,
    _ seed_length: Int,
    _ membership_id: UnsafePointer<CChar>?,
    _ membership_id_length: Int,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_time_provider_manual_create")
internal func native_epp_time_provider_manual_create(
    _ initial_now_unix: UInt64,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_time_provider_manual_set_now_unix")
internal func native_epp_time_provider_manual_set_now_unix(
    _ handle: UnsafeMutableRawPointer?,
    _ now_unix: UInt64,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_set_time_provider")
internal func native_epp_identity_set_time_provider(
    _ handle: UnsafeMutableRawPointer?,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_get_x25519_public")
internal func native_epp_identity_get_x25519_public(
    _ handle: UnsafeMutableRawPointer?,
    _ out_key: UnsafeMutablePointer<UInt8>?,
    _ out_key_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_get_ed25519_public")
internal func native_epp_identity_get_ed25519_public(
    _ handle: UnsafeMutableRawPointer?,
    _ out_key: UnsafeMutablePointer<UInt8>?,
    _ out_key_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_get_kyber_public")
internal func native_epp_identity_get_kyber_public(
    _ handle: UnsafeMutableRawPointer?,
    _ out_key: UnsafeMutablePointer<UInt8>?,
    _ out_key_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_identity_destroy")
internal func native_epp_identity_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

@_silgen_name("epp_time_provider_destroy")
internal func native_epp_time_provider_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Pre-key bundle

@_silgen_name("epp_prekey_bundle_create")
internal func native_epp_prekey_bundle_create(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ out_bundle: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_prekey_bundle_replenish")
internal func native_epp_prekey_bundle_replenish(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ count: UInt32,
    _ out_keys: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Handshake initiator

@_silgen_name("epp_handshake_initiator_start")
internal func native_epp_handshake_initiator_start(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ peer_prekey_bundle: UnsafePointer<UInt8>?,
    _ peer_prekey_bundle_length: Int,
    _ config: UnsafePointer<NativeEppSessionConfig>?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_handshake_init: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_handshake_initiator_finish")
internal func native_epp_handshake_initiator_finish(
    _ handle: UnsafeMutableRawPointer?,
    _ handshake_ack: UnsafePointer<UInt8>?,
    _ handshake_ack_length: Int,
    _ out_session: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_handshake_initiator_destroy")
internal func native_epp_handshake_initiator_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Handshake responder

@_silgen_name("epp_handshake_responder_start")
internal func native_epp_handshake_responder_start(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ local_prekey_bundle: UnsafePointer<UInt8>?,
    _ local_prekey_bundle_length: Int,
    _ handshake_init: UnsafePointer<UInt8>?,
    _ handshake_init_length: Int,
    _ config: UnsafePointer<NativeEppSessionConfig>?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_handshake_ack: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_handshake_responder_finish")
internal func native_epp_handshake_responder_finish(
    _ handle: UnsafeMutableRawPointer?,
    _ out_session: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_handshake_responder_destroy")
internal func native_epp_handshake_responder_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Session (1:1)

@_silgen_name("epp_session_encrypt")
internal func native_epp_session_encrypt(
    _ handle: UnsafeMutableRawPointer?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_length: Int,
    _ envelope_type: UInt32,
    _ envelope_id: UInt32,
    _ correlation_id: UnsafePointer<CChar>?,
    _ correlation_id_length: Int,
    _ out_encrypted: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_decrypt")
internal func native_epp_session_decrypt(
    _ handle: UnsafeMutableRawPointer?,
    _ encrypted: UnsafePointer<UInt8>?,
    _ encrypted_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_metadata: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_envelope_metadata_parse")
internal func native_epp_envelope_metadata_parse(
    _ metadata_bytes: UnsafePointer<UInt8>?,
    _ metadata_length: Int,
    _ out_meta: UnsafeMutablePointer<NativeEppEnvelopeMetadata>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_envelope_metadata_free")
internal func native_epp_envelope_metadata_free(
    _ meta: UnsafeMutablePointer<NativeEppEnvelopeMetadata>?
)

@_silgen_name("epp_session_serialize_sealed")
internal func native_epp_session_serialize_sealed(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ external_counter: UInt64,
    _ out_state: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_deserialize_sealed")
internal func native_epp_session_deserialize_sealed(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ min_external_counter: UInt64,
    _ out_external_counter: UnsafeMutablePointer<UInt64>?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_deserialize_sealed_with_time_provider")
internal func native_epp_session_deserialize_sealed_with_time_provider(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ min_external_counter: UInt64,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ out_external_counter: UnsafeMutablePointer<UInt64>?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_serialize_sealed_with_tracker")
internal func native_epp_session_serialize_sealed_with_tracker(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ out_state: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_deserialize_sealed_with_tracker")
internal func native_epp_session_deserialize_sealed_with_tracker(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_deserialize_sealed_with_tracker_and_time_provider")
internal func native_epp_session_deserialize_sealed_with_tracker_and_time_provider(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_export_persisted_state")
internal func native_epp_session_export_persisted_state(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ slotHandle: UnsafeMutableRawPointer?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_restore_persisted_state")
internal func native_epp_session_restore_persisted_state(
    _ slotHandle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_restore_persisted_state_with_time_provider")
internal func native_epp_session_restore_persisted_state_with_time_provider(
    _ slotHandle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_nonce_remaining")
internal func native_epp_session_nonce_remaining(
    _ handle: UnsafeMutableRawPointer?,
    _ out_remaining: UnsafeMutablePointer<UInt64>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_get_id")
internal func native_epp_session_get_id(
    _ handle: UnsafeMutableRawPointer?,
    _ out_session_id: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_get_identity_binding_hash")
internal func native_epp_session_get_identity_binding_hash(
    _ handle: UnsafeMutableRawPointer?,
    _ out_binding_hash: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_get_peer_identity")
internal func native_epp_session_get_peer_identity(
    _ handle: UnsafeMutableRawPointer?,
    _ out_identity: UnsafeMutablePointer<NativeEppSessionPeerIdentity>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_get_local_identity")
internal func native_epp_session_get_local_identity(
    _ handle: UnsafeMutableRawPointer?,
    _ out_identity: UnsafeMutablePointer<NativeEppSessionPeerIdentity>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_session_destroy")
internal func native_epp_session_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Envelope validation / crypto utilities

@_silgen_name("epp_envelope_validate")
internal func native_epp_envelope_validate(
    _ data: UnsafePointer<UInt8>?,
    _ data_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_derive_root_key")
internal func native_epp_derive_root_key(
    _ opaque_session_key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ user_context: UnsafePointer<UInt8>?,
    _ context_length: Int,
    _ out_root_key: UnsafeMutablePointer<UInt8>?,
    _ out_key_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_shamir_split")
internal func native_epp_shamir_split(
    _ secret: UnsafePointer<UInt8>?,
    _ secret_length: Int,
    _ threshold: UInt8,
    _ share_count: UInt8,
    _ auth_key: UnsafePointer<UInt8>?,
    _ auth_key_length: Int,
    _ out_shares: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_share_length: UnsafeMutablePointer<Int>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_shamir_reconstruct")
internal func native_epp_shamir_reconstruct(
    _ shares: UnsafePointer<UInt8>?,
    _ shares_length: Int,
    _ share_length: Int,
    _ share_count: Int,
    _ auth_key: UnsafePointer<UInt8>?,
    _ auth_key_length: Int,
    _ out_secret: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_secure_wipe")
internal func native_epp_secure_wipe(
    _ data: UnsafeMutablePointer<UInt8>?,
    _ length: Int
) -> UInt32

// MARK: - Buffer / Error management

@_silgen_name("epp_buffer_release")
internal func native_epp_buffer_release(
    _ buffer: UnsafeMutablePointer<NativeEppBuffer>?
)

@_silgen_name("epp_buffer_alloc")
internal func native_epp_buffer_alloc(
    _ capacity: Int
) -> UnsafeMutablePointer<NativeEppBuffer>?

@_silgen_name("epp_buffer_free")
internal func native_epp_buffer_free(
    _ buffer: UnsafeMutablePointer<NativeEppBuffer>?
)

@_silgen_name("epp_error_free")
internal func native_epp_error_free(
    _ error: UnsafeMutablePointer<NativeEppError>?
)

@_silgen_name("epp_error_string")
internal func native_epp_error_string(
    _ code: UInt32
) -> UnsafePointer<CChar>?

// MARK: - Managed sealed-state counter tracker

@_silgen_name("epp_sealed_state_counter_tracker_create")
internal func native_epp_sealed_state_counter_tracker_create(
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_counter_tracker_create_from_serialized")
internal func native_epp_sealed_state_counter_tracker_create_from_serialized(
    _ data: UnsafePointer<UInt8>?,
    _ dataLength: Int,
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_counter_tracker_serialize")
internal func native_epp_sealed_state_counter_tracker_serialize(
    _ handle: UnsafeMutableRawPointer?,
    _ outState: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_counter_tracker_get_max_restored_counter")
internal func native_epp_sealed_state_counter_tracker_get_max_restored_counter(
    _ handle: UnsafeMutableRawPointer?,
    _ outCounter: UnsafeMutablePointer<UInt64>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_counter_tracker_get_latest_issued_counter")
internal func native_epp_sealed_state_counter_tracker_get_latest_issued_counter(
    _ handle: UnsafeMutableRawPointer?,
    _ outCounter: UnsafeMutablePointer<UInt64>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_counter_tracker_destroy")
internal func native_epp_sealed_state_counter_tracker_destroy(
    _ handlePtr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

@_silgen_name("epp_sealed_state_slot_create")
internal func native_epp_sealed_state_slot_create(
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_slot_create_from_serialized")
internal func native_epp_sealed_state_slot_create_from_serialized(
    _ data: UnsafePointer<UInt8>?,
    _ dataLength: Int,
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_slot_serialize")
internal func native_epp_sealed_state_slot_serialize(
    _ handle: UnsafeMutableRawPointer?,
    _ outState: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_slot_get_max_restored_counter")
internal func native_epp_sealed_state_slot_get_max_restored_counter(
    _ handle: UnsafeMutableRawPointer?,
    _ outCounter: UnsafeMutablePointer<UInt64>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_slot_get_latest_issued_counter")
internal func native_epp_sealed_state_slot_get_latest_issued_counter(
    _ handle: UnsafeMutableRawPointer?,
    _ outCounter: UnsafeMutablePointer<UInt64>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_sealed_state_slot_destroy")
internal func native_epp_sealed_state_slot_destroy(
    _ handlePtr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Group: key package

@_silgen_name("epp_group_generate_key_package")
internal func native_epp_group_generate_key_package(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ credential: UnsafePointer<UInt8>?,
    _ credential_length: Int,
    _ out_key_package: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_secrets: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_key_package_secrets_destroy")
internal func native_epp_group_key_package_secrets_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Group: creation / join

@_silgen_name("epp_group_create")
internal func native_epp_group_create(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ credential: UnsafePointer<UInt8>?,
    _ credential_length: Int,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_create_shielded")
internal func native_epp_group_create_shielded(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ credential: UnsafePointer<UInt8>?,
    _ credential_length: Int,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_create_with_policy")
internal func native_epp_group_create_with_policy(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ credential: UnsafePointer<UInt8>?,
    _ credential_length: Int,
    _ policy: UnsafePointer<NativeEppGroupSecurityPolicy>?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_is_shielded")
internal func native_epp_group_is_shielded(
    _ handle: UnsafeMutableRawPointer?,
    _ out_shielded: UnsafeMutablePointer<UInt8>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_get_security_policy")
internal func native_epp_group_get_security_policy(
    _ handle: UnsafeMutableRawPointer?,
    _ out_policy: UnsafeMutablePointer<NativeEppGroupSecurityPolicy>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_join")
internal func native_epp_group_join(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ welcome_bytes: UnsafePointer<UInt8>?,
    _ welcome_length: Int,
    _ secrets_handle: UnsafeMutableRawPointer?,
    _ out_group_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_authorize_external_join")
internal func native_epp_group_authorize_external_join(
    _ handle: UnsafeMutableRawPointer?,
    _ joiner_identity_ed25519_public: UnsafePointer<UInt8>?,
    _ joiner_identity_ed25519_public_length: Int,
    _ joiner_identity_x25519_public: UnsafePointer<UInt8>?,
    _ joiner_identity_x25519_public_length: Int,
    _ joiner_credential: UnsafePointer<UInt8>?,
    _ joiner_credential_length: Int,
    _ out_authorization: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_join_external")
internal func native_epp_group_join_external(
    _ identity_handle: UnsafeMutableRawPointer?,
    _ public_state: UnsafePointer<UInt8>?,
    _ public_state_length: Int,
    _ authorization: UnsafePointer<UInt8>?,
    _ authorization_length: Int,
    _ credential: UnsafePointer<UInt8>?,
    _ credential_length: Int,
    _ out_group_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_commit: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Group: membership

@_silgen_name("epp_group_add_member")
internal func native_epp_group_add_member(
    _ handle: UnsafeMutableRawPointer?,
    _ key_package: UnsafePointer<UInt8>?,
    _ key_package_length: Int,
    _ out_commit: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_welcome: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_remove_member")
internal func native_epp_group_remove_member(
    _ handle: UnsafeMutableRawPointer?,
    _ leaf_index: UInt32,
    _ out_commit: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_update")
internal func native_epp_group_update(
    _ handle: UnsafeMutableRawPointer?,
    _ out_commit: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_process_commit")
internal func native_epp_group_process_commit(
    _ handle: UnsafeMutableRawPointer?,
    _ commit_bytes: UnsafePointer<UInt8>?,
    _ commit_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Group: messaging

@_silgen_name("epp_group_encrypt")
internal func native_epp_group_encrypt(
    _ handle: UnsafeMutableRawPointer?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_length: Int,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_decrypt")
internal func native_epp_group_decrypt(
    _ handle: UnsafeMutableRawPointer?,
    _ ciphertext: UnsafePointer<UInt8>?,
    _ ciphertext_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_sender_leaf: UnsafeMutablePointer<UInt32>?,
    _ out_generation: UnsafeMutablePointer<UInt32>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_encrypt_sealed")
internal func native_epp_group_encrypt_sealed(
    _ handle: UnsafeMutableRawPointer?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_length: Int,
    _ hint: UnsafePointer<UInt8>?,
    _ hint_length: Int,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_encrypt_disappearing")
internal func native_epp_group_encrypt_disappearing(
    _ handle: UnsafeMutableRawPointer?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_length: Int,
    _ ttl_seconds: UInt32,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_encrypt_frankable")
internal func native_epp_group_encrypt_frankable(
    _ handle: UnsafeMutableRawPointer?,
    _ plaintext: UnsafePointer<UInt8>?,
    _ plaintext_length: Int,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_encrypt_edit")
internal func native_epp_group_encrypt_edit(
    _ handle: UnsafeMutableRawPointer?,
    _ new_content: UnsafePointer<UInt8>?,
    _ new_content_length: Int,
    _ target_message_id: UnsafePointer<UInt8>?,
    _ target_message_id_length: Int,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_encrypt_delete")
internal func native_epp_group_encrypt_delete(
    _ handle: UnsafeMutableRawPointer?,
    _ target_message_id: UnsafePointer<UInt8>?,
    _ target_message_id_length: Int,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_decrypt_ex")
internal func native_epp_group_decrypt_ex(
    _ handle: UnsafeMutableRawPointer?,
    _ ciphertext: UnsafePointer<UInt8>?,
    _ ciphertext_length: Int,
    _ out_result: UnsafeMutablePointer<NativeEppGroupDecryptResult>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_decrypt_result_free")
internal func native_epp_group_decrypt_result_free(
    _ result: UnsafeMutablePointer<NativeEppGroupDecryptResult>?
)

// MARK: - Group: state queries

@_silgen_name("epp_group_get_id")
internal func native_epp_group_get_id(
    _ handle: UnsafeMutableRawPointer?,
    _ out_group_id: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_get_epoch")
internal func native_epp_group_get_epoch(
    _ handle: UnsafeMutableRawPointer?
) -> UInt64

@_silgen_name("epp_group_get_my_leaf_index")
internal func native_epp_group_get_my_leaf_index(
    _ handle: UnsafeMutableRawPointer?
) -> UInt32

@_silgen_name("epp_group_get_member_count")
internal func native_epp_group_get_member_count(
    _ handle: UnsafeMutableRawPointer?
) -> UInt32

@_silgen_name("epp_group_get_member_leaf_indices")
internal func native_epp_group_get_member_leaf_indices(
    _ handle: UnsafeMutableRawPointer?,
    _ out_indices: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Group: serialization

@_silgen_name("epp_group_serialize")
internal func native_epp_group_serialize(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ external_counter: UInt64,
    _ out_state: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_deserialize")
internal func native_epp_group_deserialize(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ min_external_counter: UInt64,
    _ out_external_counter: UnsafeMutablePointer<UInt64>?,
    _ identity_handle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_serialize_with_tracker")
internal func native_epp_group_serialize_with_tracker(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ out_state: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_deserialize_with_tracker")
internal func native_epp_group_deserialize_with_tracker(
    _ state_bytes: UnsafePointer<UInt8>?,
    _ state_length: Int,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ identityHandle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_export_persisted_state")
internal func native_epp_group_export_persisted_state(
    _ handle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ slotHandle: UnsafeMutableRawPointer?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_restore_persisted_state")
internal func native_epp_group_restore_persisted_state(
    _ slotHandle: UnsafeMutableRawPointer?,
    _ key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ identityHandle: UnsafeMutableRawPointer?,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_export_public_state")
internal func native_epp_group_export_public_state(
    _ handle: UnsafeMutableRawPointer?,
    _ out_public_state: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Group: crypto verification

@_silgen_name("epp_group_compute_message_id")
internal func native_epp_group_compute_message_id(
    _ group_id: UnsafePointer<UInt8>?,
    _ group_id_length: Int,
    _ epoch: UInt64,
    _ sender_leaf_index: UInt32,
    _ generation: UInt32,
    _ out_message_id: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_reveal_sealed")
internal func native_epp_group_reveal_sealed(
    _ hint: UnsafePointer<UInt8>?,
    _ hint_length: Int,
    _ encrypted_content: UnsafePointer<UInt8>?,
    _ encrypted_content_length: Int,
    _ nonce: UnsafePointer<UInt8>?,
    _ nonce_length: Int,
    _ seal_key: UnsafePointer<UInt8>?,
    _ seal_key_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_verify_franking")
internal func native_epp_group_verify_franking(
    _ franking_tag: UnsafePointer<UInt8>?,
    _ franking_tag_length: Int,
    _ franking_key: UnsafePointer<UInt8>?,
    _ franking_key_length: Int,
    _ content: UnsafePointer<UInt8>?,
    _ content_length: Int,
    _ sealed_content: UnsafePointer<UInt8>?,
    _ sealed_content_length: Int,
    _ out_valid: UnsafeMutablePointer<UInt8>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

// MARK: - Group: PSK / reinit

@_silgen_name("epp_group_set_psk")
internal func native_epp_group_set_psk(
    _ handle: UnsafeMutableRawPointer?,
    _ psk_id: UnsafePointer<UInt8>?,
    _ psk_id_length: Int,
    _ psk: UnsafePointer<UInt8>?,
    _ psk_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_get_pending_reinit")
internal func native_epp_group_get_pending_reinit(
    _ handle: UnsafeMutableRawPointer?,
    _ out_new_group_id: UnsafeMutablePointer<NativeEppBuffer>?,
    _ out_new_version: UnsafeMutablePointer<UInt32>?,
    _ out_error: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_group_destroy")
internal func native_epp_group_destroy(
    _ handle_ptr: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
)

// MARK: - Internal helpers

/// Reads data from a NativeEppBuffer and returns it as Data. Does NOT release the buffer.
internal func dataFromBuffer(_ buffer: NativeEppBuffer) -> Data? {
    guard let ptr = buffer.data, buffer.length > 0 else { return nil }
    return Data(bytes: ptr, count: buffer.length)
}

/// Calls the FFI, checks the error code, releases the native error, and throws on failure.
internal struct NativeEppEncryptedFrame {
    var call_id: NativeEppBuffer
    var ssrc: UInt32
    var frame_counter: UInt64
    var ratchet_generation: UInt32
    var encrypted_payload: NativeEppBuffer
    var nonce: NativeEppBuffer
    var encrypted_header: NativeEppBuffer
}

internal struct NativeEppDecryptedFrame {
    var payload: NativeEppBuffer
    var payload_type: UInt8
    var ssrc: UInt32
    var timestamp: UInt32
    var sequence_number: UInt16
    var frame_counter: UInt64
    var ratchet_generation: UInt32
}

internal struct NativeEppCallStatistics {
    var frames_sent: UInt64
    var frames_received: UInt64
    var frames_dropped: UInt64
    var rekey_count: UInt32
    var ratchet_generation: UInt32
    var call_duration_secs: UInt64
}

@_silgen_name("epp_voip_accept_call")
internal func native_epp_voip_accept_call(
    _ identity: UnsafeRawPointer?,
    _ callInitBytes: UnsafePointer<UInt8>?,
    _ callInitLen: Int,
    _ peerKyberPublic: UnsafePointer<UInt8>?,
    _ peerKyberPublicLen: Int,
    _ outAcceptBytes: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_call_init_start")
internal func native_epp_voip_call_init_start(
    _ identity: UnsafeRawPointer?,
    _ peerKyberPublic: UnsafePointer<UInt8>?,
    _ peerKyberPublicLen: Int,
    _ shieldMode: UInt8,
    _ ratchetIntervalFrames: UInt32,
    _ pqRekeyIntervalSecs: UInt32,
    _ outInitBytes: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outInitiator: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_call_init_complete")
internal func native_epp_voip_call_init_complete(
    _ initiatorHandle: UnsafeMutableRawPointer?,
    _ identity: UnsafeRawPointer?,
    _ acceptBytes: UnsafePointer<UInt8>?,
    _ acceptLen: Int,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_call_initiator_destroy")
internal func native_epp_voip_call_initiator_destroy(
    _ handle: UnsafeMutableRawPointer?
)

@_silgen_name("epp_voip_encrypt_frame")
internal func native_epp_voip_encrypt_frame(
    _ handle: UnsafeRawPointer?,
    _ payloadType: UInt8,
    _ ssrc: UInt32,
    _ timestamp: UInt32,
    _ sequenceNumber: UInt16,
    _ payload: UnsafePointer<UInt8>?,
    _ payloadLen: Int,
    _ outFrame: UnsafeMutablePointer<NativeEppEncryptedFrame>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_decrypt_frame")
internal func native_epp_voip_decrypt_frame(
    _ handle: UnsafeRawPointer?,
    _ callId: UnsafePointer<UInt8>?,
    _ callIdLen: Int,
    _ ssrc: UInt32,
    _ frameCounter: UInt64,
    _ ratchetGeneration: UInt32,
    _ encryptedPayload: UnsafePointer<UInt8>?,
    _ encryptedPayloadLen: Int,
    _ nonce: UnsafePointer<UInt8>?,
    _ nonceLen: Int,
    _ encryptedHeader: UnsafePointer<UInt8>?,
    _ encryptedHeaderLen: Int,
    _ outFrame: UnsafeMutablePointer<NativeEppDecryptedFrame>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_call_id")
internal func native_epp_voip_call_id(
    _ handle: UnsafeRawPointer?,
    _ outBuf: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_ssrc")
internal func native_epp_voip_ssrc(
    _ handle: UnsafeRawPointer?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_is_shield_mode")
internal func native_epp_voip_is_shield_mode(
    _ handle: UnsafeRawPointer?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt8

@_silgen_name("epp_voip_end_call")
internal func native_epp_voip_end_call(
    _ handle: UnsafeRawPointer?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_generate_call_end_hmac")
internal func native_epp_voip_generate_call_end_hmac(
    _ handle: UnsafeRawPointer?,
    _ deviceId: UnsafePointer<UInt8>?,
    _ deviceIdLen: Int,
    _ timestamp: UInt64,
    _ outHmac: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_verify_call_end_hmac")
internal func native_epp_voip_verify_call_end_hmac(
    _ handle: UnsafeRawPointer?,
    _ deviceId: UnsafePointer<UInt8>?,
    _ deviceIdLen: Int,
    _ timestamp: UInt64,
    _ hmacValue: UnsafePointer<UInt8>?,
    _ hmacValueLen: Int,
    _ outValid: UnsafeMutablePointer<UInt8>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_build_call_end")
internal func native_epp_voip_build_call_end(
    _ handle: UnsafeRawPointer?,
    _ deviceId: UnsafePointer<UInt8>?,
    _ deviceIdLen: Int,
    _ timestamp: UInt64,
    _ outBuf: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_process_call_end")
internal func native_epp_voip_process_call_end(
    _ handle: UnsafeRawPointer?,
    _ callEndBytes: UnsafePointer<UInt8>?,
    _ callEndLen: Int,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_encrypt_call_control")
internal func native_epp_voip_encrypt_call_control(
    _ handle: UnsafeRawPointer?,
    _ controlType: UInt8,
    _ dtmfDigit: UInt8,
    _ outFrame: UnsafeMutablePointer<NativeEppEncryptedFrame>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_export_sealed_state")
internal func native_epp_voip_export_sealed_state(
    _ handle: UnsafeRawPointer?,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ externalCounter: UInt64,
    _ outBuf: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_export_sealed_state_with_tracker")
internal func native_epp_voip_export_sealed_state_with_tracker(
    _ handle: UnsafeRawPointer?,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ outBuf: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_export_persisted_state")
internal func native_epp_voip_export_persisted_state(
    _ handle: UnsafeRawPointer?,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ slotHandle: UnsafeMutableRawPointer?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_initiate_rekey")
internal func native_epp_voip_initiate_rekey(
    _ handle: UnsafeRawPointer?,
    _ identity: UnsafeRawPointer?,
    _ peerKyberPublic: UnsafePointer<UInt8>?,
    _ peerKyberPublicLen: Int,
    _ outRekeyBytes: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_process_rekey")
internal func native_epp_voip_process_rekey(
    _ handle: UnsafeRawPointer?,
    _ identity: UnsafeRawPointer?,
    _ peerEd25519Public: UnsafePointer<UInt8>?,
    _ peerEd25519PublicLen: Int,
    _ rekeyBytes: UnsafePointer<UInt8>?,
    _ rekeyLen: Int,
    _ peerKyberPublic: UnsafePointer<UInt8>?,
    _ peerKyberPublicLen: Int,
    _ outAckBytes: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_process_rekey_ack")
internal func native_epp_voip_process_rekey_ack(
    _ handle: UnsafeRawPointer?,
    _ identity: UnsafeRawPointer?,
    _ peerEd25519Public: UnsafePointer<UInt8>?,
    _ peerEd25519PublicLen: Int,
    _ ackBytes: UnsafePointer<UInt8>?,
    _ ackLen: Int,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_import_sealed_state")
internal func native_epp_voip_import_sealed_state(
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ minExternalCounter: UInt64,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_import_sealed_state_with_time_provider")
internal func native_epp_voip_import_sealed_state_with_time_provider(
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ minExternalCounter: UInt64,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_import_sealed_state_with_tracker")
internal func native_epp_voip_import_sealed_state_with_tracker(
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_import_sealed_state_with_tracker_and_time_provider")
internal func native_epp_voip_import_sealed_state_with_tracker_and_time_provider(
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ trackerHandle: UnsafeMutableRawPointer?,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_restore_persisted_state")
internal func native_epp_voip_restore_persisted_state(
    _ slotHandle: UnsafeMutableRawPointer?,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_restore_persisted_state_with_time_provider")
internal func native_epp_voip_restore_persisted_state_with_time_provider(
    _ slotHandle: UnsafeMutableRawPointer?,
    _ stateKey: UnsafePointer<UInt8>?,
    _ stateKeyLen: Int,
    _ time_provider_handle: UnsafeMutableRawPointer?,
    _ outSession: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_sealed_state_external_counter")
internal func native_epp_voip_sealed_state_external_counter(
    _ data: UnsafePointer<UInt8>?,
    _ dataLen: Int,
    _ outExternalCounter: UnsafeMutablePointer<UInt64>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_session_destroy")
internal func native_epp_voip_session_destroy(
    _ handle: UnsafeMutableRawPointer?
)

@_silgen_name("epp_voip_set_screen_share_meta")
internal func native_epp_voip_set_screen_share_meta(
    _ handle: UnsafeRawPointer?,
    _ width: UInt32,
    _ height: UInt32,
    _ frameRate: UInt32,
    _ codecHint: UnsafePointer<UInt8>?,
    _ codecHintLength: Int,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_get_screen_share_meta")
internal func native_epp_voip_get_screen_share_meta(
    _ handle: UnsafeRawPointer?,
    _ outWidth: UnsafeMutablePointer<UInt32>?,
    _ outHeight: UnsafeMutablePointer<UInt32>?,
    _ outFrameRate: UnsafeMutablePointer<UInt32>?,
    _ outCodecHint: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_clear_screen_share_meta")
internal func native_epp_voip_clear_screen_share_meta(
    _ handle: UnsafeRawPointer?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_get_call_statistics")
internal func native_epp_voip_get_call_statistics(
    _ handle: UnsafeRawPointer?,
    _ outStats: UnsafeMutablePointer<NativeEppCallStatistics>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_set_recording_consent")
internal func native_epp_voip_set_recording_consent(
    _ handle: UnsafeRawPointer?,
    _ consent: Int32,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_get_local_recording_consent")
internal func native_epp_voip_get_local_recording_consent(
    _ handle: UnsafeRawPointer?
) -> Int32

@_silgen_name("epp_voip_get_remote_recording_consent")
internal func native_epp_voip_get_remote_recording_consent(
    _ handle: UnsafeRawPointer?
) -> Int32

@_silgen_name("epp_voip_both_consented_to_recording")
internal func native_epp_voip_both_consented_to_recording(
    _ handle: UnsafeRawPointer?
) -> Bool

@_silgen_name("epp_voip_build_recording_consent_message")
internal func native_epp_voip_build_recording_consent_message(
    _ handle: UnsafeRawPointer?,
    _ identity: UnsafeRawPointer?,
    _ consent: Int32,
    _ timestampUnix: UInt64,
    _ outMessage: UnsafeMutablePointer<NativeEppBuffer>?,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

@_silgen_name("epp_voip_process_recording_consent_message")
internal func native_epp_voip_process_recording_consent_message(
    _ handle: UnsafeRawPointer?,
    _ peerEd25519Public: UnsafePointer<UInt8>?,
    _ peerEd25519PublicLen: Int,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: Int,
    _ outError: UnsafeMutablePointer<NativeEppError>?
) -> UInt32

internal func checkResult(_ code: UInt32, _ nativeError: inout NativeEppError) throws {
    guard code == EPP_SUCCESS else {
        let error = EppError.from(code: code, nativeError: nativeError)
        native_epp_error_free(&nativeError)
        throw error
    }
    native_epp_error_free(&nativeError)
}

// MARK: - Attachment

@_silgen_name("epp_attachment_generate_id")
internal func native_epp_attachment_generate_id(
    _ out_attachment_id: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_generate_file_key")
internal func native_epp_attachment_generate_file_key(
    _ out_file_key: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_encrypt_chunk")
internal func native_epp_attachment_encrypt_chunk(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<CChar>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_index: UInt32,
    _ chunk_count: UInt32,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintext_length: Int,
    _ out_nonce: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_decrypt_chunk")
internal func native_epp_attachment_decrypt_chunk(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<CChar>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_index: UInt32,
    _ chunk_count: UInt32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_length: Int,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_manifest_create")
internal func native_epp_attachment_manifest_create(
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<CChar>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_count: UInt32,
    _ file_sha256: UnsafePointer<UInt8>,
    _ file_sha256_length: Int,
    _ encrypted_file_key: UnsafePointer<UInt8>,
    _ encrypted_file_key_length: Int,
    _ out_manifest: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_manifest_validate")
internal func native_epp_attachment_manifest_validate(
    _ manifest_bytes: UnsafePointer<UInt8>,
    _ manifest_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_chunk_validate")
internal func native_epp_attachment_chunk_validate(
    _ manifest_bytes: UnsafePointer<UInt8>,
    _ manifest_length: Int,
    _ chunk_index: UInt32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_length: Int,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_encrypt_thumbnail")
internal func native_epp_attachment_encrypt_thumbnail(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ thumbnail_mime_type: UnsafePointer<UInt8>,
    _ thumbnail_mime_type_length: Int,
    _ thumbnail_plaintext: UnsafePointer<UInt8>,
    _ thumbnail_plaintext_length: Int,
    _ out_nonce: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_ciphertext: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_decrypt_thumbnail")
internal func native_epp_attachment_decrypt_thumbnail(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ thumbnail_mime_type: UnsafePointer<UInt8>,
    _ thumbnail_mime_type_length: Int,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_length: Int,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_validate_ttl")
internal func native_epp_attachment_validate_ttl(
    _ ttl_seconds: UInt64,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_is_expired")
internal func native_epp_attachment_is_expired(
    _ created_at_unix: UInt64,
    _ ttl_seconds: UInt64,
    _ now_unix: UInt64
) -> Bool

@_silgen_name("epp_attachment_progress_create")
internal func native_epp_attachment_progress_create(
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ chunk_count: UInt32,
    _ out_progress: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_progress_mark_completed")
internal func native_epp_attachment_progress_mark_completed(
    _ progress_bytes: UnsafePointer<UInt8>,
    _ progress_length: Int,
    _ chunk_index: UInt32,
    _ bytes_transferred: UInt64,
    _ now_unix: UInt64,
    _ out_updated_progress: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_progress_get_remaining")
internal func native_epp_attachment_progress_get_remaining(
    _ progress_bytes: UnsafePointer<UInt8>,
    _ progress_length: Int,
    _ out_remaining: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_remaining_count: UnsafeMutablePointer<UInt32>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_progress_is_complete")
internal func native_epp_attachment_progress_is_complete(
    _ progress_bytes: UnsafePointer<UInt8>,
    _ progress_length: Int
) -> Bool

@_silgen_name("epp_attachment_generate_collage_id")
internal func native_epp_attachment_generate_collage_id(
    _ out_collage_id: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_collage_create")
internal func native_epp_attachment_collage_create(
    _ manifest_array: UnsafePointer<UnsafePointer<UInt8>?>,
    _ manifest_lengths: UnsafePointer<Int>,
    _ manifest_count: Int,
    _ out_collage: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_collage_validate")
internal func native_epp_attachment_collage_validate(
    _ collage_bytes: UnsafePointer<UInt8>,
    _ collage_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_encryptor_create")
internal func native_epp_attachment_streaming_encryptor_create(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<UInt8>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_count: UInt32,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_encryptor_write")
internal func native_epp_attachment_streaming_encryptor_write(
    _ handle: UnsafeMutableRawPointer,
    _ data: UnsafePointer<UInt8>,
    _ data_length: Int,
    _ out_chunks: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_chunk_count: UnsafeMutablePointer<UInt32>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_encryptor_finish")
internal func native_epp_attachment_streaming_encryptor_finish(
    _ handle: UnsafeMutableRawPointer,
    _ out_chunk: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_has_chunk: UnsafeMutablePointer<UInt8>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_encryptor_destroy")
internal func native_epp_attachment_streaming_encryptor_destroy(
    _ handle: UnsafeMutableRawPointer
)

@_silgen_name("epp_attachment_streaming_decryptor_create")
internal func native_epp_attachment_streaming_decryptor_create(
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<UInt8>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_count: UInt32,
    _ out_handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_decryptor_write")
internal func native_epp_attachment_streaming_decryptor_write(
    _ handle: UnsafeMutableRawPointer,
    _ chunk_index: UInt32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_length: Int,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_length: Int,
    _ out_plaintext: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_streaming_decryptor_is_complete")
internal func native_epp_attachment_streaming_decryptor_is_complete(
    _ handle: UnsafeMutableRawPointer
) -> Bool

@_silgen_name("epp_attachment_streaming_decryptor_destroy")
internal func native_epp_attachment_streaming_decryptor_destroy(
    _ handle: UnsafeMutableRawPointer
)

@_silgen_name("epp_attachment_manifest_create_v2")
internal func native_epp_attachment_manifest_create_v2(
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<UInt8>,
    _ mime_type_length: Int,
    _ total_size: UInt64,
    _ chunk_size: UInt32,
    _ chunk_count: UInt32,
    _ file_sha256: UnsafePointer<UInt8>,
    _ file_sha256_length: Int,
    _ encrypted_file_key: UnsafePointer<UInt8>,
    _ encrypted_file_key_length: Int,
    _ collage_index: Int64,
    _ thumbnail_ciphertext: UnsafePointer<UInt8>?,
    _ thumbnail_ciphertext_length: Int,
    _ thumbnail_nonce: UnsafePointer<UInt8>?,
    _ thumbnail_nonce_length: Int,
    _ thumbnail_mime_type: UnsafePointer<UInt8>?,
    _ thumbnail_mime_type_length: Int,
    _ thumbnail_original_size: UInt32,
    _ ttl_seconds: UInt64,
    _ created_at_unix: UInt64,
    _ out_manifest: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_encrypt_file_key")
internal func native_epp_attachment_encrypt_file_key(
    _ handle: UnsafeMutableRawPointer,
    _ file_key: UnsafePointer<UInt8>,
    _ file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ out_encrypted_file_key: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_decrypt_file_key")
internal func native_epp_attachment_decrypt_file_key(
    _ handle: UnsafeMutableRawPointer,
    _ encrypted_file_key: UnsafePointer<UInt8>,
    _ encrypted_file_key_length: Int,
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ out_file_key: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_validate_magic_bytes")
internal func native_epp_attachment_validate_magic_bytes(
    _ header: UnsafePointer<UInt8>,
    _ header_length: Int,
    _ mime_type: UnsafePointer<UInt8>,
    _ mime_type_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_detect_mime")
internal func native_epp_attachment_detect_mime(
    _ header: UnsafePointer<UInt8>,
    _ header_length: Int,
    _ out_mime: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_validate_filename")
internal func native_epp_attachment_validate_filename(
    _ name: UnsafePointer<UInt8>,
    _ name_length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_sanitize_filename")
internal func native_epp_attachment_sanitize_filename(
    _ name: UnsafePointer<UInt8>,
    _ name_length: Int,
    _ out_sanitized: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_collage_create_with_metadata")
internal func native_epp_attachment_collage_create_with_metadata(
    _ manifest_array: UnsafePointer<UnsafePointer<UInt8>?>,
    _ manifest_lengths: UnsafePointer<Int>,
    _ manifest_count: Int,
    _ name: UnsafePointer<UInt8>?,
    _ name_length: Int,
    _ description: UnsafePointer<UInt8>?,
    _ description_length: Int,
    _ layout: Int32,
    _ out_collage: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_inline_validate")
internal func native_epp_attachment_inline_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_inline_create")
internal func native_epp_attachment_inline_create(
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ mime_type: UnsafePointer<UInt8>,
    _ mime_type_length: Int,
    _ data: UnsafePointer<UInt8>,
    _ data_length: Int,
    _ original_filename: UnsafePointer<UInt8>?,
    _ original_filename_length: Int,
    _ has_content_policy: UInt8,
    _ view_once: UInt8,
    _ no_forward: UInt8,
    _ no_save: UInt8,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_reference_validate")
internal func native_epp_attachment_reference_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_reference_create")
internal func native_epp_attachment_reference_create(
    _ attachment_id: UnsafePointer<UInt8>,
    _ attachment_id_length: Int,
    _ reference_type: Int32,
    _ source_message_id: UnsafePointer<UInt8>?,
    _ source_message_id_length: Int,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_voice_meta_validate")
internal func native_epp_attachment_voice_meta_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_voice_meta_create")
internal func native_epp_attachment_voice_meta_create(
    _ waveform_samples: UnsafePointer<Float>?,
    _ waveform_count: Int,
    _ transcript: UnsafePointer<UInt8>?,
    _ transcript_length: Int,
    _ playback_speed_hint: Float,
    _ has_playback_speed: UInt8,
    _ is_listened: UInt8,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_location_validate")
internal func native_epp_attachment_location_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_location_create")
internal func native_epp_attachment_location_create(
    _ latitude: Double,
    _ longitude: Double,
    _ accuracy_meters: Double,
    _ has_accuracy: UInt8,
    _ label: UnsafePointer<UInt8>?,
    _ label_length: Int,
    _ timestamp_unix: UInt64,
    _ has_timestamp: UInt8,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_contact_card_validate")
internal func native_epp_attachment_contact_card_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_contact_card_create")
internal func native_epp_attachment_contact_card_create(
    _ display_name: UnsafePointer<UInt8>,
    _ display_name_length: Int,
    _ phone: UnsafePointer<UInt8>?,
    _ phone_length: Int,
    _ email: UnsafePointer<UInt8>?,
    _ email_length: Int,
    _ avatar_data: UnsafePointer<UInt8>?,
    _ avatar_data_length: Int,
    _ organization: UnsafePointer<UInt8>?,
    _ organization_length: Int,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_link_preview_validate")
internal func native_epp_attachment_link_preview_validate(
    _ bytes: UnsafePointer<UInt8>,
    _ length: Int,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32

@_silgen_name("epp_attachment_link_preview_create")
internal func native_epp_attachment_link_preview_create(
    _ url: UnsafePointer<UInt8>,
    _ url_length: Int,
    _ title: UnsafePointer<UInt8>?,
    _ title_length: Int,
    _ description: UnsafePointer<UInt8>?,
    _ description_length: Int,
    _ preview_image: UnsafePointer<UInt8>?,
    _ preview_image_length: Int,
    _ preview_image_mime: UnsafePointer<UInt8>?,
    _ preview_image_mime_length: Int,
    _ domain: UnsafePointer<UInt8>?,
    _ domain_length: Int,
    _ out_buffer: UnsafeMutablePointer<NativeEppBuffer>,
    _ out_error: UnsafeMutablePointer<NativeEppError>
) -> UInt32
