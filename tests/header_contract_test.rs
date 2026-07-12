// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

const COMMON_HEADER: &str = include_str!("../include/aura_common_api.h");
const CLIENT_HEADER: &str = include_str!("../include/aura_client_api.h");

#[test]
fn common_header_exports_current_version_and_voip_errors() {
    assert!(
        COMMON_HEADER.contains("#define AURA_API_VERSION_MAJOR 2"),
        "common header must expose current API major version"
    );
    assert!(
        COMMON_HEADER.contains("#define AURA_API_VERSION_MINOR 0"),
        "common header must expose current API minor version"
    );
    assert!(
        COMMON_HEADER.contains("#define AURA_API_VERSION_PATCH 0"),
        "common header must expose current API patch version"
    );
    assert!(
        COMMON_HEADER.contains("#define AURA_LIBRARY_VERSION \"2.0.0\""),
        "common header library version must match crate/ffi version"
    );
    assert!(
        COMMON_HEADER.contains("AURA_ERROR_VOIP_CALL = 26"),
        "common header must expose VoIP call error code"
    );
    assert!(
        COMMON_HEADER.contains("AURA_ERROR_VOIP_MEDIA = 27"),
        "common header must expose VoIP media error code"
    );
    assert!(
        COMMON_HEADER.contains("AURA_ERROR_VOIP_REKEY = 28"),
        "common header must expose VoIP rekey error code"
    );
    assert!(
        COMMON_HEADER.contains("AURA_ERROR_BUSY = 29"),
        "common header must expose busy-handle error code"
    );
}

#[test]
fn client_header_exports_voip_handles_types_and_critical_functions() {
    for required in [
        "typedef struct AuraVoipSessionHandle       AuraVoipSessionHandle;",
        "typedef struct AuraVoipCallInitiatorHandle AuraVoipCallInitiatorHandle;",
        "typedef struct AuraSealedStateCounterTrackerHandle AuraSealedStateCounterTrackerHandle;",
        "typedef struct AuraSealedStateSlotHandle AuraSealedStateSlotHandle;",
        "typedef struct AuraTimeProviderHandle AuraTimeProviderHandle;",
        "} AuraEncryptedFrame;",
        "} AuraDecryptedFrame;",
        "} AuraCallStatistics;",
        "AURA_VOIP_CALL_CONTROL_DTMF = 5",
        "aura_sealed_state_counter_tracker_create(",
        "aura_sealed_state_counter_tracker_create_from_serialized(",
        "aura_sealed_state_counter_tracker_serialize(",
        "aura_sealed_state_counter_tracker_get_max_restored_counter(",
        "aura_sealed_state_counter_tracker_get_latest_issued_counter(",
        "aura_sealed_state_counter_tracker_destroy(",
        "aura_sealed_state_slot_create(",
        "aura_sealed_state_slot_create_from_serialized(",
        "aura_sealed_state_slot_serialize(",
        "aura_sealed_state_slot_get_max_restored_counter(",
        "aura_sealed_state_slot_get_latest_issued_counter(",
        "aura_sealed_state_slot_destroy(",
        "aura_time_provider_manual_create(",
        "aura_time_provider_manual_set_now_unix(",
        "aura_identity_set_time_provider(",
        "aura_time_provider_destroy(",
        "aura_voip_call_init(",
        "aura_voip_call_init_start(",
        "aura_voip_call_init_complete(",
        "aura_voip_accept_call(",
        "aura_voip_encrypt_frame(",
        "aura_voip_decrypt_frame(",
        "aura_attachment_streaming_encryptor_destroy(\n    AuraStreamingEncryptorHandle** handle_ptr);",
        "aura_attachment_streaming_decryptor_destroy(\n    AuraStreamingDecryptorHandle** handle_ptr);",
        "aura_voip_call_initiator_destroy(AuraVoipCallInitiatorHandle** handle);",
        "aura_voip_session_destroy(AuraVoipSessionHandle** handle);",
        "aura_session_serialize_sealed_with_tracker(",
        "aura_session_deserialize_sealed_with_tracker(",
        "aura_session_deserialize_sealed_with_time_provider(",
        "aura_session_deserialize_sealed_with_tracker_and_time_provider(",
        "aura_session_export_persisted_state(",
        "aura_session_restore_persisted_state(",
        "aura_session_restore_persisted_state_with_time_provider(",
        "aura_envelope_validate(",
        "aura_group_serialize_with_tracker(",
        "aura_group_deserialize_with_tracker(",
        "aura_group_export_persisted_state(",
        "aura_group_restore_persisted_state(",
        "AURA_GROUP_SECURITY_TIER_SHIELD_V1 = 2",
        "aura_group_get_security_tier(",
        "aura_group_decrypt_open_sealed_ex(",
        "aura_voip_export_sealed_state(",
        "aura_voip_export_sealed_state_with_tracker(",
        "aura_voip_export_persisted_state(",
        "aura_voip_import_sealed_state(",
        "aura_voip_import_sealed_state_with_time_provider(",
        "aura_voip_import_sealed_state_with_tracker(",
        "aura_voip_import_sealed_state_with_tracker_and_time_provider(",
        "aura_voip_restore_persisted_state(",
        "aura_voip_restore_persisted_state_with_time_provider(",
        "aura_voip_get_call_statistics(",
        "aura_voip_set_screen_share_meta(",
        "aura_voip_get_screen_share_meta(",
        "aura_voip_set_recording_consent(",
        "aura_voip_both_consented_to_recording(",
        "aura_voip_build_recording_consent_message(",
        "aura_voip_process_recording_consent_message(",
    ] {
        assert!(
            CLIENT_HEADER.contains(required),
            "client header is missing required VoIP declaration fragment: {required}"
        );
    }

    for forbidden in [
        "aura_attachment_streaming_encryptor_destroy(\n    AuraStreamingEncryptorHandle* handle);",
        "aura_attachment_streaming_decryptor_destroy(\n    AuraStreamingDecryptorHandle* handle);",
    ] {
        assert!(
            !CLIENT_HEADER.contains(forbidden),
            "client header must keep the pointer-nulling attachment destroy ABI: {forbidden}"
        );
    }
}

#[test]
fn client_header_documents_external_join_freshness_and_rollout_constraints() {
    for required in [
        "joiners reject expired artifacts during bootstrap",
        "pre-commit group state rather than their local wall clock",
        "signed auth-format version",
        "use ExternalInit only between peers",
        "payload format",
    ] {
        assert!(
            CLIENT_HEADER.contains(required),
            "client header is missing required external join contract fragment: {required}"
        );
    }
}

#[test]
fn client_header_documents_current_ffi_output_ownership_contract() {
    for required in [
        "The FFI layer does not inspect or free",
        "destroy any previous",
        "handle before passing the same slot",
        "call aura_buffer_release() before reusing the same buffer slot",
        "Simple `AuraBuffer*` and",
        "Compound output structs",
        "MUST still be zero-initialized",
        "same zero-initialization/reuse",
        "semantics as aura_voip_encrypt_frame",
    ] {
        assert!(
            CLIENT_HEADER.contains(required),
            "client header is missing required FFI output ownership fragment: {required}"
        );
    }

    for forbidden in [
        "the FFI layer replaces any previous\n *     FFI-owned handle",
        "layer replaces any previous FFI-owned contents",
    ] {
        assert!(
            !CLIENT_HEADER.contains(forbidden),
            "client header must not promise automatic output-slot replacement: {forbidden}"
        );
    }
}
