// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

const COMMON_HEADER: &str = include_str!("../include/epp_common_api.h");
const CLIENT_HEADER: &str = include_str!("../include/epp_client_api.h");

#[test]
fn common_header_exports_current_version_and_voip_errors() {
    assert!(
        COMMON_HEADER.contains("#define EPP_API_VERSION_MAJOR 1"),
        "common header must expose current API major version"
    );
    assert!(
        COMMON_HEADER.contains("#define EPP_API_VERSION_MINOR 1"),
        "common header must expose current API minor version"
    );
    assert!(
        COMMON_HEADER.contains("#define EPP_API_VERSION_PATCH 1"),
        "common header must expose current API patch version"
    );
    assert!(
        COMMON_HEADER.contains("#define EPP_LIBRARY_VERSION \"1.1.1\""),
        "common header library version must match crate/ffi version"
    );
    assert!(
        COMMON_HEADER.contains("EPP_ERROR_VOIP_CALL = 26"),
        "common header must expose VoIP call error code"
    );
    assert!(
        COMMON_HEADER.contains("EPP_ERROR_VOIP_MEDIA = 27"),
        "common header must expose VoIP media error code"
    );
    assert!(
        COMMON_HEADER.contains("EPP_ERROR_VOIP_REKEY = 28"),
        "common header must expose VoIP rekey error code"
    );
}

#[test]
fn client_header_exports_voip_handles_types_and_critical_functions() {
    for required in [
        "typedef struct EppVoipSessionHandle       EppVoipSessionHandle;",
        "typedef struct EppVoipCallInitiatorHandle EppVoipCallInitiatorHandle;",
        "typedef struct EppSealedStateCounterTrackerHandle EppSealedStateCounterTrackerHandle;",
        "typedef struct EppSealedStateSlotHandle EppSealedStateSlotHandle;",
        "typedef struct EppTimeProviderHandle EppTimeProviderHandle;",
        "} EppEncryptedFrame;",
        "} EppDecryptedFrame;",
        "} EppCallStatistics;",
        "EPP_VOIP_CALL_CONTROL_DTMF = 5",
        "epp_sealed_state_counter_tracker_create(",
        "epp_sealed_state_counter_tracker_create_from_serialized(",
        "epp_sealed_state_counter_tracker_serialize(",
        "epp_sealed_state_counter_tracker_get_max_restored_counter(",
        "epp_sealed_state_counter_tracker_get_latest_issued_counter(",
        "epp_sealed_state_counter_tracker_destroy(",
        "epp_sealed_state_slot_create(",
        "epp_sealed_state_slot_create_from_serialized(",
        "epp_sealed_state_slot_serialize(",
        "epp_sealed_state_slot_get_max_restored_counter(",
        "epp_sealed_state_slot_get_latest_issued_counter(",
        "epp_sealed_state_slot_destroy(",
        "epp_time_provider_manual_create(",
        "epp_time_provider_manual_set_now_unix(",
        "epp_identity_set_time_provider(",
        "epp_time_provider_destroy(",
        "epp_voip_call_init(",
        "epp_voip_call_init_start(",
        "epp_voip_call_init_complete(",
        "epp_voip_accept_call(",
        "epp_voip_encrypt_frame(",
        "epp_voip_decrypt_frame(",
        "epp_session_serialize_sealed_with_tracker(",
        "epp_session_deserialize_sealed_with_tracker(",
        "epp_session_deserialize_sealed_with_time_provider(",
        "epp_session_deserialize_sealed_with_tracker_and_time_provider(",
        "epp_session_export_persisted_state(",
        "epp_session_restore_persisted_state(",
        "epp_session_restore_persisted_state_with_time_provider(",
        "epp_group_serialize_with_tracker(",
        "epp_group_deserialize_with_tracker(",
        "epp_group_export_persisted_state(",
        "epp_group_restore_persisted_state(",
        "epp_voip_export_sealed_state(",
        "epp_voip_export_sealed_state_with_tracker(",
        "epp_voip_export_persisted_state(",
        "epp_voip_import_sealed_state(",
        "epp_voip_import_sealed_state_with_time_provider(",
        "epp_voip_import_sealed_state_with_tracker(",
        "epp_voip_import_sealed_state_with_tracker_and_time_provider(",
        "epp_voip_restore_persisted_state(",
        "epp_voip_restore_persisted_state_with_time_provider(",
        "epp_voip_get_call_statistics(",
        "epp_voip_set_screen_share_meta(",
        "epp_voip_get_screen_share_meta(",
        "epp_voip_set_recording_consent(",
        "epp_voip_both_consented_to_recording(",
        "epp_voip_build_recording_consent_message(",
        "epp_voip_process_recording_consent_message(",
    ] {
        assert!(
            CLIENT_HEADER.contains(required),
            "client header is missing required VoIP declaration fragment: {required}"
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
