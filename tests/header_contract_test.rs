// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::borrow::Cow;

const COMMON_HEADER: &str = include_str!("../include/aura_common_api.h");
const CLIENT_HEADER: &str = include_str!("../include/aura_client_api.h");

fn normalize_newlines(header: &str) -> Cow<'_, str> {
    if header.contains('\r') {
        Cow::Owned(header.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        Cow::Borrowed(header)
    }
}

#[test]
fn header_contract_normalization_accepts_windows_newlines() {
    assert_eq!(
        normalize_newlines("first\r\nsecond\rthird").as_ref(),
        "first\nsecond\nthird"
    );
}

#[test]
fn common_header_exports_current_version_and_voip_errors() {
    assert!(
        COMMON_HEADER.contains("#define AURA_API_VERSION_MAJOR 3"),
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
        COMMON_HEADER.contains("#define AURA_LIBRARY_VERSION \"3.0.0\""),
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
    let client_header = normalize_newlines(CLIENT_HEADER);

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
            client_header.contains(required),
            "client header is missing required VoIP declaration fragment: {required}"
        );
    }

    for forbidden in [
        "aura_attachment_streaming_encryptor_destroy(\n    AuraStreamingEncryptorHandle* handle);",
        "aura_attachment_streaming_decryptor_destroy(\n    AuraStreamingDecryptorHandle* handle);",
    ] {
        assert!(
            !client_header.contains(forbidden),
            "client header must keep the pointer-nulling attachment destroy ABI: {forbidden}"
        );
    }
}

#[test]
fn client_header_documents_external_join_freshness_and_rollout_constraints() {
    let client_header = normalize_newlines(CLIENT_HEADER);

    for required in [
        "joiners reject expired artifacts during bootstrap",
        "pre-commit group state rather than their local wall clock",
        "signed auth-format version",
        "use ExternalInit only between peers",
        "payload format",
    ] {
        assert!(
            client_header.contains(required),
            "client header is missing required external join contract fragment: {required}"
        );
    }
}

#[test]
fn client_header_documents_current_ffi_output_ownership_contract() {
    let client_header = normalize_newlines(CLIENT_HEADER);

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
            client_header.contains(required),
            "client header is missing required FFI output ownership fragment: {required}"
        );
    }

    for forbidden in [
        "the FFI layer replaces any previous\n *     FFI-owned handle",
        "layer replaces any previous FFI-owned contents",
    ] {
        assert!(
            !client_header.contains(forbidden),
            "client header must not promise automatic output-slot replacement: {forbidden}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ABI drift
// ═══════════════════════════════════════════════════════════════════════════

const FFI_API: &str = include_str!("../src/ffi/api.rs");
const FFI_MOD: &str = include_str!("../src/ffi/mod.rs");

/// Symbols that are deliberately exported without a public declaration.
///
/// Empty on purpose: any future exception has to be added here, which makes it
/// a reviewed decision rather than something that drifts in unnoticed.
const ALLOWED_UNDECLARED: &[&str] = &[];

/// Every `#[no_mangle] extern "C" fn` name in `src/ffi/`.
fn exported_symbols() -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for source in [FFI_API, FFI_MOD] {
        let normalized = normalize_newlines(source);
        let lines: Vec<&str> = normalized.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            if line.trim() != "#[no_mangle]" {
                continue;
            }
            // Scan forward past doc comments and further attributes to the
            // signature line.
            for candidate in lines.iter().skip(idx + 1).take(8) {
                let trimmed = candidate.trim();
                if trimmed.starts_with("///") || trimmed.starts_with("#[") || trimmed.is_empty() {
                    continue;
                }
                if let Some(rest) = trimmed.split("extern \"C\" fn ").nth(1) {
                    if let Some(name) = rest.split('(').next() {
                        names.insert(name.trim().to_string());
                    }
                }
                break;
            }
        }
    }
    names
}

/// Every `aura_*` function declared with `AURA_API` in the public headers.
fn declared_symbols() -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for header in [COMMON_HEADER, CLIENT_HEADER] {
        for line in normalize_newlines(header).lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("AURA_API") {
                continue;
            }
            // The declared name is the last `aura_*` token immediately followed
            // by `(`, which covers every return-type shape in these headers.
            let Some(paren) = trimmed.find('(') else {
                continue;
            };
            let before = &trimmed[..paren];
            let name: String = before
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if name.starts_with("aura_") {
                names.insert(name);
            }
        }
    }
    names
}

/// The C headers are the contract every Swift/.NET/C++ integrator codes
/// against, and the only prior guard was a hand-curated list of "critical"
/// functions — so exported-but-undocumented ABI accumulated silently (13
/// symbols at the time this test was written, including message franking and
/// the sealed key-package secrets round trip).
#[test]
fn ffi_exports_match_public_headers() {
    let exported = exported_symbols();
    let declared = declared_symbols();

    assert!(
        exported.len() > 150,
        "symbol extraction looks broken: only {} exports found",
        exported.len()
    );

    let undeclared: Vec<&String> = exported
        .difference(&declared)
        .filter(|name| !ALLOWED_UNDECLARED.contains(&name.as_str()))
        .collect();
    assert!(
        undeclared.is_empty(),
        "exported but not declared in the public headers: {undeclared:#?}"
    );

    let unexported: Vec<&String> = declared.difference(&exported).collect();
    assert!(
        unexported.is_empty(),
        "declared in the public headers but not exported: {unexported:#?}"
    );
}
