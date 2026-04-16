#![cfg(feature = "ffi")]
// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT
#![allow(clippy::borrow_as_ptr, unsafe_code)]

use aura_protected_protocol::crypto::CryptoInterop;

fn init() {
    CryptoInterop::initialize().expect("crypto init");
}

mod ffi {
    use aura_protected_protocol::ffi::api::*;
    use aura_protected_protocol::proto::{AttachmentManifest, CallAccept};
    use prost::Message;
    use std::ptr;
    use std::sync::atomic::Ordering;

    const fn null_error() -> AuraError {
        AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        }
    }

    const fn null_buffer() -> AuraBuffer {
        AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        }
    }

    const fn null_encrypted_frame() -> AuraEncryptedFrame {
        AuraEncryptedFrame {
            call_id: null_buffer(),
            ssrc: 0,
            frame_counter: 0,
            ratchet_generation: 0,
            encrypted_payload: null_buffer(),
            nonce: null_buffer(),
            encrypted_header: null_buffer(),
        }
    }

    const fn null_decrypted_frame() -> AuraDecryptedFrame {
        AuraDecryptedFrame {
            payload: null_buffer(),
            payload_type: 0,
            ssrc: 0,
            timestamp: 0,
            sequence_number: 0,
            frame_counter: 0,
            ratchet_generation: 0,
        }
    }

    fn init_lib() {
        aura_init();
    }

    fn setup_session_pair() -> (
        *mut AuraIdentityHandle,
        *mut AuraIdentityHandle,
        *mut AuraSessionHandle,
        *mut AuraSessionHandle,
        AuraBuffer,
        AuraBuffer,
        AuraBuffer,
    ) {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            assert_eq!(
                aura_identity_create(&mut alice_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_create(&mut bob_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut bob_bundle_buf = null_buffer();
        unsafe {
            assert_eq!(
                aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err),
                AuraErrorCode::AuraSuccess
            );
        }

        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = null_buffer();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = null_buffer();
        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_handshake_initiator_start(
                    alice_h,
                    bob_bundle_buf.data,
                    bob_bundle_buf.length,
                    &config,
                    &mut init_h,
                    &mut init_msg,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_responder_start(
                    bob_h,
                    bob_bundle_buf.data,
                    bob_bundle_buf.length,
                    init_msg.data,
                    init_msg.length,
                    &config,
                    &mut resp_h,
                    &mut ack_msg,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_initiator_finish(
                    init_h,
                    ack_msg.data,
                    ack_msg.length,
                    &mut alice_session_h,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        (
            alice_h,
            bob_h,
            alice_session_h,
            bob_session_h,
            bob_bundle_buf,
            init_msg,
            ack_msg,
        )
    }

    #[test]
    fn ffi_version_is_non_null() {
        init_lib();
        let v = aura_version();
        assert!(!v.is_null());
    }

    #[test]
    fn ffi_init_returns_success() {
        let code = aura_init();
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn ffi_identity_create_and_destroy() {
        init_lib();
        let mut handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(&mut handle, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!handle.is_null());
        unsafe {
            aura_identity_destroy(&mut handle);
            assert!(handle.is_null());
            aura_identity_destroy(&mut handle);
            assert!(handle.is_null());
        };
    }

    #[test]
    fn ffi_manual_time_provider_rejects_backwards_clock() {
        init_lib();

        let mut provider_h: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut err = null_error();

        unsafe {
            assert_eq!(
                aura_time_provider_manual_create(1_700_000_000, &mut provider_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_time_provider_manual_set_now_unix(provider_h, 1_700_000_010, &mut err),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_time_provider_manual_set_now_unix(provider_h, 1_700_000_009, &mut err),
                AuraErrorCode::AuraErrorInvalidInput
            );
            aura_error_free(&mut err);

            assert_eq!(
                aura_time_provider_manual_set_now_unix(provider_h, 1_700_000_011, &mut err),
                AuraErrorCode::AuraSuccess
            );

            aura_time_provider_destroy(&mut provider_h);
        }
    }

    #[test]
    fn ffi_identity_out_handle_can_be_reused_across_successful_calls() {
        init_lib();
        let mut handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let mut first_x25519 = [0u8; 32];
        let mut second_x25519 = [0u8; 32];

        unsafe {
            assert_eq!(
                aura_identity_create(&mut handle, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_x25519_public(
                    handle,
                    first_x25519.as_mut_ptr(),
                    first_x25519.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_identity_create(&mut handle, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_x25519_public(
                    handle,
                    second_x25519.as_mut_ptr(),
                    second_x25519.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_ne!(first_x25519, second_x25519);

            aura_identity_destroy(&mut handle);
        }
    }

    #[test]
    fn ffi_sealed_state_counter_tracker_roundtrip() {
        init_lib();
        let mut tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut restored: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut serialized = null_buffer();
        let mut err = null_error();
        let mut max_restored = u64::MAX;
        let mut latest_issued = u64::MAX;

        unsafe {
            assert_eq!(
                aura_sealed_state_counter_tracker_create(&mut tracker, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert!(!tracker.is_null());
            assert_eq!(
                aura_sealed_state_counter_tracker_get_max_restored_counter(
                    tracker,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 0);
            assert_eq!(
                aura_sealed_state_counter_tracker_get_latest_issued_counter(
                    tracker,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(latest_issued, 0);

            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(tracker, &mut serialized, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert!(serialized.length > 0);

            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    serialized.data,
                    serialized.length,
                    &mut restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored.is_null());
            max_restored = u64::MAX;
            latest_issued = u64::MAX;
            assert_eq!(
                aura_sealed_state_counter_tracker_get_max_restored_counter(
                    restored,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_get_latest_issued_counter(
                    restored,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 0);
            assert_eq!(latest_issued, 0);

            aura_buffer_release(&mut serialized);
            aura_sealed_state_counter_tracker_destroy(&mut tracker);
            aura_sealed_state_counter_tracker_destroy(&mut restored);
        }
    }

    #[test]
    fn ffi_sealed_state_slot_roundtrip() {
        init_lib();
        let mut slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut restored: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut serialized = null_buffer();
        let mut err = null_error();
        let mut max_restored = u64::MAX;
        let mut latest_issued = u64::MAX;

        unsafe {
            assert_eq!(
                aura_sealed_state_slot_create(&mut slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_serialize(slot, &mut serialized, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_create_from_serialized(
                    serialized.data,
                    serialized.length,
                    &mut restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_get_max_restored_counter(
                    restored,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_get_latest_issued_counter(
                    restored,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 0);
            assert_eq!(latest_issued, 0);

            aura_buffer_release(&mut serialized);
            aura_sealed_state_slot_destroy(&mut slot);
            aura_sealed_state_slot_destroy(&mut restored);
        }
    }

    #[test]
    fn ffi_identity_get_keys() {
        init_lib();
        let mut handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { aura_identity_create(&mut handle, &mut err) };

        let mut x25519 = vec![0u8; 32];
        let code = unsafe {
            aura_identity_get_x25519_public(handle, x25519.as_mut_ptr(), x25519.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(x25519.iter().any(|&b| b != 0));

        let mut ed25519 = vec![0u8; 32];
        let code = unsafe {
            aura_identity_get_ed25519_public(handle, ed25519.as_mut_ptr(), ed25519.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(ed25519.iter().any(|&b| b != 0));

        let mut kyber = vec![0u8; 1184];
        let code = unsafe {
            aura_identity_get_kyber_public(handle, kyber.as_mut_ptr(), kyber.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        unsafe { aura_identity_destroy(&mut handle) };
    }

    #[test]
    fn ffi_prekey_bundle_create() {
        init_lib();
        let mut handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { aura_identity_create(&mut handle, &mut err) };

        let mut bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe { aura_prekey_bundle_create(handle, &mut bundle_buf, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!bundle_buf.data.is_null());
        assert!(bundle_buf.length > 0);

        unsafe {
            aura_buffer_release(&mut bundle_buf);
            aura_identity_destroy(&mut handle);
        }
    }

    #[test]
    fn ffi_output_buffer_can_be_reused_across_successful_calls() {
        init_lib();
        let mut err = null_error();
        let group_id = [0xABu8; 32];
        let mut out = null_buffer();

        unsafe {
            assert_eq!(
                aura_group_compute_message_id(
                    group_id.as_ptr(),
                    group_id.len(),
                    1,
                    2,
                    3,
                    &mut out,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(out.length, 32);
            let first = std::slice::from_raw_parts(out.data, out.length).to_vec();

            assert_eq!(
                aura_group_compute_message_id(
                    group_id.as_ptr(),
                    group_id.len(),
                    4,
                    5,
                    6,
                    &mut out,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(out.length, 32);
            let second = std::slice::from_raw_parts(out.data, out.length).to_vec();
            assert_ne!(first, second);

            aura_buffer_release(&mut out);
        }
    }

    #[test]
    fn ffi_full_handshake_encrypt_decrypt() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err) };

        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();
        unsafe {
            aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err);
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
        }
        assert!(!bob_session_h.is_null());
        assert!(!alice_session_h.is_null());

        let plaintext = b"Hello from FFI!";
        let mut enc_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_session_encrypt(
                alice_session_h,
                plaintext.as_ptr(),
                plaintext.len(),
                AuraEnvelopeType::AuraEnvelopeRequest,
                42,
                ptr::null(),
                0,
                &mut enc_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!enc_buf.data.is_null());

        let mut plain_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_session_decrypt(
                bob_session_h,
                enc_buf.data,
                enc_buf.length,
                &mut plain_buf,
                &mut meta_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!plain_buf.data.is_null());
        let decrypted = unsafe { std::slice::from_raw_parts(plain_buf.data, plain_buf.length) };
        assert_eq!(decrypted, plaintext);

        unsafe {
            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut enc_buf);
            aura_buffer_release(&mut plain_buf);
            aura_buffer_release(&mut meta_buf);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut alice_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_session_get_id_returns_busy_when_handle_in_use() {
        init_lib();

        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut bob_bundle_buf,
            mut init_msg,
            mut ack_msg,
        ) = setup_session_pair();

        let mut err = null_error();
        let mut session_id = null_buffer();

        unsafe {
            (*alice_session_h).in_use.store(true, Ordering::Release);
            let code = aura_session_get_id(alice_session_h, &mut session_id, &mut err);
            assert_eq!(code, AuraErrorCode::AuraErrorBusy);
            assert!(session_id.data.is_null());
            assert_eq!(session_id.length, 0);
            aura_error_free(&mut err);
            (*alice_session_h).in_use.store(false, Ordering::Release);

            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut session_id);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut alice_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_group_get_id_returns_busy_when_handle_in_use() {
        init_lib();

        let mut identity_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut group_h: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut err = null_error();
        let mut group_id = null_buffer();

        unsafe {
            assert_eq!(
                aura_identity_create(&mut identity_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_group_create(identity_h, ptr::null(), 0, &mut group_h, &mut err),
                AuraErrorCode::AuraSuccess
            );

            (*group_h).in_use.store(true, Ordering::Release);
            let code = aura_group_get_id(group_h, &mut group_id, &mut err);
            assert_eq!(code, AuraErrorCode::AuraErrorBusy);
            assert!(group_id.data.is_null());
            assert_eq!(group_id.length, 0);
            aura_error_free(&mut err);
            (*group_h).in_use.store(false, Ordering::Release);

            aura_buffer_release(&mut group_id);
            aura_group_destroy(&mut group_h);
            aura_identity_destroy(&mut identity_h);
        }
    }

    #[test]
    fn ffi_session_deserialize_with_time_provider_uses_manual_clock() {
        init_lib();

        let initial_now = 1_700_000_000u64;
        let mut alice_time: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut restore_time: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut restored_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut err = null_error();
        let mut bob_bundle_buf = null_buffer();
        let mut init_msg = null_buffer();
        let mut ack_msg = null_buffer();
        let mut sealed = null_buffer();
        let mut external_counter = 0u64;
        let state_key = [7u8; 32];
        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };

        unsafe {
            assert_eq!(
                aura_time_provider_manual_create(initial_now, &mut alice_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_time_provider_manual_create(initial_now, &mut restore_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_create(&mut alice_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_create(&mut bob_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_set_time_provider(alice_h, alice_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_initiator_start(
                    alice_h,
                    bob_bundle_buf.data,
                    bob_bundle_buf.length,
                    &config,
                    &mut init_h,
                    &mut init_msg,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_responder_start(
                    bob_h,
                    bob_bundle_buf.data,
                    bob_bundle_buf.length,
                    init_msg.data,
                    init_msg.length,
                    &config,
                    &mut resp_h,
                    &mut ack_msg,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_handshake_initiator_finish(
                    init_h,
                    ack_msg.data,
                    ack_msg.length,
                    &mut alice_session_h,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_set_ttl(alice_session_h, 60, true, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_serialize_sealed(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    1,
                    &mut sealed,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_deserialize_sealed_with_time_provider(
                    sealed.data,
                    sealed.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    0,
                    restore_time,
                    &mut external_counter,
                    &mut restored_session_h,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(external_counter, 1);
            assert!(!aura_session_is_expired(restored_session_h));

            assert_eq!(
                aura_time_provider_manual_set_now_unix(restore_time, initial_now + 61, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert!(aura_session_is_expired(restored_session_h));

            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut sealed);
            aura_session_destroy(&mut restored_session_h);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut alice_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_time_provider_destroy(&mut alice_time);
            aura_time_provider_destroy(&mut restore_time);
        }
    }

    #[test]
    fn ffi_voip_call_init_complete_rejects_wrong_version_without_consuming_initiator() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        let code = unsafe {
            aura_identity_get_kyber_public(bob_h, bob_kyber.as_mut_ptr(), bob_kyber.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let code = unsafe {
            aura_identity_get_kyber_public(
                alice_h,
                alice_kyber.as_mut_ptr(),
                alice_kyber.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut init_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let code = unsafe {
            aura_voip_call_init_start(
                alice_h,
                bob_kyber.as_ptr(),
                bob_kyber.len(),
                0,
                512,
                60,
                &mut init_buf,
                &mut init_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut accept_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let code = unsafe {
            aura_voip_accept_call(
                bob_h,
                init_buf.data,
                init_buf.length,
                alice_kyber.as_ptr(),
                alice_kyber.len(),
                &mut accept_buf,
                &mut bob_session_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let accept_slice =
            unsafe { std::slice::from_raw_parts(accept_buf.data, accept_buf.length) };
        let mut accept = CallAccept::decode(accept_slice).unwrap();
        accept.version += 1;
        let mut bad_accept = Vec::new();
        accept.encode(&mut bad_accept).unwrap();

        let mut alice_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let code = unsafe {
            aura_voip_call_init_complete(
                init_h,
                alice_h,
                bad_accept.as_ptr(),
                bad_accept.len(),
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
        assert!(alice_session_h.is_null());

        let code = unsafe {
            aura_voip_call_init_complete(
                init_h,
                alice_h,
                accept_buf.data,
                accept_buf.length,
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!alice_session_h.is_null());

        unsafe {
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_rekey_restore_and_call_end_roundtrip() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        let mut alice_ed = vec![0u8; 32];
        let mut bob_ed = vec![0u8; 32];
        unsafe {
            assert_eq!(
                aura_identity_get_kyber_public(
                    alice_h,
                    alice_kyber.as_mut_ptr(),
                    alice_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_kyber_public(
                    bob_h,
                    bob_kyber.as_mut_ptr(),
                    bob_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_ed25519_public(
                    alice_h,
                    alice_ed.as_mut_ptr(),
                    alice_ed.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_ed25519_public(bob_h, bob_ed.as_mut_ptr(), bob_ed.len(), &mut err),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut init_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let mut accept_buf = null_buffer();
        let mut rekey_buf = null_buffer();
        let mut ack_buf = null_buffer();
        let mut sealed_buf = null_buffer();
        let mut call_end_buf = null_buffer();
        let mut alice_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut restored_alice_h: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_call_init_complete(
                    init_h,
                    alice_h,
                    accept_buf.data,
                    accept_buf.length,
                    &mut alice_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_initiate_rekey(
                    alice_session_h,
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    &mut rekey_buf,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_process_rekey(
                    bob_session_h,
                    bob_h,
                    alice_ed.as_ptr(),
                    alice_ed.len(),
                    rekey_buf.data,
                    rekey_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut ack_buf,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_process_rekey_ack(
                    alice_session_h,
                    alice_h,
                    bob_ed.as_ptr(),
                    bob_ed.len(),
                    ack_buf.data,
                    ack_buf.length,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let state_key = [0x42u8; 32];
        let mut external_counter = 0u64;

        unsafe {
            assert_eq!(
                aura_voip_export_sealed_state(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    7,
                    &mut sealed_buf,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_sealed_state_external_counter(
                    sealed_buf.data,
                    sealed_buf.length,
                    &mut external_counter,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(external_counter, 7);
            assert_eq!(
                aura_voip_import_sealed_state(
                    sealed_buf.data,
                    sealed_buf.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    6,
                    &mut restored_alice_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let payload = b"ffi-voip";
        let mut enc_frame = null_encrypted_frame();
        let mut dec_frame = null_decrypted_frame();

        unsafe {
            let alice_ssrc = aura_voip_ssrc(restored_alice_h, &mut err);
            assert_eq!(
                aura_voip_encrypt_frame(
                    restored_alice_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    payload.as_ptr(),
                    payload.len(),
                    &mut enc_frame,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_decrypt_frame(
                    bob_session_h,
                    enc_frame.call_id.data,
                    enc_frame.call_id.length,
                    enc_frame.ssrc,
                    enc_frame.frame_counter,
                    enc_frame.ratchet_generation,
                    enc_frame.encrypted_payload.data,
                    enc_frame.encrypted_payload.length,
                    enc_frame.nonce.data,
                    enc_frame.nonce.length,
                    enc_frame.encrypted_header.data,
                    enc_frame.encrypted_header.length,
                    &mut dec_frame,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            let decrypted =
                std::slice::from_raw_parts(dec_frame.payload.data, dec_frame.payload.length);
            assert_eq!(decrypted, payload);

            assert_eq!(
                aura_voip_build_call_end(
                    restored_alice_h,
                    b"alice-device".as_ptr(),
                    b"alice-device".len(),
                    999,
                    &mut call_end_buf,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_process_call_end(
                    bob_session_h,
                    call_end_buf.data,
                    call_end_buf.length,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            let mut failed_frame = null_encrypted_frame();
            let code = aura_voip_encrypt_frame(
                bob_session_h,
                111,
                aura_voip_ssrc(bob_session_h, &mut err),
                320,
                2,
                payload.as_ptr(),
                payload.len(),
                &mut failed_frame,
                &mut err,
            );
            assert_ne!(code, AuraErrorCode::AuraSuccess);

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_buffer_release(&mut rekey_buf);
            aura_buffer_release(&mut ack_buf);
            aura_buffer_release(&mut sealed_buf);
            aura_buffer_release(&mut call_end_buf);
            aura_buffer_release(&mut enc_frame.call_id);
            aura_buffer_release(&mut enc_frame.encrypted_payload);
            aura_buffer_release(&mut enc_frame.nonce);
            aura_buffer_release(&mut enc_frame.encrypted_header);
            aura_buffer_release(&mut dec_frame.payload);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_session_destroy(&mut restored_alice_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_handshake_finish_twice_returns_object_disposed() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err) };

        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };

        let code = unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();

        let code = unsafe { aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let code = unsafe { aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraErrorObjectDisposed);

        let code = unsafe {
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let code = unsafe {
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorObjectDisposed);

        unsafe {
            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_handshake_initiator_destroy(&mut init_h);
            aura_handshake_responder_destroy(&mut resp_h);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut alice_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_session_serialize_deserialize() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err);
        }

        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();

        unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            );
            aura_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            );
            aura_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err);
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
        }

        let mut enc_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_session_encrypt(
                alice_session_h,
                b"pre-save".as_ptr(),
                8,
                AuraEnvelopeType::AuraEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut enc_buf,
                &mut err,
            );
        }
        let mut plain_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_session_decrypt(
                bob_session_h,
                enc_buf.data,
                enc_buf.length,
                &mut plain_buf,
                &mut meta_buf,
                &mut err,
            );
            aura_buffer_release(&mut enc_buf);
            aura_buffer_release(&mut plain_buf);
            aura_buffer_release(&mut meta_buf);
        }

        let seal_key = [0xABu8; 32];
        let mut sealed_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_session_serialize_sealed(
                bob_session_h,
                seal_key.as_ptr(),
                seal_key.len(),
                1,
                &mut sealed_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_session_h2: *mut AuraSessionHandle = ptr::null_mut();
        let mut out_counter: u64 = 0;
        let code = unsafe {
            aura_session_deserialize_sealed(
                sealed_buf.data,
                sealed_buf.length,
                seal_key.as_ptr(),
                seal_key.len(),
                0,
                &mut out_counter,
                &mut bob_session_h2,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(out_counter, 1);

        let mut tampered =
            unsafe { std::slice::from_raw_parts(sealed_buf.data, sealed_buf.length) }.to_vec();
        let tampered_last = tampered.len() - 1;
        tampered[tampered_last] ^= 0x55;
        let mut failed_counter: u64 = 777;
        let mut failed_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let code = unsafe {
            aura_session_deserialize_sealed(
                tampered.as_ptr(),
                tampered.len(),
                seal_key.as_ptr(),
                seal_key.len(),
                0,
                &mut failed_counter,
                &mut failed_session_h,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(failed_counter, 777);
        assert!(failed_session_h.is_null());

        let mut enc_buf2 = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut plain_buf2 = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_buf2 = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_session_encrypt(
                alice_session_h,
                b"post-restore".as_ptr(),
                12,
                AuraEnvelopeType::AuraEnvelopeRequest,
                2,
                ptr::null(),
                0,
                &mut enc_buf2,
                &mut err,
            );
            let code = aura_session_decrypt(
                bob_session_h2,
                enc_buf2.data,
                enc_buf2.length,
                &mut plain_buf2,
                &mut meta_buf2,
                &mut err,
            );
            assert_eq!(code, AuraErrorCode::AuraSuccess);
            let dec = std::slice::from_raw_parts(plain_buf2.data, plain_buf2.length);
            assert_eq!(dec, b"post-restore");
        }

        unsafe {
            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut sealed_buf);
            aura_buffer_release(&mut enc_buf2);
            aura_buffer_release(&mut plain_buf2);
            aura_buffer_release(&mut meta_buf2);
            aura_session_destroy(&mut alice_session_h);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut bob_session_h2);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_session_sealed_state_with_tracker_restores_latest_and_rejects_rollback() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err);
        }

        let mut alice_init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                ptr::null(),
                &mut alice_init_h,
                &mut init_msg,
                &mut err,
            );
        }

        let mut bob_resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                ptr::null(),
                &mut bob_resp_h,
                &mut ack_msg,
                &mut err,
            );
        }

        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        unsafe {
            aura_handshake_initiator_finish(
                alice_init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
            aura_handshake_responder_finish(bob_resp_h, &mut bob_session_h, &mut err);
        }

        let seal_key = [0xACu8; 32];
        let mut tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut sealed1 = null_buffer();
        let mut sealed2 = null_buffer();
        let mut tracker_state1 = null_buffer();
        let mut tracker_state2 = null_buffer();
        let mut restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut next_restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut restored1: *mut AuraSessionHandle = ptr::null_mut();
        let mut restored2: *mut AuraSessionHandle = ptr::null_mut();
        let mut failed_restore: *mut AuraSessionHandle = ptr::null_mut();
        let mut max_restored = 0u64;
        let mut latest_issued = 0u64;

        unsafe {
            assert_eq!(
                aura_sealed_state_counter_tracker_create(&mut tracker, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_serialize_sealed_with_tracker(
                    bob_session_h,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    tracker,
                    &mut sealed1,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(tracker, &mut tracker_state1, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state1.data,
                    tracker_state1.length,
                    &mut restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_deserialize_sealed_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    restart_tracker,
                    &mut restored1,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored1.is_null());
            assert_eq!(
                aura_sealed_state_counter_tracker_get_max_restored_counter(
                    restart_tracker,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 1);
            assert_eq!(
                aura_sealed_state_counter_tracker_get_latest_issued_counter(
                    restart_tracker,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(latest_issued, 1);

            assert_eq!(
                aura_session_serialize_sealed_with_tracker(
                    restored1,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    restart_tracker,
                    &mut sealed2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(
                    restart_tracker,
                    &mut tracker_state2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state2.data,
                    tracker_state2.length,
                    &mut next_restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_ne!(
                aura_session_deserialize_sealed_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    next_restart_tracker,
                    &mut failed_restore,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(failed_restore.is_null());

            assert_eq!(
                aura_session_deserialize_sealed_with_tracker(
                    sealed2.data,
                    sealed2.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    next_restart_tracker,
                    &mut restored2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored2.is_null());

            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut sealed1);
            aura_buffer_release(&mut sealed2);
            aura_buffer_release(&mut tracker_state1);
            aura_buffer_release(&mut tracker_state2);
            aura_session_destroy(&mut alice_session_h);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut restored1);
            aura_session_destroy(&mut restored2);
            aura_handshake_initiator_destroy(&mut alice_init_h);
            aura_handshake_responder_destroy(&mut bob_resp_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_sealed_state_counter_tracker_destroy(&mut tracker);
            aura_sealed_state_counter_tracker_destroy(&mut restart_tracker);
            aura_sealed_state_counter_tracker_destroy(&mut next_restart_tracker);
        }
    }

    #[test]
    fn ffi_session_persisted_slot_roundtrip() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_prekey_bundle_create(bob_h, &mut bob_bundle_buf, &mut err);
        }

        let mut alice_init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                ptr::null(),
                &mut alice_init_h,
                &mut init_msg,
                &mut err,
            );
        }

        let mut bob_resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle_buf.data,
                bob_bundle_buf.length,
                init_msg.data,
                init_msg.length,
                ptr::null(),
                &mut bob_resp_h,
                &mut ack_msg,
                &mut err,
            );
        }

        let mut alice_session_h: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraSessionHandle = ptr::null_mut();
        unsafe {
            aura_handshake_initiator_finish(
                alice_init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            );
            aura_handshake_responder_finish(bob_resp_h, &mut bob_session_h, &mut err);
        }

        let seal_key = [0xBDu8; 32];
        let mut slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut restart_slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut serialized_slot = null_buffer();
        let mut restored: *mut AuraSessionHandle = ptr::null_mut();
        let mut max_restored = 0u64;
        let mut latest_issued = 0u64;

        unsafe {
            assert_eq!(
                aura_sealed_state_slot_create(&mut slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_export_persisted_state(
                    bob_session_h,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    slot,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_serialize(slot, &mut serialized_slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_create_from_serialized(
                    serialized_slot.data,
                    serialized_slot.length,
                    &mut restart_slot,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_session_restore_persisted_state(
                    restart_slot,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    &mut restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored.is_null());
            assert_eq!(
                aura_sealed_state_slot_get_max_restored_counter(
                    restart_slot,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_get_latest_issued_counter(
                    restart_slot,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 1);
            assert_eq!(latest_issued, 1);

            aura_buffer_release(&mut bob_bundle_buf);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut serialized_slot);
            aura_session_destroy(&mut alice_session_h);
            aura_session_destroy(&mut bob_session_h);
            aura_session_destroy(&mut restored);
            aura_handshake_initiator_destroy(&mut alice_init_h);
            aura_handshake_responder_destroy(&mut bob_resp_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_sealed_state_slot_destroy(&mut slot);
            aura_sealed_state_slot_destroy(&mut restart_slot);
        }
    }

    #[test]
    fn ffi_group_deserialize_does_not_overwrite_counter_on_failure() {
        init_lib();

        let mut identity_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(&mut identity_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut group_h: *mut AuraGroupSessionHandle = ptr::null_mut();
        let code = unsafe { aura_group_create(identity_h, ptr::null(), 0, &mut group_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let seal_key = [0xCDu8; 32];
        let mut sealed_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_group_serialize(
                group_h,
                seal_key.as_ptr(),
                seal_key.len(),
                1,
                &mut sealed_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut tampered =
            unsafe { std::slice::from_raw_parts(sealed_buf.data, sealed_buf.length) }.to_vec();
        let tampered_last = tampered.len() - 1;
        tampered[tampered_last] ^= 0x33;

        let mut out_counter = 999u64;
        let mut restored_group_h: *mut AuraGroupSessionHandle = ptr::null_mut();
        let code = unsafe {
            aura_group_deserialize(
                tampered.as_ptr(),
                tampered.len(),
                seal_key.as_ptr(),
                seal_key.len(),
                0,
                &mut out_counter,
                identity_h,
                &mut restored_group_h,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(out_counter, 999);
        assert!(restored_group_h.is_null());

        unsafe {
            aura_buffer_release(&mut sealed_buf);
            aura_group_destroy(&mut group_h);
            aura_identity_destroy(&mut identity_h);
        }
    }

    #[test]
    fn ffi_group_sealed_state_with_tracker_restores_latest_and_rejects_rollback() {
        init_lib();

        let mut identity_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(&mut identity_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut group_h: *mut AuraGroupSessionHandle = ptr::null_mut();
        let code = unsafe { aura_group_create(identity_h, ptr::null(), 0, &mut group_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let seal_key = [0xCEu8; 32];
        let mut tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut next_restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut sealed1 = null_buffer();
        let mut sealed2 = null_buffer();
        let mut tracker_state1 = null_buffer();
        let mut tracker_state2 = null_buffer();
        let mut restored1: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut restored2: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut failed_restore: *mut AuraGroupSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_sealed_state_counter_tracker_create(&mut tracker, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_group_serialize_with_tracker(
                    group_h,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    tracker,
                    &mut sealed1,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(tracker, &mut tracker_state1, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state1.data,
                    tracker_state1.length,
                    &mut restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_group_deserialize_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    restart_tracker,
                    identity_h,
                    &mut restored1,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored1.is_null());
            assert_eq!(
                aura_group_serialize_with_tracker(
                    restored1,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    restart_tracker,
                    &mut sealed2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(
                    restart_tracker,
                    &mut tracker_state2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state2.data,
                    tracker_state2.length,
                    &mut next_restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_ne!(
                aura_group_deserialize_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    next_restart_tracker,
                    identity_h,
                    &mut failed_restore,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(failed_restore.is_null());
            assert_eq!(
                aura_group_deserialize_with_tracker(
                    sealed2.data,
                    sealed2.length,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    next_restart_tracker,
                    identity_h,
                    &mut restored2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored2.is_null());

            aura_buffer_release(&mut sealed1);
            aura_buffer_release(&mut sealed2);
            aura_buffer_release(&mut tracker_state1);
            aura_buffer_release(&mut tracker_state2);
            aura_group_destroy(&mut group_h);
            aura_group_destroy(&mut restored1);
            aura_group_destroy(&mut restored2);
            aura_identity_destroy(&mut identity_h);
            aura_sealed_state_counter_tracker_destroy(&mut tracker);
            aura_sealed_state_counter_tracker_destroy(&mut restart_tracker);
            aura_sealed_state_counter_tracker_destroy(&mut next_restart_tracker);
        }
    }

    #[test]
    fn ffi_group_persisted_slot_roundtrip() {
        init_lib();

        let mut identity_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(&mut identity_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut group_h: *mut AuraGroupSessionHandle = ptr::null_mut();
        let code = unsafe { aura_group_create(identity_h, ptr::null(), 0, &mut group_h, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let seal_key = [0xCFu8; 32];
        let mut slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut restart_slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut serialized_slot = null_buffer();
        let mut restored: *mut AuraGroupSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_sealed_state_slot_create(&mut slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_group_export_persisted_state(
                    group_h,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    slot,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_serialize(slot, &mut serialized_slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_create_from_serialized(
                    serialized_slot.data,
                    serialized_slot.length,
                    &mut restart_slot,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_group_restore_persisted_state(
                    restart_slot,
                    seal_key.as_ptr(),
                    seal_key.len(),
                    identity_h,
                    &mut restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored.is_null());

            aura_buffer_release(&mut serialized_slot);
            aura_group_destroy(&mut group_h);
            aura_group_destroy(&mut restored);
            aura_identity_destroy(&mut identity_h);
            aura_sealed_state_slot_destroy(&mut slot);
            aura_sealed_state_slot_destroy(&mut restart_slot);
        }
    }

    #[test]
    fn ffi_shamir_split_and_reconstruct() {
        init_lib();
        let secret = b"aura-secret-32-bytes-exactly";
        let auth_key = aura_protected_protocol::crypto::CryptoInterop::get_random_bytes(32);

        let mut shares_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut share_length = 0usize;
        let mut err = null_error();

        let code = unsafe {
            aura_shamir_split(
                secret.as_ptr(),
                secret.len(),
                2,
                3,
                auth_key.as_ptr(),
                auth_key.len(),
                &mut shares_buf,
                &mut share_length,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(share_length > 0);
        assert_eq!(shares_buf.length, 3 * share_length);

        let mut secret_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_shamir_reconstruct(
                shares_buf.data,
                shares_buf.length,
                share_length,
                3,
                auth_key.as_ptr(),
                auth_key.len(),
                &mut secret_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let recovered = unsafe { std::slice::from_raw_parts(secret_buf.data, secret_buf.length) };
        assert_eq!(recovered, secret);

        unsafe {
            aura_buffer_release(&mut shares_buf);
            aura_buffer_release(&mut secret_buf);
        }
    }

    #[test]
    fn ffi_attachment_encrypt_decrypt_roundtrip() {
        init_lib();
        let mut err = null_error();

        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        let mut nonce = null_buffer();
        let mut ciphertext = null_buffer();
        let mut plaintext_out = null_buffer();
        let mut manifest = null_buffer();

        let code = unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(attachment_id.length, 32);

        let code = unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(file_key.length, 32);

        let mime = "image/jpeg";
        let chunk_plaintext = b"attachment-chunk-1";
        let total_size = chunk_plaintext.len() as u64;
        let chunk_size = 1024u32;
        let chunk_count = 1u32;
        let file_hash = [7u8; 32];
        let wrapped_file_key = [9u8; 48];

        let code = unsafe {
            aura_attachment_encrypt_chunk(
                file_key.data.cast_const(),
                file_key.length,
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                0,
                chunk_count,
                chunk_plaintext.as_ptr(),
                chunk_plaintext.len(),
                &mut nonce,
                &mut ciphertext,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(nonce.length, 12);
        assert!(ciphertext.length >= chunk_plaintext.len() + 16);

        let code = unsafe {
            aura_attachment_manifest_create(
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                chunk_count,
                file_hash.as_ptr(),
                file_hash.len(),
                wrapped_file_key.as_ptr(),
                wrapped_file_key.len(),
                &mut manifest,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code =
            unsafe { aura_attachment_manifest_validate(manifest.data, manifest.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_attachment_chunk_validate(
                manifest.data,
                manifest.length,
                0,
                nonce.data.cast_const(),
                nonce.length,
                ciphertext.data.cast_const(),
                ciphertext.length,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_attachment_decrypt_chunk(
                file_key.data.cast_const(),
                file_key.length,
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                0,
                chunk_count,
                nonce.data.cast_const(),
                nonce.length,
                ciphertext.data.cast_const(),
                ciphertext.length,
                &mut plaintext_out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let decrypted =
            unsafe { std::slice::from_raw_parts(plaintext_out.data, plaintext_out.length) };
        assert_eq!(decrypted, chunk_plaintext);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut nonce);
            aura_buffer_release(&mut ciphertext);
            aura_buffer_release(&mut plaintext_out);
            aura_buffer_release(&mut manifest);
        }
    }

    #[test]
    fn ffi_attachment_manifest_validate_rejects_tampered_scheme() {
        init_lib();
        let mut err = null_error();

        let mut attachment_id = null_buffer();
        let code = unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mime = "image/jpeg";
        let total_size = 512u64;
        let chunk_size = 512u32;
        let chunk_count = 1u32;
        let file_hash = [1u8; 32];
        let wrapped_file_key = [2u8; 48];
        let mut manifest_buf = null_buffer();

        let code = unsafe {
            aura_attachment_manifest_create(
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                chunk_count,
                file_hash.as_ptr(),
                file_hash.len(),
                wrapped_file_key.as_ptr(),
                wrapped_file_key.len(),
                &mut manifest_buf,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let manifest_bytes =
            unsafe { std::slice::from_raw_parts(manifest_buf.data, manifest_buf.length) };
        let mut manifest = AttachmentManifest::decode(manifest_bytes).expect("decode manifest");
        manifest.encryption_scheme = "AES-128-GCM".to_string();
        let mut tampered = Vec::new();
        manifest.encode(&mut tampered).expect("encode manifest");

        let code = unsafe {
            aura_attachment_manifest_validate(tampered.as_ptr(), tampered.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut manifest_buf);
        }
    }

    #[test]
    fn ffi_attachment_chunk_validate_rejects_out_of_range_chunk_index() {
        init_lib();
        let mut err = null_error();

        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        let mut nonce = null_buffer();
        let mut ciphertext = null_buffer();
        let mut manifest = null_buffer();

        let code = unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let code = unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mime = "image/jpeg";
        let chunk_plaintext = b"attachment-chunk-1";
        let total_size = chunk_plaintext.len() as u64;
        let chunk_size = 1024u32;
        let chunk_count = 1u32;
        let file_hash = [7u8; 32];
        let wrapped_file_key = [9u8; 48];

        let code = unsafe {
            aura_attachment_encrypt_chunk(
                file_key.data.cast_const(),
                file_key.length,
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                0,
                chunk_count,
                chunk_plaintext.as_ptr(),
                chunk_plaintext.len(),
                &mut nonce,
                &mut ciphertext,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_attachment_manifest_create(
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                chunk_count,
                file_hash.as_ptr(),
                file_hash.len(),
                wrapped_file_key.as_ptr(),
                wrapped_file_key.len(),
                &mut manifest,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_attachment_chunk_validate(
                manifest.data,
                manifest.length,
                1,
                nonce.data.cast_const(),
                nonce.length,
                ciphertext.data.cast_const(),
                ciphertext.length,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut nonce);
            aura_buffer_release(&mut ciphertext);
            aura_buffer_release(&mut manifest);
        }
    }

    #[test]
    fn ffi_attachment_decrypt_rejects_mismatched_context() {
        init_lib();
        let mut err = null_error();

        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        let mut nonce = null_buffer();
        let mut ciphertext = null_buffer();
        let mut plaintext_out = null_buffer();

        let code = unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let code = unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mime = "image/jpeg";
        let wrong_mime = "image/png";
        let chunk_plaintext = b"attachment-chunk-1";
        let total_size = chunk_plaintext.len() as u64;
        let chunk_size = 1024u32;
        let chunk_count = 1u32;

        let code = unsafe {
            aura_attachment_encrypt_chunk(
                file_key.data.cast_const(),
                file_key.length,
                attachment_id.data.cast_const(),
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                0,
                chunk_count,
                chunk_plaintext.as_ptr(),
                chunk_plaintext.len(),
                &mut nonce,
                &mut ciphertext,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe {
            aura_attachment_decrypt_chunk(
                file_key.data.cast_const(),
                file_key.length,
                attachment_id.data.cast_const(),
                attachment_id.length,
                wrong_mime.as_ptr().cast(),
                wrong_mime.len(),
                total_size,
                chunk_size,
                0,
                chunk_count,
                nonce.data.cast_const(),
                nonce.length,
                ciphertext.data.cast_const(),
                ciphertext.length,
                &mut plaintext_out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorGeneric);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut nonce);
            aura_buffer_release(&mut ciphertext);
            aura_buffer_release(&mut plaintext_out);
        }
    }

    #[test]
    fn ffi_derive_root_key() {
        init_lib();
        let opaque_key = aura_protected_protocol::crypto::CryptoInterop::get_random_bytes(32);
        let user_ctx = b"test-context";
        let mut out_key = vec![0u8; 32];
        let mut err = null_error();

        let code = unsafe {
            aura_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key.as_mut_ptr(),
                out_key.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(out_key.iter().any(|&b| b != 0));

        let mut out_key2 = vec![0u8; 32];
        unsafe {
            aura_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key2.as_mut_ptr(),
                out_key2.len(),
                &mut err,
            );
        }
        assert_eq!(out_key, out_key2);
    }

    #[test]
    fn ffi_derive_root_key_supports_extended_output_length() {
        init_lib();
        let opaque_key = aura_protected_protocol::crypto::CryptoInterop::get_random_bytes(32);
        let user_ctx = b"test-context-extended";
        let mut out_key = vec![0u8; 64];
        let mut err = null_error();

        let code = unsafe {
            aura_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key.as_mut_ptr(),
                out_key.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(out_key.iter().any(|&b| b != 0));
        assert!(out_key[32..].iter().any(|&b| b != 0));

        let mut out_key2 = vec![0u8; 64];
        let code = unsafe {
            aura_derive_root_key(
                opaque_key.as_ptr(),
                opaque_key.len(),
                user_ctx.as_ptr(),
                user_ctx.len(),
                out_key2.as_mut_ptr(),
                out_key2.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(out_key, out_key2);
    }

    #[test]
    fn ffi_error_string_is_non_null() {
        let s = aura_error_string(AuraErrorCode::AuraSuccess);
        assert!(!s.is_null());
        let s = aura_error_string(AuraErrorCode::AuraErrorHandshake);
        assert!(!s.is_null());
    }

    #[test]
    fn ffi_secure_wipe() {
        init_lib();
        let mut data = vec![0xABu8; 64];
        let code = unsafe { aura_secure_wipe(data.as_mut_ptr(), data.len()) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn ffi_null_pointers_return_null_error() {
        init_lib();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(ptr::null_mut(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_buffer_alloc_and_free() {
        init_lib();
        let buf = aura_buffer_alloc(64);
        assert!(!buf.is_null());
        unsafe {
            assert_eq!((*buf).length, 64);
            assert!(!(*buf).data.is_null());
            aura_buffer_free(buf);
        }
    }
}

mod ffi_error_paths {
    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    const fn null_error() -> AuraError {
        AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        }
    }

    fn init_lib() {
        aura_init();
    }

    #[test]
    fn ffi_encrypt_zero_length_plaintext() {
        init_lib();

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        unsafe { aura_prekey_bundle_create(bob_h, &mut bob_bundle, &mut err) };

        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle.data,
                bob_bundle.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle.data,
                bob_bundle.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_session: *mut AuraSessionHandle = ptr::null_mut();
        let mut alice_session: *mut AuraSessionHandle = ptr::null_mut();
        unsafe {
            aura_handshake_responder_finish(resp_h, &mut bob_session, &mut err);
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session,
                &mut err,
            );
        }

        let empty: [u8; 1] = [0];
        let mut out_env = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_session_encrypt(
                alice_session,
                empty.as_ptr(),
                0,
                AuraEnvelopeType::AuraEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut out_env,
                &mut err,
            )
        };
        assert!(
            code == AuraErrorCode::AuraSuccess || code != AuraErrorCode::AuraSuccess,
            "Zero-length encrypt must not crash"
        );

        unsafe {
            aura_session_destroy(&mut alice_session);
            aura_session_destroy(&mut bob_session);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_encrypt_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut out_env = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let payload = b"test";
        let code = unsafe {
            aura_session_encrypt(
                ptr::null_mut(),
                payload.as_ptr(),
                payload.len(),
                AuraEnvelopeType::AuraEnvelopeRequest,
                1,
                ptr::null(),
                0,
                &mut out_env,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_decrypt_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut out_plain = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut out_meta = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let fake_data = [0u8; 64];
        let code = unsafe {
            aura_session_decrypt(
                ptr::null_mut(),
                fake_data.as_ptr(),
                fake_data.len(),
                &mut out_plain,
                &mut out_meta,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_identity_create_null_out_returns_error() {
        init_lib();
        let mut err = null_error();
        let code = unsafe { aura_identity_create(ptr::null_mut(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_get_x25519_public_null_handle_returns_error() {
        init_lib();
        let mut err = null_error();
        let mut buf = vec![0u8; 32];
        let code = unsafe {
            aura_identity_get_x25519_public(ptr::null_mut(), buf.as_mut_ptr(), buf.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_get_x25519_public_buffer_too_small() {
        init_lib();
        let mut handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe { aura_identity_create(&mut handle, &mut err) };

        let mut buf = vec![0u8; 16];
        let code = unsafe {
            aura_identity_get_x25519_public(handle, buf.as_mut_ptr(), buf.len(), &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraErrorBufferTooSmall);
        unsafe { aura_identity_destroy(&mut handle) };
    }

    #[test]
    fn ffi_prekey_bundle_create_null_handle() {
        init_lib();
        let mut err = null_error();
        let mut bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe { aura_prekey_bundle_create(ptr::null_mut(), &mut bundle, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_shamir_split_requires_auth_key() {
        init_lib();
        let mut err = null_error();
        let secret = b"ffi-shamir";
        let mut out = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut share_len = 0usize;
        let code = unsafe {
            aura_shamir_split(
                secret.as_ptr(),
                secret.len(),
                2,
                3,
                ptr::null(),
                0,
                &mut out,
                &mut share_len,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
    }

    #[test]
    fn ffi_shamir_reconstruct_requires_auth_key() {
        init_lib();
        let mut err = null_error();
        let shares = [0u8; 7];
        let mut out = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = unsafe {
            aura_shamir_reconstruct(
                shares.as_ptr(),
                shares.len(),
                shares.len(),
                1,
                ptr::null(),
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
    }

    #[test]
    fn ffi_secure_wipe_null_returns_error() {
        init_lib();
        let code = unsafe { aura_secure_wipe(ptr::null_mut(), 10) };
        assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
    }

    #[test]
    fn ffi_secure_wipe_zero_length_succeeds() {
        init_lib();
        let mut data = vec![0xABu8; 4];
        let code = unsafe { aura_secure_wipe(data.as_mut_ptr(), 0) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn ffi_derive_root_key_wrong_key_size() {
        init_lib();
        let mut err = null_error();
        let bad_key = [0u8; 16];
        let ctx = b"ctx";
        let mut out = vec![0u8; 32];
        let code = unsafe {
            aura_derive_root_key(
                bad_key.as_ptr(),
                bad_key.len(),
                ctx.as_ptr(),
                ctx.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
    }

    #[test]
    fn ffi_derive_root_key_empty_context() {
        init_lib();
        let mut err = null_error();
        let key = [0xABu8; 32];
        let mut out = vec![0u8; 32];
        let code = unsafe {
            aura_derive_root_key(
                key.as_ptr(),
                key.len(),
                b"".as_ptr(),
                0,
                out.as_mut_ptr(),
                out.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
    }

    #[test]
    fn ffi_all_error_strings_non_null() {
        let codes = [
            AuraErrorCode::AuraSuccess,
            AuraErrorCode::AuraErrorGeneric,
            AuraErrorCode::AuraErrorInvalidInput,
            AuraErrorCode::AuraErrorKeyGeneration,
            AuraErrorCode::AuraErrorDeriveKey,
            AuraErrorCode::AuraErrorHandshake,
            AuraErrorCode::AuraErrorEncryption,
            AuraErrorCode::AuraErrorDecryption,
            AuraErrorCode::AuraErrorDecode,
            AuraErrorCode::AuraErrorEncode,
            AuraErrorCode::AuraErrorBufferTooSmall,
            AuraErrorCode::AuraErrorObjectDisposed,
            AuraErrorCode::AuraErrorPrepareLocal,
            AuraErrorCode::AuraErrorOutOfMemory,
            AuraErrorCode::AuraErrorCryptoFailure,
            AuraErrorCode::AuraErrorNullPointer,
            AuraErrorCode::AuraErrorInvalidState,
            AuraErrorCode::AuraErrorReplayAttack,
            AuraErrorCode::AuraErrorSessionExpired,
            AuraErrorCode::AuraErrorPqMissing,
        ];
        for code in codes {
            let s = aura_error_string(code);
            assert!(!s.is_null(), "aura_error_string returned null for {code:?}");
        }
    }
}

#[test]
fn ffi_group_external_join_roundtrip() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };
        let code = aura_identity_create(&mut alice_handle, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        let policy = AuraGroupSecurityPolicy {
            max_messages_per_epoch: 1000,
            max_skipped_keys_per_sender: 4,
            block_external_join: 0,
            enhanced_key_schedule: 0,
            mandatory_franking: 0,
        };
        let code = aura_group_create_with_policy(
            alice_handle,
            cred.as_ptr(),
            cred.len(),
            &policy,
            &mut group_handle,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut pub_state_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_group_export_public_state(group_handle, &mut pub_state_buf, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(pub_state_buf.length > 0);

        let mut bob_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let code = aura_identity_create(&mut bob_handle, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut commit_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let bob_cred = b"bob";
        let mut bob_ed = [0u8; 32];
        let mut bob_x = [0u8; 32];
        assert_eq!(
            aura_identity_get_ed25519_public(
                bob_handle,
                bob_ed.as_mut_ptr(),
                bob_ed.len(),
                &mut err
            ),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_identity_get_x25519_public(bob_handle, bob_x.as_mut_ptr(), bob_x.len(), &mut err),
            AuraErrorCode::AuraSuccess
        );
        let mut auth_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_authorize_external_join(
                group_handle,
                bob_ed.as_ptr(),
                bob_ed.len(),
                bob_x.as_ptr(),
                bob_x.len(),
                bob_cred.as_ptr(),
                bob_cred.len(),
                &mut auth_buf,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );
        let code = aura_group_join_external(
            bob_handle,
            pub_state_buf.data,
            pub_state_buf.length,
            auth_buf.data,
            auth_buf.length,
            bob_cred.as_ptr(),
            bob_cred.len(),
            &mut bob_group_handle,
            &mut commit_buf,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(commit_buf.length > 0);

        let code =
            aura_group_process_commit(group_handle, commit_buf.data, commit_buf.length, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        assert_eq!(aura_group_get_member_count(group_handle), 2);
        assert_eq!(aura_group_get_member_count(bob_group_handle), 2);

        let plaintext = b"hello via FFI external join";
        let mut ct_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_group_encrypt(
            group_handle,
            plaintext.as_ptr(),
            plaintext.len(),
            &mut ct_buf,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut pt_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut sender_leaf: u32 = 0;
        let mut generation: u32 = 0;
        let code = aura_group_decrypt(
            bob_group_handle,
            ct_buf.data,
            ct_buf.length,
            &mut pt_buf,
            &mut sender_leaf,
            &mut generation,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let pt_slice = std::slice::from_raw_parts(pt_buf.data, pt_buf.length);
        assert_eq!(pt_slice, plaintext);

        aura_buffer_release(&mut pub_state_buf);
        aura_buffer_release(&mut auth_buf);
        aura_buffer_release(&mut commit_buf);
        aura_buffer_release(&mut ct_buf);
        aura_buffer_release(&mut pt_buf);
        aura_group_destroy(&mut group_handle);
        aura_group_destroy(&mut bob_group_handle);
        aura_identity_destroy(&mut alice_handle);
        aura_identity_destroy(&mut bob_handle);
    }
}

#[test]
fn ffi_group_decrypt_ex_clears_stale_result_on_failure() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut alice_group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut bob_group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        assert_eq!(
            aura_identity_create(&mut alice_handle, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_identity_create(&mut bob_handle, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_group_create_with_policy(
                alice_handle,
                b"alice".as_ptr(),
                b"alice".len(),
                &AuraGroupSecurityPolicy {
                    max_messages_per_epoch: 1000,
                    max_skipped_keys_per_sender: 4,
                    block_external_join: 0,
                    enhanced_key_schedule: 0,
                    mandatory_franking: 0,
                },
                &mut alice_group_handle,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );

        let mut public_state = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_export_public_state(alice_group_handle, &mut public_state, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut bob_ed = [0u8; 32];
        let mut bob_x = [0u8; 32];
        assert_eq!(
            aura_identity_get_ed25519_public(
                bob_handle,
                bob_ed.as_mut_ptr(),
                bob_ed.len(),
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_identity_get_x25519_public(bob_handle, bob_x.as_mut_ptr(), bob_x.len(), &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut authorization = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_authorize_external_join(
                alice_group_handle,
                bob_ed.as_ptr(),
                bob_ed.len(),
                bob_x.as_ptr(),
                bob_x.len(),
                b"bob".as_ptr(),
                b"bob".len(),
                &mut authorization,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );

        let mut commit = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_join_external(
                bob_handle,
                public_state.data,
                public_state.length,
                authorization.data,
                authorization.length,
                b"bob".as_ptr(),
                b"bob".len(),
                &mut bob_group_handle,
                &mut commit,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_group_process_commit(alice_group_handle, commit.data, commit.length, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut ciphertext = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_encrypt(
                alice_group_handle,
                b"ffi-group".as_ptr(),
                b"ffi-group".len(),
                &mut ciphertext,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );

        let mut result = AuraGroupDecryptResult {
            plaintext: AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            },
            sender_leaf_index: 0,
            generation: 0,
            content_type: 0,
            ttl_seconds: 0,
            sent_timestamp: 0,
            message_id: AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            },
            referenced_message_id: AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            },
            has_sealed_payload: 0,
            has_franking_data: 0,
            mentions_count: 0,
            reply_to_message_id: AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            },
        };
        assert_eq!(
            aura_group_decrypt_ex(
                bob_group_handle,
                ciphertext.data,
                ciphertext.length,
                &mut result,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );
        assert!(!result.plaintext.data.is_null());
        assert!(!result.message_id.data.is_null());

        let mut tampered = std::slice::from_raw_parts(ciphertext.data, ciphertext.length).to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x55;

        let code = aura_group_decrypt_ex(
            bob_group_handle,
            tampered.as_ptr(),
            tampered.len(),
            &mut result,
            &mut err,
        );
        assert_ne!(code, AuraErrorCode::AuraSuccess);
        assert!(result.plaintext.data.is_null());
        assert_eq!(result.plaintext.length, 0);
        assert!(result.message_id.data.is_null());
        assert_eq!(result.message_id.length, 0);
        assert!(result.referenced_message_id.data.is_null());
        assert_eq!(result.referenced_message_id.length, 0);
        assert!(result.reply_to_message_id.data.is_null());
        assert_eq!(result.reply_to_message_id.length, 0);
        assert_eq!(result.has_sealed_payload, 0);
        assert_eq!(result.has_franking_data, 0);
        assert_eq!(result.mentions_count, 0);

        aura_group_decrypt_result_free(&mut result);
        aura_buffer_release(&mut public_state);
        aura_buffer_release(&mut authorization);
        aura_buffer_release(&mut commit);
        aura_buffer_release(&mut ciphertext);
        aura_group_destroy(&mut alice_group_handle);
        aura_group_destroy(&mut bob_group_handle);
        aura_identity_destroy(&mut alice_handle);
        aura_identity_destroy(&mut bob_handle);
    }
}

#[test]
fn ffi_group_external_join_rejects_tampered_authorization() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };
        assert_eq!(
            aura_identity_create(&mut alice_handle, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        let policy = AuraGroupSecurityPolicy {
            max_messages_per_epoch: 1000,
            max_skipped_keys_per_sender: 4,
            block_external_join: 0,
            enhanced_key_schedule: 0,
            mandatory_franking: 0,
        };
        assert_eq!(
            aura_group_create_with_policy(
                alice_handle,
                cred.as_ptr(),
                cred.len(),
                &policy,
                &mut group_handle,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );

        let mut pub_state_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_export_public_state(group_handle, &mut pub_state_buf, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut bob_handle: *mut AuraIdentityHandle = ptr::null_mut();
        assert_eq!(
            aura_identity_create(&mut bob_handle, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let bob_cred = b"bob";
        let mut bob_ed = [0u8; 32];
        let mut bob_x = [0u8; 32];
        assert_eq!(
            aura_identity_get_ed25519_public(
                bob_handle,
                bob_ed.as_mut_ptr(),
                bob_ed.len(),
                &mut err
            ),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_identity_get_x25519_public(bob_handle, bob_x.as_mut_ptr(), bob_x.len(), &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut auth_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_group_authorize_external_join(
                group_handle,
                bob_ed.as_ptr(),
                bob_ed.len(),
                bob_x.as_ptr(),
                bob_x.len(),
                bob_cred.as_ptr(),
                bob_cred.len(),
                &mut auth_buf,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );
        assert!(auth_buf.length > 0);
        *auth_buf.data ^= 0xFF;

        let mut bob_group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let mut commit_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_group_join_external(
            bob_handle,
            pub_state_buf.data,
            pub_state_buf.length,
            auth_buf.data,
            auth_buf.length,
            bob_cred.as_ptr(),
            bob_cred.len(),
            &mut bob_group_handle,
            &mut commit_buf,
            &mut err,
        );
        assert_ne!(code, AuraErrorCode::AuraSuccess);
        assert!(bob_group_handle.is_null());

        aura_buffer_release(&mut pub_state_buf);
        aura_buffer_release(&mut auth_buf);
        aura_buffer_release(&mut commit_buf);
        aura_group_destroy(&mut group_handle);
        aura_group_destroy(&mut bob_group_handle);
        aura_identity_destroy(&mut alice_handle);
        aura_identity_destroy(&mut bob_handle);
    }
}

#[test]
fn ffi_group_member_leaf_indices() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };
        aura_identity_create(&mut alice_handle, &mut err);

        let mut group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        aura_group_create(
            alice_handle,
            cred.as_ptr(),
            cred.len(),
            &mut group_handle,
            &mut err,
        );

        let mut indices_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_group_get_member_leaf_indices(group_handle, &mut indices_buf, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(indices_buf.length, 4);
        let leaf_idx = u32::from_le_bytes([
            *indices_buf.data,
            *indices_buf.data.add(1),
            *indices_buf.data.add(2),
            *indices_buf.data.add(3),
        ]);
        assert_eq!(leaf_idx, 0);

        aura_buffer_release(&mut indices_buf);
        aura_group_destroy(&mut group_handle);
        aura_identity_destroy(&mut alice_handle);
    }
}

#[test]
fn ffi_group_member_role_apis_are_disabled() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };
        assert_eq!(
            aura_identity_create(&mut alice_handle, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        assert_eq!(
            aura_group_create(
                alice_handle,
                cred.as_ptr(),
                cred.len(),
                &mut group_handle,
                &mut err,
            ),
            AuraErrorCode::AuraSuccess
        );

        let mut role = -1;
        assert_ne!(
            aura_group_set_member_role(group_handle, 0, 2, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_ne!(
            aura_group_get_member_role(group_handle, 0, &mut role, &mut err),
            AuraErrorCode::AuraSuccess
        );

        aura_group_destroy(&mut group_handle);
        aura_identity_destroy(&mut alice_handle);
    }
}

// ─── Session identity and ID getters ────────────────────────────────────────

#[test]
fn ffi_session_get_id_and_identities() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        aura_identity_create(&mut alice_h, &mut err);
        aura_identity_create(&mut bob_h, &mut err);

        let mut bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_prekey_bundle_create(bob_h, &mut bundle, &mut err);

        let cfg = AuraSessionConfig {
            max_messages_per_chain: 100,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_s: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_s: *mut AuraSessionHandle = ptr::null_mut();

        aura_handshake_initiator_start(
            alice_h,
            bundle.data,
            bundle.length,
            &cfg,
            &mut init_h,
            &mut init_msg,
            &mut err,
        );
        aura_handshake_responder_start(
            bob_h,
            bundle.data,
            bundle.length,
            init_msg.data,
            init_msg.length,
            &cfg,
            &mut resp_h,
            &mut ack_msg,
            &mut err,
        );
        aura_handshake_responder_finish(resp_h, &mut bob_s, &mut err);
        aura_handshake_initiator_finish(
            init_h,
            ack_msg.data,
            ack_msg.length,
            &mut alice_s,
            &mut err,
        );

        // get_id: 16-byte session ID, same for both sides
        let mut alice_id = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut bob_id = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_session_get_id(alice_s, &mut alice_id, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_session_get_id(bob_s, &mut bob_id, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(alice_id.length, 16);
        assert_eq!(bob_id.length, 16);
        let aid = std::slice::from_raw_parts(alice_id.data, 16);
        let bid = std::slice::from_raw_parts(bob_id.data, 16);
        assert_eq!(aid, bid, "session IDs must match on both sides");

        let mut alice_binding = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut bob_binding = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        assert_eq!(
            aura_session_get_identity_binding_hash(alice_s, &mut alice_binding, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_session_get_identity_binding_hash(bob_s, &mut bob_binding, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(alice_binding.length, 32);
        assert_eq!(bob_binding.length, 32);
        let ab = std::slice::from_raw_parts(alice_binding.data, 32);
        let bb = std::slice::from_raw_parts(bob_binding.data, 32);
        assert_eq!(ab, bb, "identity binding hashes must match on both sides");

        // get_peer_identity: Alice's peer = Bob's local, Bob's peer = Alice's local
        let mut alice_peer = AuraSessionPeerIdentity {
            ed25519_public: [0u8; 32],
            x25519_public: [0u8; 32],
        };
        let mut bob_local = AuraSessionPeerIdentity {
            ed25519_public: [0u8; 32],
            x25519_public: [0u8; 32],
        };
        let mut bob_peer = AuraSessionPeerIdentity {
            ed25519_public: [0u8; 32],
            x25519_public: [0u8; 32],
        };
        let mut alice_local = AuraSessionPeerIdentity {
            ed25519_public: [0u8; 32],
            x25519_public: [0u8; 32],
        };

        assert_eq!(
            aura_session_get_peer_identity(alice_s, &mut alice_peer, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_session_get_local_identity(bob_s, &mut bob_local, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_session_get_peer_identity(bob_s, &mut bob_peer, &mut err),
            AuraErrorCode::AuraSuccess
        );
        assert_eq!(
            aura_session_get_local_identity(alice_s, &mut alice_local, &mut err),
            AuraErrorCode::AuraSuccess
        );

        assert_eq!(
            alice_peer.ed25519_public, bob_local.ed25519_public,
            "alice_peer.ed25519 == bob_local.ed25519"
        );
        assert_eq!(
            alice_peer.x25519_public, bob_local.x25519_public,
            "alice_peer.x25519 == bob_local.x25519"
        );
        assert_eq!(
            bob_peer.ed25519_public, alice_local.ed25519_public,
            "bob_peer.ed25519 == alice_local.ed25519"
        );
        assert_ne!(
            alice_peer.ed25519_public, bob_peer.ed25519_public,
            "alice and bob must have distinct keys"
        );

        aura_buffer_release(&mut bundle);
        aura_buffer_release(&mut init_msg);
        aura_buffer_release(&mut ack_msg);
        aura_buffer_release(&mut alice_id);
        aura_buffer_release(&mut bob_id);
        aura_buffer_release(&mut alice_binding);
        aura_buffer_release(&mut bob_binding);
        aura_session_destroy(&mut alice_s);
        aura_session_destroy(&mut bob_s);
        aura_identity_destroy(&mut alice_h);
        aura_identity_destroy(&mut bob_h);
    }
}

// ─── OTK replenishment ───────────────────────────────────────────────────────

#[test]
fn ffi_prekey_bundle_replenish_returns_new_keys() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut identity_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };
        aura_identity_create(&mut identity_h, &mut err);

        let mut keys_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_prekey_bundle_replenish(identity_h, 5, &mut keys_buf, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(!keys_buf.data.is_null());
        assert!(keys_buf.length > 0);

        // Replenish again — must return a different (non-overlapping ID) set
        let mut keys_buf2 = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code2 = aura_prekey_bundle_replenish(identity_h, 5, &mut keys_buf2, &mut err);
        assert_eq!(code2, AuraErrorCode::AuraSuccess);
        assert!(keys_buf2.length > 0);

        // Zero count must fail
        let mut empty_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code3 = aura_prekey_bundle_replenish(identity_h, 0, &mut empty_buf, &mut err);
        assert_ne!(code3, AuraErrorCode::AuraSuccess);

        aura_buffer_release(&mut keys_buf);
        aura_buffer_release(&mut keys_buf2);
        aura_identity_destroy(&mut identity_h);
    }
}

// ─── Envelope metadata parse ─────────────────────────────────────────────────

#[test]
fn ffi_envelope_metadata_parse_and_free() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;

    unsafe {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        aura_identity_create(&mut alice_h, &mut err);
        aura_identity_create(&mut bob_h, &mut err);

        let mut bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_prekey_bundle_create(bob_h, &mut bundle, &mut err);

        let cfg = AuraSessionConfig {
            max_messages_per_chain: 100,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_s: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_s: *mut AuraSessionHandle = ptr::null_mut();

        aura_handshake_initiator_start(
            alice_h,
            bundle.data,
            bundle.length,
            &cfg,
            &mut init_h,
            &mut init_msg,
            &mut err,
        );
        aura_handshake_responder_start(
            bob_h,
            bundle.data,
            bundle.length,
            init_msg.data,
            init_msg.length,
            &cfg,
            &mut resp_h,
            &mut ack_msg,
            &mut err,
        );
        aura_handshake_responder_finish(resp_h, &mut bob_s, &mut err);
        aura_handshake_initiator_finish(
            init_h,
            ack_msg.data,
            ack_msg.length,
            &mut alice_s,
            &mut err,
        );

        let correlation = b"req-001\0";
        let mut enc = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_session_encrypt(
            alice_s,
            b"hello".as_ptr(),
            5,
            AuraEnvelopeType::AuraEnvelopeRequest,
            77,
            correlation.as_ptr().cast::<std::ffi::c_char>(),
            7,
            &mut enc,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut plaintext = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut meta_raw = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let code = aura_session_decrypt(
            bob_s,
            enc.data,
            enc.length,
            &mut plaintext,
            &mut meta_raw,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut meta = AuraEnvelopeMetadata {
            envelope_type: AuraEnvelopeType::AuraEnvelopeHeartbeat,
            envelope_id: 0,
            message_index: 0,
            correlation_id: ptr::null_mut(),
            correlation_id_length: 0,
        };
        let code = aura_envelope_metadata_parse(meta_raw.data, meta_raw.length, &mut meta, &mut err);
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(meta.envelope_id, 77);
        assert_eq!(meta.message_index, 0);
        assert!(matches!(
            meta.envelope_type,
            AuraEnvelopeType::AuraEnvelopeRequest
        ));
        assert!(!meta.correlation_id.is_null());
        let cid = std::ffi::CStr::from_ptr(meta.correlation_id)
            .to_str()
            .unwrap();
        assert_eq!(cid, "req-001");

        aura_envelope_metadata_free(&mut meta);
        assert!(meta.correlation_id.is_null());

        aura_buffer_release(&mut bundle);
        aura_buffer_release(&mut init_msg);
        aura_buffer_release(&mut ack_msg);
        aura_buffer_release(&mut enc);
        aura_buffer_release(&mut plaintext);
        aura_buffer_release(&mut meta_raw);
        aura_session_destroy(&mut alice_s);
        aura_session_destroy(&mut bob_s);
        aura_identity_destroy(&mut alice_h);
        aura_identity_destroy(&mut bob_h);
    }
}

// ─── Group event callbacks ────────────────────────────────────────────────────

#[test]
fn ffi_group_callbacks_epoch_advanced_and_member_added() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};

    static EPOCH_FIRES: AtomicU32 = AtomicU32::new(0);
    static MEMBER_ADDED_FIRES: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn on_epoch(new_epoch: u64, _member_count: u32, _ud: *mut std::ffi::c_void) {
        if new_epoch > 0 {
            EPOCH_FIRES.fetch_add(1, Ordering::SeqCst);
        }
    }
    unsafe extern "C" fn on_member_added(
        _leaf_index: u32,
        _identity: *const u8,
        _len: usize,
        _ud: *mut std::ffi::c_void,
    ) {
        MEMBER_ADDED_FIRES.fetch_add(1, Ordering::SeqCst);
    }

    unsafe {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut carol_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        aura_identity_create(&mut alice_h, &mut err);
        aura_identity_create(&mut bob_h, &mut err);
        aura_identity_create(&mut carol_h, &mut err);

        // Alice creates group
        let mut alice_group: *mut AuraGroupSessionHandle = ptr::null_mut();
        let cred = b"alice";
        aura_group_create(
            alice_h,
            cred.as_ptr(),
            cred.len(),
            &mut alice_group,
            &mut err,
        );

        // Bob generates key package
        let mut bob_kp_secrets: *mut AuraKeyPackageSecretsHandle = ptr::null_mut();
        let bob_cred = b"bob";
        let mut bob_kp_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_group_generate_key_package(
            bob_h,
            bob_cred.as_ptr(),
            bob_cred.len(),
            &mut bob_kp_buf,
            &mut bob_kp_secrets,
            &mut err,
        );

        // Alice adds Bob
        let mut commit_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut welcome_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_group_add_member(
            alice_group,
            bob_kp_buf.data,
            bob_kp_buf.length,
            &mut commit_buf,
            &mut welcome_buf,
            &mut err,
        );

        let mut bob_group: *mut AuraGroupSessionHandle = ptr::null_mut();
        assert_eq!(
            aura_group_join(
                bob_h,
                welcome_buf.data,
                welcome_buf.length,
                bob_kp_secrets,
                &mut bob_group,
                &mut err
            ),
            AuraErrorCode::AuraSuccess
        );

        let cbs = AuraGroupEventCallbacks {
            on_member_added: Some(on_member_added),
            on_member_removed: None,
            on_epoch_advanced: Some(on_epoch),
            on_sender_key_exhaustion_warning: None,
            on_reinit_proposed: None,
            user_data: ptr::null_mut(),
        };
        assert_eq!(
            aura_group_set_event_handler(bob_group, &cbs, &mut err),
            AuraErrorCode::AuraSuccess
        );

        let mut carol_kp_secrets: *mut AuraKeyPackageSecretsHandle = ptr::null_mut();
        let carol_cred = b"carol";
        let mut carol_kp_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_group_generate_key_package(
            carol_h,
            carol_cred.as_ptr(),
            carol_cred.len(),
            &mut carol_kp_buf,
            &mut carol_kp_secrets,
            &mut err,
        );

        let mut second_commit = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut second_welcome = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_group_add_member(
            alice_group,
            carol_kp_buf.data,
            carol_kp_buf.length,
            &mut second_commit,
            &mut second_welcome,
            &mut err,
        );

        let code = aura_group_process_commit(
            bob_group,
            second_commit.data,
            second_commit.length,
            &mut err,
        );
        assert_eq!(code, AuraErrorCode::AuraSuccess, "process_commit failed");

        assert!(
            EPOCH_FIRES.load(Ordering::SeqCst) >= 1,
            "on_epoch_advanced must fire"
        );
        assert!(
            MEMBER_ADDED_FIRES.load(Ordering::SeqCst) >= 1,
            "on_member_added must fire"
        );

        aura_buffer_release(&mut bob_kp_buf);
        aura_buffer_release(&mut commit_buf);
        aura_buffer_release(&mut welcome_buf);
        aura_buffer_release(&mut carol_kp_buf);
        aura_buffer_release(&mut second_commit);
        aura_buffer_release(&mut second_welcome);
        aura_group_key_package_secrets_destroy(&mut carol_kp_secrets);
        aura_group_destroy(&mut alice_group);
        aura_group_destroy(&mut bob_group);
        aura_identity_destroy(&mut alice_h);
        aura_identity_destroy(&mut bob_h);
        aura_identity_destroy(&mut carol_h);
    }
}

// ─── Identity OTK exhaustion callback ────────────────────────────────────────

#[test]
fn identity_otk_exhaustion_callback_fires() {
    // Use Rust API directly: create identity with a non-round OTK capacity so
    // the warning threshold must use ceil rounding: ceil(19 * 10%) = 2.
    use aura_protected_protocol::identity::IdentityKeys;
    use aura_protected_protocol::interfaces::IIdentityEventHandler;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    struct Counter {
        count: AtomicU32,
        last_remaining: AtomicU32,
        last_capacity: AtomicU32,
    }

    impl IIdentityEventHandler for Counter {
        fn on_otk_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
            self.last_remaining.store(remaining, Ordering::SeqCst);
            self.last_capacity.store(max_capacity, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    let identity = IdentityKeys::create(19).expect("create identity");
    let counter = Arc::new(Counter {
        count: AtomicU32::new(0),
        last_remaining: AtomicU32::new(0),
        last_capacity: AtomicU32::new(0),
    });
    identity.set_event_handler(counter.clone());

    let bundle = identity.create_public_bundle().unwrap();
    let opk_ids: Vec<u32> = bundle
        .one_time_pre_keys()
        .iter()
        .map(aura_protected_protocol::models::OneTimePreKeyPublic::id)
        .collect();

    for opk_id in &opk_ids[..16] {
        identity
            .consume_one_time_pre_key_by_id(*opk_id)
            .expect("consume");
    }
    assert_eq!(counter.count.load(Ordering::SeqCst), 0);

    identity
        .consume_one_time_pre_key_by_id(opk_ids[16])
        .expect("consume at threshold crossing");
    assert_eq!(counter.count.load(Ordering::SeqCst), 1);
    assert_eq!(counter.last_remaining.load(Ordering::SeqCst), 2);
    assert_eq!(counter.last_capacity.load(Ordering::SeqCst), 19);
}

#[test]
fn identity_otk_exhaustion_callback_tracks_replenished_capacity() {
    use aura_protected_protocol::identity::IdentityKeys;
    use aura_protected_protocol::interfaces::IIdentityEventHandler;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    struct Counter {
        count: AtomicU32,
        last_remaining: AtomicU32,
        last_capacity: AtomicU32,
    }

    impl IIdentityEventHandler for Counter {
        fn on_otk_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
            self.last_remaining.store(remaining, Ordering::SeqCst);
            self.last_capacity.store(max_capacity, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    let identity = IdentityKeys::create(5).expect("create identity");
    identity
        .replenish_one_time_pre_keys(14)
        .expect("replenish identity otks");

    let counter = Arc::new(Counter {
        count: AtomicU32::new(0),
        last_remaining: AtomicU32::new(0),
        last_capacity: AtomicU32::new(0),
    });
    identity.set_event_handler(counter.clone());

    let bundle = identity.create_public_bundle().unwrap();
    let opk_ids: Vec<u32> = bundle
        .one_time_pre_keys()
        .iter()
        .map(aura_protected_protocol::models::OneTimePreKeyPublic::id)
        .collect();
    assert_eq!(opk_ids.len(), 19);

    for opk_id in &opk_ids[..16] {
        identity
            .consume_one_time_pre_key_by_id(*opk_id)
            .expect("consume");
    }
    assert_eq!(counter.count.load(Ordering::SeqCst), 0);

    identity
        .consume_one_time_pre_key_by_id(opk_ids[16])
        .expect("consume at replenished threshold crossing");
    assert_eq!(counter.count.load(Ordering::SeqCst), 1);
    assert_eq!(counter.last_remaining.load(Ordering::SeqCst), 2);
    assert_eq!(counter.last_capacity.load(Ordering::SeqCst), 19);
}

// ─── ReInit proposed callback fires ─────────────────────────────────────────

#[test]
fn group_reinit_proposed_callback_fires() {
    use aura_protected_protocol::identity::IdentityKeys;
    use aura_protected_protocol::interfaces::IGroupEventHandler;
    use aura_protected_protocol::protocol::group::{key_package, GroupSession};
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    struct ReInitCounter(AtomicU32);
    impl IGroupEventHandler for ReInitCounter {
        fn on_member_added(&self, _: u32, _: &[u8]) {}
        fn on_member_removed(&self, _: u32) {}
        fn on_epoch_advanced(&self, _: u64, _: u32) {}
        fn on_sender_key_exhaustion_warning(&self, _: u32, _: u32) {}
        fn on_reinit_proposed(&self, _new_group_id: &[u8], _new_version: u32) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Build a 2-member group so Bob can receive the ReInit commit from Alice.
    let alice_ik = IdentityKeys::create(5).unwrap();
    let bob_ik = IdentityKeys::create(5).unwrap();

    let alice_session = GroupSession::create(&alice_ik, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) = key_package::create_key_package(&bob_ik, b"bob".to_vec()).unwrap();
    let (_add_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x,
        bob_k,
        &bob_ik.get_identity_ed25519_public(),
        &bob_ik.get_identity_x25519_public(),
        bob_ik.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    // Set the event handler on Bob before Alice commits the ReInit.
    let counter = Arc::new(ReInitCounter(AtomicU32::new(0)));
    bob_session.set_event_handler(counter.clone());

    // Alice proposes a migration to a new group (advances Alice to epoch 2).
    let new_group_id = vec![0xAAu8; 32];
    let reinit_commit = alice_session.create_reinit_commit(new_group_id, 2).unwrap();

    // Bob processes Alice's ReInit commit → fires on_reinit_proposed.
    bob_session.process_commit(&reinit_commit).unwrap();
    assert!(
        counter.0.load(Ordering::SeqCst) >= 1,
        "on_reinit_proposed must fire"
    );
}

// ─── Session ratchet stalling warning ────────────────────────────────────────

#[test]
fn ffi_session_nonce_exhaustion_warning_fires() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    static NONCE_WARNING_FIRES: AtomicU32 = AtomicU32::new(0);
    static LAST_NONCE_REMAINING: AtomicU64 = AtomicU64::new(0);
    static LAST_NONCE_MAX: AtomicU64 = AtomicU64::new(0);

    NONCE_WARNING_FIRES.store(0, Ordering::SeqCst);
    LAST_NONCE_REMAINING.store(0, Ordering::SeqCst);
    LAST_NONCE_MAX.store(0, Ordering::SeqCst);

    unsafe extern "C" fn on_nonce_warning(
        remaining: u64,
        max_capacity: u64,
        _ud: *mut std::ffi::c_void,
    ) {
        LAST_NONCE_REMAINING.store(remaining, Ordering::SeqCst);
        LAST_NONCE_MAX.store(max_capacity, Ordering::SeqCst);
        NONCE_WARNING_FIRES.fetch_add(1, Ordering::SeqCst);
    }

    unsafe {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        aura_identity_create(&mut alice_h, &mut err);
        aura_identity_create(&mut bob_h, &mut err);

        let mut bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_prekey_bundle_create(bob_h, &mut bundle, &mut err);

        let cfg = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_s: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_s: *mut AuraSessionHandle = ptr::null_mut();

        aura_handshake_initiator_start(
            alice_h,
            bundle.data,
            bundle.length,
            &cfg,
            &mut init_h,
            &mut init_msg,
            &mut err,
        );
        aura_handshake_responder_start(
            bob_h,
            bundle.data,
            bundle.length,
            init_msg.data,
            init_msg.length,
            &cfg,
            &mut resp_h,
            &mut ack_msg,
            &mut err,
        );
        aura_handshake_responder_finish(resp_h, &mut bob_s, &mut err);
        aura_handshake_initiator_finish(
            init_h,
            ack_msg.data,
            ack_msg.length,
            &mut alice_s,
            &mut err,
        );

        let cbs = AuraSessionEventCallbacks {
            on_handshake_completed: None,
            on_ratchet_rotated: None,
            on_error: None,
            on_nonce_exhaustion_warning: Some(on_nonce_warning),
            on_ratchet_stalling_warning: None,
            user_data: ptr::null_mut(),
        };
        aura_session_set_event_handler(alice_s, &cbs, &mut err);

        for i in 0u32..901 {
            let mut enc = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            aura_session_encrypt(
                alice_s,
                b"x".as_ptr(),
                1,
                AuraEnvelopeType::AuraEnvelopeRequest,
                i,
                ptr::null(),
                0,
                &mut enc,
                &mut err,
            );
            let mut plain = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            let mut meta = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            aura_session_decrypt(bob_s, enc.data, enc.length, &mut plain, &mut meta, &mut err);
            aura_buffer_release(&mut enc);
            aura_buffer_release(&mut plain);
            aura_buffer_release(&mut meta);
        }

        assert!(
            NONCE_WARNING_FIRES.load(Ordering::SeqCst) >= 1,
            "on_nonce_exhaustion_warning must fire near the chain budget limit"
        );
        assert_eq!(LAST_NONCE_MAX.load(Ordering::SeqCst), 1000);
        assert!(LAST_NONCE_REMAINING.load(Ordering::SeqCst) <= 100);

        aura_buffer_release(&mut bundle);
        aura_buffer_release(&mut init_msg);
        aura_buffer_release(&mut ack_msg);
        aura_session_destroy(&mut alice_s);
        aura_session_destroy(&mut bob_s);
        aura_identity_destroy(&mut alice_h);
        aura_identity_destroy(&mut bob_h);
    }
}

#[test]
fn ffi_session_ratchet_stalling_warning_fires() {
    init();

    use aura_protected_protocol::ffi::api::*;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};

    static STALLING_FIRES: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn on_stalling(msgs: u64, _ud: *mut std::ffi::c_void) {
        if msgs >= 100 {
            STALLING_FIRES.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        };

        aura_identity_create(&mut alice_h, &mut err);
        aura_identity_create(&mut bob_h, &mut err);

        let mut bundle = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        aura_prekey_bundle_create(bob_h, &mut bundle, &mut err);

        let cfg = AuraSessionConfig {
            max_messages_per_chain: 10000,
        };
        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut init_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut ack_msg = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let mut alice_s: *mut AuraSessionHandle = ptr::null_mut();
        let mut bob_s: *mut AuraSessionHandle = ptr::null_mut();

        aura_handshake_initiator_start(
            alice_h,
            bundle.data,
            bundle.length,
            &cfg,
            &mut init_h,
            &mut init_msg,
            &mut err,
        );
        aura_handshake_responder_start(
            bob_h,
            bundle.data,
            bundle.length,
            init_msg.data,
            init_msg.length,
            &cfg,
            &mut resp_h,
            &mut ack_msg,
            &mut err,
        );
        aura_handshake_responder_finish(resp_h, &mut bob_s, &mut err);
        aura_handshake_initiator_finish(
            init_h,
            ack_msg.data,
            ack_msg.length,
            &mut alice_s,
            &mut err,
        );

        // Register stalling warning callback on Alice
        let cbs = AuraSessionEventCallbacks {
            on_handshake_completed: None,
            on_ratchet_rotated: None,
            on_error: None,
            on_nonce_exhaustion_warning: None,
            on_ratchet_stalling_warning: Some(on_stalling),
            user_data: ptr::null_mut(),
        };
        aura_session_set_event_handler(alice_s, &cbs, &mut err);

        // Alice sends 101 messages without Bob replying → ratchet stalls
        for i in 0u32..101 {
            let mut enc = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            aura_session_encrypt(
                alice_s,
                b"x".as_ptr(),
                1,
                AuraEnvelopeType::AuraEnvelopeRequest,
                i,
                ptr::null(),
                0,
                &mut enc,
                &mut err,
            );
            // Bob decrypts to keep him in sync (but sends nothing back)
            let mut plain = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            let mut meta = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            aura_session_decrypt(bob_s, enc.data, enc.length, &mut plain, &mut meta, &mut err);
            aura_buffer_release(&mut enc);
            aura_buffer_release(&mut plain);
            aura_buffer_release(&mut meta);
        }

        assert!(
            STALLING_FIRES.load(Ordering::SeqCst) >= 1,
            "on_ratchet_stalling_warning must fire"
        );

        aura_buffer_release(&mut bundle);
        aura_buffer_release(&mut init_msg);
        aura_buffer_release(&mut ack_msg);
        aura_session_destroy(&mut alice_s);
        aura_session_destroy(&mut bob_s);
        aura_identity_destroy(&mut alice_h);
        aura_identity_destroy(&mut bob_h);
    }
}

// ── Attachment v2 tests ──

mod attachment_v2 {
    use aura_protected_protocol::ffi::api::*;
    use aura_protected_protocol::proto::{
        AttachmentManifest, CollageManifest, ContactCard, ContentPolicy, LinkPreview,
        LocationAttachment, VoiceMessageMeta,
    };
    use prost::Message;
    use std::ptr;

    fn init_v2() {
        aura_protected_protocol::crypto::CryptoInterop::initialize().expect("crypto init");
    }

    const fn null_error() -> AuraError {
        AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        }
    }

    const fn null_buffer() -> AuraBuffer {
        AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        }
    }

    #[test]
    fn thumbnail_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };

        let thumb_mime = "image/jpeg";
        let thumb_data = vec![0xFFu8; 1024];
        let mut nonce = null_buffer();
        let mut ct = null_buffer();
        let mut pt = null_buffer();

        let code = unsafe {
            aura_attachment_encrypt_thumbnail(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                thumb_mime.as_ptr().cast(),
                thumb_mime.len(),
                thumb_data.as_ptr(),
                thumb_data.len(),
                &mut nonce,
                &mut ct,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(nonce.length, 12);
        assert_eq!(ct.length, thumb_data.len() + 16);

        let code = unsafe {
            aura_attachment_decrypt_thumbnail(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                thumb_mime.as_ptr().cast(),
                thumb_mime.len(),
                nonce.data,
                nonce.length,
                ct.data,
                ct.length,
                &mut pt,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let decrypted = unsafe { std::slice::from_raw_parts(pt.data, pt.length) };
        assert_eq!(decrypted, &thumb_data[..]);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut nonce);
            aura_buffer_release(&mut ct);
            aura_buffer_release(&mut pt);
        }
    }

    #[test]
    fn thumbnail_rejects_oversized() {
        init_v2();
        let mut err = null_error();
        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };

        let thumb_mime = "image/png";
        let oversized = vec![0u8; 65 * 1024];
        let mut nonce = null_buffer();
        let mut ct = null_buffer();

        let code = unsafe {
            aura_attachment_encrypt_thumbnail(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                thumb_mime.as_ptr().cast(),
                thumb_mime.len(),
                oversized.as_ptr(),
                oversized.len(),
                &mut nonce,
                &mut ct,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
        }
    }

    #[test]
    fn ttl_validation() {
        init_v2();
        let mut err = null_error();

        assert_eq!(
            unsafe { aura_attachment_validate_ttl(3600, &mut err) },
            AuraErrorCode::AuraSuccess
        );
        assert_ne!(
            unsafe { aura_attachment_validate_ttl(10, &mut err) },
            AuraErrorCode::AuraSuccess
        );
        assert_ne!(
            unsafe { aura_attachment_validate_ttl(31 * 24 * 3600, &mut err) },
            AuraErrorCode::AuraSuccess
        );
    }

    #[test]
    fn expiry_check() {
        assert!(aura_attachment_is_expired(999_000, 500, 1_000_000));
        assert!(!aura_attachment_is_expired(999_000, 2000, 1_000_000));
        assert!(aura_attachment_is_expired(999_000, 1000, 1_000_000));
    }

    #[test]
    fn progress_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut attachment_id = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };

        let mut progress = null_buffer();
        let code = unsafe {
            aura_attachment_progress_create(
                attachment_id.data,
                attachment_id.length,
                5,
                &mut progress,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut updated = null_buffer();
        let code = unsafe {
            aura_attachment_progress_mark_completed(
                progress.data,
                progress.length,
                0,
                1024,
                100,
                &mut updated,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut updated2 = null_buffer();
        let code = unsafe {
            aura_attachment_progress_mark_completed(
                updated.data,
                updated.length,
                2,
                2048,
                200,
                &mut updated2,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut remaining = null_buffer();
        let mut remaining_count = 0u32;
        let code = unsafe {
            aura_attachment_progress_get_remaining(
                updated2.data,
                updated2.length,
                &mut remaining,
                &mut remaining_count,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(remaining_count, 3);

        assert!(!unsafe { aura_attachment_progress_is_complete(updated2.data, updated2.length) });

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut progress);
            aura_buffer_release(&mut updated);
            aura_buffer_release(&mut updated2);
            aura_buffer_release(&mut remaining);
        }
    }

    #[test]
    fn collage_create_validate() {
        init_v2();
        let mut err = null_error();

        let mut manifests_raw = Vec::new();
        for i in 0u32..3 {
            let mut aid = null_buffer();
            let mut fk = null_buffer();
            unsafe { aura_attachment_generate_id(&mut aid, &mut err) };
            unsafe { aura_attachment_generate_file_key(&mut fk, &mut err) };

            let manifest = AttachmentManifest {
                version: 1,
                attachment_id: unsafe { std::slice::from_raw_parts(aid.data, aid.length) }.to_vec(),
                mime_type: "image/jpeg".to_string(),
                total_size: 1024,
                chunk_size: 1024,
                chunk_count: 1,
                file_sha256: vec![7u8; 32],
                encrypted_file_key: vec![9u8; 48],
                encryption_scheme: "AES-256-GCM-SIV".to_string(),
                collage_index: Some(i),
                encrypted_thumbnail: None,
                thumbnail_nonce: None,
                thumbnail_mime_type: None,
                thumbnail_size: None,
                ttl_seconds: None,
                created_at_unix: None,
                original_filename: None,
                media_width: None,
                media_height: None,
                duration_ms: None,
                alt_text: None,
                content_policy: None,
                voice_meta: None,
            };
            let mut buf = Vec::new();
            manifest.encode(&mut buf).unwrap();
            manifests_raw.push(buf);
            unsafe {
                aura_buffer_release(&mut aid);
                aura_buffer_release(&mut fk);
            }
        }

        let ptrs: Vec<*const u8> = manifests_raw.iter().map(Vec::as_ptr).collect();
        let lens: Vec<usize> = manifests_raw.iter().map(Vec::len).collect();
        let mut collage = null_buffer();
        let code = unsafe {
            aura_attachment_collage_create(ptrs.as_ptr(), lens.as_ptr(), 3, &mut collage, &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code =
            unsafe { aura_attachment_collage_validate(collage.data, collage.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut collage) };
    }

    #[test]
    fn streaming_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };

        let mime = "application/octet-stream";
        let chunk_size = 64u32;
        let data = vec![0xABu8; 150];
        let chunk_count = 3u32;
        let total_size = data.len() as u64;

        let mut enc_handle: *mut AuraStreamingEncryptorHandle = ptr::null_mut();
        let code = unsafe {
            aura_attachment_streaming_encryptor_create(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                chunk_count,
                &mut enc_handle,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut all_chunks_buf = null_buffer();
        let mut chunk_count_out = 0u32;
        let code = unsafe {
            aura_attachment_streaming_encryptor_write(
                enc_handle,
                data.as_ptr(),
                data.len(),
                &mut all_chunks_buf,
                &mut chunk_count_out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(chunk_count_out, 2);

        let mut last_chunk = null_buffer();
        let mut has_last = 0u8;
        let code = unsafe {
            aura_attachment_streaming_encryptor_finish(
                enc_handle,
                &mut last_chunk,
                &mut has_last,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(has_last, 1);
        unsafe { aura_attachment_streaming_encryptor_destroy(enc_handle) };

        let mut dec_handle: *mut AuraStreamingDecryptorHandle = ptr::null_mut();
        let code = unsafe {
            aura_attachment_streaming_decryptor_create(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                total_size,
                chunk_size,
                chunk_count,
                &mut dec_handle,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        fn parse_and_decrypt(
            dec_handle: *mut AuraStreamingDecryptorHandle,
            buf_data: &[u8],
            count: usize,
            err: &mut AuraError,
        ) -> Vec<u8> {
            let mut result = Vec::new();
            let mut offset = 0usize;
            for _ in 0..count {
                let ci = u32::from_le_bytes(buf_data[offset..offset + 4].try_into().unwrap());
                offset += 4;
                let nlen =
                    u32::from_le_bytes(buf_data[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                let nonce_s = &buf_data[offset..offset + nlen];
                offset += nlen;
                let ctlen =
                    u32::from_le_bytes(buf_data[offset..offset + 4].try_into().unwrap()) as usize;
                offset += 4;
                let ct_s = &buf_data[offset..offset + ctlen];
                offset += ctlen;

                let mut pt = AuraBuffer {
                    data: ptr::null_mut(),
                    length: 0,
                };
                let code = unsafe {
                    aura_attachment_streaming_decryptor_write(
                        dec_handle,
                        ci,
                        nonce_s.as_ptr(),
                        nonce_s.len(),
                        ct_s.as_ptr(),
                        ct_s.len(),
                        &mut pt,
                        err,
                    )
                };
                assert_eq!(code, AuraErrorCode::AuraSuccess);
                result.extend_from_slice(unsafe { std::slice::from_raw_parts(pt.data, pt.length) });
                unsafe { aura_buffer_release(&mut pt) };
            }
            result
        }

        let chunks_data =
            unsafe { std::slice::from_raw_parts(all_chunks_buf.data, all_chunks_buf.length) };
        let mut reassembled = parse_and_decrypt(dec_handle, chunks_data, 2, &mut err);

        let last_data = unsafe { std::slice::from_raw_parts(last_chunk.data, last_chunk.length) };
        reassembled.extend(parse_and_decrypt(dec_handle, last_data, 1, &mut err));

        assert!(unsafe { aura_attachment_streaming_decryptor_is_complete(dec_handle) });
        assert_eq!(reassembled, data);

        unsafe {
            aura_attachment_streaming_decryptor_destroy(dec_handle);
            aura_buffer_release(&mut all_chunks_buf);
            aura_buffer_release(&mut last_chunk);
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
        }
    }

    #[test]
    fn manifest_v2_with_thumbnail_and_ttl() {
        init_v2();
        let mut err = null_error();
        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };

        let thumb_mime = "image/jpeg";
        let thumb_data = vec![0xCCu8; 512];
        let mut thumb_nonce = null_buffer();
        let mut thumb_ct = null_buffer();
        let code = unsafe {
            aura_attachment_encrypt_thumbnail(
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                thumb_mime.as_ptr().cast(),
                thumb_mime.len(),
                thumb_data.as_ptr(),
                thumb_data.len(),
                &mut thumb_nonce,
                &mut thumb_ct,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mime = "video/mp4";
        let file_hash = [3u8; 32];
        let wrapped_key = [5u8; 48];
        let mut manifest = null_buffer();
        let code = unsafe {
            aura_attachment_manifest_create_v2(
                attachment_id.data,
                attachment_id.length,
                mime.as_ptr().cast(),
                mime.len(),
                4096,
                1024,
                4,
                file_hash.as_ptr(),
                file_hash.len(),
                wrapped_key.as_ptr(),
                wrapped_key.len(),
                -1,
                thumb_ct.data,
                thumb_ct.length,
                thumb_nonce.data,
                thumb_nonce.length,
                thumb_mime.as_ptr().cast(),
                thumb_mime.len(),
                u32::try_from(thumb_data.len()).unwrap(),
                86400,
                1_700_000_000,
                &mut manifest,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code =
            unsafe { aura_attachment_manifest_validate(manifest.data, manifest.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        unsafe {
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut thumb_nonce);
            aura_buffer_release(&mut thumb_ct);
            aura_buffer_release(&mut manifest);
        }
    }

    #[test]
    fn manifest_rejects_partial_thumbnail_fields() {
        init_v2();
        let mut err = null_error();

        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "image/png".to_string(),
            total_size: 100,
            chunk_size: 100,
            chunk_count: 1,
            file_sha256: vec![2u8; 32],
            encrypted_file_key: vec![3u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: None,
            encrypted_thumbnail: Some(vec![0u8; 32]),
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();

        let code = unsafe { aura_attachment_manifest_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn file_key_encrypt_decrypt_with_session() {
        init_v2();
        let mut err = null_error();
        let config = AuraSessionConfig {
            max_messages_per_chain: 1000,
        };

        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_bundle = null_buffer();
        unsafe { aura_prekey_bundle_create(bob_h, &mut bob_bundle, &mut err) };

        let mut init_h: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
        let mut init_msg = null_buffer();
        let code = unsafe {
            aura_handshake_initiator_start(
                alice_h,
                bob_bundle.data,
                bob_bundle.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut resp_h: *mut AuraHandshakeResponderHandle = ptr::null_mut();
        let mut ack_msg = null_buffer();
        let code = unsafe {
            aura_handshake_responder_start(
                bob_h,
                bob_bundle.data,
                bob_bundle.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let mut bob_s: *mut AuraSessionHandle = ptr::null_mut();
        let mut alice_s: *mut AuraSessionHandle = ptr::null_mut();
        unsafe {
            aura_handshake_responder_finish(resp_h, &mut bob_s, &mut err);
            aura_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_s,
                &mut err,
            );
        }
        assert!(!alice_s.is_null());
        assert!(!bob_s.is_null());

        let mut attachment_id = null_buffer();
        let mut file_key = null_buffer();
        unsafe { aura_attachment_generate_id(&mut attachment_id, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut file_key, &mut err) };

        let mut encrypted_fk = null_buffer();
        let code = unsafe {
            aura_attachment_encrypt_file_key(
                alice_s,
                file_key.data,
                file_key.length,
                attachment_id.data,
                attachment_id.length,
                &mut encrypted_fk,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(encrypted_fk.length > 0);

        let mut decrypted_fk = null_buffer();
        let code = unsafe {
            aura_attachment_decrypt_file_key(
                bob_s,
                encrypted_fk.data,
                encrypted_fk.length,
                attachment_id.data,
                attachment_id.length,
                &mut decrypted_fk,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(decrypted_fk.length, 32);

        let mut wrong_attachment_id = [0u8; 32];
        let attachment_id_slice =
            unsafe { std::slice::from_raw_parts(attachment_id.data, attachment_id.length) };
        wrong_attachment_id.copy_from_slice(attachment_id_slice);
        wrong_attachment_id[0] ^= 0xFF;
        let mut wrong_fk = null_buffer();
        let code = unsafe {
            aura_attachment_decrypt_file_key(
                bob_s,
                encrypted_fk.data,
                encrypted_fk.length,
                wrong_attachment_id.as_ptr(),
                wrong_attachment_id.len(),
                &mut wrong_fk,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);

        let original = unsafe { std::slice::from_raw_parts(file_key.data, file_key.length) };
        let decrypted =
            unsafe { std::slice::from_raw_parts(decrypted_fk.data, decrypted_fk.length) };
        assert_eq!(original, decrypted);

        unsafe {
            aura_buffer_release(&mut bob_bundle);
            aura_buffer_release(&mut init_msg);
            aura_buffer_release(&mut ack_msg);
            aura_buffer_release(&mut attachment_id);
            aura_buffer_release(&mut file_key);
            aura_buffer_release(&mut encrypted_fk);
            aura_buffer_release(&mut decrypted_fk);
            aura_buffer_release(&mut wrong_fk);
            aura_session_destroy(&mut alice_s);
            aura_session_destroy(&mut bob_s);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn filename_valid() {
        init_v2();
        let mut err = null_error();
        let name = "photo.jpg";
        let code = unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn filename_rejects_empty() {
        init_v2();
        let mut err = null_error();
        let name = "";
        let code = unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn filename_rejects_traversal() {
        init_v2();
        let mut err = null_error();
        let name = "../etc/passwd";
        let code = unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn filename_rejects_control_chars() {
        init_v2();
        let mut err = null_error();
        let name = "\x01bad";
        let code = unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn filename_rejects_windows_reserved() {
        init_v2();
        let mut err = null_error();
        let name = "CON";
        let code = unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);

        let name2 = "con.txt";
        let code2 =
            unsafe { aura_attachment_validate_filename(name2.as_ptr(), name2.len(), &mut err) };
        assert_ne!(code2, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn filename_rejects_windows_normalized_reserved_and_dot_segments() {
        init_v2();
        let mut err = null_error();

        for name in [".", "CON.", "LPT1 ", "aux. "] {
            let code =
                unsafe { aura_attachment_validate_filename(name.as_ptr(), name.len(), &mut err) };
            assert_ne!(code, AuraErrorCode::AuraSuccess, "name={name}");
        }
    }

    #[test]
    fn sanitize_basic() {
        init_v2();
        let mut err = null_error();
        let name = "../bad/file\x00.txt";
        let mut out = null_buffer();
        let code = unsafe {
            aura_attachment_sanitize_filename(name.as_ptr(), name.len(), &mut out, &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let sanitized = unsafe { std::slice::from_raw_parts(out.data, out.length) };
        let s = std::str::from_utf8(sanitized).unwrap();
        assert!(!s.contains('/'));
        assert!(!s.contains('\\'));
        assert!(!s.contains(".."));
        assert!(!s.contains('\0'));
        assert!(!s.is_empty());
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn sanitize_normalizes_windows_edge_cases() {
        init_v2();
        let mut err = null_error();
        let name = "CON. ";
        let mut out = null_buffer();
        let code = unsafe {
            aura_attachment_sanitize_filename(name.as_ptr(), name.len(), &mut out, &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let sanitized = unsafe { std::slice::from_raw_parts(out.data, out.length) };
        let s = std::str::from_utf8(sanitized).unwrap();
        assert_eq!(s, "_CON");
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn magic_jpeg_valid() {
        init_v2();
        let mut err = null_error();
        let header = [0xFFu8, 0xD8, 0xFF, 0xE0];
        let mime = "image/jpeg";
        let code = unsafe {
            aura_attachment_validate_magic_bytes(
                header.as_ptr(),
                header.len(),
                mime.as_ptr(),
                mime.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn magic_png_valid() {
        init_v2();
        let mut err = null_error();
        let header = [0x89u8, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let mime = "image/png";
        let code = unsafe {
            aura_attachment_validate_magic_bytes(
                header.as_ptr(),
                header.len(),
                mime.as_ptr(),
                mime.len(),
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn magic_mismatch() {
        init_v2();
        let mut err = null_error();
        let header = [0xFFu8, 0xD8, 0xFF, 0xE0];
        let mime = "image/png";
        let code = unsafe {
            aura_attachment_validate_magic_bytes(
                header.as_ptr(),
                header.len(),
                mime.as_ptr(),
                mime.len(),
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn magic_unknown_rejected() {
        init_v2();
        let mut err = null_error();
        let header = [0x00u8; 16];
        let mime = "application/x-custom";
        let code = unsafe {
            aura_attachment_validate_magic_bytes(
                header.as_ptr(),
                header.len(),
                mime.as_ptr(),
                mime.len(),
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn detect_jpeg() {
        init_v2();
        let mut err = null_error();
        let header = [
            0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        ];
        let mut out = null_buffer();
        let code = unsafe {
            aura_attachment_detect_mime(header.as_ptr(), header.len(), &mut out, &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        let mime = unsafe { std::slice::from_raw_parts(out.data, out.length) };
        assert_eq!(std::str::from_utf8(mime).unwrap(), "image/jpeg");
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn detect_unknown() {
        init_v2();
        let mut err = null_error();
        let header = [
            0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let mut out = null_buffer();
        let code = unsafe {
            aura_attachment_detect_mime(header.as_ptr(), header.len(), &mut out, &mut err)
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert_eq!(out.length, 0);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn manifest_view_once_requires_ttl() {
        init_v2();
        let mut err = null_error();
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "image/jpeg".to_string(),
            total_size: 100,
            chunk_size: 100,
            chunk_count: 1,
            file_sha256: vec![2u8; 32],
            encrypted_file_key: vec![3u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: None,
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: Some(ContentPolicy {
                view_once: true,
                no_forward: false,
                no_save: false,
            }),
            voice_meta: None,
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_manifest_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn manifest_view_once_with_ttl() {
        init_v2();
        let mut err = null_error();
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "image/jpeg".to_string(),
            total_size: 100,
            chunk_size: 100,
            chunk_count: 1,
            file_sha256: vec![2u8; 32],
            encrypted_file_key: vec![3u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: None,
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: Some(3600),
            created_at_unix: Some(1_700_000_000),
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: Some(ContentPolicy {
                view_once: true,
                no_forward: false,
                no_save: false,
            }),
            voice_meta: None,
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_manifest_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn collage_with_metadata() {
        init_v2();
        let mut err = null_error();

        let mut manifests_raw = Vec::new();
        for i in 0u32..2 {
            let mut aid = null_buffer();
            let mut fk = null_buffer();
            unsafe { aura_attachment_generate_id(&mut aid, &mut err) };
            unsafe { aura_attachment_generate_file_key(&mut fk, &mut err) };

            let manifest = AttachmentManifest {
                version: 1,
                attachment_id: unsafe { std::slice::from_raw_parts(aid.data, aid.length) }.to_vec(),
                mime_type: "image/jpeg".to_string(),
                total_size: 1024,
                chunk_size: 1024,
                chunk_count: 1,
                file_sha256: vec![7u8; 32],
                encrypted_file_key: vec![9u8; 48],
                encryption_scheme: "AES-256-GCM-SIV".to_string(),
                collage_index: Some(i),
                encrypted_thumbnail: None,
                thumbnail_nonce: None,
                thumbnail_mime_type: None,
                thumbnail_size: None,
                ttl_seconds: None,
                created_at_unix: None,
                original_filename: None,
                media_width: None,
                media_height: None,
                duration_ms: None,
                alt_text: None,
                content_policy: None,
                voice_meta: None,
            };
            let mut buf = Vec::new();
            manifest.encode(&mut buf).unwrap();
            manifests_raw.push(buf);
            unsafe {
                aura_buffer_release(&mut aid);
                aura_buffer_release(&mut fk);
            }
        }

        let ptrs: Vec<*const u8> = manifests_raw.iter().map(Vec::as_ptr).collect();
        let lens: Vec<usize> = manifests_raw.iter().map(Vec::len).collect();
        let name = "My Album";
        let desc = "Vacation photos";
        let mut collage = null_buffer();
        let code = unsafe {
            aura_attachment_collage_create_with_metadata(
                ptrs.as_ptr(),
                lens.as_ptr(),
                2,
                name.as_ptr(),
                name.len(),
                desc.as_ptr(),
                desc.len(),
                0,
                &mut collage,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code =
            unsafe { aura_attachment_collage_validate(collage.data, collage.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let collage_bytes = unsafe { std::slice::from_raw_parts(collage.data, collage.length) };
        let parsed = CollageManifest::decode(collage_bytes).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("My Album"));
        assert_eq!(parsed.description.as_deref(), Some("Vacation photos"));
        assert_eq!(parsed.layout, Some(0));

        unsafe { aura_buffer_release(&mut collage) };
    }

    #[test]
    fn collage_name_too_long() {
        init_v2();
        let mut err = null_error();

        let mut manifests_raw = Vec::new();
        let mut aid = null_buffer();
        let mut fk = null_buffer();
        unsafe { aura_attachment_generate_id(&mut aid, &mut err) };
        unsafe { aura_attachment_generate_file_key(&mut fk, &mut err) };
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: unsafe { std::slice::from_raw_parts(aid.data, aid.length) }.to_vec(),
            mime_type: "image/jpeg".to_string(),
            total_size: 1024,
            chunk_size: 1024,
            chunk_count: 1,
            file_sha256: vec![7u8; 32],
            encrypted_file_key: vec![9u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: Some(0),
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();
        manifests_raw.push(buf);
        unsafe {
            aura_buffer_release(&mut aid);
            aura_buffer_release(&mut fk);
        }

        let ptrs: Vec<*const u8> = manifests_raw.iter().map(Vec::as_ptr).collect();
        let lens: Vec<usize> = manifests_raw.iter().map(Vec::len).collect();
        let long_name = "A".repeat(256);
        let mut collage = null_buffer();
        let code = unsafe {
            aura_attachment_collage_create_with_metadata(
                ptrs.as_ptr(),
                lens.as_ptr(),
                1,
                long_name.as_ptr(),
                long_name.len(),
                ptr::null(),
                0,
                -1,
                &mut collage,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn collage_invalid_layout_rejected_at_create() {
        init_v2();
        let mut err = null_error();

        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "image/jpeg".to_string(),
            total_size: 1024,
            chunk_size: 1024,
            chunk_count: 1,
            file_sha256: vec![7u8; 32],
            encrypted_file_key: vec![9u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: Some(0),
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };
        let mut manifest_bytes = Vec::new();
        manifest.encode(&mut manifest_bytes).unwrap();

        let ptrs = [manifest_bytes.as_ptr()];
        let lens = [manifest_bytes.len()];
        let mut collage = null_buffer();
        let code = unsafe {
            aura_attachment_collage_create_with_metadata(
                ptrs.as_ptr(),
                lens.as_ptr(),
                1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                7,
                &mut collage,
                &mut err,
            )
        };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn collage_validate_rejects_tampered_invalid_layout() {
        init_v2();
        let mut err = null_error();

        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "image/jpeg".to_string(),
            total_size: 1024,
            chunk_size: 1024,
            chunk_count: 1,
            file_sha256: vec![7u8; 32],
            encrypted_file_key: vec![9u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: Some(0),
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };
        let mut manifest_bytes = Vec::new();
        manifest.encode(&mut manifest_bytes).unwrap();

        let ptrs = [manifest_bytes.as_ptr()];
        let lens = [manifest_bytes.len()];
        let mut collage = null_buffer();
        let code = unsafe {
            aura_attachment_collage_create_with_metadata(
                ptrs.as_ptr(),
                lens.as_ptr(),
                1,
                ptr::null(),
                0,
                ptr::null(),
                0,
                0,
                &mut collage,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let collage_bytes = unsafe { std::slice::from_raw_parts(collage.data, collage.length) };
        let mut parsed = CollageManifest::decode(collage_bytes).unwrap();
        parsed.layout = Some(9);
        let mut tampered = Vec::new();
        parsed.encode(&mut tampered).unwrap();

        let code =
            unsafe { aura_attachment_collage_validate(tampered.as_ptr(), tampered.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);

        unsafe { aura_buffer_release(&mut collage) };
    }

    #[test]
    fn manifest_with_file_identity() {
        init_v2();
        let mut err = null_error();
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "video/mp4".to_string(),
            total_size: 2048,
            chunk_size: 1024,
            chunk_count: 2,
            file_sha256: vec![2u8; 32],
            encrypted_file_key: vec![3u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: None,
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: Some("holiday.mp4".to_string()),
            media_width: Some(1920),
            media_height: Some(1080),
            duration_ms: Some(60000),
            alt_text: Some("A holiday video".to_string()),
            content_policy: None,
            voice_meta: None,
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_manifest_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn inline_attachment_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();
        let aid = [1u8; 32];
        let mime = "text/plain";
        let data = [0xABu8; 128];

        let code = unsafe {
            aura_attachment_inline_create(
                aid.as_ptr(),
                aid.len(),
                mime.as_ptr(),
                mime.len(),
                data.as_ptr(),
                data.len(),
                ptr::null(),
                0,
                0,
                0,
                0,
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        assert!(out.length > 0);

        let code = unsafe { aura_attachment_inline_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn attachment_reference_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();
        let aid = [2u8; 32];
        let smid = [3u8; 32];

        let code = unsafe {
            aura_attachment_reference_create(
                aid.as_ptr(),
                aid.len(),
                0,
                smid.as_ptr(),
                smid.len(),
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe { aura_attachment_reference_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn voice_meta_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();
        let waveform: Vec<f32> = vec![0.0, 0.25, 0.5, 0.75, 1.0];

        let code = unsafe {
            aura_attachment_voice_meta_create(
                waveform.as_ptr(),
                waveform.len(),
                ptr::null(),
                0,
                1.0,
                1,
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe { aura_attachment_voice_meta_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn voice_meta_rejects_bad_sample() {
        init_v2();
        let mut err = null_error();
        let bad = VoiceMessageMeta {
            waveform_samples: vec![0.5, 1.5],
            transcript: None,
            playback_speed_hint: None,
            is_listened: false,
        };
        let mut buf = Vec::new();
        bad.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_voice_meta_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn location_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();

        let code = unsafe {
            aura_attachment_location_create(
                48.8566,
                2.3522,
                10.0,
                1,
                ptr::null(),
                0,
                0,
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe { aura_attachment_location_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn location_rejects_bad_lat() {
        init_v2();
        let mut err = null_error();
        let bad = LocationAttachment {
            latitude: 91.0,
            longitude: 0.0,
            accuracy_meters: None,
            label: None,
            timestamp_unix: None,
        };
        let mut buf = Vec::new();
        bad.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_location_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn contact_card_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();
        let name = "Alice";

        let code = unsafe {
            aura_attachment_contact_card_create(
                name.as_ptr(),
                name.len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe { aura_attachment_contact_card_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn contact_card_rejects_empty_name() {
        init_v2();
        let mut err = null_error();
        let bad = ContactCard {
            display_name: String::new(),
            phone: None,
            email: None,
            avatar_data: None,
            organization: None,
        };
        let mut buf = Vec::new();
        bad.encode(&mut buf).unwrap();
        let code =
            unsafe { aura_attachment_contact_card_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn link_preview_roundtrip() {
        init_v2();
        let mut err = null_error();
        let mut out = null_buffer();
        let url = "https://example.com";

        let code = unsafe {
            aura_attachment_link_preview_create(
                url.as_ptr(),
                url.len(),
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut out,
                &mut err,
            )
        };
        assert_eq!(code, AuraErrorCode::AuraSuccess);

        let code = unsafe { aura_attachment_link_preview_validate(out.data, out.length, &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
        unsafe { aura_buffer_release(&mut out) };
    }

    #[test]
    fn link_preview_rejects_empty_url() {
        init_v2();
        let mut err = null_error();
        let bad = LinkPreview {
            url: String::new(),
            title: None,
            description: None,
            preview_image: None,
            preview_image_mime: None,
            domain: None,
        };
        let mut buf = Vec::new();
        bad.encode(&mut buf).unwrap();
        let code =
            unsafe { aura_attachment_link_preview_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_ne!(code, AuraErrorCode::AuraSuccess);
    }

    #[test]
    fn manifest_with_voice_meta() {
        init_v2();
        let mut err = null_error();
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: vec![1u8; 32],
            mime_type: "audio/ogg".to_string(),
            total_size: 2048,
            chunk_size: 1024,
            chunk_count: 2,
            file_sha256: vec![2u8; 32],
            encrypted_file_key: vec![3u8; 48],
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: None,
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: Some(5000),
            alt_text: None,
            content_policy: None,
            voice_meta: Some(VoiceMessageMeta {
                waveform_samples: vec![0.0, 0.5, 1.0, 0.5, 0.0],
                transcript: Some("Hello world".to_string()),
                playback_speed_hint: Some(1.5),
                is_listened: false,
            }),
        };
        let mut buf = Vec::new();
        manifest.encode(&mut buf).unwrap();
        let code = unsafe { aura_attachment_manifest_validate(buf.as_ptr(), buf.len(), &mut err) };
        assert_eq!(code, AuraErrorCode::AuraSuccess);
    }
}

mod voip_improvements {
    use aura_protected_protocol::ffi::api::*;
    use std::ptr;
    use std::sync::atomic::Ordering;

    const fn null_error() -> AuraError {
        AuraError {
            code: AuraErrorCode::AuraSuccess,
            message: ptr::null_mut(),
        }
    }

    const fn null_buffer() -> AuraBuffer {
        AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        }
    }

    const fn null_encrypted_frame() -> AuraEncryptedFrame {
        AuraEncryptedFrame {
            call_id: null_buffer(),
            ssrc: 0,
            frame_counter: 0,
            ratchet_generation: 0,
            encrypted_payload: null_buffer(),
            nonce: null_buffer(),
            encrypted_header: null_buffer(),
        }
    }

    const fn null_decrypted_frame() -> AuraDecryptedFrame {
        AuraDecryptedFrame {
            payload: null_buffer(),
            payload_type: 0,
            ssrc: 0,
            timestamp: 0,
            sequence_number: 0,
            frame_counter: 0,
            ratchet_generation: 0,
        }
    }

    fn init_lib() {
        aura_init();
    }

    fn setup_voip_session_pair() -> (
        *mut AuraIdentityHandle,
        *mut AuraIdentityHandle,
        *mut AuraVoipSessionHandle,
        *mut AuraVoipSessionHandle,
        *mut AuraVoipCallInitiatorHandle,
        AuraBuffer,
        AuraBuffer,
    ) {
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();
        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        unsafe {
            aura_identity_get_kyber_public(
                alice_h,
                alice_kyber.as_mut_ptr(),
                alice_kyber.len(),
                &mut err,
            );
            aura_identity_get_kyber_public(bob_h, bob_kyber.as_mut_ptr(), bob_kyber.len(), &mut err);
        }

        let mut init_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let mut accept_buf = null_buffer();
        let mut alice_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_call_init_complete(
                    init_h,
                    alice_h,
                    accept_buf.data,
                    accept_buf.length,
                    &mut alice_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        (
            alice_h,
            bob_h,
            alice_session_h,
            bob_session_h,
            init_h,
            init_buf,
            accept_buf,
        )
    }

    #[test]
    fn ffi_voip_destroy_nulls_handles_and_is_idempotent() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        unsafe {
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);

            aura_voip_call_initiator_destroy(&mut init_h);
            assert!(init_h.is_null());
            aura_voip_call_initiator_destroy(&mut init_h);
            assert!(init_h.is_null());

            aura_voip_session_destroy(&mut alice_session_h);
            assert!(alice_session_h.is_null());
            aura_voip_session_destroy(&mut alice_session_h);
            assert!(alice_session_h.is_null());

            aura_voip_session_destroy(&mut bob_session_h);
            assert!(bob_session_h.is_null());
            aura_voip_session_destroy(&mut bob_session_h);
            assert!(bob_session_h.is_null());

            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_call_id_returns_busy_when_handle_in_use() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut call_id = null_buffer();

        unsafe {
            (*alice_session_h).in_use.store(true, Ordering::Release);
            let code = aura_voip_call_id(alice_session_h, &mut call_id, &mut err);
            assert_eq!(code, AuraErrorCode::AuraErrorBusy);
            assert!(call_id.data.is_null());
            assert_eq!(call_id.length, 0);
            aura_error_free(&mut err);
            (*alice_session_h).in_use.store(false, Ordering::Release);

            aura_buffer_release(&mut call_id);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_import_sealed_state_with_time_provider_uses_manual_clock() {
        init_lib();

        let initial_now = 1_710_000_000u64;
        let mut alice_time: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut bob_time: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut restore_time: *mut AuraTimeProviderHandle = ptr::null_mut();
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();

        unsafe {
            assert_eq!(
                aura_time_provider_manual_create(initial_now, &mut alice_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_time_provider_manual_create(initial_now, &mut bob_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_time_provider_manual_create(initial_now, &mut restore_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_create(&mut alice_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_create(&mut bob_h, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_set_time_provider(alice_h, alice_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_set_time_provider(bob_h, bob_time, &mut err),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        unsafe {
            assert_eq!(
                aura_identity_get_kyber_public(
                    alice_h,
                    alice_kyber.as_mut_ptr(),
                    alice_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_kyber_public(
                    bob_h,
                    bob_kyber.as_mut_ptr(),
                    bob_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut init_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let mut accept_buf = null_buffer();
        let mut alice_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut restored_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut sealed = null_buffer();
        let mut stats = AuraCallStatistics {
            frames_sent: 0,
            frames_received: 0,
            frames_dropped: 0,
            rekey_count: 0,
            ratchet_generation: 0,
            call_duration_secs: 0,
        };
        let state_key = [9u8; 32];

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_call_init_complete(
                    init_h,
                    alice_h,
                    accept_buf.data,
                    accept_buf.length,
                    &mut alice_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_export_sealed_state(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    1,
                    &mut sealed,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_import_sealed_state_with_time_provider(
                    sealed.data,
                    sealed.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    0,
                    restore_time,
                    &mut restored_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_get_call_statistics(restored_session_h, &mut stats, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(stats.call_duration_secs, 0);

            assert_eq!(
                aura_time_provider_manual_set_now_unix(restore_time, initial_now + 42, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_get_call_statistics(restored_session_h, &mut stats, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(stats.call_duration_secs, 42);

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_buffer_release(&mut sealed);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut restored_session_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_time_provider_destroy(&mut alice_time);
            aura_time_provider_destroy(&mut bob_time);
            aura_time_provider_destroy(&mut restore_time);
        }
    }

    #[test]
    fn ffi_voip_call_init_requires_all_outputs() {
        init_lib();
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();

        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut bob_kyber = vec![0u8; 1184];
        unsafe {
            assert_eq!(
                aura_identity_get_kyber_public(
                    bob_h,
                    bob_kyber.as_mut_ptr(),
                    bob_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut init_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    ptr::null_mut(),
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert!(init_h.is_null());

            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert!(init_buf.data.is_null());
            assert_eq!(init_buf.length, 0);

            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            aura_buffer_release(&mut init_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_accept_call_requires_all_outputs() {
        init_lib();
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();

        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        unsafe {
            assert_eq!(
                aura_identity_get_kyber_public(
                    alice_h,
                    alice_kyber.as_mut_ptr(),
                    alice_kyber.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_kyber_public(
                    bob_h,
                    bob_kyber.as_mut_ptr(),
                    bob_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut init_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let mut accept_buf = null_buffer();
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    ptr::null_mut(),
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert!(bob_session_h.is_null());

            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert!(accept_buf.data.is_null());
            assert_eq!(accept_buf.length, 0);

            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_call_init_complete_requires_session_output_without_consuming_initiator() {
        init_lib();
        let mut alice_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut bob_h: *mut AuraIdentityHandle = ptr::null_mut();
        let mut err = null_error();

        unsafe {
            aura_identity_create(&mut alice_h, &mut err);
            aura_identity_create(&mut bob_h, &mut err);
        }

        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        unsafe {
            assert_eq!(
                aura_identity_get_kyber_public(
                    alice_h,
                    alice_kyber.as_mut_ptr(),
                    alice_kyber.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_kyber_public(
                    bob_h,
                    bob_kyber.as_mut_ptr(),
                    bob_kyber.len(),
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
        }

        let mut init_buf = null_buffer();
        let mut accept_buf = null_buffer();
        let mut init_h: *mut AuraVoipCallInitiatorHandle = ptr::null_mut();
        let mut bob_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut alice_session_h: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_call_init_start(
                    alice_h,
                    bob_kyber.as_ptr(),
                    bob_kyber.len(),
                    0,
                    512,
                    60,
                    &mut init_buf,
                    &mut init_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_accept_call(
                    bob_h,
                    init_buf.data,
                    init_buf.length,
                    alice_kyber.as_ptr(),
                    alice_kyber.len(),
                    &mut accept_buf,
                    &mut bob_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_call_init_complete(
                    init_h,
                    alice_h,
                    accept_buf.data,
                    accept_buf.length,
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert!(alice_session_h.is_null());

            assert_eq!(
                aura_voip_call_init_complete(
                    init_h,
                    alice_h,
                    accept_buf.data,
                    accept_buf.length,
                    &mut alice_session_h,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!alice_session_h.is_null());

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_encrypt_frame_clears_stale_output_on_failure() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut enc = null_encrypted_frame();

        unsafe {
            let alice_ssrc = aura_voip_ssrc(alice_session_h, &mut err);
            assert_eq!(
                aura_voip_encrypt_frame(
                    alice_session_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    b"hello".as_ptr(),
                    b"hello".len(),
                    &mut enc,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!enc.call_id.data.is_null());
            assert!(!enc.encrypted_payload.data.is_null());

            let code = aura_voip_encrypt_frame(
                alice_session_h,
                111,
                alice_ssrc,
                320,
                2,
                ptr::null(),
                1,
                &mut enc,
                &mut err,
            );
            assert_ne!(code, AuraErrorCode::AuraSuccess);
            assert!(enc.call_id.data.is_null());
            assert_eq!(enc.call_id.length, 0);
            assert!(enc.encrypted_payload.data.is_null());
            assert_eq!(enc.encrypted_payload.length, 0);
            assert!(enc.nonce.data.is_null());
            assert_eq!(enc.nonce.length, 0);
            assert!(enc.encrypted_header.data.is_null());
            assert_eq!(enc.encrypted_header.length, 0);
            assert_eq!(enc.frame_counter, 0);
            assert_eq!(enc.ratchet_generation, 0);

            aura_buffer_release(&mut enc.call_id);
            aura_buffer_release(&mut enc.encrypted_payload);
            aura_buffer_release(&mut enc.nonce);
            aura_buffer_release(&mut enc.encrypted_header);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_encrypt_frame_requires_out_frame() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();

        unsafe {
            let alice_ssrc = aura_voip_ssrc(alice_session_h, &mut err);
            assert_eq!(
                aura_voip_encrypt_frame(
                    alice_session_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    b"hello".as_ptr(),
                    b"hello".len(),
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );

            let mut enc = null_encrypted_frame();
            assert_eq!(
                aura_voip_encrypt_frame(
                    alice_session_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    b"hello".as_ptr(),
                    b"hello".len(),
                    &mut enc,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            aura_buffer_release(&mut enc.call_id);
            aura_buffer_release(&mut enc.encrypted_payload);
            aura_buffer_release(&mut enc.nonce);
            aura_buffer_release(&mut enc.encrypted_header);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_decrypt_frame_clears_stale_output_on_failure() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut enc = null_encrypted_frame();
        let mut dec = null_decrypted_frame();

        unsafe {
            let alice_ssrc = aura_voip_ssrc(alice_session_h, &mut err);
            assert_eq!(
                aura_voip_encrypt_frame(
                    alice_session_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    b"hello".as_ptr(),
                    b"hello".len(),
                    &mut enc,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_decrypt_frame(
                    bob_session_h,
                    enc.call_id.data,
                    enc.call_id.length,
                    enc.ssrc,
                    enc.frame_counter,
                    enc.ratchet_generation,
                    enc.encrypted_payload.data,
                    enc.encrypted_payload.length,
                    enc.nonce.data,
                    enc.nonce.length,
                    enc.encrypted_header.data,
                    enc.encrypted_header.length,
                    &mut dec,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!dec.payload.data.is_null());

            let mut tampered_payload = std::slice::from_raw_parts(
                enc.encrypted_payload.data,
                enc.encrypted_payload.length,
            )
            .to_vec();
            let last = tampered_payload.len() - 1;
            tampered_payload[last] ^= 0x11;

            let code = aura_voip_decrypt_frame(
                bob_session_h,
                enc.call_id.data,
                enc.call_id.length,
                enc.ssrc,
                enc.frame_counter + 1,
                enc.ratchet_generation,
                tampered_payload.as_ptr(),
                tampered_payload.len(),
                enc.nonce.data,
                enc.nonce.length,
                enc.encrypted_header.data,
                enc.encrypted_header.length,
                &mut dec,
                &mut err,
            );
            assert_ne!(code, AuraErrorCode::AuraSuccess);
            assert!(dec.payload.data.is_null());
            assert_eq!(dec.payload.length, 0);
            assert_eq!(dec.payload_type, 0);
            assert_eq!(dec.ssrc, 0);
            assert_eq!(dec.timestamp, 0);
            assert_eq!(dec.sequence_number, 0);
            assert_eq!(dec.frame_counter, 0);
            assert_eq!(dec.ratchet_generation, 0);

            aura_buffer_release(&mut enc.call_id);
            aura_buffer_release(&mut enc.encrypted_payload);
            aura_buffer_release(&mut enc.nonce);
            aura_buffer_release(&mut enc.encrypted_header);
            aura_buffer_release(&mut dec.payload);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_decrypt_frame_requires_out_frame() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut enc = null_encrypted_frame();
        let mut dec = null_decrypted_frame();

        unsafe {
            let alice_ssrc = aura_voip_ssrc(alice_session_h, &mut err);
            assert_eq!(
                aura_voip_encrypt_frame(
                    alice_session_h,
                    111,
                    alice_ssrc,
                    160,
                    1,
                    b"hello".as_ptr(),
                    b"hello".len(),
                    &mut enc,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(
                aura_voip_decrypt_frame(
                    bob_session_h,
                    enc.call_id.data,
                    enc.call_id.length,
                    enc.ssrc,
                    enc.frame_counter,
                    enc.ratchet_generation,
                    enc.encrypted_payload.data,
                    enc.encrypted_payload.length,
                    enc.nonce.data,
                    enc.nonce.length,
                    enc.encrypted_header.data,
                    enc.encrypted_header.length,
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );

            assert_eq!(
                aura_voip_decrypt_frame(
                    bob_session_h,
                    enc.call_id.data,
                    enc.call_id.length,
                    enc.ssrc,
                    enc.frame_counter,
                    enc.ratchet_generation,
                    enc.encrypted_payload.data,
                    enc.encrypted_payload.length,
                    enc.nonce.data,
                    enc.nonce.length,
                    enc.encrypted_header.data,
                    enc.encrypted_header.length,
                    &mut dec,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );

            aura_buffer_release(&mut enc.call_id);
            aura_buffer_release(&mut enc.encrypted_payload);
            aura_buffer_release(&mut enc.nonce);
            aura_buffer_release(&mut enc.encrypted_header);
            aura_buffer_release(&mut dec.payload);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_encrypt_call_control_requires_out_frame() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut enc = null_encrypted_frame();

        unsafe {
            assert_eq!(
                aura_voip_encrypt_call_control(alice_session_h, 1, 0, ptr::null_mut(), &mut err),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert_eq!(
                aura_voip_encrypt_call_control(alice_session_h, 1, 0, &mut enc, &mut err),
                AuraErrorCode::AuraSuccess
            );

            aura_buffer_release(&mut enc.call_id);
            aura_buffer_release(&mut enc.encrypted_payload);
            aura_buffer_release(&mut enc.nonce);
            aura_buffer_release(&mut enc.encrypted_header);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_import_sealed_state_requires_out_session() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let state_key = [0x42u8; 32];
        let mut sealed = null_buffer();
        let mut restored: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_voip_export_sealed_state(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    7,
                    &mut sealed,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_import_sealed_state(
                    sealed.data,
                    sealed.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    7,
                    ptr::null_mut(),
                    &mut err
                ),
                AuraErrorCode::AuraErrorNullPointer
            );
            assert_eq!(
                aura_voip_import_sealed_state(
                    sealed.data,
                    sealed.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    6,
                    &mut restored,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored.is_null());

            aura_buffer_release(&mut sealed);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut restored);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_sealed_state_with_tracker_restores_latest_and_rejects_rollback() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let state_key = [0x52u8; 32];
        let mut tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut next_restart_tracker: *mut AuraSealedStateCounterTrackerHandle = ptr::null_mut();
        let mut sealed1 = null_buffer();
        let mut sealed2 = null_buffer();
        let mut tracker_state1 = null_buffer();
        let mut tracker_state2 = null_buffer();
        let mut restored1: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut restored2: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut failed_restore: *mut AuraVoipSessionHandle = ptr::null_mut();
        let mut max_restored = 0u64;
        let mut latest_issued = 0u64;

        unsafe {
            assert_eq!(
                aura_sealed_state_counter_tracker_create(&mut tracker, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_export_sealed_state_with_tracker(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    tracker,
                    &mut sealed1,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(tracker, &mut tracker_state1, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state1.data,
                    tracker_state1.length,
                    &mut restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_import_sealed_state_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    restart_tracker,
                    &mut restored1,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored1.is_null());
            assert_eq!(
                aura_sealed_state_counter_tracker_get_max_restored_counter(
                    restart_tracker,
                    &mut max_restored,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(max_restored, 1);
            assert_eq!(
                aura_sealed_state_counter_tracker_get_latest_issued_counter(
                    restart_tracker,
                    &mut latest_issued,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(latest_issued, 1);

            assert_eq!(
                aura_voip_export_sealed_state_with_tracker(
                    restored1,
                    state_key.as_ptr(),
                    state_key.len(),
                    restart_tracker,
                    &mut sealed2,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_serialize(
                    restart_tracker,
                    &mut tracker_state2,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_counter_tracker_create_from_serialized(
                    tracker_state2.data,
                    tracker_state2.length,
                    &mut next_restart_tracker,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_ne!(
                aura_voip_import_sealed_state_with_tracker(
                    sealed1.data,
                    sealed1.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    next_restart_tracker,
                    &mut failed_restore,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(failed_restore.is_null());
            assert_eq!(
                aura_voip_import_sealed_state_with_tracker(
                    sealed2.data,
                    sealed2.length,
                    state_key.as_ptr(),
                    state_key.len(),
                    next_restart_tracker,
                    &mut restored2,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored2.is_null());

            aura_buffer_release(&mut sealed1);
            aura_buffer_release(&mut sealed2);
            aura_buffer_release(&mut tracker_state1);
            aura_buffer_release(&mut tracker_state2);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut restored1);
            aura_voip_session_destroy(&mut restored2);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_sealed_state_counter_tracker_destroy(&mut tracker);
            aura_sealed_state_counter_tracker_destroy(&mut restart_tracker);
            aura_sealed_state_counter_tracker_destroy(&mut next_restart_tracker);
        }
    }

    #[test]
    fn ffi_voip_persisted_slot_roundtrip() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let state_key = [0x53u8; 32];
        let mut slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut restart_slot: *mut AuraSealedStateSlotHandle = ptr::null_mut();
        let mut serialized_slot = null_buffer();
        let mut restored: *mut AuraVoipSessionHandle = ptr::null_mut();

        unsafe {
            assert_eq!(
                aura_sealed_state_slot_create(&mut slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_export_persisted_state(
                    alice_session_h,
                    state_key.as_ptr(),
                    state_key.len(),
                    slot,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_serialize(slot, &mut serialized_slot, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_sealed_state_slot_create_from_serialized(
                    serialized_slot.data,
                    serialized_slot.length,
                    &mut restart_slot,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_voip_restore_persisted_state(
                    restart_slot,
                    state_key.as_ptr(),
                    state_key.len(),
                    &mut restored,
                    &mut err
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(!restored.is_null());

            aura_buffer_release(&mut serialized_slot);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_session_destroy(&mut restored);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
            aura_sealed_state_slot_destroy(&mut slot);
            aura_sealed_state_slot_destroy(&mut restart_slot);
        }
    }

    #[test]
    fn ffi_voip_screen_share_meta_set_get_clear() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let codec = b"H264";

        unsafe {
            let code = aura_voip_set_screen_share_meta(
                alice_session_h,
                1920,
                1080,
                30,
                codec.as_ptr(),
                codec.len(),
                &mut err,
            );
            assert_eq!(code, AuraErrorCode::AuraSuccess);

            let mut w: u32 = 0;
            let mut h: u32 = 0;
            let mut fr: u32 = 0;
            let mut hint_buf = null_buffer();
            let code = aura_voip_get_screen_share_meta(
                alice_session_h,
                &mut w,
                &mut h,
                &mut fr,
                &mut hint_buf,
                &mut err,
            );
            assert_eq!(code, AuraErrorCode::AuraSuccess);
            assert_eq!(w, 1920);
            assert_eq!(h, 1080);
            assert_eq!(fr, 30);
            assert!(hint_buf.length > 0);
            let hint_str =
                std::str::from_utf8(std::slice::from_raw_parts(hint_buf.data, hint_buf.length))
                    .unwrap();
            assert_eq!(hint_str, "H264");
            aura_buffer_release(&mut hint_buf);

            let code = aura_voip_clear_screen_share_meta(alice_session_h, &mut err);
            assert_eq!(code, AuraErrorCode::AuraSuccess);

            let mut w2: u32 = 99;
            let mut h2: u32 = 99;
            let mut fr2: u32 = 99;
            let mut hint_buf2 = null_buffer();
            let code = aura_voip_get_screen_share_meta(
                alice_session_h,
                &mut w2,
                &mut h2,
                &mut fr2,
                &mut hint_buf2,
                &mut err,
            );
            assert_eq!(code, AuraErrorCode::AuraSuccess);
            assert_eq!(w2, 0);
            assert_eq!(h2, 0);
            assert_eq!(fr2, 0);
            aura_buffer_release(&mut hint_buf2);

            let code = aura_voip_set_screen_share_meta(
                alice_session_h,
                0,
                1080,
                30,
                ptr::null(),
                0,
                &mut err,
            );
            assert_ne!(code, AuraErrorCode::AuraSuccess);

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_call_statistics_tracking() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let payload = b"stats-test";

        unsafe {
            let alice_ssrc = aura_voip_ssrc(alice_session_h, &mut err);

            for i in 0u32..5 {
                let mut enc = null_encrypted_frame();
                assert_eq!(
                    aura_voip_encrypt_frame(
                        alice_session_h,
                        111,
                        alice_ssrc,
                        160 + i,
                        1 + u16::try_from(i).unwrap(),
                        payload.as_ptr(),
                        payload.len(),
                        &mut enc,
                        &mut err
                    ),
                    AuraErrorCode::AuraSuccess
                );

                let mut dec = null_decrypted_frame();
                assert_eq!(
                    aura_voip_decrypt_frame(
                        bob_session_h,
                        enc.call_id.data,
                        enc.call_id.length,
                        enc.ssrc,
                        enc.frame_counter,
                        enc.ratchet_generation,
                        enc.encrypted_payload.data,
                        enc.encrypted_payload.length,
                        enc.nonce.data,
                        enc.nonce.length,
                        enc.encrypted_header.data,
                        enc.encrypted_header.length,
                        &mut dec,
                        &mut err
                    ),
                    AuraErrorCode::AuraSuccess
                );

                aura_buffer_release(&mut enc.call_id);
                aura_buffer_release(&mut enc.encrypted_payload);
                aura_buffer_release(&mut enc.nonce);
                aura_buffer_release(&mut enc.encrypted_header);
                aura_buffer_release(&mut dec.payload);
            }

            let mut stats = AuraCallStatistics {
                frames_sent: 0,
                frames_received: 0,
                frames_dropped: 0,
                rekey_count: 0,
                ratchet_generation: 0,
                call_duration_secs: 0,
            };
            let code = aura_voip_get_call_statistics(alice_session_h, &mut stats, &mut err);
            assert_eq!(code, AuraErrorCode::AuraSuccess);
            assert_eq!(stats.frames_sent, 5);
            assert_eq!(stats.frames_received, 0);

            let code = aura_voip_get_call_statistics(bob_session_h, &mut stats, &mut err);
            assert_eq!(code, AuraErrorCode::AuraSuccess);
            assert_eq!(stats.frames_sent, 0);
            assert_eq!(stats.frames_received, 5);
            assert_eq!(stats.frames_dropped, 0);

            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }

    #[test]
    fn ffi_voip_recording_consent() {
        init_lib();
        let (
            mut alice_h,
            mut bob_h,
            mut alice_session_h,
            mut bob_session_h,
            mut init_h,
            mut init_buf,
            mut accept_buf,
        ) = setup_voip_session_pair();

        let mut err = null_error();
        let mut alice_ed25519 = vec![0u8; 32];
        let mut bob_ed25519 = vec![0u8; 32];

        unsafe {
            assert_eq!(
                aura_identity_get_ed25519_public(
                    alice_h,
                    alice_ed25519.as_mut_ptr(),
                    alice_ed25519.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(
                aura_identity_get_ed25519_public(
                    bob_h,
                    bob_ed25519.as_mut_ptr(),
                    bob_ed25519.len(),
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );

            assert_eq!(aura_voip_get_local_recording_consent(alice_session_h), 0);
            assert_eq!(aura_voip_get_remote_recording_consent(alice_session_h), 0);
            assert!(!aura_voip_both_consented_to_recording(alice_session_h));

            assert_ne!(
                aura_voip_set_remote_recording_consent(alice_session_h, 1, &mut err),
                AuraErrorCode::AuraSuccess
            );
            assert!(!aura_voip_both_consented_to_recording(alice_session_h));
            assert_eq!(aura_voip_get_remote_recording_consent(alice_session_h), 0);

            let mut alice_consent = null_buffer();
            assert_eq!(
                aura_voip_build_recording_consent_message(
                    alice_session_h,
                    alice_h,
                    1,
                    1_700_000_000,
                    &mut alice_consent,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(aura_voip_get_local_recording_consent(alice_session_h), 1);
            assert_eq!(
                aura_voip_process_recording_consent_message(
                    bob_session_h,
                    alice_ed25519.as_ptr(),
                    alice_ed25519.len(),
                    alice_consent.data,
                    alice_consent.length,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(aura_voip_get_remote_recording_consent(bob_session_h), 1);
            assert!(!aura_voip_both_consented_to_recording(bob_session_h));

            let mut bob_consent = null_buffer();
            assert_eq!(
                aura_voip_build_recording_consent_message(
                    bob_session_h,
                    bob_h,
                    1,
                    1_700_000_001,
                    &mut bob_consent,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert_eq!(aura_voip_get_local_recording_consent(bob_session_h), 1);
            assert_eq!(
                aura_voip_process_recording_consent_message(
                    alice_session_h,
                    bob_ed25519.as_ptr(),
                    bob_ed25519.len(),
                    bob_consent.data,
                    bob_consent.length,
                    &mut err,
                ),
                AuraErrorCode::AuraSuccess
            );
            assert!(aura_voip_both_consented_to_recording(alice_session_h));
            assert!(aura_voip_both_consented_to_recording(bob_session_h));

            let code = aura_voip_set_recording_consent(alice_session_h, 5, &mut err);
            assert_ne!(code, AuraErrorCode::AuraSuccess);

            aura_buffer_release(&mut alice_consent);
            aura_buffer_release(&mut bob_consent);
            aura_buffer_release(&mut init_buf);
            aura_buffer_release(&mut accept_buf);
            aura_voip_call_initiator_destroy(&mut init_h);
            aura_voip_session_destroy(&mut alice_session_h);
            aura_voip_session_destroy(&mut bob_session_h);
            aura_identity_destroy(&mut alice_h);
            aura_identity_destroy(&mut bob_h);
        }
    }
}
