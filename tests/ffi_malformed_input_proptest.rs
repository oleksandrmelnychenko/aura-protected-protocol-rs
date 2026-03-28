#![cfg(feature = "ffi")]
// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT
#![allow(clippy::pedantic, clippy::nursery, unsafe_code)]

use std::ptr;
use std::sync::Once;

use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::ffi::api::*;
use proptest::collection::vec;
use proptest::prelude::*;

static INIT_ONCE: Once = Once::new();

fn init_lib() {
    INIT_ONCE.call_once(|| {
        CryptoInterop::initialize().unwrap();
        assert_eq!(epp_init(), EppErrorCode::EppSuccess);
    });
}

const fn null_error() -> EppError {
    EppError {
        code: EppErrorCode::EppSuccess,
        message: ptr::null_mut(),
    }
}

const fn null_buffer() -> EppBuffer {
    EppBuffer {
        data: ptr::null_mut(),
        length: 0,
    }
}

fn buffer_to_vec(buffer: &EppBuffer) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(buffer.data, buffer.length) }.to_vec()
}

fn mutate_bytes(base: &[u8], ops: &[u8]) -> Vec<u8> {
    let mut data = if base.is_empty() {
        vec![0xA5]
    } else {
        base.to_vec()
    };
    let max_len = base.len().saturating_add(16).max(2);

    for chunk in ops.chunks(3).take(8) {
        let op = chunk[0];
        let arg1 = *chunk.get(1).unwrap_or(&0);
        let arg2 = chunk.get(2).copied().unwrap_or(1).max(1);
        match op % 5 {
            0 => {
                let idx = usize::from(arg1) % data.len();
                data[idx] ^= arg2;
            }
            1 => {
                let idx = usize::from(arg1) % data.len();
                data[idx] = data[idx].wrapping_add(arg2);
            }
            2 => {
                if data.len() > 1 {
                    let idx = usize::from(arg1) % data.len();
                    data.remove(idx);
                } else {
                    data.push(arg2);
                }
            }
            3 => {
                if data.len() < max_len {
                    let idx = usize::from(arg1) % (data.len() + 1);
                    data.insert(idx, arg2);
                } else {
                    let idx = usize::from(arg1) % data.len();
                    data[idx] ^= arg2;
                }
            }
            _ => {
                if data.len() > 1 {
                    let new_len = 1 + (usize::from(arg1) % data.len());
                    data.truncate(new_len);
                } else {
                    data[0] ^= arg2;
                }
            }
        }
    }

    if data == base {
        if let Some(first) = data.first_mut() {
            *first ^= 0x80;
        } else {
            data.push(0x80);
        }
    }
    data
}

fn build_session_sealed_state() -> Vec<u8> {
    let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
    let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
    let mut init_h: *mut EppHandshakeInitiatorHandle = ptr::null_mut();
    let mut resp_h: *mut EppHandshakeResponderHandle = ptr::null_mut();
    let mut alice_session_h: *mut EppSessionHandle = ptr::null_mut();
    let mut bob_session_h: *mut EppSessionHandle = ptr::null_mut();
    let mut bob_bundle = null_buffer();
    let mut init_msg = null_buffer();
    let mut ack_msg = null_buffer();
    let mut sealed = null_buffer();
    let mut err = null_error();
    let state_key = [0x44u8; 32];
    let config = EppSessionConfig {
        max_messages_per_chain: 1000,
    };

    unsafe {
        assert_eq!(
            epp_identity_create(&mut alice_h, &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_identity_create(&mut bob_h, &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_prekey_bundle_create(bob_h, &mut bob_bundle, &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_handshake_initiator_start(
                alice_h,
                bob_bundle.data,
                bob_bundle.length,
                &config,
                &mut init_h,
                &mut init_msg,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_handshake_responder_start(
                bob_h,
                bob_bundle.data,
                bob_bundle.length,
                init_msg.data,
                init_msg.length,
                &config,
                &mut resp_h,
                &mut ack_msg,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_handshake_responder_finish(resp_h, &mut bob_session_h, &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_handshake_initiator_finish(
                init_h,
                ack_msg.data,
                ack_msg.length,
                &mut alice_session_h,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_session_serialize_sealed(
                alice_session_h,
                state_key.as_ptr(),
                state_key.len(),
                1,
                &mut sealed,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );

        let out = buffer_to_vec(&sealed);
        epp_buffer_release(&mut bob_bundle);
        epp_buffer_release(&mut init_msg);
        epp_buffer_release(&mut ack_msg);
        epp_buffer_release(&mut sealed);
        epp_session_destroy(&mut alice_session_h);
        epp_session_destroy(&mut bob_session_h);
        epp_identity_destroy(&mut alice_h);
        epp_identity_destroy(&mut bob_h);
        epp_error_free(&mut err);
        out
    }
}

fn build_voip_sealed_state() -> Vec<u8> {
    let mut alice_h: *mut EppIdentityHandle = ptr::null_mut();
    let mut bob_h: *mut EppIdentityHandle = ptr::null_mut();
    let mut init_h: *mut EppVoipCallInitiatorHandle = ptr::null_mut();
    let mut alice_session_h: *mut EppVoipSessionHandle = ptr::null_mut();
    let mut bob_session_h: *mut EppVoipSessionHandle = ptr::null_mut();
    let mut init_buf = null_buffer();
    let mut accept_buf = null_buffer();
    let mut sealed = null_buffer();
    let mut err = null_error();
    let state_key = [0x55u8; 32];

    unsafe {
        assert_eq!(
            epp_identity_create(&mut alice_h, &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_identity_create(&mut bob_h, &mut err),
            EppErrorCode::EppSuccess
        );
        let mut alice_kyber = vec![0u8; 1184];
        let mut bob_kyber = vec![0u8; 1184];
        assert_eq!(
            epp_identity_get_kyber_public(
                alice_h,
                alice_kyber.as_mut_ptr(),
                alice_kyber.len(),
                &mut err
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_identity_get_kyber_public(bob_h, bob_kyber.as_mut_ptr(), bob_kyber.len(), &mut err),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_voip_call_init_start(
                alice_h,
                bob_kyber.as_ptr(),
                bob_kyber.len(),
                0,
                512,
                60,
                &mut init_buf,
                &mut init_h,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_voip_accept_call(
                bob_h,
                init_buf.data,
                init_buf.length,
                alice_kyber.as_ptr(),
                alice_kyber.len(),
                &mut accept_buf,
                &mut bob_session_h,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_voip_call_init_complete(
                init_h,
                alice_h,
                accept_buf.data,
                accept_buf.length,
                &mut alice_session_h,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );
        assert_eq!(
            epp_voip_export_sealed_state(
                alice_session_h,
                state_key.as_ptr(),
                state_key.len(),
                1,
                &mut sealed,
                &mut err,
            ),
            EppErrorCode::EppSuccess
        );

        let out = buffer_to_vec(&sealed);
        epp_buffer_release(&mut init_buf);
        epp_buffer_release(&mut accept_buf);
        epp_buffer_release(&mut sealed);
        epp_voip_call_initiator_destroy(init_h);
        epp_voip_session_destroy(alice_session_h);
        epp_voip_session_destroy(bob_session_h);
        epp_identity_destroy(&mut alice_h);
        epp_identity_destroy(&mut bob_h);
        epp_error_free(&mut err);
        out
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    #[test]
    fn ffi_session_restore_rejects_mutated_sealed_state(ops in vec(any::<u8>(), 1..24)) {
        init_lib();
        let sealed = build_session_sealed_state();
        let mutated = mutate_bytes(&sealed, &ops);
        prop_assert_ne!(mutated.as_slice(), sealed.as_slice());

        let mut provider_h: *mut EppTimeProviderHandle = ptr::null_mut();
        let mut restored_h: *mut EppSessionHandle = ptr::null_mut();
        let mut counter = 0u64;
        let mut err = null_error();
        let state_key = [0x44u8; 32];

        unsafe {
            prop_assert_eq!(
                epp_time_provider_manual_create(1_700_000_000, &mut provider_h, &mut err),
                EppErrorCode::EppSuccess
            );
            let code = epp_session_deserialize_sealed_with_time_provider(
                mutated.as_ptr(),
                mutated.len(),
                state_key.as_ptr(),
                state_key.len(),
                0,
                provider_h,
                &mut counter,
                &mut restored_h,
                &mut err,
            );
            prop_assert_ne!(code, EppErrorCode::EppSuccess);

            if !restored_h.is_null() {
                epp_session_destroy(&mut restored_h);
            }
            epp_time_provider_destroy(&mut provider_h);
            epp_error_free(&mut err);
        }
    }

    #[test]
    fn ffi_voip_restore_rejects_mutated_sealed_state(ops in vec(any::<u8>(), 1..24)) {
        init_lib();
        let sealed = build_voip_sealed_state();
        let mutated = mutate_bytes(&sealed, &ops);
        prop_assert_ne!(mutated.as_slice(), sealed.as_slice());

        let mut provider_h: *mut EppTimeProviderHandle = ptr::null_mut();
        let mut restored_h: *mut EppVoipSessionHandle = ptr::null_mut();
        let mut err = null_error();
        let state_key = [0x55u8; 32];

        unsafe {
            prop_assert_eq!(
                epp_time_provider_manual_create(1_710_000_000, &mut provider_h, &mut err),
                EppErrorCode::EppSuccess
            );
            let code = epp_voip_import_sealed_state_with_time_provider(
                mutated.as_ptr(),
                mutated.len(),
                state_key.as_ptr(),
                state_key.len(),
                0,
                provider_h,
                &mut restored_h,
                &mut err,
            );
            prop_assert_ne!(code, EppErrorCode::EppSuccess);

            if !restored_h.is_null() {
                epp_voip_session_destroy(restored_h);
            }
            epp_time_provider_destroy(&mut provider_h);
            epp_error_free(&mut err);
        }
    }
}
