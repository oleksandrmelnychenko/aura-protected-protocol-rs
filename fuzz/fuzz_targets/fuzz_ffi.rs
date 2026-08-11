#![no_main]
use libfuzzer_sys::fuzz_target;
use std::ptr;
use std::sync::Once;

use aura_protected_protocol::ffi::api::*;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        aura_init();
    });

    let mut error = AuraError {
        code: AuraErrorCode::AuraSuccess,
        message: ptr::null_mut(),
    };

    // --- aura_envelope_validate with arbitrary bytes ---
    unsafe {
        let _ = aura_envelope_validate(data.as_ptr(), data.len(), &mut error);
        aura_error_free(&mut error);
    }

    // --- aura_session_deserialize_sealed with arbitrary state bytes ---
    if data.len() >= 32 {
        unsafe {
            let key = data[..32].as_ptr();
            let state = &data[32..];
            let mut counter: u64 = 0;
            let mut session_handle: *mut AuraSessionHandle = ptr::null_mut();
            let _ = aura_session_deserialize_sealed(
                state.as_ptr(),
                state.len(),
                key,
                32,
                0,
                &mut counter,
                &mut session_handle,
                &mut error,
            );
            aura_error_free(&mut error);
            if !session_handle.is_null() {
                aura_session_destroy(&mut session_handle);
            }
        }
    }

    // --- aura_derive_root_key with arbitrary inputs ---
    if data.len() >= 33 {
        unsafe {
            let key = data[..32].as_ptr();
            let context = &data[32..];
            let mut out_root = [0u8; 32];
            let _ = aura_derive_root_key(
                key,
                32,
                context.as_ptr(),
                context.len(),
                out_root.as_mut_ptr(),
                32,
                &mut error,
            );
            aura_error_free(&mut error);
        }
    }

    // --- aura_shamir_reconstruct with arbitrary share data ---
    if data.len() >= 64 {
        unsafe {
            let auth_key = data[..32].as_ptr();
            let shares = &data[32..];
            let share_count = 3usize;
            let share_len = shares.len().saturating_sub(32) / share_count.max(1);
            if share_len > 0 {
                let mut out_secret = AuraBuffer {
                    data: ptr::null_mut(),
                    length: 0,
                };
                let _ = aura_shamir_reconstruct(
                    shares.as_ptr(),
                    shares.len(),
                    share_len,
                    share_count,
                    auth_key,
                    32,
                    &mut out_secret,
                    &mut error,
                );
                aura_error_free(&mut error);
                aura_buffer_release(&mut out_secret);
            }
        }
    }

    // --- aura_handshake_initiator_start with fuzzed bundle ---
    unsafe {
        let mut identity_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let result = aura_identity_create(&mut identity_handle, &mut error);
        aura_error_free(&mut error);

        if result == AuraErrorCode::AuraSuccess && !identity_handle.is_null() {
            let mut initiator_handle: *mut AuraHandshakeInitiatorHandle = ptr::null_mut();
            let mut init_msg = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            let _ = aura_handshake_initiator_start(
                identity_handle,
                data.as_ptr(),
                data.len(),
                ptr::null(),
                &mut initiator_handle,
                &mut init_msg,
                &mut error,
            );
            aura_error_free(&mut error);
            aura_buffer_release(&mut init_msg);
            if !initiator_handle.is_null() {
                aura_handshake_initiator_destroy(&mut initiator_handle);
            }
            aura_identity_destroy(&mut identity_handle);
        }
    }

    // --- aura_group_process_commit with fuzzed commit bytes ---
    unsafe {
        let mut identity_handle: *mut AuraIdentityHandle = ptr::null_mut();
        let result = aura_identity_create(&mut identity_handle, &mut error);
        aura_error_free(&mut error);

        if result == AuraErrorCode::AuraSuccess && !identity_handle.is_null() {
            let mut group_handle: *mut AuraGroupSessionHandle = ptr::null_mut();
            let result = aura_group_create(
                identity_handle,
                ptr::null(),
                0,
                &mut group_handle,
                &mut error,
            );
            aura_error_free(&mut error);

            if result == AuraErrorCode::AuraSuccess && !group_handle.is_null() {
                // Process fuzzed commit
                let _ = aura_group_process_commit(
                    group_handle,
                    data.as_ptr(),
                    data.len(),
                    &mut error,
                );
                aura_error_free(&mut error);

                // Decrypt fuzzed group message
                let mut out_plaintext = AuraBuffer {
                    data: ptr::null_mut(),
                    length: 0,
                };
                let mut sender_leaf: u32 = 0;
                let mut generation: u32 = 0;
                let _ = aura_group_decrypt(
                    group_handle,
                    data.as_ptr(),
                    data.len(),
                    &mut out_plaintext,
                    &mut sender_leaf,
                    &mut generation,
                    &mut error,
                );
                aura_error_free(&mut error);
                aura_buffer_release(&mut out_plaintext);

                aura_group_destroy(&mut group_handle);
            }
            aura_identity_destroy(&mut identity_handle);
        }
    }

    // --- NULL pointer resilience for all major functions ---
    unsafe {
        let _ = aura_envelope_validate(ptr::null(), 0, &mut error);
        aura_error_free(&mut error);

        let _ = aura_identity_create(ptr::null_mut(), &mut error);
        aura_error_free(&mut error);

        let mut out_key = [0u8; 32];
        let _ = aura_identity_get_x25519_public(ptr::null(), out_key.as_mut_ptr(), 32, &mut error);
        aura_error_free(&mut error);

        let _ = aura_identity_get_ed25519_public(ptr::null(), out_key.as_mut_ptr(), 32, &mut error);
        aura_error_free(&mut error);

        let mut out_buf = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let _ = aura_prekey_bundle_create(ptr::null(), &mut out_buf, &mut error);
        aura_error_free(&mut error);
        aura_buffer_release(&mut out_buf);

        let _session: *mut AuraSessionHandle = ptr::null_mut();
        let _ = aura_session_encrypt(
            ptr::null_mut(),
            data.as_ptr(),
            data.len(),
            AuraEnvelopeType::AuraEnvelopeRequest,
            0,
            ptr::null(),
            0,
            &mut out_buf,
            &mut error,
        );
        aura_error_free(&mut error);
        aura_buffer_release(&mut out_buf);

        let mut out_meta = AuraBuffer {
            data: ptr::null_mut(),
            length: 0,
        };
        let _ = aura_session_decrypt(
            ptr::null_mut(),
            data.as_ptr(),
            data.len(),
            &mut out_buf,
            &mut out_meta,
            &mut error,
        );
        aura_error_free(&mut error);
        aura_buffer_release(&mut out_buf);
        aura_buffer_release(&mut out_meta);

        let _ = aura_group_encrypt(
            ptr::null_mut(),
            data.as_ptr(),
            data.len(),
            &mut out_buf,
            &mut error,
        );
        aura_error_free(&mut error);
        aura_buffer_release(&mut out_buf);
    }

    // --- aura_group_reveal_sealed with arbitrary inputs ---
    if data.len() >= 44 {
        unsafe {
            let nonce = &data[..12];
            let seal_key = &data[12..44];
            let content = &data[44..];
            let mut out_plaintext = AuraBuffer {
                data: ptr::null_mut(),
                length: 0,
            };
            let _ = aura_group_reveal_sealed(
                ptr::null(),
                0,
                content.as_ptr(),
                content.len(),
                nonce.as_ptr(),
                12,
                seal_key.as_ptr(),
                32,
                &mut out_plaintext,
                &mut error,
            );
            aura_error_free(&mut error);
            aura_buffer_release(&mut out_plaintext);
        }
    }

    // --- aura_group_verify_franking with arbitrary inputs ---
    if data.len() >= 64 {
        unsafe {
            let franking_tag = &data[..32];
            let franking_key = &data[32..64];
            let content = &data[64..];
            let mut valid: u8 = 0;
            let _ = aura_group_verify_franking(
                franking_tag.as_ptr(),
                32,
                franking_key.as_ptr(),
                32,
                content.as_ptr(),
                content.len(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                &mut valid,
                &mut error,
            );
            aura_error_free(&mut error);
        }
    }

    // --- aura_secure_wipe on fuzz-derived buffer ---
    if !data.is_empty() {
        let mut buf = data.to_vec();
        unsafe {
            let _ = aura_secure_wipe(buf.as_mut_ptr(), buf.len());
        }
    }
});
