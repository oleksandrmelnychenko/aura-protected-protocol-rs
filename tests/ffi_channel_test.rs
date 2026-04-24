#![cfg(feature = "ffi")]
// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT
//
// FFI integration tests for channel encryption (Phase 4).
//
// Exercises the C-ABI surface end-to-end from Rust callers, covering:
//   - generate_key
//   - wrap_key_for_device / unwrap_key_blob roundtrip and tamper rejection
//   - encrypt_message / decrypt_message roundtrip and tamper rejection
//   - null-pointer guards
//   - AuraBuffer lifecycle
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr, unsafe_code)]

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::ffi::api::*;
use ed25519_dalek::SigningKey as EdSigningKey;
use std::ptr;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

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

fn init() {
    let _ = CryptoInterop::initialize();
}

fn fixture_device() -> ([u8; 32], [u8; 32]) {
    let secret = X25519Secret::random_from_rng(rand_core::OsRng);
    let public = X25519Public::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn fixture_signing() -> EdSigningKey {
    EdSigningKey::from_bytes(&[0x33; 32])
}

#[test]
fn generate_key_produces_uuid_v4_and_nonzero_key() {
    init();
    let mut key_id = [0u8; 16];
    let mut key = [0u8; 32];
    let mut err = null_error();
    let code = unsafe {
        aura_channel_generate_key(key_id.as_mut_ptr(), key.as_mut_ptr(), &mut err as *mut _)
    };
    assert_eq!(code, AuraErrorCode::AuraSuccess);
    assert_eq!(key_id[6] & 0xF0, 0x40, "UUID v4 version bits");
    assert_eq!(key_id[8] & 0xC0, 0x80, "UUID v4 variant bits");
    assert!(key.iter().any(|&b| b != 0), "key must be non-zero");
}

#[test]
fn generate_key_rejects_null_outputs() {
    init();
    let mut err = null_error();
    let code =
        unsafe { aura_channel_generate_key(ptr::null_mut(), ptr::null_mut(), &mut err as *mut _) };
    assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
}

#[test]
fn wrap_unwrap_roundtrip_via_ffi() {
    init();
    let (device_secret, device_public) = fixture_device();
    let channel_key = [0xAB_u8; 32];

    let mut blob = null_buffer();
    let mut err = null_error();
    let code = unsafe {
        aura_channel_wrap_key_for_device(
            channel_key.as_ptr(),
            device_public.as_ptr(),
            &mut blob as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraSuccess);
    assert_eq!(blob.length, 92, "wrapped blob is 92 bytes");

    let mut recovered = [0u8; 32];
    let unwrap_code = unsafe {
        aura_channel_unwrap_key_blob(
            blob.data,
            blob.length,
            device_secret.as_ptr(),
            recovered.as_mut_ptr(),
            &mut err as *mut _,
        )
    };
    assert_eq!(unwrap_code, AuraErrorCode::AuraSuccess);
    assert_eq!(recovered, channel_key);

    unsafe { aura_buffer_release(&mut blob as *mut _) };
}

#[test]
fn unwrap_rejects_tampered_blob() {
    init();
    let (device_secret, device_public) = fixture_device();
    let channel_key = [0xAB_u8; 32];

    let mut blob = null_buffer();
    let mut err = null_error();
    unsafe {
        aura_channel_wrap_key_for_device(
            channel_key.as_ptr(),
            device_public.as_ptr(),
            &mut blob as *mut _,
            &mut err as *mut _,
        );
        // Flip a byte inside the ciphertext region.
        let last = blob.data.add(blob.length - 1);
        *last ^= 0xFF;
    }

    let mut recovered = [0u8; 32];
    let code = unsafe {
        aura_channel_unwrap_key_blob(
            blob.data,
            blob.length,
            device_secret.as_ptr(),
            recovered.as_mut_ptr(),
            &mut err as *mut _,
        )
    };
    assert_ne!(code, AuraErrorCode::AuraSuccess);

    unsafe { aura_buffer_release(&mut blob as *mut _) };
}

#[test]
fn unwrap_rejects_wrong_blob_length() {
    init();
    let (device_secret, _) = fixture_device();
    let bogus = [0u8; 50];
    let mut recovered = [0u8; 32];
    let mut err = null_error();
    let code = unsafe {
        aura_channel_unwrap_key_blob(
            bogus.as_ptr(),
            bogus.len(),
            device_secret.as_ptr(),
            recovered.as_mut_ptr(),
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraErrorInvalidInput);
}

#[test]
fn encrypt_decrypt_roundtrip_via_ffi() {
    init();
    let signing = fixture_signing();
    let channel_key = [0xCD_u8; 32];
    let channel_id = [0x11_u8; 16];
    let channel_key_id = [0x22_u8; 16];
    let plaintext = b"hello channel".to_vec();

    let mut nonce = [0u8; 12];
    let mut signature = [0u8; 64];
    let mut ciphertext = null_buffer();
    let mut err = null_error();
    let secret_bytes = signing.to_bytes();

    let code = unsafe {
        aura_channel_encrypt_message(
            plaintext.as_ptr(),
            plaintext.len(),
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            channel_key_id.as_ptr(),
            7,
            secret_bytes.as_ptr(),
            nonce.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut ciphertext as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraSuccess);
    assert_eq!(
        ciphertext.length,
        plaintext.len() + 16,
        "ciphertext + AEAD tag"
    );

    let sender_pub = signing.verifying_key().to_bytes();
    let mut decrypted = null_buffer();
    let dec_code = unsafe {
        aura_channel_decrypt_message(
            ciphertext.data,
            ciphertext.length,
            nonce.as_ptr(),
            signature.as_ptr(),
            channel_key_id.as_ptr(),
            7,
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            sender_pub.as_ptr(),
            &mut decrypted as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(dec_code, AuraErrorCode::AuraSuccess);
    assert_eq!(decrypted.length, plaintext.len());
    let recovered =
        unsafe { std::slice::from_raw_parts(decrypted.data, decrypted.length).to_vec() };
    assert_eq!(recovered, plaintext);

    unsafe {
        aura_buffer_release(&mut ciphertext as *mut _);
        aura_buffer_release(&mut decrypted as *mut _);
    }
}

#[test]
fn encrypt_with_empty_plaintext_via_ffi() {
    init();
    let signing = fixture_signing();
    let channel_key = [0xCD_u8; 32];
    let channel_id = [0x11_u8; 16];
    let channel_key_id = [0x22_u8; 16];

    let mut nonce = [0u8; 12];
    let mut signature = [0u8; 64];
    let mut ciphertext = null_buffer();
    let mut err = null_error();
    let secret_bytes = signing.to_bytes();

    let code = unsafe {
        aura_channel_encrypt_message(
            ptr::null(),
            0,
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            secret_bytes.as_ptr(),
            nonce.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut ciphertext as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraSuccess);
    assert_eq!(
        ciphertext.length, 16,
        "empty plaintext yields tag-only ciphertext"
    );

    unsafe { aura_buffer_release(&mut ciphertext as *mut _) };
}

#[test]
fn decrypt_rejects_tampered_ciphertext_via_ffi() {
    init();
    let signing = fixture_signing();
    let channel_key = [0xCD_u8; 32];
    let channel_id = [0x11_u8; 16];
    let channel_key_id = [0x22_u8; 16];
    let plaintext = b"secret".to_vec();

    let mut nonce = [0u8; 12];
    let mut signature = [0u8; 64];
    let mut ciphertext = null_buffer();
    let mut err = null_error();
    let secret_bytes = signing.to_bytes();
    unsafe {
        aura_channel_encrypt_message(
            plaintext.as_ptr(),
            plaintext.len(),
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            secret_bytes.as_ptr(),
            nonce.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut ciphertext as *mut _,
            &mut err as *mut _,
        );
        *ciphertext.data ^= 0xFF;
    }

    let sender_pub = signing.verifying_key().to_bytes();
    let mut decrypted = null_buffer();
    let dec_code = unsafe {
        aura_channel_decrypt_message(
            ciphertext.data,
            ciphertext.length,
            nonce.as_ptr(),
            signature.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            sender_pub.as_ptr(),
            &mut decrypted as *mut _,
            &mut err as *mut _,
        )
    };
    assert_ne!(dec_code, AuraErrorCode::AuraSuccess);

    unsafe {
        aura_buffer_release(&mut ciphertext as *mut _);
        aura_buffer_release(&mut decrypted as *mut _);
    }
}

#[test]
fn decrypt_rejects_wrong_channel_key_via_ffi() {
    init();
    let signing = fixture_signing();
    let channel_key = [0xCD_u8; 32];
    let wrong_key = [0xEE_u8; 32];
    let channel_id = [0x11_u8; 16];
    let channel_key_id = [0x22_u8; 16];
    let plaintext = b"secret".to_vec();

    let mut nonce = [0u8; 12];
    let mut signature = [0u8; 64];
    let mut ciphertext = null_buffer();
    let mut err = null_error();
    let secret_bytes = signing.to_bytes();
    unsafe {
        aura_channel_encrypt_message(
            plaintext.as_ptr(),
            plaintext.len(),
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            secret_bytes.as_ptr(),
            nonce.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut ciphertext as *mut _,
            &mut err as *mut _,
        );
    }

    let sender_pub = signing.verifying_key().to_bytes();
    let mut decrypted = null_buffer();
    let dec_code = unsafe {
        aura_channel_decrypt_message(
            ciphertext.data,
            ciphertext.length,
            nonce.as_ptr(),
            signature.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            wrong_key.as_ptr(),
            channel_id.as_ptr(),
            sender_pub.as_ptr(),
            &mut decrypted as *mut _,
            &mut err as *mut _,
        )
    };
    assert_ne!(dec_code, AuraErrorCode::AuraSuccess);

    unsafe {
        aura_buffer_release(&mut ciphertext as *mut _);
        aura_buffer_release(&mut decrypted as *mut _);
    }
}

#[test]
fn encrypt_rejects_null_pointers() {
    init();
    let mut nonce = [0u8; 12];
    let mut signature = [0u8; 64];
    let mut ciphertext = null_buffer();
    let mut err = null_error();
    let signing = fixture_signing();
    let secret_bytes = signing.to_bytes();
    let channel_key = [0xCD_u8; 32];
    let channel_id = [0x11_u8; 16];
    let channel_key_id = [0x22_u8; 16];

    let code = unsafe {
        aura_channel_encrypt_message(
            ptr::null(),
            16, // non-zero length with null plaintext is invalid
            channel_key.as_ptr(),
            channel_id.as_ptr(),
            channel_key_id.as_ptr(),
            0,
            secret_bytes.as_ptr(),
            nonce.as_mut_ptr(),
            signature.as_mut_ptr(),
            &mut ciphertext as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
}

#[test]
fn decrypt_rejects_null_pointers() {
    init();
    let mut decrypted = null_buffer();
    let mut err = null_error();
    let code = unsafe {
        aura_channel_decrypt_message(
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &mut decrypted as *mut _,
            &mut err as *mut _,
        )
    };
    assert_eq!(code, AuraErrorCode::AuraErrorNullPointer);
}
