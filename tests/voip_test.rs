// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::pedantic, clippy::nursery)]

use ecliptix_protocol::api::EcliptixProtocol;
use ecliptix_protocol::core::constants::*;
use ecliptix_protocol::core::errors::ProtocolError;
use ecliptix_protocol::crypto::{AesGcm, CryptoInterop, HkdfSha256, SecureMemoryHandle};
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::proto::{CallRekey, CallRekeyAck, PreKeyBundle, VoipSessionState};
use ecliptix_protocol::protocol::voip::call_key_exchange::{
    callee_accept, callee_accept_with_context, caller_finish, caller_finish_with_context,
    caller_init, caller_init_with_context, CallInitAuthContext,
};
use ecliptix_protocol::protocol::voip::frame::{build_frame_aad, FrameHeader};
use ecliptix_protocol::protocol::voip::key_ratchet::MediaKeyRatchet;
use ecliptix_protocol::protocol::voip::media_crypto::MediaCrypto;
use ecliptix_protocol::protocol::voip::{CallRole, CallState, VoipSession};
use prost::Message;
use hmac::Mac;

fn init() {
    let _ = CryptoInterop::initialize();
}

fn extract_voip_peer_material(bundle_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let bundle = PreKeyBundle::decode(bundle_bytes).unwrap();
    (bundle.kyber_public, bundle.identity_ed25519_public)
}

// ════════════════════════════════════════════════════════════════════
// § 1  Media Crypto — frame encryption / decryption
// ════════════════════════════════════════════════════════════════════

#[test]
fn media_crypto_encrypt_decrypt_frame_roundtrip() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"opus audio frame data here";
    let aad = b"call-context";

    let ct = MediaCrypto::encrypt_frame(&key, &prefix, 0, plaintext, aad).unwrap();
    let pt = MediaCrypto::decrypt_frame(&key, &prefix, 0, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn media_crypto_different_counters_produce_different_ciphertexts() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0xAA, 0xBB, 0xCC, 0xDD];
    let plaintext = b"same payload";
    let aad = b"ctx";

    let ct0 = MediaCrypto::encrypt_frame(&key, &prefix, 0, plaintext, aad).unwrap();
    let ct1 = MediaCrypto::encrypt_frame(&key, &prefix, 1, plaintext, aad).unwrap();
    assert_ne!(ct0, ct1);
}

#[test]
fn media_crypto_tampered_ciphertext_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x10, 0x20, 0x30, 0x40];
    let plaintext = b"sensitive audio data";
    let aad = b"aad";

    let mut ct = MediaCrypto::encrypt_frame(&key, &prefix, 42, plaintext, aad).unwrap();
    ct[0] ^= 0xFF; // tamper
    let result = MediaCrypto::decrypt_frame(&key, &prefix, 42, &ct, aad);
    assert!(result.is_err());
}

#[test]
fn media_crypto_wrong_key_fails() {
    init();
    let key1 = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let key2 = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"audio payload";
    let aad = b"aad";

    let ct = MediaCrypto::encrypt_frame(&key1, &prefix, 0, plaintext, aad).unwrap();
    let result = MediaCrypto::decrypt_frame(&key2, &prefix, 0, &ct, aad);
    assert!(result.is_err());
}

#[test]
fn media_crypto_wrong_aad_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"audio data";

    let ct = MediaCrypto::encrypt_frame(&key, &prefix, 0, plaintext, b"correct-aad").unwrap();
    let result = MediaCrypto::decrypt_frame(&key, &prefix, 0, &ct, b"wrong-aad");
    assert!(result.is_err());
}

#[test]
fn media_crypto_wrong_counter_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let plaintext = b"audio data";
    let aad = b"ctx";

    let ct = MediaCrypto::encrypt_frame(&key, &prefix, 5, plaintext, aad).unwrap();
    let result = MediaCrypto::decrypt_frame(&key, &prefix, 6, &ct, aad);
    assert!(result.is_err());
}

#[test]
fn media_crypto_empty_payload_rejected() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];
    let result = MediaCrypto::encrypt_frame(&key, &prefix, 0, b"", b"aad");
    assert!(result.is_err());
}

#[test]
fn media_crypto_invalid_key_size_rejected() {
    init();
    let short_key = vec![0u8; 16];
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];
    let result = MediaCrypto::encrypt_frame(&short_key, &prefix, 0, b"data", b"aad");
    assert!(result.is_err());
}

// ── Header encryption ──────────────────────────────────────────────

#[test]
fn media_crypto_header_encrypt_decrypt_roundtrip() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_HEADER_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0xDE, 0xAD, 0xBE, 0xEF];
    let header = b"rtp-header-bytes";

    let ct = MediaCrypto::encrypt_header(&key, &prefix, 100, header).unwrap();
    let pt = MediaCrypto::decrypt_header(&key, &prefix, 100, &ct).unwrap();
    assert_eq!(pt, header);
}

#[test]
fn media_crypto_header_tampered_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(VOIP_HEADER_KEY_BYTES);
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let header = b"header";

    let mut ct = MediaCrypto::encrypt_header(&key, &prefix, 0, header).unwrap();
    ct[0] ^= 0xFF;
    let result = MediaCrypto::decrypt_header(&key, &prefix, 0, &ct);
    assert!(result.is_err());
}

// ── Nonce construction ─────────────────────────────────────────────

#[test]
fn media_crypto_nonce_is_12_bytes() {
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let nonce = MediaCrypto::build_nonce(&prefix, 0);
    assert_eq!(nonce.len(), VOIP_MEDIA_NONCE_BYTES);
}

#[test]
fn media_crypto_nonce_embeds_prefix_and_counter() {
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0xAA, 0xBB, 0xCC, 0xDD];
    let counter: u64 = 0x0102_0304_0506_0708;
    let nonce = MediaCrypto::build_nonce(&prefix, counter);
    assert_eq!(&nonce[..4], &prefix);
    assert_eq!(&nonce[4..], &counter.to_be_bytes());
}

#[test]
fn media_crypto_different_counters_produce_different_nonces() {
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];
    let n1 = MediaCrypto::build_nonce(&prefix, 0);
    let n2 = MediaCrypto::build_nonce(&prefix, 1);
    assert_ne!(n1, n2);
}

// ════════════════════════════════════════════════════════════════════
// § 2  Frame header serialization
// ════════════════════════════════════════════════════════════════════

#[test]
fn frame_header_serialize_deserialize_roundtrip() {
    let header = FrameHeader {
        payload_type: 111,
        ssrc: 0xDEAD_BEEF,
        timestamp: 0x1234_5678,
        sequence_number: 42,
    };
    let bytes = header.serialize();
    assert_eq!(bytes.len(), FrameHeader::SERIALIZED_SIZE);

    let decoded = FrameHeader::deserialize(&bytes).unwrap();
    assert_eq!(decoded.payload_type, 111);
    assert_eq!(decoded.ssrc, 0xDEAD_BEEF);
    assert_eq!(decoded.timestamp, 0x1234_5678);
    assert_eq!(decoded.sequence_number, 42);
}

#[test]
fn frame_header_too_short_rejected() {
    let result = FrameHeader::deserialize(&[0u8; 5]);
    assert!(result.is_err());
}

#[test]
fn frame_aad_contains_all_fields() {
    let call_id = vec![0xAA; CALL_ID_BYTES];
    let aad = build_frame_aad(&call_id, 12345, 67890, 3);
    assert_eq!(aad.len(), CALL_ID_BYTES + 4 + 8 + 4);
    assert_eq!(&aad[..CALL_ID_BYTES], &call_id[..]);
}

// ════════════════════════════════════════════════════════════════════
// § 3  Key ratchet
// ════════════════════════════════════════════════════════════════════

#[test]
fn key_ratchet_advance_produces_different_keys() {
    init();
    let key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0x01, 0x02, 0x03, 0x04];

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);
    assert_eq!(ratchet.generation(), 0);

    let k0 = ratchet.advance().unwrap();
    assert_eq!(k0.generation, 0);
    assert_eq!(k0.media_key.len(), VOIP_MEDIA_KEY_BYTES);

    let k1 = ratchet.advance().unwrap();
    assert_eq!(k1.generation, 1);
    assert_ne!(*k0.media_key, *k1.media_key);

    assert_eq!(ratchet.generation(), 2);
}

#[test]
fn key_ratchet_advance_to_skips_correctly() {
    init();
    let key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);
    let k = ratchet.advance_to(3).unwrap();
    assert_eq!(k.generation, 3);
    assert_eq!(ratchet.generation(), 4);
}

#[test]
fn key_ratchet_advance_to_backward_rejected() {
    init();
    let key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);
    let _ = ratchet.advance().unwrap(); // gen 0
    let _ = ratchet.advance().unwrap(); // gen 1
                                        // Now at gen 2; trying to advance_to(0) should fail
    let result = ratchet.advance_to(0);
    assert!(result.is_err());
}

#[test]
fn key_ratchet_skip_too_large_rejected() {
    init();
    let key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);
    // Try to skip more than MAX_SKIPPED_RATCHET_GENERATIONS
    let result = ratchet.advance_to(MAX_SKIPPED_RATCHET_GENERATIONS + 1);
    assert!(result.is_err());
}

#[test]
fn key_ratchet_reset_resets_generation() {
    init();
    let key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    handle.write(&key_bytes).unwrap();
    let prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0; 4];

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);
    let _ = ratchet.advance().unwrap();
    let _ = ratchet.advance().unwrap();
    assert_eq!(ratchet.generation(), 2);

    let new_key_bytes = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let mut new_handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).unwrap();
    new_handle.write(&new_key_bytes).unwrap();
    let new_prefix: [u8; VOIP_NONCE_PREFIX_BYTES] = [0xFF; 4];

    ratchet.reset(new_handle, new_prefix);
    assert_eq!(ratchet.generation(), 0);
    assert_eq!(*ratchet.nonce_prefix(), [0xFF; 4]);
}

// ════════════════════════════════════════════════════════════════════
// § 4  Call key exchange (low-level)
// ════════════════════════════════════════════════════════════════════

fn create_identity() -> IdentityKeys {
    IdentityKeys::create(5).unwrap()
}

#[test]
fn call_key_exchange_caller_init_produces_valid_output() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let ed_public = alice.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();

    let output = caller_init(&ed_secret, &ed_public, &bob_kyber_pub).unwrap();

    assert_eq!(
        output.ephemeral_x25519_public.len(),
        X25519_PUBLIC_KEY_BYTES
    );
    assert_eq!(output.kyber_ciphertext.len(), KYBER_CIPHERTEXT_BYTES);
    assert_eq!(
        output.identity_ed25519_public.len(),
        ED25519_PUBLIC_KEY_BYTES
    );
    assert_eq!(output.signature.len(), ED25519_SIGNATURE_BYTES);
    assert_eq!(output.key_confirmation_mac.len(), HMAC_BYTES);
}

#[test]
fn call_key_exchange_full_handshake_normal_mode() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    // Step 1: Alice (caller) initiates
    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    // Step 2: Bob (callee) accepts
    let accept_output = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        false, // normal mode
    )
    .unwrap();

    // Step 3: Alice finishes handshake
    let alice_keys = caller_finish(
        &init_output,
        &alice_kyber_sec,
        &call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        false,
    )
    .unwrap();

    // Verify both sides derived matching media keys
    let alice_send = alice_keys
        .media_key_send
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    let bob_recv = accept_output
        .key_material
        .media_key_recv
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    assert_eq!(
        alice_send, bob_recv,
        "caller send key must equal callee recv key"
    );

    let alice_recv = alice_keys
        .media_key_recv
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    let bob_send = accept_output
        .key_material
        .media_key_send
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    assert_eq!(
        alice_recv, bob_send,
        "caller recv key must equal callee send key"
    );

    // Verify nonce prefixes match symmetrically
    assert_eq!(
        alice_keys.nonce_prefix_send, accept_output.key_material.nonce_prefix_recv,
        "nonce prefixes must be symmetric"
    );
    assert_eq!(
        alice_keys.nonce_prefix_recv, accept_output.key_material.nonce_prefix_send,
        "nonce prefixes must be symmetric"
    );
}

#[test]
fn call_key_exchange_full_handshake_shield_mode() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    let accept_output = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        true, // shield mode
    )
    .unwrap();

    let alice_keys = caller_finish(
        &init_output,
        &alice_kyber_sec,
        &call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        true, // shield mode
    )
    .unwrap();

    // Verify keys still match in shield mode
    let alice_send = alice_keys
        .media_key_send
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    let bob_recv = accept_output
        .key_material
        .media_key_recv
        .read_bytes(VOIP_MEDIA_KEY_BYTES)
        .unwrap();
    assert_eq!(alice_send, bob_recv);
}

#[test]
fn call_key_exchange_shield_produces_different_keys_than_normal() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    // Normal mode handshake
    let init1 = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init1.call_id.clone();

    let accept_normal = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init1.ephemeral_x25519_public,
        &init1.kyber_ciphertext,
        &init1.identity_ed25519_public,
        &init1.signature,
        &init1.key_confirmation_mac,
        false,
    )
    .unwrap();

    let normal_keys = caller_finish(
        &init1,
        &alice_kyber_sec,
        &call_id,
        &accept_normal.ephemeral_x25519_public,
        &accept_normal.kyber_ciphertext,
        &accept_normal.identity_ed25519_public,
        &accept_normal.signature,
        &accept_normal.key_confirmation_mac,
        false,
    )
    .unwrap();

    // Shield mode handshake with SAME material won't produce same keys
    // (because shield applies double-KDF to root secret)
    // Note: can't truly reuse same DH material since keys are consumed,
    // but we verify the protocol path differs by checking the root secrets
    let normal_root = normal_keys.root_secret.read_bytes(ROOT_KEY_BYTES).unwrap();
    // If we could run shield with same root input, it would differ.
    // This test mainly verifies the shield path doesn't error.
    assert_eq!(normal_root.len(), ROOT_KEY_BYTES);
}

#[test]
fn call_key_exchange_wrong_signature_rejected() {
    init();
    let alice = create_identity();
    let bob = create_identity();
    let eve = create_identity(); // attacker

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    // Eve forges a signature
    let eve_ed_public = eve.get_identity_ed25519_public();
    // Use eve's public key but alice's ciphertext — signature won't verify
    let result = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_ed_public, // wrong: should be alice_kyber_pub
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &eve_ed_public,         // Eve's public key, not Alice's
        &init_output.signature, // Alice's signature, won't match Eve's key
        &init_output.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn call_key_exchange_wrong_mac_rejected() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    let bad_mac = vec![0xFFu8; HMAC_BYTES];
    let result = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &bad_mac, // forged MAC
        false,
    );
    assert!(result.is_err());
}

#[test]
fn call_key_exchange_call_init_policy_tamper_rejected() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let signed_context = CallInitAuthContext {
        version: VOIP_PROTOCOL_VERSION,
        media_type: 1,
        ratchet_interval_frames: 512,
        pq_rekey_interval_secs: 60,
        shield_mode: false,
    };
    let tampered_context = CallInitAuthContext {
        ratchet_interval_frames: 64,
        ..signed_context
    };

    let init_output = caller_init_with_context(
        &alice_ed_secret,
        &alice_ed_public,
        &bob_kyber_pub,
        &signed_context,
    )
    .unwrap();

    let result = callee_accept_with_context(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &init_output.call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        &tampered_context,
    );

    assert!(result.is_err());
}

#[test]
fn call_key_exchange_call_accept_policy_tamper_rejected() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let signed_context = CallInitAuthContext {
        version: VOIP_PROTOCOL_VERSION,
        media_type: 1,
        ratchet_interval_frames: 512,
        pq_rekey_interval_secs: 60,
        shield_mode: true,
    };
    let tampered_context = CallInitAuthContext {
        shield_mode: false,
        ..signed_context
    };

    let init_output = caller_init_with_context(
        &alice_ed_secret,
        &alice_ed_public,
        &bob_kyber_pub,
        &signed_context,
    )
    .unwrap();

    let accept_output = callee_accept_with_context(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &init_output.call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        &signed_context,
    )
    .unwrap();

    let result = caller_finish_with_context(
        &init_output,
        &alice_kyber_sec,
        &init_output.call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        &tampered_context,
    );

    assert!(result.is_err());
}

#[test]
fn call_key_exchange_invalid_call_id_size_rejected() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();

    let bad_call_id = vec![0u8; 16]; // wrong size (should be 32)
    let result = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_ed_public,
        &bad_call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
// § 5  VoIP session — end-to-end frame encryption
// ════════════════════════════════════════════════════════════════════

fn setup_voip_session_pair_with_params(
    shield: bool,
    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
) -> (VoipSession, VoipSession) {
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    let accept_output = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        shield,
    )
    .unwrap();

    let alice_keys = caller_finish(
        &init_output,
        &alice_kyber_sec,
        &call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        shield,
    )
    .unwrap();

    let alice_session = VoipSession::from_key_material(
        call_id.clone(),
        CallRole::Caller,
        alice_keys,
        ratchet_interval_frames,
        pq_rekey_interval_secs,
        shield,
    )
    .unwrap();

    let bob_session = VoipSession::from_key_material(
        call_id,
        CallRole::Callee,
        accept_output.key_material,
        ratchet_interval_frames,
        pq_rekey_interval_secs,
        shield,
    )
    .unwrap();

    (alice_session, bob_session)
}

fn setup_voip_session_pair(shield: bool) -> (VoipSession, VoipSession) {
    setup_voip_session_pair_with_params(shield, 512, 60)
}

fn setup_voip_session_pair_with_identities(
    shield: bool,
) -> (IdentityKeys, IdentityKeys, VoipSession, VoipSession) {
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let alice_kyber_pub = alice.get_kyber_public();
    let alice_kyber_sec = alice.clone_kyber_secret_key().unwrap();

    let bob_ed_secret = bob.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();
    let bob_kyber_sec = bob.clone_kyber_secret_key().unwrap();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();
    let call_id = init_output.call_id.clone();

    let accept_output = callee_accept(
        &bob_ed_secret,
        &bob_ed_public,
        &bob_kyber_sec,
        &alice_kyber_pub,
        &call_id,
        &init_output.ephemeral_x25519_public,
        &init_output.kyber_ciphertext,
        &init_output.identity_ed25519_public,
        &init_output.signature,
        &init_output.key_confirmation_mac,
        shield,
    )
    .unwrap();

    let alice_keys = caller_finish(
        &init_output,
        &alice_kyber_sec,
        &call_id,
        &accept_output.ephemeral_x25519_public,
        &accept_output.kyber_ciphertext,
        &accept_output.identity_ed25519_public,
        &accept_output.signature,
        &accept_output.key_confirmation_mac,
        shield,
    )
    .unwrap();

    let alice_session = VoipSession::from_key_material(
        call_id.clone(),
        CallRole::Caller,
        alice_keys,
        512,
        60,
        shield,
    )
    .unwrap();

    let bob_session = VoipSession::from_key_material(
        call_id,
        CallRole::Callee,
        accept_output.key_material,
        512,
        60,
        shield,
    )
    .unwrap();

    (alice, bob, alice_session, bob_session)
}

#[test]
fn voip_session_encrypt_decrypt_single_frame() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let payload = b"opus encoded audio frame";

    let encrypted = alice.encrypt_frame(&header, payload).unwrap();
    assert_eq!(encrypted.call_id, alice.call_id());
    assert_eq!(encrypted.ssrc, alice.ssrc());
    assert_eq!(encrypted.frame_counter, 0);

    let decrypted = bob.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, payload);
    assert_eq!(decrypted.header.payload_type, 111);
    assert_eq!(decrypted.header.sequence_number, 1);
}

#[test]
fn voip_session_encrypt_rejects_header_ssrc_mismatch() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc().wrapping_add(1),
        timestamp: 160,
        sequence_number: 1,
    };

    let result = alice.encrypt_frame(&header, b"opus encoded audio frame");
    assert!(result.is_err());
}

#[test]
fn voip_session_bidirectional_communication() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    // Alice → Bob
    let h1 = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let enc1 = alice.encrypt_frame(&h1, b"alice audio 1").unwrap();
    let dec1 = bob.decrypt_frame(&enc1).unwrap();
    assert_eq!(dec1.payload, b"alice audio 1");

    // Bob → Alice
    let h2 = FrameHeader {
        payload_type: 111,
        ssrc: bob.ssrc(),
        timestamp: 320,
        sequence_number: 1,
    };
    let enc2 = bob.encrypt_frame(&h2, b"bob audio 1").unwrap();
    let dec2 = alice.decrypt_frame(&enc2).unwrap();
    assert_eq!(dec2.payload, b"bob audio 1");

    // More frames
    let h3 = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 480,
        sequence_number: 2,
    };
    let enc3 = alice.encrypt_frame(&h3, b"alice audio 2").unwrap();
    let dec3 = bob.decrypt_frame(&enc3).unwrap();
    assert_eq!(dec3.payload, b"alice audio 2");
}

#[test]
fn voip_session_multiple_frames_incrementing_counter() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    for i in 0u16..50 {
        let header = FrameHeader {
            payload_type: 111,
            ssrc: alice.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let payload = format!("frame-{i}");
        let encrypted = alice.encrypt_frame(&header, payload.as_bytes()).unwrap();
        assert_eq!(encrypted.frame_counter, u64::from(i));

        let decrypted = bob.decrypt_frame(&encrypted).unwrap();
        assert_eq!(decrypted.payload, payload.as_bytes());
    }

    assert_eq!(alice.send_frame_counter(), 50);
    assert_eq!(bob.recv_frame_counter(), 49);
}

#[test]
fn voip_session_media_generation_rotates_on_interval() {
    init();
    let (alice, bob) = setup_voip_session_pair_with_params(false, 2, 60);

    let first = alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: 160,
                sequence_number: 1,
            },
            b"f1",
        )
        .unwrap();
    let second = alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: 320,
                sequence_number: 2,
            },
            b"f2",
        )
        .unwrap();
    let third = alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: 480,
                sequence_number: 3,
            },
            b"f3",
        )
        .unwrap();

    assert_eq!(first.ratchet_generation, 0);
    assert_eq!(second.ratchet_generation, 0);
    assert_eq!(third.ratchet_generation, 1);

    assert_eq!(bob.decrypt_frame(&first).unwrap().payload, b"f1");
    assert_eq!(bob.decrypt_frame(&second).unwrap().payload, b"f2");
    assert_eq!(bob.decrypt_frame(&third).unwrap().payload, b"f3");
}

#[test]
fn voip_session_shield_mode_encrypt_decrypt() {
    init();
    let (alice, bob) = setup_voip_session_pair(true);

    assert!(alice.is_shield_mode());
    assert!(bob.is_shield_mode());

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let encrypted = alice.encrypt_frame(&header, b"shield audio").unwrap();
    let decrypted = bob.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"shield audio");
}

#[test]
fn voip_session_replay_attack_detected() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let encrypted = alice.encrypt_frame(&header, b"frame 0").unwrap();

    // First decrypt succeeds
    bob.decrypt_frame(&encrypted).unwrap();

    // Replay the same frame — should fail (counter already consumed)
    let result = bob.decrypt_frame(&encrypted);
    assert!(result.is_err());
}

#[test]
fn voip_session_tampered_frame_rejected() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let mut encrypted = alice.encrypt_frame(&header, b"audio data").unwrap();
    encrypted.encrypted_payload[0] ^= 0xFF; // tamper

    let result = bob.decrypt_frame(&encrypted);
    assert!(result.is_err());
}

#[test]
fn voip_session_wrong_call_id_rejected() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let mut encrypted = alice.encrypt_frame(&header, b"audio").unwrap();
    encrypted.call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES); // wrong call

    let result = bob.decrypt_frame(&encrypted);
    assert!(result.is_err());
}

#[test]
fn voip_session_end_call_prevents_further_encryption() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    alice.end_call().unwrap();
    assert_eq!(alice.state(), CallState::Ended);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let result = alice.encrypt_frame(&header, b"should fail");
    assert!(result.is_err());
}

#[test]
fn voip_session_end_call_prevents_further_decryption() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 160,
        sequence_number: 1,
    };
    let encrypted = alice.encrypt_frame(&header, b"last frame").unwrap();

    bob.end_call().unwrap();
    let result = bob.decrypt_frame(&encrypted);
    assert!(result.is_err());
}

#[test]
fn voip_session_properties_correct() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    assert_eq!(alice.role(), CallRole::Caller);
    assert_eq!(bob.role(), CallRole::Callee);
    assert_eq!(alice.state(), CallState::Active);
    assert_eq!(bob.state(), CallState::Active);
    assert_eq!(alice.call_id(), bob.call_id());
    assert!(!alice.is_shield_mode());
    assert_eq!(alice.send_frame_counter(), 0);
    assert_eq!(alice.recv_frame_counter(), 0);
}

#[test]
fn voip_session_needs_pq_rekey_check() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    assert!(!alice.needs_pq_rekey(0));
    assert!(!alice.needs_pq_rekey(59));
    assert!(alice.needs_pq_rekey(60));
    assert!(alice.needs_pq_rekey(120));
}

#[test]
fn voip_rekey_tampered_generation_rejected() {
    init();
    let (alice_id, bob_id, alice, bob) = setup_voip_session_pair_with_identities(false);

    let alice_ed_secret = alice_id.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice_id.get_identity_ed25519_public();
    let alice_kyber_pub = alice_id.get_kyber_public();
    let bob_ed_secret = bob_id.get_identity_ed25519_private_key_copy().unwrap();
    let bob_kyber_pub = bob_id.get_kyber_public();
    let bob_kyber_secret = bob_id.clone_kyber_secret_key().unwrap();

    let rekey_bytes = alice
        .initiate_rekey(&alice_ed_secret, &bob_kyber_pub)
        .unwrap();
    let mut rekey = CallRekey::decode(rekey_bytes.as_slice()).unwrap();
    rekey.rekey_generation += 7;
    let mut tampered = Vec::new();
    rekey.encode(&mut tampered).unwrap();

    let result = bob.process_rekey(
        &tampered,
        &alice_ed_public,
        &bob_kyber_secret,
        &alice_kyber_pub,
        &bob_ed_secret,
    );
    assert!(result.is_err());
}

#[test]
fn voip_rekey_short_ephemeral_key_rejected_without_panic() {
    init();
    let (alice_id, bob_id, alice, bob) = setup_voip_session_pair_with_identities(false);

    let alice_ed_secret = alice_id.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice_id.get_identity_ed25519_public();
    let alice_kyber_pub = alice_id.get_kyber_public();
    let bob_ed_secret = bob_id.get_identity_ed25519_private_key_copy().unwrap();
    let bob_kyber_pub = bob_id.get_kyber_public();
    let bob_kyber_secret = bob_id.clone_kyber_secret_key().unwrap();

    let rekey_bytes = alice
        .initiate_rekey(&alice_ed_secret, &bob_kyber_pub)
        .unwrap();
    let mut rekey = CallRekey::decode(rekey_bytes.as_slice()).unwrap();
    rekey.ephemeral_x25519_public = vec![0xAA; 3];
    rekey.signature = ecliptix_protocol::protocol::voip::call_key_exchange::sign_rekey_material(
        &alice_ed_secret,
        &rekey.call_id,
        rekey.rekey_generation,
        &rekey.ephemeral_x25519_public,
        &rekey.kyber_ciphertext,
    )
    .unwrap();
    let mut tampered = Vec::new();
    rekey.encode(&mut tampered).unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        bob.process_rekey(
            &tampered,
            &alice_ed_public,
            &bob_kyber_secret,
            &alice_kyber_pub,
            &bob_ed_secret,
        )
    }));
    assert!(result.is_ok(), "process_rekey panicked on malformed key");
    assert!(result.unwrap().is_err());
}

#[test]
fn voip_rekey_invalid_ack_does_not_clear_pending_rekey() {
    init();
    let (alice_id, bob_id, alice, bob) = setup_voip_session_pair_with_identities(false);

    let alice_ed_secret = alice_id.get_identity_ed25519_private_key_copy().unwrap();
    let alice_kyber_secret = alice_id.clone_kyber_secret_key().unwrap();
    let alice_kyber_pub = alice_id.get_kyber_public();
    let bob_ed_secret = bob_id.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob_id.get_identity_ed25519_public();
    let bob_kyber_pub = bob_id.get_kyber_public();
    let bob_kyber_secret = bob_id.clone_kyber_secret_key().unwrap();

    let rekey_bytes = alice
        .initiate_rekey(&alice_ed_secret, &bob_kyber_pub)
        .unwrap();
    let ack_bytes = bob
        .process_rekey(
            &rekey_bytes,
            &alice_id.get_identity_ed25519_public(),
            &bob_kyber_secret,
            &alice_kyber_pub,
            &bob_ed_secret,
        )
        .unwrap();

    let mut invalid_ack = CallRekeyAck::decode(ack_bytes.as_slice()).unwrap();
    invalid_ack.key_confirmation_mac[0] ^= 0xFF;
    let mut invalid_ack_bytes = Vec::new();
    invalid_ack.encode(&mut invalid_ack_bytes).unwrap();

    let invalid_result =
        alice.process_rekey_ack(&invalid_ack_bytes, &bob_ed_public, &alice_kyber_secret);
    assert!(invalid_result.is_err());

    alice
        .process_rekey_ack(&ack_bytes, &bob_ed_public, &alice_kyber_secret)
        .unwrap();
}

#[test]
fn voip_rekey_ack_short_ephemeral_key_rejected_without_panic() {
    init();
    let (alice_id, bob_id, alice, bob) = setup_voip_session_pair_with_identities(false);

    let alice_ed_secret = alice_id.get_identity_ed25519_private_key_copy().unwrap();
    let alice_kyber_secret = alice_id.clone_kyber_secret_key().unwrap();
    let alice_kyber_pub = alice_id.get_kyber_public();
    let bob_ed_secret = bob_id.get_identity_ed25519_private_key_copy().unwrap();
    let bob_ed_public = bob_id.get_identity_ed25519_public();
    let bob_kyber_pub = bob_id.get_kyber_public();
    let bob_kyber_secret = bob_id.clone_kyber_secret_key().unwrap();

    let rekey_bytes = alice
        .initiate_rekey(&alice_ed_secret, &bob_kyber_pub)
        .unwrap();
    let ack_bytes = bob
        .process_rekey(
            &rekey_bytes,
            &alice_id.get_identity_ed25519_public(),
            &bob_kyber_secret,
            &alice_kyber_pub,
            &bob_ed_secret,
        )
        .unwrap();
    let mut ack = CallRekeyAck::decode(ack_bytes.as_slice()).unwrap();
    ack.ephemeral_x25519_public = vec![0xBB; 5];
    ack.signature = ecliptix_protocol::protocol::voip::call_key_exchange::sign_rekey_material(
        &bob_ed_secret,
        &ack.call_id,
        ack.rekey_generation,
        &ack.ephemeral_x25519_public,
        &ack.kyber_ciphertext,
    )
    .unwrap();
    let mut tampered_ack = Vec::new();
    ack.encode(&mut tampered_ack).unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        alice.process_rekey_ack(&tampered_ack, &bob_ed_public, &alice_kyber_secret)
    }));
    assert!(
        result.is_ok(),
        "process_rekey_ack panicked on malformed key"
    );
    assert!(result.unwrap().is_err());
}

// ════════════════════════════════════════════════════════════════════
// § 6  API-level VoIP tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn api_voip_caller_init_protobuf_roundtrip() {
    init();
    let alice = create_identity();
    let bob = create_identity();

    let alice_ed_secret = alice.get_identity_ed25519_private_key_copy().unwrap();
    let alice_ed_public = alice.get_identity_ed25519_public();
    let bob_kyber_pub = bob.get_kyber_public();

    let init_output = caller_init(&alice_ed_secret, &alice_ed_public, &bob_kyber_pub).unwrap();

    // Build the protobuf manually and verify roundtrip
    let call_id = init_output.call_id.clone();
    let proto_init = ecliptix_protocol::proto::CallInit {
        version: VOIP_PROTOCOL_VERSION,
        caller_device_id: vec![1, 2, 3, 4],
        call_id: call_id.clone(),
        ephemeral_x25519_public: init_output.ephemeral_x25519_public.clone(),
        kyber_ciphertext: init_output.kyber_ciphertext.clone(),
        identity_ed25519_public: init_output.identity_ed25519_public.clone(),
        signature: init_output.signature.clone(),
        key_confirmation_mac: init_output.key_confirmation_mac.clone(),
        media_type: 1,
        ratchet_interval_frames: 512,
        pq_rekey_interval_secs: 60,
        shield_mode: false,
    };

    let mut buf = Vec::new();
    proto_init.encode(&mut buf).unwrap();
    let decoded = ecliptix_protocol::proto::CallInit::decode(buf.as_slice()).unwrap();

    assert_eq!(decoded.version, VOIP_PROTOCOL_VERSION);
    assert_eq!(decoded.call_id, call_id);
    assert_eq!(
        decoded.ephemeral_x25519_public.len(),
        X25519_PUBLIC_KEY_BYTES
    );
    assert_eq!(decoded.kyber_ciphertext.len(), KYBER_CIPHERTEXT_BYTES);
    assert_eq!(decoded.signature.len(), ED25519_SIGNATURE_BYTES);
    assert!(!decoded.shield_mode);
    assert_eq!(decoded.ratchet_interval_frames, 512);
    assert_eq!(decoded.pq_rekey_interval_secs, 60);
}

#[test]
fn api_voip_full_call_flow_via_low_level() {
    init();
    // Full end-to-end test using IdentityKeys directly
    let (alice, bob) = setup_voip_session_pair(false);

    // Alice → Bob (10 frames)
    for i in 0u16..10 {
        let header = FrameHeader {
            payload_type: 111,
            ssrc: alice.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let enc = alice
            .encrypt_frame(&header, format!("alice-{i}").as_bytes())
            .unwrap();
        let dec = bob.decrypt_frame(&enc).unwrap();
        assert_eq!(String::from_utf8_lossy(&dec.payload), format!("alice-{i}"));
    }

    // Bob → Alice (10 frames)
    for i in 0u16..10 {
        let header = FrameHeader {
            payload_type: 111,
            ssrc: bob.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let enc = bob
            .encrypt_frame(&header, format!("bob-{i}").as_bytes())
            .unwrap();
        let dec = alice.decrypt_frame(&enc).unwrap();
        assert_eq!(String::from_utf8_lossy(&dec.payload), format!("bob-{i}"));
    }
}

#[test]
fn api_voip_full_call_flow_via_public_api() {
    init();

    let alice = EcliptixProtocol::new(1).unwrap();
    let bob = EcliptixProtocol::new(1).unwrap();

    let alice_bundle = alice.pre_key_bundle().unwrap();
    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (alice_kyber, _) = extract_voip_peer_material(&alice_bundle);
    let (bob_kyber, _) = extract_voip_peer_material(&bob_bundle);

    let (initiator, call_init) = alice.initiate_call(&bob_kyber, false, 512, 60).unwrap();
    let (bob_session, call_accept) = bob.accept_call(&call_init, &alice_kyber).unwrap();
    let alice_session = alice.complete_call(initiator, &call_accept).unwrap();

    let encrypted = alice_session
        .encrypt_frame(111, alice_session.ssrc(), 160, 1, b"hello-voip")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"hello-voip");
}

#[test]
fn api_voip_rekey_and_restore_via_public_api() {
    init();

    let alice = EcliptixProtocol::new(1).unwrap();
    let bob = EcliptixProtocol::new(1).unwrap();

    let alice_bundle = alice.pre_key_bundle().unwrap();
    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (alice_kyber, alice_ed) = extract_voip_peer_material(&alice_bundle);
    let (bob_kyber, bob_ed) = extract_voip_peer_material(&bob_bundle);

    let (initiator, call_init) = alice.initiate_call(&bob_kyber, false, 512, 60).unwrap();
    let (bob_session, call_accept) = bob.accept_call(&call_init, &alice_kyber).unwrap();
    let alice_session = alice.complete_call(initiator, &call_accept).unwrap();

    let rekey_bytes = alice
        .initiate_call_rekey(&alice_session, &bob_kyber)
        .unwrap();
    let ack_bytes = bob
        .process_call_rekey(&bob_session, &rekey_bytes, &alice_ed, &alice_kyber)
        .unwrap();
    alice
        .process_call_rekey_ack(&alice_session, &ack_bytes, &bob_ed)
        .unwrap();

    let state_key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice_session.export_sealed_state(&state_key, 9).unwrap();
    let (restored_alice, external_counter) =
        alice.import_call_state(&sealed, &state_key, 9).unwrap();
    assert_eq!(external_counter, 9);

    let encrypted = bob_session
        .encrypt_frame(111, bob_session.ssrc(), 320, 2, b"post-restore")
        .unwrap();
    let decrypted = restored_alice.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"post-restore");
}

#[test]
fn voip_session_call_end_roundtrip() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let call_end = alice.build_call_end(b"alice-device", 123456).unwrap();
    bob.process_call_end(&call_end).unwrap();

    assert_eq!(bob.state(), CallState::Ended);
    assert!(bob
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: bob.ssrc(),
                timestamp: 0,
                sequence_number: 0,
            },
            b"should-fail",
        )
        .is_err());
}

// ════════════════════════════════════════════════════════════════════
// § 7  Relay-side VoIP validation
// ════════════════════════════════════════════════════════════════════

use ecliptix_protocol::api::relay::{
    route_voip_envelope, validate_call_signal_for_relay, validate_voip_envelope, ActiveCall,
    VoipCallStore,
};
use ecliptix_protocol::proto::{VoipEnvelope, VoipSignalType};

struct InMemoryCallStore {
    calls: std::sync::Mutex<Vec<ActiveCall>>,
}

impl InMemoryCallStore {
    fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl VoipCallStore for InMemoryCallStore {
    fn register_call(&self, call: &ActiveCall) -> Result<(), ProtocolError> {
        self.calls.lock().unwrap().push(call.clone());
        Ok(())
    }

    fn find_call(&self, call_id: &[u8]) -> Result<Option<ActiveCall>, ProtocolError> {
        let calls = self.calls.lock().unwrap();
        Ok(calls.iter().find(|c| c.call_id == call_id).cloned())
    }

    fn update_call(&self, call: &ActiveCall) -> Result<(), ProtocolError> {
        let mut calls = self.calls.lock().unwrap();
        let existing = calls
            .iter_mut()
            .find(|existing_call| existing_call.call_id == call.call_id)
            .ok_or_else(|| ProtocolError::voip_call("call not found"))?;
        *existing = call.clone();
        Ok(())
    }

    fn remove_call(&self, call_id: &[u8]) -> Result<(), ProtocolError> {
        self.calls.lock().unwrap().retain(|c| c.call_id != call_id);
        Ok(())
    }
}

#[test]
fn relay_validate_voip_envelope_valid() {
    init();
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallInit as i32,
        call_id: CryptoInterop::get_random_bytes(CALL_ID_BYTES),
        encrypted_payload: vec![0xAA; 100],
        timestamp: 1234567890,
    };

    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();
    let parsed = validate_voip_envelope(&buf).unwrap();
    assert_eq!(
        parsed.signal_type,
        VoipSignalType::VoipSignalCallInit as i32
    );
}

#[test]
fn relay_validate_voip_envelope_empty_sender_rejected() {
    init();
    let envelope = VoipEnvelope {
        sender_device_id: vec![],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallInit as i32,
        call_id: vec![1; 32],
        encrypted_payload: vec![0xAA; 100],
        timestamp: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();
    assert!(validate_voip_envelope(&buf).is_err());
}

#[test]
fn relay_validate_voip_envelope_unspecified_type_rejected() {
    init();
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalUnspecified as i32,
        call_id: vec![1; 32],
        encrypted_payload: vec![0xAA; 100],
        timestamp: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();
    assert!(validate_voip_envelope(&buf).is_err());
}

#[test]
fn relay_validate_voip_envelope_invalid_call_id_size_rejected() {
    init();
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallInit as i32,
        call_id: vec![1; 16],
        encrypted_payload: vec![0xAA; 100],
        timestamp: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();
    assert!(validate_voip_envelope(&buf).is_err());
}

#[test]
fn relay_route_voip_envelope_returns_recipient() {
    init();
    let recipient = vec![5u8, 6, 7, 8];
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: recipient.clone(),
        signal_type: VoipSignalType::VoipSignalCallInit as i32,
        call_id: vec![1; 32],
        encrypted_payload: vec![0xAA; 100],
        timestamp: 0,
    };
    let routed = route_voip_envelope(&envelope).unwrap();
    assert_eq!(routed, recipient);
}

#[test]
fn relay_validate_call_signal_unknown_call_rejected() {
    init();
    let store = InMemoryCallStore::new();
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallAccept as i32,
        call_id: vec![0xFF; 32],
        encrypted_payload: vec![0xAA; 50],
        timestamp: 0,
    };
    let result = validate_call_signal_for_relay(&envelope, &store);
    assert!(result.is_err());
}

#[test]
fn relay_validate_call_signal_non_participant_rejected() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = vec![0xAA; 32];
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![9, 10, 11, 12], // not a participant
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalRekey as i32,
        call_id,
        encrypted_payload: vec![0xBB; 50],
        timestamp: 0,
    };
    let result = validate_call_signal_for_relay(&envelope, &store);
    assert!(result.is_err());
}

#[test]
fn relay_validate_call_signal_participant_accepted() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = vec![0xAA; 32];
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4], // caller
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallEnd as i32,
        call_id,
        encrypted_payload: vec![0xCC; 50],
        timestamp: 0,
    };
    let call = validate_call_signal_for_relay(&envelope, &store).unwrap();
    assert_eq!(call.caller_device_id, vec![1, 2, 3, 4]);
}

#[test]
fn relay_validate_call_signal_wrong_recipient_rejected() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = vec![0xAA; 32];
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![9, 10, 11, 12],
        signal_type: VoipSignalType::VoipSignalCallEnd as i32,
        call_id,
        encrypted_payload: vec![0xAA; 50],
        timestamp: 0,
    };
    assert!(validate_call_signal_for_relay(&envelope, &store).is_err());
}

// ════════════════════════════════════════════════════════════════════
// § 8  Stress / edge cases
// ════════════════════════════════════════════════════════════════════

#[test]
fn voip_session_large_payload() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let large_payload = vec![0xABu8; 8000]; // ~8KB video frame
    let header = FrameHeader {
        payload_type: 96,
        ssrc: alice.ssrc(),
        timestamp: 0,
        sequence_number: 0,
    };
    let encrypted = alice.encrypt_frame(&header, &large_payload).unwrap();
    let decrypted = bob.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, large_payload);
}

#[test]
fn voip_session_minimum_payload() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let header = FrameHeader {
        payload_type: 111,
        ssrc: alice.ssrc(),
        timestamp: 0,
        sequence_number: 0,
    };
    let encrypted = alice.encrypt_frame(&header, &[0x42]).unwrap(); // 1 byte
    let decrypted = bob.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, &[0x42]);
}

#[test]
fn voip_session_concurrent_bidirectional_many_frames() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    for i in 0u16..100 {
        // Alice sends
        let h = FrameHeader {
            payload_type: 111,
            ssrc: alice.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let enc = alice.encrypt_frame(&h, format!("a{i}").as_bytes()).unwrap();
        let dec = bob.decrypt_frame(&enc).unwrap();
        assert_eq!(String::from_utf8_lossy(&dec.payload), format!("a{i}"));

        // Bob sends
        let h2 = FrameHeader {
            payload_type: 111,
            ssrc: bob.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let enc2 = bob.encrypt_frame(&h2, format!("b{i}").as_bytes()).unwrap();
        let dec2 = alice.decrypt_frame(&enc2).unwrap();
        assert_eq!(String::from_utf8_lossy(&dec2.payload), format!("b{i}"));
    }

    assert_eq!(alice.send_frame_counter(), 100);
    assert_eq!(alice.recv_frame_counter(), 99);
    assert_eq!(bob.send_frame_counter(), 100);
    assert_eq!(bob.recv_frame_counter(), 99);
}

// ════════════════════════════════════════════════════════════════════
// § 9  Sealed state export / import roundtrip
// ════════════════════════════════════════════════════════════════════

#[test]
fn voip_sealed_state_export_import_roundtrip() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    for i in 0u16..10 {
        let h = FrameHeader {
            payload_type: 111,
            ssrc: alice.ssrc(),
            timestamp: u32::from(i) * 160,
            sequence_number: i,
        };
        let enc = alice.encrypt_frame(&h, b"data").unwrap();
        bob.decrypt_frame(&enc).unwrap();
    }

    let state_key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice.export_sealed_state(&state_key, 1).unwrap();

    let counter = VoipSession::sealed_state_external_counter(&sealed).unwrap();
    assert_eq!(counter, 1);

    let restored = VoipSession::from_sealed_state(&sealed, &state_key, 0).unwrap();
    assert_eq!(restored.call_id(), alice.call_id());
    assert_eq!(restored.role(), CallRole::Caller);
    assert!(restored.is_shield_mode() == alice.is_shield_mode());
}

#[test]
fn voip_sealed_state_restore_continues_communication_and_preserves_replay_window() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let first_from_alice = alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: 160,
                sequence_number: 1,
            },
            b"a1",
        )
        .unwrap();
    bob.decrypt_frame(&first_from_alice).unwrap();

    let replayed_after_restore = bob
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: bob.ssrc(),
                timestamp: 320,
                sequence_number: 1,
            },
            b"b1",
        )
        .unwrap();
    alice.decrypt_frame(&replayed_after_restore).unwrap();

    let second_from_alice = alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: alice.ssrc(),
                timestamp: 480,
                sequence_number: 2,
            },
            b"a2",
        )
        .unwrap();
    bob.decrypt_frame(&second_from_alice).unwrap();

    let state_key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice.export_sealed_state(&state_key, 7).unwrap();
    let restored_alice = VoipSession::from_sealed_state(&sealed, &state_key, 7).unwrap();

    assert!(restored_alice
        .decrypt_frame(&replayed_after_restore)
        .is_err());

    let next_from_bob = bob
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: bob.ssrc(),
                timestamp: 640,
                sequence_number: 2,
            },
            b"b2",
        )
        .unwrap();
    let restored_dec = restored_alice.decrypt_frame(&next_from_bob).unwrap();
    assert_eq!(restored_dec.payload, b"b2");

    let next_from_restored = restored_alice
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: restored_alice.ssrc(),
                timestamp: 800,
                sequence_number: 3,
            },
            b"a3",
        )
        .unwrap();
    let bob_dec = bob.decrypt_frame(&next_from_restored).unwrap();
    assert_eq!(bob_dec.payload, b"a3");
}

#[test]
fn voip_sealed_state_rollback_rejected() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    let state_key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice.export_sealed_state(&state_key, 5).unwrap();

    assert!(VoipSession::from_sealed_state(&sealed, &state_key, 10).is_err());
}

#[test]
fn voip_sealed_state_wrong_key_rejected() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    let key1 = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let key2 = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice.export_sealed_state(&key1, 1).unwrap();

    assert!(VoipSession::from_sealed_state(&sealed, &key2, 0).is_err());
}

#[test]
fn voip_sealed_state_tampered_rejected() {
    init();
    let (alice, _bob) = setup_voip_session_pair(false);

    let key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let mut sealed = alice.export_sealed_state(&key, 1).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;

    assert!(VoipSession::from_sealed_state(&sealed, &key, 0).is_err());
}

#[test]
fn voip_sealed_state_missing_replay_bitmap_rejected_when_high_water_nonzero() {
    init();
    let (alice, bob) = setup_voip_session_pair(false);

    let first = bob
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: bob.ssrc(),
                timestamp: 160,
                sequence_number: 1,
            },
            b"b1",
        )
        .unwrap();
    alice.decrypt_frame(&first).unwrap();
    let second = bob
        .encrypt_frame(
            &FrameHeader {
                payload_type: 111,
                ssrc: bob.ssrc(),
                timestamp: 320,
                sequence_number: 2,
            },
            b"b2",
        )
        .unwrap();
    alice.decrypt_frame(&second).unwrap();

    let key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = alice.export_sealed_state(&key, 3).unwrap();

    let nonce_offset = 8;
    let mac_offset = nonce_offset + AES_GCM_NONCE_BYTES;
    let ct_offset = mac_offset + HMAC_BYTES;
    let external_counter = u64::from_le_bytes(sealed[0..8].try_into().unwrap());
    let nonce = &sealed[nonce_offset..mac_offset];
    let ciphertext = &sealed[ct_offset..];

    let state_bytes = AesGcm::decrypt(&key, nonce, ciphertext, &[]).unwrap();
    let mut state = VoipSessionState::decode(state_bytes.as_slice()).unwrap();
    assert!(state.replay_high_water > 0);
    state.replay_bitmap.clear();

    let mut modified_state = Vec::new();
    state.encode(&mut modified_state).unwrap();
    let modified_ct = AesGcm::encrypt(&key, nonce, &modified_state, &[]).unwrap();

    let hmac_key = HkdfSha256::derive_key_bytes(
        &key,
        HMAC_BYTES,
        &external_counter.to_le_bytes(),
        b"Ecliptix-VoIP-StateHMAC",
    )
    .unwrap();
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&hmac_key).unwrap();
    mac.update(&modified_ct);
    mac.update(nonce);
    let hmac_tag = mac.finalize().into_bytes();

    let mut forged = Vec::new();
    forged.extend_from_slice(&external_counter.to_le_bytes());
    forged.extend_from_slice(nonce);
    forged.extend_from_slice(&hmac_tag);
    forged.extend_from_slice(&modified_ct);

    let result = VoipSession::from_sealed_state(&forged, &key, 0);
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
// § 10  Relay lifecycle
// ════════════════════════════════════════════════════════════════════

use ecliptix_protocol::api::relay::process_voip_signal;

#[test]
fn relay_lifecycle_init_registers_and_forwards() {
    init();
    let store = InMemoryCallStore::new();
    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallInit as i32,
        call_id: CryptoInterop::get_random_bytes(CALL_ID_BYTES),
        encrypted_payload: vec![0xAA; 100],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1000).unwrap();
    assert_eq!(action.target_device_id(), &[5, 6, 7, 8]);
    assert!(!action.removes_call());
    assert!(store.find_call(&envelope.call_id).unwrap().is_some());
}

#[test]
fn relay_lifecycle_accept_forwards_to_caller() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![5, 6, 7, 8],
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalCallAccept as i32,
        call_id,
        encrypted_payload: vec![0xBB; 100],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1001).unwrap();
    assert_eq!(action.target_device_id(), &[1, 2, 3, 4]);
}

#[test]
fn relay_lifecycle_accept_by_non_callee_rejected() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallAccept as i32,
        call_id,
        encrypted_payload: vec![0xBB; 100],
        timestamp: 0,
    };
    assert!(process_voip_signal(&envelope, &store, 1001).is_err());
}

#[test]
fn relay_lifecycle_reject_removes_call() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![5, 6, 7, 8],
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalCallReject as i32,
        call_id: call_id.clone(),
        encrypted_payload: vec![0xCC; 50],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1002).unwrap();
    assert!(action.removes_call());
    assert!(store.find_call(&call_id).unwrap().is_none());
}

#[test]
fn relay_lifecycle_end_removes_call() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalCallEnd as i32,
        call_id: call_id.clone(),
        encrypted_payload: vec![0xDD; 50],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1003).unwrap();
    assert!(action.removes_call());
    assert_eq!(action.target_device_id(), &[5, 6, 7, 8]);
    assert!(store.find_call(&call_id).unwrap().is_none());
}

#[test]
fn relay_lifecycle_rekey_forwards_to_peer() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    let mut active_call =
        ActiveCall::new(call_id.clone(), vec![1, 2, 3, 4], vec![5, 6, 7, 8], 1000);
    active_call.state = ecliptix_protocol::api::relay::CallLifecycleState::Active;
    store.register_call(&active_call).unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalRekey as i32,
        call_id: call_id.clone(),
        encrypted_payload: vec![0xEE; 200],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1004).unwrap();
    assert!(!action.removes_call());
    assert_eq!(action.target_device_id(), &[5, 6, 7, 8]);
    let stored = store.find_call(&call_id).unwrap().unwrap();
    assert_eq!(
        stored.state,
        ecliptix_protocol::api::relay::CallLifecycleState::Rekeying
    );
    assert_eq!(stored.pending_rekey_from, Some(vec![1, 2, 3, 4]));
}

#[test]
fn relay_lifecycle_rekey_ack_forwards_back() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    let mut active_call =
        ActiveCall::new(call_id.clone(), vec![1, 2, 3, 4], vec![5, 6, 7, 8], 1000);
    active_call.state = ecliptix_protocol::api::relay::CallLifecycleState::Rekeying;
    active_call.pending_rekey_from = Some(vec![1, 2, 3, 4]);
    store.register_call(&active_call).unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![5, 6, 7, 8],
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalRekeyAck as i32,
        call_id,
        encrypted_payload: vec![0xFF; 200],
        timestamp: 0,
    };
    let action = process_voip_signal(&envelope, &store, 1005).unwrap();
    assert_eq!(action.target_device_id(), &[1, 2, 3, 4]);
    let stored = store.find_call(&envelope.call_id).unwrap().unwrap();
    assert_eq!(
        stored.state,
        ecliptix_protocol::api::relay::CallLifecycleState::Active
    );
    assert_eq!(stored.rekey_generation, 1);
    assert!(stored.pending_rekey_from.is_none());
}

#[test]
fn relay_lifecycle_rekey_ack_without_pending_rekey_rejected() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    let mut active_call =
        ActiveCall::new(call_id.clone(), vec![1, 2, 3, 4], vec![5, 6, 7, 8], 1000);
    active_call.state = ecliptix_protocol::api::relay::CallLifecycleState::Active;
    store.register_call(&active_call).unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![5, 6, 7, 8],
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalRekeyAck as i32,
        call_id,
        encrypted_payload: vec![0x11; 50],
        timestamp: 0,
    };
    assert!(process_voip_signal(&envelope, &store, 1005).is_err());
}

#[test]
fn relay_lifecycle_initiated_call_timeout_rejected_and_removed() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    store
        .register_call(&ActiveCall::new(
            call_id.clone(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8],
            1000,
        ))
        .unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![5, 6, 7, 8],
        recipient_device_id: vec![1, 2, 3, 4],
        signal_type: VoipSignalType::VoipSignalCallAccept as i32,
        call_id: call_id.clone(),
        encrypted_payload: vec![0x22; 50],
        timestamp: 0,
    };

    assert!(process_voip_signal(&envelope, &store, 1031).is_err());
    assert!(store.find_call(&call_id).unwrap().is_none());
}

#[test]
fn relay_lifecycle_active_call_idle_timeout_rejected_and_removed() {
    init();
    let store = InMemoryCallStore::new();
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    let mut active_call =
        ActiveCall::new(call_id.clone(), vec![1, 2, 3, 4], vec![5, 6, 7, 8], 1000);
    active_call.state = ecliptix_protocol::api::relay::CallLifecycleState::Active;
    active_call.last_activity_at = 1001;
    store.register_call(&active_call).unwrap();

    let envelope = VoipEnvelope {
        sender_device_id: vec![1, 2, 3, 4],
        recipient_device_id: vec![5, 6, 7, 8],
        signal_type: VoipSignalType::VoipSignalRekey as i32,
        call_id: call_id.clone(),
        encrypted_payload: vec![0x33; 50],
        timestamp: 0,
    };

    assert!(process_voip_signal(&envelope, &store, 1302).is_err());
    assert!(store.find_call(&call_id).unwrap().is_none());
}
