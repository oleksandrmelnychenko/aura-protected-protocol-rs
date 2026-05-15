// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use aura_protected_protocol::crypto::{AesGcm, CryptoInterop, HkdfSha256, KyberInterop};
use aura_protected_protocol::identity::IdentityKeys;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

#[test]
fn paper_hkdf_vector_is_stable() {
    let hkdf = HkdfSha256::derive_key_bytes(
        b"aura paper vector ikm v1",
        32,
        b"aura paper vector salt v1",
        b"Aura-Hybrid-Ratchet|test-vector|v1",
    )
    .unwrap();

    assert_eq!(
        hex(&hkdf),
        "12681430d33e0fe7f4503dfe5973133f512f79771386beb6b44acc111669619b"
    );
}

#[test]
fn paper_aes_gcm_siv_vector_is_stable() {
    let key: Vec<u8> = (0u8..32).collect();
    let nonce: Vec<u8> = (0xa0u8..0xac).collect();
    let ciphertext = AesGcm::encrypt(
        &key,
        &nonce,
        b"Aura paper vector payload",
        b"Aura paper vector aad",
    )
    .unwrap();

    assert_eq!(
        hex(&ciphertext),
        "6aca6cf28cb9ff275c9b42d14942ef300e2e25b10d1f3afd8df881ad849838d88d9c1fa3e31c6c7a76"
    );
    let decrypted = AesGcm::decrypt(&key, &nonce, &ciphertext, b"Aura paper vector aad").unwrap();
    assert_eq!(decrypted, b"Aura paper vector payload");
}

#[test]
fn paper_ml_kem_seeded_public_key_vector_is_stable() {
    CryptoInterop::initialize().unwrap();
    let (_secret, public) = KyberInterop::generate_keypair_from_seed(&[0x42; 32]).unwrap();

    assert_eq!(public.len(), 1184);
    assert_eq!(
        sha256_hex(&public),
        "c26fd76b17dd6308177ad6836daebe1abcff186ac4b8fe8c1443432bf4ad9b34"
    );
}

#[test]
fn paper_master_key_identity_vectors_are_stable() {
    CryptoInterop::initialize().unwrap();
    let alice = IdentityKeys::create_from_master_key(&[0x11; 32], "paper-alice", 5).unwrap();
    let bob = IdentityKeys::create_from_master_key(&[0x22; 32], "paper-bob", 5).unwrap();

    assert_eq!(
        hex(&alice.get_identity_ed25519_public()),
        "50e05e9588ce97fe804c8c50d1e3e22a7edde912f9b32ea9783aeb566087b2bd"
    );
    assert_eq!(
        hex(&alice.get_identity_x25519_public()),
        "eba38f76c0c34b1efe76edc04f447ab7175f5edb058d351ef50f39318e992011"
    );
    assert_eq!(
        sha256_hex(&alice.get_kyber_public()),
        "00b6d3eea0c738ed18d821f7d7d0d8dd134a1018ff44dd417fa6827c08490f00"
    );
    assert_eq!(
        hex(&bob.get_identity_ed25519_public()),
        "2edea9597d39b986615d3c3454c2a6a0f982fbf50cd092b21466582e81e26db3"
    );
    assert_eq!(
        hex(&bob.get_identity_x25519_public()),
        "da67e35d4976287e10be7a8f2aac99bc680fec5f611c2dea36707ef25f803e49"
    );
    assert_eq!(
        sha256_hex(&bob.get_kyber_public()),
        "c5a17545a177bf666198263203923758f9602b2abd1dedde7a9c517b40897e9a"
    );
}
