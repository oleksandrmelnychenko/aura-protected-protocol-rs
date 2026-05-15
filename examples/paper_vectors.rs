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

fn main() {
    CryptoInterop::initialize().expect("crypto init");

    let hkdf = HkdfSha256::derive_key_bytes(
        b"aura paper vector ikm v1",
        32,
        b"aura paper vector salt v1",
        b"Aura-Hybrid-Ratchet|test-vector|v1",
    )
    .expect("hkdf vector");
    println!("hkdf_sha256_32={}", hex(&hkdf));

    let key: Vec<u8> = (0u8..32).collect();
    let nonce: Vec<u8> = (0xa0u8..0xac).collect();
    let ciphertext = AesGcm::encrypt(
        &key,
        &nonce,
        b"Aura paper vector payload",
        b"Aura paper vector aad",
    )
    .expect("aes-gcm-siv vector");
    println!("aes256_gcm_siv_ciphertext_tag={}", hex(&ciphertext));

    let (_kyber_secret, kyber_public) =
        KyberInterop::generate_keypair_from_seed(&[0x42; 32]).expect("ml-kem vector");
    println!("ml_kem_768_public_len={}", kyber_public.len());
    println!("ml_kem_768_public_sha256={}", sha256_hex(&kyber_public));

    let alice = IdentityKeys::create_from_master_key(&[0x11; 32], "paper-alice", 5)
        .expect("alice identity vector");
    let bob = IdentityKeys::create_from_master_key(&[0x22; 32], "paper-bob", 5)
        .expect("bob identity vector");
    println!(
        "alice_ed25519_public={}",
        hex(&alice.get_identity_ed25519_public())
    );
    println!(
        "alice_x25519_public={}",
        hex(&alice.get_identity_x25519_public())
    );
    println!(
        "alice_kyber_public_sha256={}",
        sha256_hex(&alice.get_kyber_public())
    );
    println!(
        "bob_ed25519_public={}",
        hex(&bob.get_identity_ed25519_public())
    );
    println!(
        "bob_x25519_public={}",
        hex(&bob.get_identity_x25519_public())
    );
    println!(
        "bob_kyber_public_sha256={}",
        sha256_hex(&bob.get_kyber_public())
    );
}
