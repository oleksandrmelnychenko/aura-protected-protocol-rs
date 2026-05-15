// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use aura_protected_protocol::crypto::{AesGcm, CryptoInterop, HkdfSha256, KyberInterop};
use aura_protected_protocol::identity::IdentityKeys;
#[cfg(feature = "test-vectors")]
use aura_protected_protocol::{
    core::{
        constants::{AES_GCM_NONCE_BYTES, NONCE_PREFIX_BYTES, PROTOCOL_VERSION},
        errors::ProtocolError,
    },
    interfaces::ITimeProvider,
    proto::{OneTimePreKey, PreKeyBundle},
    protocol::{HandshakeInitiator, HandshakeResponder},
};
#[cfg(feature = "test-vectors")]
use prost::Message;
use sha2::{Digest, Sha256};
#[cfg(feature = "test-vectors")]
use std::sync::Arc;

#[cfg(feature = "test-vectors")]
struct FixedTimeProvider;

#[cfg(feature = "test-vectors")]
impl ITimeProvider for FixedTimeProvider {
    fn now_unix_secs(&self) -> Result<u64, ProtocolError> {
        Ok(1_800_000_000)
    }
}

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

#[cfg(feature = "test-vectors")]
fn encode_pre_key_bundle(identity: &IdentityKeys) -> PreKeyBundle {
    let bundle = identity.create_public_bundle().expect("public bundle");
    let one_time_pre_keys = bundle
        .one_time_pre_keys()
        .iter()
        .map(|opk| OneTimePreKey {
            one_time_pre_key_id: opk.id(),
            public_key: opk.public_key_vec(),
        })
        .collect();

    PreKeyBundle {
        version: PROTOCOL_VERSION,
        identity_ed25519_public: bundle.identity_ed25519_public().to_vec(),
        identity_x25519_public: bundle.identity_x25519_public().to_vec(),
        identity_x25519_signature: bundle.identity_x25519_signature().to_vec(),
        signed_pre_key_id: bundle.signed_pre_key_id(),
        signed_pre_key_public: bundle.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: bundle.signed_pre_key_signature().to_vec(),
        one_time_pre_keys,
        kyber_public: bundle.kyber_public().expect("kyber public").to_vec(),
    }
}

#[cfg(feature = "test-vectors")]
fn print_handshake_vector() {
    let mut alice = IdentityKeys::create_from_master_key(&[0x11; 32], "paper-alice", 0)
        .expect("alice handshake identity vector");
    let mut bob = IdentityKeys::create_from_master_key(&[0x22; 32], "paper-bob", 0)
        .expect("bob handshake identity vector");
    let bob_bundle = encode_pre_key_bundle(&bob);
    let time_provider = Arc::new(FixedTimeProvider);

    alice
        .set_ephemeral_key_pair_from_seed(&[0x33; 32])
        .expect("initiator ephemeral vector");
    let initiator = HandshakeInitiator::start_with_test_vector_entropy(
        &mut alice,
        &bob_bundle,
        1000,
        time_provider.clone(),
        &[0x44; 32],
    )
    .expect("handshake init vector");
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process_with_replay_guard_and_time_provider(
        &mut bob,
        &bob_bundle,
        &init_bytes,
        1000,
        None,
        time_provider,
    )
    .expect("handshake ack vector");
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().expect("bob session");
    let alice_session = initiator.finish(&ack_bytes).expect("alice session");
    assert_eq!(alice_session.get_session_id(), bob_session.get_session_id());

    println!("handshake_init_len={}", init_bytes.len());
    println!("handshake_init_sha256={}", sha256_hex(&init_bytes));
    println!("handshake_ack_len={}", ack_bytes.len());
    println!("handshake_ack_sha256={}", sha256_hex(&ack_bytes));
    println!(
        "handshake_session_id={}",
        hex(&alice_session.get_session_id())
    );

    alice_session
        .set_test_vector_nonce_state([0x55; NONCE_PREFIX_BYTES], 0)
        .expect("envelope nonce vector");
    let envelope = alice_session
        .encrypt_with_test_vector_header_nonce(
            b"Aura post-handshake envelope vector",
            7,
            42,
            Some("paper-envelope"),
            &[0x66; AES_GCM_NONCE_BYTES],
        )
        .expect("envelope vector");
    let decrypted = bob_session.decrypt(&envelope).expect("envelope decrypt");
    assert_eq!(decrypted.plaintext, b"Aura post-handshake envelope vector");
    let mut envelope_bytes = Vec::new();
    envelope
        .encode(&mut envelope_bytes)
        .expect("encode envelope");
    println!("envelope_len={}", envelope_bytes.len());
    println!("envelope_sha256={}", sha256_hex(&envelope_bytes));
    println!(
        "envelope_metadata_sha256={}",
        sha256_hex(&envelope.encrypted_metadata)
    );
    println!(
        "envelope_payload_sha256={}",
        sha256_hex(&envelope.encrypted_payload)
    );

    bob_session
        .set_test_vector_ratchet_entropy(
            &[0x77; 32],
            &[0x88; 32],
            &[0x99; 32],
            [0xaa; NONCE_PREFIX_BYTES],
            0,
        )
        .expect("ratchet entropy vector");
    let ratchet_envelope = bob_session
        .encrypt_with_test_vector_header_nonce(
            b"Aura cross-ratchet envelope vector",
            8,
            43,
            Some("paper-ratchet"),
            &[0xbb; AES_GCM_NONCE_BYTES],
        )
        .expect("cross-ratchet envelope vector");
    let ratchet_decrypted = alice_session
        .decrypt(&ratchet_envelope)
        .expect("cross-ratchet decrypt");
    assert_eq!(
        ratchet_decrypted.plaintext,
        b"Aura cross-ratchet envelope vector"
    );
    let mut ratchet_envelope_bytes = Vec::new();
    ratchet_envelope
        .encode(&mut ratchet_envelope_bytes)
        .expect("encode cross-ratchet envelope");
    println!(
        "cross_ratchet_envelope_len={}",
        ratchet_envelope_bytes.len()
    );
    println!(
        "cross_ratchet_envelope_sha256={}",
        sha256_hex(&ratchet_envelope_bytes)
    );
    println!(
        "cross_ratchet_header_dh_sha256={}",
        sha256_hex(ratchet_envelope.dh_public_key.as_ref().unwrap())
    );
    println!(
        "cross_ratchet_header_kyber_ct_sha256={}",
        sha256_hex(ratchet_envelope.kyber_ciphertext.as_ref().unwrap())
    );
    println!(
        "cross_ratchet_header_new_kyber_sha256={}",
        sha256_hex(ratchet_envelope.new_kyber_public.as_ref().unwrap())
    );
    println!(
        "cross_ratchet_metadata_sha256={}",
        sha256_hex(&ratchet_envelope.encrypted_metadata)
    );
    println!(
        "cross_ratchet_payload_sha256={}",
        sha256_hex(&ratchet_envelope.encrypted_payload)
    );
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

    #[cfg(feature = "test-vectors")]
    print_handshake_vector();
}
