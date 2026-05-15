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
    let bundle = identity.create_public_bundle().unwrap();
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
        kyber_public: bundle.kyber_public().unwrap_or(&[]).to_vec(),
    }
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

#[cfg(feature = "test-vectors")]
#[test]
fn paper_full_handshake_transcript_vector_is_stable() {
    CryptoInterop::initialize().unwrap();
    let mut alice = IdentityKeys::create_from_master_key(&[0x11; 32], "paper-alice", 0).unwrap();
    let mut bob = IdentityKeys::create_from_master_key(&[0x22; 32], "paper-bob", 0).unwrap();
    let bob_bundle = encode_pre_key_bundle(&bob);
    let time_provider = Arc::new(FixedTimeProvider);

    alice.set_ephemeral_key_pair_from_seed(&[0x33; 32]).unwrap();
    let initiator = HandshakeInitiator::start_with_test_vector_entropy(
        &mut alice,
        &bob_bundle,
        1000,
        time_provider.clone(),
        &[0x44; 32],
    )
    .unwrap();
    let init_bytes = initiator.encoded_message().to_vec();

    let responder = HandshakeResponder::process_with_replay_guard_and_time_provider(
        &mut bob,
        &bob_bundle,
        &init_bytes,
        1000,
        None,
        time_provider,
    )
    .unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    assert_eq!(alice_session.get_session_id(), bob_session.get_session_id());
    assert_eq!(init_bytes.len(), 2485);
    assert_eq!(ack_bytes.len(), 36);
    assert_eq!(
        sha256_hex(&init_bytes),
        "dceaef8ef7f38a0c7a4f54e8139aa236eda6339d123a65b79699ad62f56d4151"
    );
    assert_eq!(
        sha256_hex(&ack_bytes),
        "5192f0e16fc61f1ea4c38e1737c93feb613075c2447ea711c76b53965bacf265"
    );
    assert_eq!(
        hex(&alice_session.get_session_id()),
        "7775055d40940c50c28a6bac2edf50e6"
    );

    alice_session
        .set_test_vector_nonce_state([0x55; NONCE_PREFIX_BYTES], 0)
        .unwrap();
    let envelope = alice_session
        .encrypt_with_test_vector_header_nonce(
            b"Aura post-handshake envelope vector",
            7,
            42,
            Some("paper-envelope"),
            &[0x66; AES_GCM_NONCE_BYTES],
        )
        .unwrap();
    let mut envelope_bytes = Vec::new();
    envelope.encode(&mut envelope_bytes).unwrap();
    let decrypted = bob_session.decrypt(&envelope).unwrap();

    assert_eq!(decrypted.plaintext, b"Aura post-handshake envelope vector");
    assert_eq!(decrypted.metadata.message_index, 0);
    assert_eq!(decrypted.metadata.envelope_type, 7);
    assert_eq!(decrypted.metadata.envelope_id, 42);
    assert_eq!(
        decrypted.metadata.correlation_id.as_deref(),
        Some("paper-envelope")
    );
    assert_eq!(envelope_bytes.len(), 158);
    assert_eq!(
        sha256_hex(&envelope_bytes),
        "a32fa29e3cb71093b294e7225aeb6a1a2aaeb54e04b9313166ae5b311e3ea799"
    );
    assert_eq!(
        sha256_hex(&envelope.encrypted_metadata),
        "ac8130223d5d655159914f9ce920be8c28f8b85d239d1eab2ab0315b38c6b867"
    );
    assert_eq!(
        sha256_hex(&envelope.encrypted_payload),
        "e142dbef61b3b62e92428585a61c7e79dc38bddec10004e073fff20be4ec801e"
    );
}
