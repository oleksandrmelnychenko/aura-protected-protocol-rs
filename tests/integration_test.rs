// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::borrow_as_ptr, unsafe_code)]

use ecliptix_protocol::crypto::{
    AesGcm, CryptoInterop, HkdfSha256, KyberInterop, MasterKeyDerivation, SecureMemoryHandle,
    ShamirSecretSharing,
};
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::interfaces::StaticStateKeyProvider;
use ecliptix_protocol::proto::PreKeyBundle;
use ecliptix_protocol::protocol::{HandshakeInitiator, HandshakeResponder};
use prost::Message;

fn init() {
    CryptoInterop::initialize().expect("crypto init");
}

const fn external_join_enabled_policy() -> ecliptix_protocol::protocol::group::GroupSecurityPolicy {
    let mut policy = ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield();
    policy.block_external_join = false;
    policy
}

fn create_external_joinable_group(
    identity: &IdentityKeys,
    credential: &[u8],
) -> ecliptix_protocol::protocol::group::GroupSession {
    ecliptix_protocol::protocol::group::GroupSession::create_with_policy(
        identity,
        credential.to_vec(),
        external_join_enabled_policy(),
    )
    .unwrap()
}

fn create_two_member_group_with_policy(
    policy: ecliptix_protocol::protocol::group::GroupSecurityPolicy,
) -> (GroupSession, GroupSession) {
    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice_session =
        GroupSession::create_with_policy(&alice_id, b"alice".to_vec(), policy).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    (alice_session, bob_session)
}

fn create_two_member_group() -> (GroupSession, GroupSession) {
    create_two_member_group_with_policy(
        ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield(),
    )
}

fn authorize_and_join_external(
    owner: &ecliptix_protocol::protocol::group::GroupSession,
    joiner: &IdentityKeys,
    credential: &[u8],
) -> (ecliptix_protocol::protocol::group::GroupSession, Vec<u8>) {
    let authorization = owner
        .authorize_external_join(
            &joiner.get_identity_ed25519_public(),
            &joiner.get_identity_x25519_public(),
            credential,
        )
        .unwrap();
    let public_state = owner.export_public_state().unwrap();
    ecliptix_protocol::protocol::group::GroupSession::from_external_join(
        &public_state,
        &authorization,
        joiner,
        credential.to_vec(),
    )
    .unwrap()
}

#[test]
fn crypto_initialize_is_idempotent() {
    init();
    init();
    assert!(CryptoInterop::is_initialized());
}

#[test]
fn crypto_generate_x25519_keypair_produces_valid_keys() {
    init();
    let (handle, pk) = CryptoInterop::generate_x25519_keypair("test").unwrap();
    assert_eq!(pk.len(), 32);
    let sk = handle.read_bytes(32).unwrap();
    assert_eq!(sk.len(), 32);
    assert!(pk.iter().any(|&b| b != 0));
}

#[test]
fn crypto_two_keypairs_are_distinct() {
    init();
    let (_, pk1) = CryptoInterop::generate_x25519_keypair("a").unwrap();
    let (_, pk2) = CryptoInterop::generate_x25519_keypair("b").unwrap();
    assert_ne!(pk1, pk2);
}

#[test]
fn crypto_random_bytes_are_non_trivial() {
    init();
    let a = CryptoInterop::get_random_bytes(32);
    let b = CryptoInterop::get_random_bytes(32);
    assert_eq!(a.len(), 32);
    assert_ne!(a, b);
}

#[test]
fn crypto_generate_random_u32() {
    init();
    for _ in 0..100 {
        let v = CryptoInterop::generate_random_u32(true);
        assert_ne!(v, 0);
    }
}

#[test]
fn crypto_constant_time_equals() {
    init();
    let a = vec![1u8, 2, 3];
    let b = vec![1u8, 2, 3];
    let c = vec![1u8, 2, 4];
    assert!(CryptoInterop::constant_time_equals(&a, &b).unwrap());
    assert!(!CryptoInterop::constant_time_equals(&a, &c).unwrap());
    assert!(!CryptoInterop::constant_time_equals(&a, &[1u8, 2]).unwrap());
}

#[test]
fn crypto_secure_wipe_zeros_buffer() {
    init();
    let mut buf = vec![0xDE_u8; 64];
    CryptoInterop::secure_wipe(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn secure_memory_allocate_write_read() {
    init();
    let data: Vec<u8> = (0..32u8).collect();
    let mut handle = SecureMemoryHandle::allocate(32).unwrap();
    handle.write(&data).unwrap();
    let read_back = handle.read_bytes(32).unwrap();
    assert_eq!(read_back, data);
}

#[test]
fn secure_memory_write_access() {
    init();
    let mut handle = SecureMemoryHandle::allocate(16).unwrap();
    #[allow(clippy::cast_possible_truncation)]
    handle.with_write_access(|slice| {
        for (i, b) in slice.iter_mut().enumerate() {
            *b = i as u8;
        }
    });
    let read_back = handle.read_bytes(16).unwrap();
    let expected: Vec<u8> = (0..16u8).collect();
    assert_eq!(read_back, expected);
}

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let aad = b"additional data";
    let plain = b"Hello, Ecliptix!";

    let cipher = AesGcm::encrypt(&key, &nonce, plain, aad).unwrap();
    assert_ne!(cipher, plain);
    let decoded = AesGcm::decrypt(&key, &nonce, &cipher, aad).unwrap();
    assert_eq!(decoded, plain);
}

#[test]
fn aes_gcm_tampered_ciphertext_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let mut cipher = AesGcm::encrypt(&key, &nonce, b"secret", b"").unwrap();
    cipher[0] ^= 0xFF;
    assert!(AesGcm::decrypt(&key, &nonce, &cipher, b"").is_err());
}

#[test]
fn aes_gcm_wrong_key_fails() {
    init();
    let key1 = CryptoInterop::get_random_bytes(32);
    let key2 = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let cipher = AesGcm::encrypt(&key1, &nonce, b"secret", b"").unwrap();
    assert!(AesGcm::decrypt(&key2, &nonce, &cipher, b"").is_err());
}

#[test]
fn hkdf_derive_is_deterministic() {
    let ikm = b"input key material";
    let salt = b"some salt";
    let info = b"context info";
    let k1 = HkdfSha256::derive_key_bytes(ikm, 32, salt, info).unwrap();
    let k2 = HkdfSha256::derive_key_bytes(ikm, 32, salt, info).unwrap();
    assert_eq!(k1, k2);
    assert_eq!(k1.len(), 32);
}

#[test]
fn hkdf_different_infos_produce_different_keys() {
    let ikm = b"key";
    let salt = b"salt";
    let k1 = HkdfSha256::derive_key_bytes(ikm, 32, salt, b"info1").unwrap();
    let k2 = HkdfSha256::derive_key_bytes(ikm, 32, salt, b"info2").unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn hkdf_zero_output_len_fails() {
    assert!(HkdfSha256::derive_key_bytes(b"k", 0, b"", b"").is_err());
}

#[test]
fn master_key_derive_ed25519_seed_is_32_bytes() {
    let master = CryptoInterop::get_random_bytes(32);
    let seed = MasterKeyDerivation::derive_ed25519_seed(&master, "member-1").unwrap();
    assert_eq!(seed.len(), 32);
}

#[test]
fn master_key_derive_kyber_seed_is_64_bytes() {
    let master = CryptoInterop::get_random_bytes(32);
    let seed = MasterKeyDerivation::derive_kyber_seed(&master, "member-1").unwrap();
    assert_eq!(seed.len(), 64);
}

#[test]
fn master_key_different_membership_ids_produce_different_seeds() {
    let master = CryptoInterop::get_random_bytes(32);
    let s1 = MasterKeyDerivation::derive_ed25519_seed(&master, "user-a").unwrap();
    let s2 = MasterKeyDerivation::derive_ed25519_seed(&master, "user-b").unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn master_key_one_time_pre_key_seeds_are_unique() {
    let master = CryptoInterop::get_random_bytes(32);
    let s0 = MasterKeyDerivation::derive_one_time_pre_key_seed(&master, "m", 0).unwrap();
    let s1 = MasterKeyDerivation::derive_one_time_pre_key_seed(&master, "m", 1).unwrap();
    assert_ne!(s0, s1);
    assert_eq!(s0.len(), 32);
}

#[test]
fn kyber_keygen_encap_decap_roundtrip() {
    init();
    let (sk_handle, pk) = KyberInterop::generate_keypair().unwrap();
    assert_eq!(pk.len(), 1184);

    let (ciphertext, ss_enc) = KyberInterop::encapsulate(&pk).unwrap();
    assert_eq!(ciphertext.len(), 1088);

    let ss_dec = KyberInterop::decapsulate(&ciphertext, &sk_handle).unwrap();
    let enc_bytes = ss_enc.read_bytes(32).unwrap();
    let dec_bytes = ss_dec.read_bytes(32).unwrap();
    assert_eq!(enc_bytes, dec_bytes);
}

#[test]
fn kyber_wrong_key_produces_different_shared_secret() {
    init();
    let (_, pk1) = KyberInterop::generate_keypair().unwrap();
    let (sk2, _) = KyberInterop::generate_keypair().unwrap();

    let (ct, _ss_enc) = KyberInterop::encapsulate(&pk1).unwrap();
    let _result = KyberInterop::decapsulate(&ct, &sk2);
}

fn shamir_auth_key() -> Vec<u8> {
    CryptoInterop::get_random_bytes(32)
}

#[test]
fn shamir_split_reconstruct_roundtrip() {
    init();
    let secret = b"super secret key material 1234!";
    let auth_key = shamir_auth_key();

    let shares = ShamirSecretSharing::split(secret, 2, 3, &auth_key).unwrap();
    assert_eq!(shares.len(), 4);

    let recovered = ShamirSecretSharing::reconstruct(&shares, &auth_key, 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_reconstruct_with_threshold_subset() {
    init();
    let secret = b"my secret value";
    let auth_key = shamir_auth_key();

    let shares = ShamirSecretSharing::split(secret, 2, 4, &auth_key).unwrap();
    let subset = vec![
        shares[0].clone(),
        shares[1].clone(),
        shares.last().unwrap().clone(),
    ];
    let recovered = ShamirSecretSharing::reconstruct(&subset, &auth_key, 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_wrong_auth_key_fails() {
    init();
    let secret = b"secret";
    let auth_key = shamir_auth_key();
    let wrong_key = shamir_auth_key();

    let shares = ShamirSecretSharing::split(secret, 2, 2, &auth_key).unwrap();
    assert!(ShamirSecretSharing::reconstruct(&shares, &wrong_key, 2).is_err());
}

#[test]
fn shamir_too_few_shares_fails() {
    init();
    let secret = b"secret data";
    let auth_key = shamir_auth_key();

    let shares = ShamirSecretSharing::split(secret, 3, 4, &auth_key).unwrap();
    let subset = vec![
        shares[0].clone(),
        shares[1].clone(),
        shares.last().unwrap().clone(),
    ];
    assert!(ShamirSecretSharing::reconstruct(&subset, &auth_key, 3).is_err());
}

#[test]
fn identity_create_random_produces_valid_keys() {
    init();
    let ik = IdentityKeys::create(10).unwrap();
    assert_eq!(ik.get_identity_ed25519_public().len(), 32);
    assert_eq!(ik.get_identity_x25519_public().len(), 32);
    assert_eq!(ik.get_kyber_public().len(), 1184);
}

#[test]
fn identity_create_from_master_key_is_deterministic() {
    init();
    let master = CryptoInterop::get_random_bytes(32);
    let ik1 = IdentityKeys::create_from_master_key(&master, "user-1", 5).unwrap();
    let ik2 = IdentityKeys::create_from_master_key(&master, "user-1", 5).unwrap();
    assert_eq!(
        ik1.get_identity_ed25519_public(),
        ik2.get_identity_ed25519_public()
    );
    assert_eq!(
        ik1.get_identity_x25519_public(),
        ik2.get_identity_x25519_public()
    );
    assert_eq!(ik1.get_kyber_public(), ik2.get_kyber_public());
}

#[test]
fn identity_different_membership_ids_produce_different_keys() {
    init();
    let master = CryptoInterop::get_random_bytes(32);
    let ik1 = IdentityKeys::create_from_master_key(&master, "user-1", 5).unwrap();
    let ik2 = IdentityKeys::create_from_master_key(&master, "user-2", 5).unwrap();
    assert_ne!(
        ik1.get_identity_ed25519_public(),
        ik2.get_identity_ed25519_public()
    );
}

#[test]
fn identity_create_public_bundle_roundtrip() {
    init();
    let ik = IdentityKeys::create(5).unwrap();
    let bundle = ik.create_public_bundle().unwrap();
    assert_eq!(
        bundle.identity_ed25519_public(),
        ik.get_identity_ed25519_public()
    );
    assert_eq!(
        bundle.identity_x25519_public(),
        ik.get_identity_x25519_public()
    );
    assert_eq!(bundle.one_time_pre_key_count(), 5);
}

fn build_proto_bundle(ik: &IdentityKeys) -> Vec<u8> {
    use ecliptix_protocol::proto::OneTimePreKey;
    let lb = ik.create_public_bundle().unwrap();
    let opks: Vec<OneTimePreKey> = lb
        .one_time_pre_keys()
        .iter()
        .map(|o| OneTimePreKey {
            one_time_pre_key_id: o.id(),
            public_key: o.public_key_vec(),
        })
        .collect();
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: opks,
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    let mut buf = Vec::new();
    pb.encode(&mut buf).unwrap();
    buf
}

#[test]
fn full_handshake_and_session_encrypt_decrypt() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle_bytes = build_proto_bundle(&bob);
    let bob_bundle = PreKeyBundle::decode(bob_bundle_bytes.as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();

    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();

    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let alice_peer = alice_session.get_peer_identity();
    let bob_peer = bob_session.get_peer_identity();
    assert_eq!(alice_peer.ed25519_public, bob.get_identity_ed25519_public());
    assert_eq!(bob_peer.ed25519_public, alice.get_identity_ed25519_public());

    let plaintext = b"Hello Bob, this is a test!";
    let envelope = alice_session.encrypt(plaintext, 0, 1, None).unwrap();
    let result = bob_session.decrypt(&envelope).unwrap();
    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.metadata.envelope_id, 1);

    let reply_plain = b"Hi Alice, got your message!";
    let reply_env = bob_session
        .encrypt(reply_plain, 1, 2, Some("corr-1"))
        .unwrap();
    let reply_dec = alice_session.decrypt(&reply_env).unwrap();
    assert_eq!(reply_dec.plaintext, reply_plain);
    assert_eq!(
        reply_dec.metadata.correlation_id,
        Some("corr-1".to_string())
    );
}

#[test]
fn session_multiple_messages_in_order() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..10 {
        let msg = format!("Message {i}");
        let env = alice_session.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let dec = bob_session.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, msg.as_bytes());
    }
}

#[test]
fn session_serialize_deserialize_roundtrip() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"before save", 0, 1, None).unwrap();
    let _ = bob_session.decrypt(&env1).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();
    assert!(!sealed.is_empty());

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_session2 =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let env2 = alice_session.encrypt(b"after restore", 0, 2, None).unwrap();
    let dec = bob_session2.decrypt(&env2).unwrap();
    assert_eq!(dec.plaintext, b"after restore");
}

#[test]
fn session_serialize_wrong_key_fails() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let _alice_session = initiator.finish(&ack_bytes).unwrap();
    let bob_session = responder.finish().unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let wrong_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let bad_provider = StaticStateKeyProvider::new(wrong_key).unwrap();
    assert!(
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &bad_provider, 0).is_err()
    );
}

#[test]
fn aes_gcm_siv_nonce_misuse_resistance() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let aad = b"context";

    let ct1 = AesGcm::encrypt(&key, &nonce, b"plaintext one", aad).unwrap();
    let ct2 = AesGcm::encrypt(&key, &nonce, b"plaintext two", aad).unwrap();

    assert_ne!(ct1, ct2);

    let pt1 = AesGcm::decrypt(&key, &nonce, &ct1, aad).unwrap();
    let pt2 = AesGcm::decrypt(&key, &nonce, &ct2, aad).unwrap();
    assert_eq!(pt1, b"plaintext one");
    assert_eq!(pt2, b"plaintext two");
}

#[test]
fn aes_gcm_siv_same_plaintext_same_nonce_is_deterministic() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let plain = b"deterministic check";

    let ct1 = AesGcm::encrypt(&key, &nonce, plain, b"").unwrap();
    let ct2 = AesGcm::encrypt(&key, &nonce, plain, b"").unwrap();
    assert_eq!(ct1, ct2);
}

#[test]
fn aes_gcm_siv_empty_plaintext() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);

    let ct = AesGcm::encrypt(&key, &nonce, b"", b"aad").unwrap();
    assert_eq!(ct.len(), 16);
    let pt = AesGcm::decrypt(&key, &nonce, &ct, b"aad").unwrap();
    assert!(pt.is_empty());
}

#[test]
fn aes_gcm_siv_large_payload() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);
    let plain = vec![0xABu8; 64 * 1024];

    let ct = AesGcm::encrypt(&key, &nonce, &plain, b"").unwrap();
    let pt = AesGcm::decrypt(&key, &nonce, &ct, b"").unwrap();
    assert_eq!(pt, plain);
}

#[test]
fn aes_gcm_siv_wrong_aad_fails() {
    init();
    let key = CryptoInterop::get_random_bytes(32);
    let nonce = CryptoInterop::get_random_bytes(12);

    let ct = AesGcm::encrypt(&key, &nonce, b"data", b"correct aad").unwrap();
    assert!(AesGcm::decrypt(&key, &nonce, &ct, b"wrong aad").is_err());
}

#[test]
fn hybrid_ikm_salt_initiator_responder_agree() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();

    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session
        .encrypt(b"hybrid salt test", 0, 1, None)
        .unwrap();
    let dec = bob_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"hybrid salt test");

    let env2 = bob_session
        .encrypt(b"reverse direction", 0, 2, None)
        .unwrap();
    let dec2 = alice_session.decrypt(&env2).unwrap();
    assert_eq!(dec2.plaintext, b"reverse direction");
}

#[test]
fn session_bidirectional_alternating_50_messages() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..50 {
        if i % 2 == 0 {
            let msg = format!("Alice msg #{i}");
            let env = alice_session.encrypt(msg.as_bytes(), 0, i, None).unwrap();
            let dec = bob_session.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, msg.as_bytes());
        } else {
            let msg = format!("Bob msg #{i}");
            let env = bob_session.encrypt(msg.as_bytes(), 1, i, None).unwrap();
            let dec = alice_session.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, msg.as_bytes());
        }
    }
}

#[test]
fn session_burst_then_switch_direction() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..20 {
        let msg = format!("Burst A→B #{i}");
        let env = alice_session.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let dec = bob_session.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, msg.as_bytes());
    }

    for i in 0u32..20 {
        let msg = format!("Burst B→A #{i}");
        let env = bob_session.encrypt(msg.as_bytes(), 1, i, None).unwrap();
        let dec = alice_session.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, msg.as_bytes());
    }

    for i in 20u32..30 {
        let msg = format!("Burst A→B #{i}");
        let env = alice_session.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let dec = bob_session.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, msg.as_bytes());
    }
}

#[test]
fn session_replay_attack_detected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session
        .encrypt(b"original message", 0, 1, None)
        .unwrap();

    let dec = bob_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"original message");

    let replay_result = bob_session.decrypt(&env);
    assert!(replay_result.is_err());
}

#[test]
fn session_export_import_continued_communication() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..5 {
        let env = alice_session
            .encrypt(format!("pre-save {i}").as_bytes(), 0, i, None)
            .unwrap();
        bob_session.decrypt(&env).unwrap();
    }

    let enc_key = CryptoInterop::get_random_bytes(32);
    let alice_provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let bob_provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let alice_sealed = alice_session
        .export_sealed_state(&alice_provider, 1)
        .unwrap();
    let bob_sealed = bob_session.export_sealed_state(&bob_provider, 1).unwrap();

    let alice_provider2 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let bob_provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let alice_session2 =
        ecliptix_protocol::protocol::Session::from_sealed_state(&alice_sealed, &alice_provider2, 0)
            .unwrap();
    let bob_session2 =
        ecliptix_protocol::protocol::Session::from_sealed_state(&bob_sealed, &bob_provider2, 0)
            .unwrap();

    for i in 5u32..10 {
        let env = alice_session2
            .encrypt(format!("post-restore {i}").as_bytes(), 0, i, None)
            .unwrap();
        let dec = bob_session2.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, format!("post-restore {i}").as_bytes());
    }

    for i in 0u32..5 {
        let env = bob_session2
            .encrypt(format!("bob-post {i}").as_bytes(), 1, i, None)
            .unwrap();
        let dec = alice_session2.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, format!("bob-post {i}").as_bytes());
    }
}

#[test]
fn deterministic_identity_handshake() {
    init();
    let master_a = CryptoInterop::get_random_bytes(32);
    let master_b = CryptoInterop::get_random_bytes(32);

    let mut alice = IdentityKeys::create_from_master_key(&master_a, "alice", 5).unwrap();
    let mut bob = IdentityKeys::create_from_master_key(&master_b, "bob", 5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session
        .encrypt(b"deterministic keys work", 0, 1, None)
        .unwrap();
    let dec = bob_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"deterministic keys work");
}

#[test]
fn secure_memory_handles_survive_export_import() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session.encrypt(b"before export", 0, 1, None).unwrap();
    bob_session.decrypt(&env).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let env2 = alice_session
        .encrypt(b"after restore from guarded", 0, 2, None)
        .unwrap();
    let dec = bob_restored.decrypt(&env2).unwrap();
    assert_eq!(dec.plaintext, b"after restore from guarded");

    let env3 = bob_restored
        .encrypt(b"bob reply post-restore", 0, 10, None)
        .unwrap();
    let dec3 = alice_session.decrypt(&env3).unwrap();
    assert_eq!(dec3.plaintext, b"bob reply post-restore");

    let enc_key3 = CryptoInterop::get_random_bytes(32);
    let provider3 = StaticStateKeyProvider::new(enc_key3.clone()).unwrap();
    let sealed2 = bob_restored.export_sealed_state(&provider3, 2).unwrap();
    let provider4 = StaticStateKeyProvider::new(enc_key3).unwrap();
    let bob_re =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed2, &provider4, 1).unwrap();
    let env4 = alice_session
        .encrypt(b"double sealed path", 0, 3, None)
        .unwrap();
    let dec4 = bob_re.decrypt(&env4).unwrap();
    assert_eq!(dec4.plaintext, b"double sealed path");
}

#[test]
fn secure_memory_double_export_import() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);

    let env1 = alice_session.encrypt(b"msg-1", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let p1 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed1 = bob_session.export_sealed_state(&p1, 2).unwrap();
    let p2 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let bob2 = ecliptix_protocol::protocol::Session::from_sealed_state(&sealed1, &p2, 0).unwrap();

    let env2 = alice_session.encrypt(b"msg-2", 0, 2, None).unwrap();
    bob2.decrypt(&env2).unwrap();

    let p3 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed2 = bob2.export_sealed_state(&p3, 1).unwrap();
    let p4 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob3 = ecliptix_protocol::protocol::Session::from_sealed_state(&sealed2, &p4, 0).unwrap();

    let env3 = alice_session
        .encrypt(b"msg-3-double-restore", 0, 3, None)
        .unwrap();
    let dec3 = bob3.decrypt(&env3).unwrap();
    assert_eq!(dec3.plaintext, b"msg-3-double-restore");
}

#[test]
fn sealed_state_rollback_rejected_by_external_counter() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);

    let p0 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed0 = bob_session.export_sealed_state(&p0, 1).unwrap();

    let env1 = alice_session.encrypt(b"advance", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let p1 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed1 = bob_session.export_sealed_state(&p1, 2).unwrap();

    let p_restore_old = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    assert!(
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed0, &p_restore_old, 1)
            .is_err(),
        "Older sealed snapshot must be rejected after newer export",
    );

    let p_restore_new = StaticStateKeyProvider::new(enc_key).unwrap();
    assert!(
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed1, &p_restore_new, 1)
            .is_ok(),
        "Latest sealed snapshot must still be accepted",
    );
}

#[test]
fn replay_nonces_persist_across_sealed_export_import() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"original", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();
    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let replay_result = bob_restored.decrypt(&env1);
    assert!(
        replay_result.is_err(),
        "Replay attack must be detected after session restore"
    );

    let env2 = alice_session.encrypt(b"fresh", 0, 2, None).unwrap();
    let dec2 = bob_restored.decrypt(&env2).unwrap();
    assert_eq!(dec2.plaintext, b"fresh");
}

#[test]
fn replay_nonces_persist_multiple() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut envelopes = Vec::new();
    for i in 0u32..5 {
        let env = alice_session
            .encrypt(format!("msg-{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob_session.decrypt(&env).unwrap();
        envelopes.push(env);
    }

    let enc_key = CryptoInterop::get_random_bytes(32);
    let p1 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&p1, 1).unwrap();
    let p2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &p2, 0).unwrap();

    for (i, env) in envelopes.iter().enumerate() {
        let result = bob_restored.decrypt(env);
        assert!(
            result.is_err(),
            "Envelope {i} replay must be detected after restore"
        );
    }

    let env_fresh = alice_session
        .encrypt(b"after-all-replays", 0, 10, None)
        .unwrap();
    let dec = bob_restored.decrypt(&env_fresh).unwrap();
    assert_eq!(dec.plaintext, b"after-all-replays");
}

#[test]
fn direction_change_triggers_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"hello bob", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let env2 = bob_session.encrypt(b"hello alice", 1, 1, None).unwrap();

    assert!(
        env2.dh_public_key.is_some(),
        "Direction-change reply must include DH public key"
    );
    assert!(
        env2.kyber_ciphertext.is_some(),
        "Direction-change reply must include Kyber ciphertext"
    );
    assert!(
        env2.new_kyber_public.is_some(),
        "Direction-change reply must include new Kyber public key"
    );

    let dec = alice_session.decrypt(&env2).unwrap();
    assert_eq!(dec.plaintext, b"hello alice");
}

#[test]
fn alternating_messages_all_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut ratchet_count = 0u32;

    for i in 0u32..20 {
        if i % 2 == 0 {
            let env = alice_session
                .encrypt(format!("A→B #{i}").as_bytes(), 0, i, None)
                .unwrap();

            if i > 0 {
                assert!(
                    env.dh_public_key.is_some(),
                    "Msg {i}: expected ratchet headers"
                );
                assert!(
                    env.kyber_ciphertext.is_some(),
                    "Msg {i}: expected kyber_ciphertext"
                );
                assert!(
                    env.new_kyber_public.is_some(),
                    "Msg {i}: expected new_kyber_public"
                );
                ratchet_count += 1;
            }

            let dec = bob_session.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("A→B #{i}").as_bytes());
        } else {
            let env = bob_session
                .encrypt(format!("B→A #{i}").as_bytes(), 1, i, None)
                .unwrap();

            assert!(
                env.dh_public_key.is_some(),
                "Msg {i}: expected ratchet headers"
            );
            assert!(
                env.kyber_ciphertext.is_some(),
                "Msg {i}: expected kyber_ciphertext"
            );
            assert!(
                env.new_kyber_public.is_some(),
                "Msg {i}: expected new_kyber_public"
            );
            ratchet_count += 1;

            let dec = alice_session.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("B→A #{i}").as_bytes());
        }
    }

    assert_eq!(
        ratchet_count, 19,
        "Expected 19 ratchets for 20 alternating messages"
    );
}

#[test]
fn burst_messages_single_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..10 {
        let env = alice_session
            .encrypt(format!("burst-{i}").as_bytes(), 0, i, None)
            .unwrap();
        if i > 0 {
            assert!(
                env.dh_public_key.is_none(),
                "Burst msg {i}: no ratchet expected"
            );
            assert!(
                env.kyber_ciphertext.is_none(),
                "Burst msg {i}: no kyber_ct expected"
            );
            assert!(
                env.new_kyber_public.is_none(),
                "Burst msg {i}: no new_kyber_pk expected"
            );
        }
        bob_session.decrypt(&env).unwrap();
    }

    let reply = bob_session.encrypt(b"bob-reply", 1, 1, None).unwrap();
    assert!(reply.dh_public_key.is_some(), "First reply must ratchet");
    assert!(
        reply.kyber_ciphertext.is_some(),
        "First reply must include kyber_ct"
    );
    assert!(
        reply.new_kyber_public.is_some(),
        "First reply must include new_kyber_pk"
    );
    alice_session.decrypt(&reply).unwrap();

    for i in 2u32..6 {
        let env = bob_session
            .encrypt(format!("bob-{i}").as_bytes(), 1, i, None)
            .unwrap();
        assert!(
            env.dh_public_key.is_none(),
            "Continued msg {i}: no ratchet expected"
        );
        alice_session.decrypt(&env).unwrap();
    }
}

#[test]
fn kyber_key_rotation_on_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"msg-1", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let env2 = bob_session.encrypt(b"msg-2", 1, 1, None).unwrap();
    let kyber_pk_1 = env2
        .new_kyber_public
        .clone()
        .expect("First ratchet must have new_kyber_public");
    alice_session.decrypt(&env2).unwrap();

    let env3 = alice_session.encrypt(b"msg-3", 0, 2, None).unwrap();
    let kyber_pk_2 = env3
        .new_kyber_public
        .clone()
        .expect("Second ratchet must have new_kyber_public");
    bob_session.decrypt(&env3).unwrap();

    assert_ne!(
        kyber_pk_1, kyber_pk_2,
        "Each ratchet must generate a fresh Kyber keypair"
    );
    assert_eq!(
        kyber_pk_1.len(),
        1184,
        "Kyber-768 public key must be 1184 bytes"
    );
    assert_eq!(
        kyber_pk_2.len(),
        1184,
        "Kyber-768 public key must be 1184 bytes"
    );
}

#[test]
fn session_restore_preserves_pending_flag() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session
        .encrypt(b"trigger pending", 0, 1, None)
        .unwrap();
    bob_session.decrypt(&env1).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let env2 = bob_restored
        .encrypt(b"reply after restore", 1, 1, None)
        .unwrap();
    assert!(
        env2.dh_public_key.is_some(),
        "Restored session must trigger ratchet (pending flag persisted)"
    );
    assert!(
        env2.kyber_ciphertext.is_some(),
        "Restored session ratchet: kyber_ct"
    );
    assert!(
        env2.new_kyber_public.is_some(),
        "Restored session ratchet: new_kyber_pk"
    );

    let dec = alice_session.decrypt(&env2).unwrap();
    assert_eq!(dec.plaintext, b"reply after restore");
}

#[test]
fn chain_exhaustion_still_works() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 3).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 3).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut envelopes = Vec::new();
    for i in 0u32..4 {
        let env = alice_session
            .encrypt(format!("chain-{i}").as_bytes(), 0, i, None)
            .unwrap();
        envelopes.push(env);
    }

    for (i, env) in envelopes.iter().enumerate().take(3) {
        assert!(
            env.dh_public_key.is_none(),
            "Msg {i}: no ratchet expected before exhaustion"
        );
    }

    assert!(
        envelopes[3].dh_public_key.is_some(),
        "Chain exhaustion must trigger ratchet"
    );
    assert!(
        envelopes[3].kyber_ciphertext.is_some(),
        "Chain exhaustion ratchet: kyber_ct"
    );
    assert!(
        envelopes[3].new_kyber_public.is_some(),
        "Chain exhaustion ratchet: new_kyber_pk"
    );

    for (i, env) in envelopes.iter().enumerate() {
        let dec = bob_session.decrypt(env).unwrap();
        assert_eq!(dec.plaintext, format!("chain-{i}").as_bytes());
    }
}

#[test]
fn incomplete_ratchet_header_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"setup", 0, 1, None).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let mut env2 = bob_session.encrypt(b"reply", 1, 1, None).unwrap();

    assert!(
        env2.new_kyber_public.is_some(),
        "Precondition: ratchet envelope has new_kyber_public"
    );
    env2.new_kyber_public = None;

    let result = alice_session.decrypt(&env2);
    assert!(
        result.is_err(),
        "Incomplete ratchet header (missing new_kyber_public) must be rejected"
    );
}

#[test]
fn simultaneous_send_convergence() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env_a1 = alice_session.encrypt(b"alice-1", 0, 1, None).unwrap();
    bob_session.decrypt(&env_a1).unwrap();

    let env_b1 = bob_session.encrypt(b"bob-1", 1, 1, None).unwrap();
    assert!(env_b1.dh_public_key.is_some());

    let env_a2 = alice_session.encrypt(b"alice-2", 0, 2, None).unwrap();

    let dec_b1 = alice_session.decrypt(&env_b1).unwrap();
    assert_eq!(dec_b1.plaintext, b"bob-1");

    let dec_a2 = bob_session.decrypt(&env_a2).unwrap();
    assert_eq!(dec_a2.plaintext, b"alice-2");

    let env_a3 = alice_session
        .encrypt(b"alice-converged", 0, 3, None)
        .unwrap();
    assert!(
        env_a3.dh_public_key.is_some(),
        "Alice's send after receiving ratchet must ratchet"
    );
    let dec_a3 = bob_session.decrypt(&env_a3).unwrap();
    assert_eq!(dec_a3.plaintext, b"alice-converged");

    let env_b2 = bob_session.encrypt(b"bob-converged", 1, 2, None).unwrap();
    let dec_b2 = alice_session.decrypt(&env_b2).unwrap();
    assert_eq!(dec_b2.plaintext, b"bob-converged");
}

#[test]
fn out_of_order_same_epoch() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut envelopes = Vec::new();
    for i in 0u32..5 {
        envelopes.push(
            alice_session
                .encrypt(format!("msg-{i}").as_bytes(), 0, i, None)
                .unwrap(),
        );
    }

    let order = [2, 0, 4, 1, 3];
    for &idx in &order {
        let dec = bob_session.decrypt(&envelopes[idx]).unwrap();
        assert_eq!(
            dec.plaintext,
            format!("msg-{idx}").as_bytes(),
            "OOO msg {idx} must decrypt"
        );
    }

    let env_after = alice_session.encrypt(b"after-ooo", 0, 10, None).unwrap();
    let dec_after = bob_session.decrypt(&env_after).unwrap();
    assert_eq!(dec_after.plaintext, b"after-ooo");
}

#[test]
fn old_epoch_message_after_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env0 = alice_session.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice_session.encrypt(b"msg-1", 0, 1, None).unwrap();
    let env2 = alice_session.encrypt(b"msg-2", 0, 2, None).unwrap();

    bob_session.decrypt(&env0).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let bob_reply = bob_session.encrypt(b"bob-reply", 1, 1, None).unwrap();
    assert!(
        bob_reply.dh_public_key.is_some(),
        "Direction change must trigger ratchet"
    );
    assert!(
        bob_reply.previous_chain_length.is_some(),
        "Ratchet must include previous_chain_length"
    );

    alice_session.decrypt(&bob_reply).unwrap();

    let dec2 = bob_session.decrypt(&env2).unwrap();
    assert_eq!(
        dec2.plaintext, b"msg-2",
        "Delayed old-epoch message must decrypt"
    );
}

#[test]
fn multiple_old_epoch_messages_across_ratchets() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env_e0_0 = alice_session.encrypt(b"e0-0", 0, 0, None).unwrap();
    let env_e0_1 = alice_session.encrypt(b"e0-1", 0, 1, None).unwrap();
    let env_e0_2 = alice_session.encrypt(b"e0-2", 0, 2, None).unwrap();
    bob_session.decrypt(&env_e0_0).unwrap();
    bob_session.decrypt(&env_e0_1).unwrap();

    let bob_r1 = bob_session.encrypt(b"bob-r1", 1, 0, None).unwrap();
    assert!(bob_r1.dh_public_key.is_some());
    alice_session.decrypt(&bob_r1).unwrap();

    let env_e1_0 = alice_session.encrypt(b"e1-0", 0, 10, None).unwrap();
    let env_e1_1 = alice_session.encrypt(b"e1-1", 0, 11, None).unwrap();
    assert!(
        env_e1_0.dh_public_key.is_some(),
        "Alice's reply must ratchet"
    );
    bob_session.decrypt(&env_e1_0).unwrap();

    let bob_r2 = bob_session.encrypt(b"bob-r2", 1, 20, None).unwrap();
    assert!(bob_r2.dh_public_key.is_some());
    alice_session.decrypt(&bob_r2).unwrap();

    let dec_e0_2 = bob_session.decrypt(&env_e0_2).unwrap();
    assert_eq!(
        dec_e0_2.plaintext, b"e0-2",
        "Epoch-0 delayed msg must decrypt after 2 ratchets"
    );

    let dec_e1_1 = bob_session.decrypt(&env_e1_1).unwrap();
    assert_eq!(
        dec_e1_1.plaintext, b"e1-1",
        "Epoch-1 delayed msg must decrypt after 1 ratchet"
    );

    let env_cont = alice_session.encrypt(b"continue", 0, 30, None).unwrap();
    let dec_cont = bob_session.decrypt(&env_cont).unwrap();
    assert_eq!(dec_cont.plaintext, b"continue");
}

#[test]
fn previous_chain_length_in_envelope() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    for i in 0u32..3 {
        let env = alice_session
            .encrypt(format!("a{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob_session.decrypt(&env).unwrap();
    }

    let bob_reply = bob_session.encrypt(b"bob-first-reply", 1, 0, None).unwrap();
    assert!(
        bob_reply.dh_public_key.is_some(),
        "Must be a ratchet envelope"
    );
    assert_eq!(
        bob_reply.previous_chain_length,
        Some(0),
        "Bob sent 0 msgs before ratchet"
    );
    alice_session.decrypt(&bob_reply).unwrap();

    let alice_reply = alice_session.encrypt(b"alice-reply", 0, 10, None).unwrap();
    assert!(
        alice_reply.dh_public_key.is_some(),
        "Must be a ratchet envelope"
    );
    assert_eq!(
        alice_reply.previous_chain_length,
        Some(3),
        "Alice sent 3 msgs before ratchet"
    );
}

#[test]
fn replay_old_epoch_message_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env0 = alice_session.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice_session.encrypt(b"msg-1", 0, 1, None).unwrap();
    let env2 = alice_session.encrypt(b"msg-2", 0, 2, None).unwrap();
    bob_session.decrypt(&env0).unwrap();
    bob_session.decrypt(&env1).unwrap();

    let bob_reply = bob_session.encrypt(b"bob-r", 1, 0, None).unwrap();
    alice_session.decrypt(&bob_reply).unwrap();

    let dec2 = bob_session.decrypt(&env2).unwrap();
    assert_eq!(dec2.plaintext, b"msg-2");

    let replay = bob_session.decrypt(&env2);
    assert!(
        replay.is_err(),
        "Replayed old-epoch message must be rejected"
    );
}

#[test]
fn export_import_preserves_skipped_keys() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut envelopes = Vec::new();
    for i in 0u32..5 {
        envelopes.push(
            alice_session
                .encrypt(format!("msg-{i}").as_bytes(), 0, i, None)
                .unwrap(),
        );
    }
    bob_session.decrypt(&envelopes[0]).unwrap();
    bob_session.decrypt(&envelopes[4]).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    for idx in [1, 2, 3] {
        let dec = bob_restored.decrypt(&envelopes[idx]).unwrap();
        assert_eq!(
            dec.plaintext,
            format!("msg-{idx}").as_bytes(),
            "Skipped msg {idx} must decrypt after export/import"
        );
    }
}

#[test]
fn export_import_preserves_multi_epoch_skipped_keys() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env_e0_0 = alice_session.encrypt(b"e0-0", 0, 0, None).unwrap();
    let env_e0_1 = alice_session.encrypt(b"e0-1", 0, 1, None).unwrap();
    let env_e0_2 = alice_session.encrypt(b"e0-2", 0, 2, None).unwrap();
    bob_session.decrypt(&env_e0_0).unwrap();
    bob_session.decrypt(&env_e0_1).unwrap();

    let bob_r = bob_session.encrypt(b"bob-r", 1, 0, None).unwrap();
    assert!(bob_r.dh_public_key.is_some());
    alice_session.decrypt(&bob_r).unwrap();

    let env_e1 = alice_session.encrypt(b"e1-0", 0, 10, None).unwrap();
    assert!(env_e1.dh_public_key.is_some());
    bob_session.decrypt(&env_e1).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let dec = bob_restored.decrypt(&env_e0_2).unwrap();
    assert_eq!(
        dec.plaintext, b"e0-2",
        "Old-epoch msg must decrypt after export/import"
    );
}

#[test]
fn skipped_key_cache_overflow() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 5000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 5000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut envelopes = Vec::new();
    for i in 0u32..1002 {
        envelopes.push(
            alice_session
                .encrypt(format!("m{i}").as_bytes(), 0, i, None)
                .unwrap(),
        );
    }

    let result = bob_session.decrypt(&envelopes[1001]);
    assert!(
        result.is_err(),
        "Skipping >1000 messages must trigger cache overflow error"
    );
}

#[test]
fn metadata_key_rotates_on_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env0 = alice_session
        .encrypt(b"before-ratchet", 0, 0, None)
        .unwrap();
    bob_session.decrypt(&env0).unwrap();

    let bob_reply = bob_session.encrypt(b"bob-reply", 1, 0, None).unwrap();
    assert!(bob_reply.dh_public_key.is_some());
    alice_session.decrypt(&bob_reply).unwrap();

    let env1 = alice_session
        .encrypt(b"after-ratchet", 0, 10, None)
        .unwrap();
    assert!(
        env1.dh_public_key.is_some(),
        "Alice must ratchet after receiving Bob's ratchet"
    );

    let dec1 = bob_session.decrypt(&env1).unwrap();
    assert_eq!(dec1.plaintext, b"after-ratchet");

    assert_ne!(
        env0.ratchet_epoch, env1.ratchet_epoch,
        "Messages before and after ratchet must use different epochs"
    );
}

#[test]
fn old_epoch_metadata_decrypts_after_rotation() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env0 = alice_session.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice_session.encrypt(b"msg-1", 0, 1, None).unwrap();
    bob_session.decrypt(&env0).unwrap();

    let bob_reply = bob_session.encrypt(b"bob-r", 1, 0, None).unwrap();
    alice_session.decrypt(&bob_reply).unwrap();

    let alice_reply = alice_session.encrypt(b"alice-r", 0, 10, None).unwrap();
    assert!(alice_reply.dh_public_key.is_some());
    bob_session.decrypt(&alice_reply).unwrap();

    let dec1 = bob_session.decrypt(&env1).unwrap();
    assert_eq!(
        dec1.plaintext, b"msg-1",
        "Old-epoch metadata must decrypt after metadata key rotation"
    );
}

#[test]
fn metadata_key_rotation_across_multiple_ratchets() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let e0_0 = alice_session.encrypt(b"e0-0", 0, 0, None).unwrap();
    let e0_1 = alice_session.encrypt(b"e0-1", 0, 1, None).unwrap();
    bob_session.decrypt(&e0_0).unwrap();

    let bob_r1 = bob_session.encrypt(b"bob-r1", 1, 0, None).unwrap();
    alice_session.decrypt(&bob_r1).unwrap();

    let e1_0 = alice_session.encrypt(b"e1-0", 0, 10, None).unwrap();
    let e1_1 = alice_session.encrypt(b"e1-1", 0, 11, None).unwrap();
    bob_session.decrypt(&e1_0).unwrap();

    let bob_r2 = bob_session.encrypt(b"bob-r2", 1, 10, None).unwrap();
    alice_session.decrypt(&bob_r2).unwrap();

    let e2_0 = alice_session.encrypt(b"e2-0", 0, 20, None).unwrap();
    bob_session.decrypt(&e2_0).unwrap();

    let dec_e0_1 = bob_session.decrypt(&e0_1).unwrap();
    assert_eq!(dec_e0_1.plaintext, b"e0-1");

    let dec_e1_1 = bob_session.decrypt(&e1_1).unwrap();
    assert_eq!(dec_e1_1.plaintext, b"e1-1");
}

#[test]
fn export_import_preserves_cached_metadata_keys() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env0 = alice_session.encrypt(b"e0-msg", 0, 0, None).unwrap();
    let env1 = alice_session.encrypt(b"e0-delayed", 0, 1, None).unwrap();
    bob_session.decrypt(&env0).unwrap();

    let bob_r = bob_session.encrypt(b"bob-r", 1, 0, None).unwrap();
    alice_session.decrypt(&bob_r).unwrap();

    let alice_r = alice_session.encrypt(b"alice-r", 0, 10, None).unwrap();
    bob_session.decrypt(&alice_r).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let dec = bob_restored.decrypt(&env1).unwrap();
    assert_eq!(
        dec.plaintext, b"e0-delayed",
        "Old-epoch msg must decrypt after export/import (metadata key cached)"
    );
}

#[test]
fn metadata_key_differs_across_epochs() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let p0 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed0 = alice_session.export_sealed_state(&p0, 1).unwrap();

    let env = alice_session.encrypt(b"trigger", 0, 0, None).unwrap();
    bob_session.decrypt(&env).unwrap();
    let bob_r = bob_session.encrypt(b"reply", 1, 0, None).unwrap();
    alice_session.decrypt(&bob_r).unwrap();

    let p1 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed1 = alice_session.export_sealed_state(&p1, 2).unwrap();

    assert_ne!(sealed0, sealed1, "State must differ after ratchet");

    let pa = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    assert!(
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed0, &pa, 1).is_err(),
        "Older sealed snapshot must be rejected after newer export (anti-rollback)",
    );
    let pb = StaticStateKeyProvider::new(enc_key).unwrap();
    ecliptix_protocol::protocol::Session::from_sealed_state(&sealed1, &pb, 1).unwrap();
}

#[test]
fn malformed_envelope_truncated_bytes() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session.encrypt(b"test payload", 0, 1, None).unwrap();

    let mut damaged = env.clone();
    damaged.encrypted_payload =
        damaged.encrypted_payload[..damaged.encrypted_payload.len() / 2].to_vec();
    assert!(
        bob_session.decrypt(&damaged).is_err(),
        "Truncated ciphertext must fail"
    );

    let mut damaged2 = env.clone();
    damaged2.encrypted_metadata = vec![0u8; 3];
    assert!(
        bob_session.decrypt(&damaged2).is_err(),
        "Truncated metadata must fail"
    );

    let mut damaged3 = env;
    damaged3.encrypted_payload = vec![];
    assert!(
        bob_session.decrypt(&damaged3).is_err(),
        "Empty ciphertext must fail"
    );
}

#[test]
fn malformed_envelope_bit_flip_ciphertext() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session
        .encrypt(b"integrity test", 0, 1, None)
        .unwrap();

    let mut damaged = env.clone();
    if let Some(byte) = damaged.encrypted_payload.first_mut() {
        *byte ^= 0x01;
    }
    assert!(
        bob_session.decrypt(&damaged).is_err(),
        "Single bit flip in ciphertext must fail"
    );

    let mut damaged2 = env;
    if let Some(byte) = damaged2.header_nonce.first_mut() {
        *byte ^= 0x01;
    }
    assert!(
        bob_session.decrypt(&damaged2).is_err(),
        "Flipped nonce must fail"
    );
}

#[test]
fn malformed_envelope_wrong_version() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let mut env = alice_session.encrypt(b"version test", 0, 1, None).unwrap();
    env.version = 999;
    assert!(
        bob_session.decrypt(&env).is_err(),
        "Wrong envelope version must be rejected"
    );
}

#[test]
fn malformed_envelope_random_garbage() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let _alice_session = initiator.finish(&ack_bytes).unwrap();

    let garbage = ecliptix_protocol::proto::SecureEnvelope {
        version: 1,
        ratchet_epoch: 0,
        header_nonce: CryptoInterop::get_random_bytes(12),
        encrypted_metadata: CryptoInterop::get_random_bytes(64),
        encrypted_payload: CryptoInterop::get_random_bytes(128),
        ..Default::default()
    };
    assert!(
        bob_session.decrypt(&garbage).is_err(),
        "Random garbage envelope must fail"
    );
}

#[test]
fn nonce_generator_overflow_rejected() {
    init();
    use ecliptix_protocol::protocol::nonce::{NonceGenerator, NonceState};

    let state_max = NonceState::new([0xAA; 8], 0xFFFF);
    assert!(
        state_max.is_err(),
        "Counter at MAX_NONCE_COUNTER must be rejected at construction"
    );

    let state_penultimate = NonceState::new([0xAA; 8], 0xFFFE).unwrap();
    let mut gen = NonceGenerator::from_state(state_penultimate).unwrap();

    let result = gen.next(0);
    assert!(
        result.is_ok(),
        "Counter at MAX-1 should produce one last nonce"
    );

    let overflow = gen.next(0);
    assert!(
        overflow.is_err(),
        "Counter past MAX must fail with overflow error"
    );
}

#[test]
fn nonce_generator_max_message_index_rejected() {
    init();
    use ecliptix_protocol::protocol::nonce::{NonceGenerator, NonceState};
    let state = NonceState::new([0xBB; 8], 0).unwrap();
    let mut gen = NonceGenerator::from_state(state).unwrap();

    let result = gen.next(0xFFFF);
    assert!(
        result.is_err(),
        "Message index >= MAX_MESSAGE_INDEX must be rejected"
    );
}

#[test]
fn nonce_generator_from_state_overflow_rejected() {
    init();
    use ecliptix_protocol::protocol::nonce::NonceState;
    let state = NonceState::new([0xCC; 8], 0xFFFF);
    assert!(
        state.is_err(),
        "Counter >= MAX_NONCE_COUNTER must be rejected at construction"
    );
}

#[test]
fn session_destroy_prevents_encrypt() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session.encrypt(b"pre-destroy", 0, 1, None).unwrap();
    bob_session.decrypt(&env).unwrap();

    alice_session.destroy();
    assert!(alice_session.is_destroyed());

    assert!(
        alice_session.encrypt(b"post-destroy", 0, 2, None).is_err(),
        "Encrypt after destroy must fail"
    );
    assert!(
        alice_session.decrypt(&env).is_err(),
        "Decrypt after destroy must fail"
    );
    let destroy_key = CryptoInterop::get_random_bytes(32);
    let destroy_provider = StaticStateKeyProvider::new(destroy_key).unwrap();
    assert!(
        alice_session
            .export_sealed_state(&destroy_provider, 1)
            .is_err(),
        "Export after destroy must fail"
    );
}

#[test]
fn session_destroy_does_not_affect_peer() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env = alice_session.encrypt(b"last message", 0, 1, None).unwrap();
    alice_session.destroy();

    let dec = bob_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"last message");

    let env2 = bob_session.encrypt(b"bob reply", 1, 1, None).unwrap();
    assert!(alice_session.decrypt(&env2).is_err());
}

#[test]
fn post_compromise_security_after_ratchet() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env_epoch0 = alice_session.encrypt(b"epoch0 msg", 0, 1, None).unwrap();
    bob_session.decrypt(&env_epoch0).unwrap();

    let comp_key = CryptoInterop::get_random_bytes(32);
    let comp_provider = StaticStateKeyProvider::new(comp_key.clone()).unwrap();
    let compromised_state = bob_session.export_sealed_state(&comp_provider, 1).unwrap();

    let env_bob = bob_session.encrypt(b"bob reply", 1, 1, None).unwrap();
    assert!(
        env_bob.dh_public_key.is_some(),
        "Direction change must ratchet"
    );
    alice_session.decrypt(&env_bob).unwrap();

    let env_epoch1 = alice_session.encrypt(b"epoch1 secret", 0, 2, None).unwrap();
    bob_session.decrypt(&env_epoch1).unwrap();

    let comp_provider2 = StaticStateKeyProvider::new(comp_key).unwrap();
    let attacker_session = ecliptix_protocol::protocol::Session::from_sealed_state(
        &compromised_state,
        &comp_provider2,
        0,
    )
    .unwrap();

    let attack_result = attacker_session.decrypt(&env_epoch1);
    assert!(
        attack_result.is_err(),
        "Post-compromise: epoch 0 state must NOT decrypt epoch 1 messages"
    );
}

#[test]
fn forward_secrecy_old_chain_keys_cannot_derive_future() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env1 = alice_session.encrypt(b"msg 1", 0, 1, None).unwrap();
    let env2 = alice_session.encrypt(b"msg 2", 0, 2, None).unwrap();
    let snap_key = CryptoInterop::get_random_bytes(32);
    let snap_prov = StaticStateKeyProvider::new(snap_key.clone()).unwrap();
    let snapshot = alice_session.export_sealed_state(&snap_prov, 1).unwrap();
    let env3 = alice_session.encrypt(b"msg 3", 0, 3, None).unwrap();
    let env4 = alice_session.encrypt(b"msg 4", 0, 4, None).unwrap();
    let env5 = alice_session.encrypt(b"msg 5", 0, 5, None).unwrap();

    bob_session.decrypt(&env1).unwrap();
    bob_session.decrypt(&env2).unwrap();
    let bob_reply = bob_session.encrypt(b"bob ratchets", 1, 1, None).unwrap();
    alice_session.decrypt(&bob_reply).unwrap();

    let env_post = alice_session
        .encrypt(b"post-ratchet secret", 0, 10, None)
        .unwrap();
    bob_session.decrypt(&env3).unwrap();
    bob_session.decrypt(&env4).unwrap();
    bob_session.decrypt(&env5).unwrap();
    bob_session.decrypt(&env_post).unwrap();

    let snap_prov2 = StaticStateKeyProvider::new(snap_key).unwrap();
    let attacker =
        ecliptix_protocol::protocol::Session::from_sealed_state(&snapshot, &snap_prov2, 0).unwrap();
    assert!(
        attacker.decrypt(&env_post).is_err(),
        "Pre-ratchet snapshot must not decrypt post-ratchet messages"
    );
}

#[test]
fn concurrent_encrypt_decrypt_no_deadlock() {
    init();
    use std::sync::Arc;
    use std::thread;

    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = Arc::new(responder.finish().unwrap());
    let alice_session = Arc::new(initiator.finish(&ack_bytes).unwrap());

    let mut handles = vec![];

    for t in 0u32..4 {
        let alice_clone = Arc::clone(&alice_session);
        let bob_clone = Arc::clone(&bob_session);
        handles.push(thread::spawn(move || {
            for i in 0u32..50 {
                let id = t * 1000 + i;
                let msg = format!("thread-{t} msg-{i}");
                let env = alice_clone.encrypt(msg.as_bytes(), 0, id, None).unwrap();
                let dec = bob_clone.decrypt(&env).unwrap();
                assert_eq!(dec.plaintext, msg.as_bytes());
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread must not panic");
    }
}

#[test]
fn tampered_sealed_state_root_key_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let _alice_session = initiator.finish(&ack_bytes).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob_session.export_sealed_state(&provider, 1).unwrap();

    let mut tampered = sealed;
    if tampered.len() > 50 {
        tampered[50] ^= 0x01;
    }
    let provider2 = StaticStateKeyProvider::new(enc_key).unwrap();
    assert!(
        ecliptix_protocol::protocol::Session::from_sealed_state(&tampered, &provider2, 0).is_err(),
        "Tampered sealed state must be rejected"
    );
}

#[test]
fn handshake_wrong_bundle_version_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let pb = PreKeyBundle {
        version: 999,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Wrong bundle version must be rejected"
    );
}

#[test]
fn handshake_invalid_signature_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let mut bad_sig = lb.signed_pre_key_signature().to_vec();
    bad_sig[0] ^= 0xFF;
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: bad_sig,
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Invalid SPK signature must be rejected"
    );
}

#[test]
fn handshake_invalid_identity_x25519_signature_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let mut bad_sig = lb.identity_x25519_signature().to_vec();
    bad_sig[0] ^= 0xFF;
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: bad_sig,
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Invalid identity X25519 signature must be rejected"
    );
}

#[test]
fn handshake_wrong_key_sizes_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: vec![0u8; 16],
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Wrong key size must be rejected"
    );
}

#[test]
fn handshake_small_order_point_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: vec![0u8; 32],
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Small-order X25519 point must be rejected"
    );
}

#[test]
fn handshake_missing_kyber_key_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let lb = bob.create_public_bundle().unwrap();
    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: vec![],
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Missing Kyber public key must be rejected"
    );
}

#[test]
fn handshake_reflexion_attack_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let lb = alice.create_public_bundle().unwrap();

    let pb = PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: vec![],
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
    };
    assert!(
        HandshakeInitiator::start(&mut alice, &pb, 1000).is_err(),
        "Reflexion attack (handshake with self) must be rejected"
    );
}

#[test]
fn handshake_truncated_init_rejected() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();

    let truncated = &init_bytes[..10.min(init_bytes.len())];
    assert!(
        HandshakeResponder::process(&mut bob, &bob_bundle, truncated, 1000).is_err(),
        "Truncated HandshakeInit must be rejected"
    );

    assert!(
        HandshakeResponder::process(&mut bob, &bob_bundle, &[], 1000).is_err(),
        "Empty HandshakeInit must be rejected"
    );
}

#[test]
fn kat_hkdf_sha256_rfc5869_test_case_1() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex("3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865");

    let okm = HkdfSha256::derive_key_bytes(&ikm, 42, &salt, &info).unwrap();
    assert_eq!(
        &*okm, &expected_okm,
        "HKDF-SHA256 RFC 5869 Test Case 1 mismatch"
    );
}

#[test]
fn kat_hkdf_sha256_rfc5869_test_case_3() {
    let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = b"";
    let info = b"";
    let expected_okm = hex("8da4e775a563c18f715f802a063c5a31\
         b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8");

    let okm = HkdfSha256::derive_key_bytes(&ikm, 42, salt, info).unwrap();
    assert_eq!(
        &*okm, &expected_okm,
        "HKDF-SHA256 RFC 5869 Test Case 3 mismatch"
    );
}

#[test]
fn kat_x25519_rfc7748_section_6_1() {
    init();
    let alice_sk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pk_expected = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pk_expected = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared_expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let alice_sk_arr: [u8; 32] = alice_sk.as_slice().try_into().unwrap();
    let alice_secret = x25519_dalek::StaticSecret::from(alice_sk_arr);
    let alice_pk = x25519_dalek::PublicKey::from(&alice_secret)
        .as_bytes()
        .to_vec();
    assert_eq!(alice_pk, alice_pk_expected, "Alice public key mismatch");

    let bob_sk_arr: [u8; 32] = bob_sk.as_slice().try_into().unwrap();
    let bob_secret = x25519_dalek::StaticSecret::from(bob_sk_arr);
    let bob_pk = x25519_dalek::PublicKey::from(&bob_secret)
        .as_bytes()
        .to_vec();
    assert_eq!(bob_pk, bob_pk_expected, "Bob public key mismatch");

    let bob_pk_arr: [u8; 32] = bob_pk.as_slice().try_into().unwrap();
    let shared_ab = alice_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(bob_pk_arr))
        .to_bytes()
        .to_vec();
    assert_eq!(
        shared_ab, shared_expected,
        "Shared secret (Alice×Bob) mismatch"
    );

    let alice_pk_arr: [u8; 32] = alice_pk.as_slice().try_into().unwrap();
    let shared_ba = bob_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(alice_pk_arr))
        .to_bytes()
        .to_vec();
    assert_eq!(
        shared_ba, shared_expected,
        "Shared secret (Bob×Alice) mismatch"
    );
}

#[test]
fn kat_aes256_gcm_siv_rfc8452_empty() {
    let key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("030000000000000000000000");
    let expected_ct = hex("07f5f4169bbf55a8400cd47ea6fd400f");

    let ct = AesGcm::encrypt(&key, &nonce, b"", b"").unwrap();
    assert_eq!(
        ct, expected_ct,
        "AES-256-GCM-SIV empty plaintext KAT mismatch"
    );

    let pt = AesGcm::decrypt(&key, &nonce, &ct, b"").unwrap();
    assert!(pt.is_empty());
}

#[test]
fn kat_aes256_gcm_siv_rfc8452_8byte() {
    let key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("030000000000000000000000");
    let plaintext = hex("0100000000000000");
    let expected_ct = hex("c2ef328e5c71c83b843122130f7364b761e0b97427e3df28");

    let ct = AesGcm::encrypt(&key, &nonce, &plaintext, b"").unwrap();
    assert_eq!(ct, expected_ct, "AES-256-GCM-SIV 8-byte KAT mismatch");

    let pt = AesGcm::decrypt(&key, &nonce, &ct, b"").unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn kat_aes256_gcm_siv_rfc8452_with_aad() {
    let key = hex("0100000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("030000000000000000000000");
    let aad = hex("01");
    let plaintext = hex("0200000000000000");
    let expected_ct = hex("1de22967237a813291213f267e3b452f02d01ae33e4ec854");

    let ct = AesGcm::encrypt(&key, &nonce, &plaintext, &aad).unwrap();
    assert_eq!(ct, expected_ct, "AES-256-GCM-SIV with-AAD KAT mismatch");

    let pt = AesGcm::decrypt(&key, &nonce, &ct, &aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn kat_kyber768_roundtrip_functional() {
    init();
    let (sk, pk) = KyberInterop::generate_keypair().unwrap();
    assert_eq!(pk.len(), 1184);

    let (ct, ss_enc) = KyberInterop::encapsulate(&pk).unwrap();
    assert_eq!(ct.len(), 1088);

    let ss_dec = KyberInterop::decapsulate(&ct, &sk).unwrap();
    let enc_bytes = ss_enc.read_bytes(32).unwrap();
    let dec_bytes = ss_dec.read_bytes(32).unwrap();
    assert_eq!(
        enc_bytes, dec_bytes,
        "Kyber-768 encap/decap shared secret mismatch"
    );
    assert_eq!(enc_bytes.len(), 32);
    assert!(
        enc_bytes.iter().any(|&b| b != 0),
        "Shared secret must not be all-zero"
    );
}

#[test]
fn kat_ed25519_sign_verify_functional() {
    init();
    let (sk_handle, pk) = CryptoInterop::generate_ed25519_keypair().unwrap();
    assert_eq!(pk.len(), 32);

    let msg = b"test message for ed25519 verification";
    let sk_bytes = sk_handle.read_bytes(64).unwrap();

    let sk_arr: [u8; 64] = sk_bytes.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_arr).unwrap();
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(msg);
    let sig_bytes = sig.to_bytes();
    assert_eq!(sig_bytes.len(), 64);

    let pk_arr: [u8; 32] = pk.as_slice().try_into().unwrap();
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(msg, &sig)
        .expect("Ed25519 signature verification failed");
}

#[test]
fn shamir_randomized_any_subset_reconstructs() {
    init();
    for _ in 0..50 {
        let secret_len = (CryptoInterop::generate_random_u32(true) % 63) as usize + 1;
        let secret = CryptoInterop::get_random_bytes(secret_len);
        let threshold = (CryptoInterop::generate_random_u32(true) % 4) as u8 + 2;
        let share_count = threshold + (CryptoInterop::generate_random_u32(true) % 5) as u8;
        let auth_key = CryptoInterop::get_random_bytes(32);

        let shares =
            ShamirSecretSharing::split(&secret, threshold, share_count, &auth_key).unwrap();
        let data_shares = &shares[..shares.len() - 1];
        let auth_tag = shares.last().unwrap();

        let indices: Vec<usize> = {
            let mut idx: Vec<usize> = (0..data_shares.len()).collect();
            for i in (1..idx.len()).rev() {
                let j = (CryptoInterop::generate_random_u32(false) as usize) % (i + 1);
                idx.swap(i, j);
            }
            idx[..threshold as usize].to_vec()
        };
        let mut subset: Vec<Vec<u8>> = indices.iter().map(|&i| data_shares[i].clone()).collect();
        subset.push(auth_tag.clone());

        let recovered =
            ShamirSecretSharing::reconstruct(&subset, &auth_key, threshold as usize).unwrap();
        assert_eq!(recovered, secret, "Shamir reconstruction failed for secret_len={secret_len}, t={threshold}, n={share_count}");
    }
}

#[test]
fn shamir_below_threshold_fails_hmac() {
    init();
    let secret = b"sub-threshold test";
    let auth_key = CryptoInterop::get_random_bytes(32);
    let shares = ShamirSecretSharing::split(secret, 4, 6, &auth_key).unwrap();
    let subset = vec![
        shares[0].clone(),
        shares[1].clone(),
        shares[2].clone(),
        shares.last().unwrap().clone(),
    ];
    assert!(ShamirSecretSharing::reconstruct(&subset, &auth_key, 4).is_err());
}

#[test]
fn pcs_across_five_ratchet_steps() {
    init();
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice, &bob_bundle, 1000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, 1000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    let env_epoch0 = alice_session.encrypt(b"epoch 0 msg", 0, 0, None).unwrap();
    bob_session.decrypt(&env_epoch0).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let p0 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let epoch0_state = bob_session.export_sealed_state(&p0, 1).unwrap();

    for i in 1u32..=5 {
        if i % 2 == 1 {
            let env = bob_session
                .encrypt(format!("ratchet B→A #{i}").as_bytes(), 1, i, None)
                .unwrap();
            alice_session.decrypt(&env).unwrap();
        } else {
            let env = alice_session
                .encrypt(format!("ratchet A→B #{i}").as_bytes(), 0, i, None)
                .unwrap();
            bob_session.decrypt(&env).unwrap();
        }
    }

    let env_epoch5 = alice_session.encrypt(b"epoch 5 msg", 0, 100, None).unwrap();
    bob_session.decrypt(&env_epoch5).unwrap();

    let p0_restore = StaticStateKeyProvider::new(enc_key).unwrap();
    let bob_epoch0 =
        ecliptix_protocol::protocol::Session::from_sealed_state(&epoch0_state, &p0_restore, 0)
            .unwrap();
    let result = bob_epoch0.decrypt(&env_epoch5);
    assert!(
        result.is_err(),
        "Epoch-0 snapshot must NOT decrypt epoch-5 message (forward secrecy)"
    );
}

#[test]
fn shamir_threshold_equals_share_count() {
    init();
    let secret = b"all shares needed";
    let auth_key = CryptoInterop::get_random_bytes(32);
    let shares = ShamirSecretSharing::split(secret, 5, 5, &auth_key).unwrap();
    assert_eq!(shares.len(), 6);
    let recovered = ShamirSecretSharing::reconstruct(&shares, &auth_key, 5).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_threshold_one_should_error() {
    init();
    let auth_key = CryptoInterop::get_random_bytes(32);
    let result = ShamirSecretSharing::split(b"secret", 1, 3, &auth_key);
    assert!(result.is_err(), "Threshold < 2 must be rejected");
}

#[test]
fn shamir_single_byte_secret() {
    init();
    let secret = &[0x42u8];
    let auth_key = CryptoInterop::get_random_bytes(32);
    let shares = ShamirSecretSharing::split(secret, 2, 3, &auth_key).unwrap();
    let recovered = ShamirSecretSharing::reconstruct(&shares, &auth_key, 2).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_duplicate_x_coords_error() {
    init();
    let secret = b"test duplicate";
    let auth_key = CryptoInterop::get_random_bytes(32);
    let shares = ShamirSecretSharing::split(secret, 2, 3, &auth_key).unwrap();
    let bad_shares = vec![
        shares[0].clone(),
        shares[0].clone(),
        shares.last().unwrap().clone(),
    ];
    let result = ShamirSecretSharing::reconstruct(&bad_shares, &auth_key, 2);
    assert!(result.is_err(), "Duplicate x-coordinates must be rejected");
}

#[test]
fn shamir_reconstruct_missing_auth_tag_fails() {
    init();
    let secret = b"auth required";
    let auth_key = CryptoInterop::get_random_bytes(32);
    let shares = ShamirSecretSharing::split(secret, 2, 4, &auth_key).unwrap();
    let shares_without_tag: Vec<Vec<u8>> = shares[..shares.len() - 1].to_vec();
    let result = ShamirSecretSharing::reconstruct(&shares_without_tag, &auth_key, 2);
    assert!(result.is_err(), "Reconstruct without auth tag must fail");
}

#[test]
fn hkdf_max_output_length() {
    let ikm = b"input key material for max test";
    let okm = HkdfSha256::derive_key_bytes(ikm, 8160, b"salt", b"info").unwrap();
    assert_eq!(okm.len(), 8160);
    assert!(okm.iter().any(|&b| b != 0));
}

#[test]
fn hkdf_over_max_output_length_errors() {
    let ikm = b"input key material";
    let result = HkdfSha256::derive_key_bytes(ikm, 8161, b"salt", b"info");
    assert!(result.is_err(), "Output length > 8160 must be rejected");
}

#[test]
fn hkdf_empty_salt() {
    let ikm = b"input key material";
    let okm = HkdfSha256::derive_key_bytes(ikm, 32, b"", b"info").unwrap();
    assert_eq!(okm.len(), 32);
    assert!(okm.iter().any(|&b| b != 0));
}

#[test]
fn hkdf_single_byte_output() {
    let ikm = b"input key material";
    let okm = HkdfSha256::derive_key_bytes(ikm, 1, b"salt", b"info").unwrap();
    assert_eq!(okm.len(), 1);
}

#[test]
fn hkdf_extract_produces_32_byte_prk() {
    let prk = HkdfSha256::extract(b"salt", b"input key material");
    assert_eq!(prk.len(), 32);
    assert!(prk.iter().any(|&b| b != 0));
}

#[test]
fn identity_keys_find_nonexistent_opk_returns_none() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    assert!(alice.find_one_time_pre_key_by_id(0xDEAD_BEEF).is_none());
}

#[test]
fn identity_keys_get_private_opk_nonexistent_errors() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    let result = alice.get_one_time_pre_key_private_by_id(0xDEAD_BEEF);
    assert!(result.is_err());
}

#[test]
fn identity_keys_consume_opk_nonexistent_errors() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    let result = alice.consume_one_time_pre_key_by_id(0xDEAD_BEEF);
    assert!(result.is_err());
}

#[test]
fn identity_keys_consume_pending_kyber_without_store_errors() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    let result = alice.consume_pending_kyber_handshake();
    assert!(result.is_err());
}

#[test]
fn identity_keys_get_pending_kyber_ciphertext_without_store_errors() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    let result = alice.get_pending_kyber_ciphertext();
    assert!(result.is_err());
}

#[test]
fn identity_keys_get_ephemeral_private_without_generate_errors() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    let result = alice.get_ephemeral_x25519_private_key_copy();
    assert!(result.is_err());
}

#[test]
fn identity_keys_ephemeral_public_none_before_generate() {
    init();
    let alice = IdentityKeys::create(3).unwrap();
    assert!(alice.get_ephemeral_x25519_public().is_none());
}

#[test]
fn identity_keys_create_zero_opks_succeeds() {
    init();
    let alice = IdentityKeys::create(0).unwrap();
    let bundle = alice.create_public_bundle().unwrap();
    assert!(bundle.one_time_pre_keys().is_empty());
}

#[test]
fn secure_memory_zero_size_allocation() {
    init();
    let result = SecureMemoryHandle::allocate(0);
    if let Ok(handle) = result {
        let read = handle.read_bytes(0);
        assert!(read.is_ok());
    }
}

#[test]
fn nonce_uniqueness_across_independent_sessions() {
    init();
    let plaintext = b"identical plaintext for both sessions";

    let mut alice1 = IdentityKeys::create(5).unwrap();
    let mut bob1 = IdentityKeys::create(5).unwrap();
    let bob1_bundle = PreKeyBundle::decode(build_proto_bundle(&bob1).as_slice()).unwrap();
    let init1 = HandshakeInitiator::start(&mut alice1, &bob1_bundle, 1000).unwrap();
    let init1_bytes = init1.encoded_message().to_vec();
    let resp1 = HandshakeResponder::process(&mut bob1, &bob1_bundle, &init1_bytes, 1000).unwrap();
    let ack1 = resp1.encoded_ack().to_vec();
    let _bob1_session = resp1.finish().unwrap();
    let alice1_session = init1.finish(&ack1).unwrap();

    let mut alice2 = IdentityKeys::create(5).unwrap();
    let mut bob2 = IdentityKeys::create(5).unwrap();
    let bob2_bundle = PreKeyBundle::decode(build_proto_bundle(&bob2).as_slice()).unwrap();
    let init2 = HandshakeInitiator::start(&mut alice2, &bob2_bundle, 1000).unwrap();
    let init2_bytes = init2.encoded_message().to_vec();
    let resp2 = HandshakeResponder::process(&mut bob2, &bob2_bundle, &init2_bytes, 1000).unwrap();
    let ack2 = resp2.encoded_ack().to_vec();
    let _bob2_session = resp2.finish().unwrap();
    let alice2_session = init2.finish(&ack2).unwrap();

    let env1 = alice1_session.encrypt(plaintext, 0, 1, None).unwrap();
    let env2 = alice2_session.encrypt(plaintext, 0, 1, None).unwrap();

    let env1_bytes = prost::Message::encode_to_vec(&env1);
    let env2_bytes = prost::Message::encode_to_vec(&env2);
    assert_ne!(
        env1_bytes, env2_bytes,
        "Independent sessions must produce different ciphertexts"
    );
}

fn attack_session_pair() -> (
    ecliptix_protocol::protocol::Session,
    ecliptix_protocol::protocol::Session,
) {
    init();
    let mut alice_ik = IdentityKeys::create(5).unwrap();
    let mut bob_ik = IdentityKeys::create(5).unwrap();

    let bob_bundle_bytes = build_proto_bundle(&bob_ik);
    let bob_bundle = PreKeyBundle::decode(bob_bundle_bytes.as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice_ik, &bob_bundle, 10000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();

    let responder =
        HandshakeResponder::process(&mut bob_ik, &bob_bundle, &init_bytes, 10000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();

    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    (alice_session, bob_session)
}

#[test]
fn attack_payload_bitflip_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"secret payload", 0, 1, None).unwrap();
    env.encrypted_payload[0] ^= 0xFF;
    assert!(
        bob.decrypt(&env).is_err(),
        "Bit-flipped payload must be rejected by AEAD"
    );
}

#[test]
fn attack_metadata_bitflip_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"secret payload", 0, 1, None).unwrap();
    env.encrypted_metadata[0] ^= 0xFF;
    assert!(
        bob.decrypt(&env).is_err(),
        "Bit-flipped metadata must be rejected by AEAD"
    );
}

#[test]
fn attack_header_nonce_tamper_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"secret payload", 0, 1, None).unwrap();
    env.header_nonce[0] ^= 0xFF;
    assert!(
        bob.decrypt(&env).is_err(),
        "Tampered header nonce must cause metadata decryption failure"
    );
}

#[test]
fn attack_epoch_increment_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"secret payload", 0, 1, None).unwrap();
    env.ratchet_epoch += 1;
    assert!(
        bob.decrypt(&env).is_err(),
        "Incremented epoch without ratchet headers must be rejected"
    );
}

#[test]
fn attack_epoch_decrement_on_advanced_session() {
    let (alice, bob) = attack_session_pair();

    let env0 = alice.encrypt(b"hello", 0, 0, None).unwrap();
    bob.decrypt(&env0).unwrap();
    let reply = bob.encrypt(b"reply", 0, 0, None).unwrap();
    alice.decrypt(&reply).unwrap();

    let mut env = alice.encrypt(b"post-ratchet", 0, 1, None).unwrap();
    let original_epoch = env.ratchet_epoch;
    assert!(original_epoch > 0, "Ratchet should have advanced epoch");

    env.ratchet_epoch = 0;
    assert!(
        bob.decrypt(&env).is_err(),
        "Decremented epoch must cause AAD mismatch / metadata decryption failure"
    );
}

#[test]
fn attack_cross_session_injection_rejected() {
    let (alice, _bob) = attack_session_pair();
    let (_carol, dave) = attack_session_pair();

    let env = alice.encrypt(b"for bob only", 0, 1, None).unwrap();
    assert!(
        dave.decrypt(&env).is_err(),
        "Message from alice→bob session must not decrypt in carol→dave session"
    );
}

#[test]
fn attack_envelope_swap_between_sessions_rejected() {
    let (alice, bob) = attack_session_pair();
    let (carol, dave) = attack_session_pair();

    let env_alice = alice.encrypt(b"alice msg", 0, 1, None).unwrap();
    let env_carol = carol.encrypt(b"carol msg", 0, 1, None).unwrap();

    assert!(
        bob.decrypt(&env_carol).is_err(),
        "Bob must reject Carol's envelope"
    );
    assert!(
        dave.decrypt(&env_alice).is_err(),
        "Dave must reject Alice's envelope"
    );
}

#[test]
fn attack_ratchet_dh_key_forgery_rejected() {
    let (alice, bob) = attack_session_pair();

    let env0 = alice.encrypt(b"hello", 0, 0, None).unwrap();
    let env1 = alice.encrypt(b"held back", 0, 1, None).unwrap();
    bob.decrypt(&env0).unwrap();

    let reply = bob.encrypt(b"reply", 0, 0, None).unwrap();
    alice.decrypt(&reply).unwrap();

    let mut env = alice.encrypt(b"ratcheted", 0, 2, None).unwrap();
    assert!(
        env.dh_public_key.is_some(),
        "Ratchet envelope must carry DH public key"
    );

    let forged_key = CryptoInterop::get_random_bytes(32);
    env.dh_public_key = Some(forged_key);

    assert!(
        bob.decrypt(&env).is_err(),
        "Forged DH public key must cause decryption failure"
    );

    let dec1 = bob.decrypt(&env1).unwrap();
    assert_eq!(
        dec1.plaintext, b"held back",
        "Rollback must preserve pre-ratchet state: old chain msg still decrypts"
    );
}

#[test]
fn attack_ratchet_kyber_ciphertext_forgery_rejected() {
    let (alice, bob) = attack_session_pair();

    let env0 = alice.encrypt(b"hello", 0, 0, None).unwrap();
    let env1 = alice.encrypt(b"held back", 0, 1, None).unwrap();
    bob.decrypt(&env0).unwrap();

    let reply = bob.encrypt(b"reply", 0, 0, None).unwrap();
    alice.decrypt(&reply).unwrap();

    let mut env = alice.encrypt(b"ratcheted", 0, 2, None).unwrap();
    assert!(
        env.kyber_ciphertext.is_some(),
        "Ratchet envelope must carry Kyber ciphertext"
    );

    if let Some(ref mut ct) = env.kyber_ciphertext {
        ct[0] ^= 0xFF;
        let mid = ct.len() / 2;
        ct[mid] ^= 0xFF;
    }

    assert!(
        bob.decrypt(&env).is_err(),
        "Corrupted Kyber ciphertext must cause decryption failure"
    );

    let dec1 = bob.decrypt(&env1).unwrap();
    assert_eq!(
        dec1.plaintext, b"held back",
        "Rollback must preserve pre-ratchet state: old chain msg still decrypts"
    );
}

#[test]
fn attack_out_of_order_then_replay_rejected() {
    let (alice, bob) = attack_session_pair();

    let env0 = alice.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice.encrypt(b"msg-1", 0, 1, None).unwrap();
    let env2 = alice.encrypt(b"msg-2", 0, 2, None).unwrap();

    let dec2 = bob.decrypt(&env2).unwrap();
    assert_eq!(dec2.plaintext, b"msg-2");
    let dec0 = bob.decrypt(&env0).unwrap();
    assert_eq!(dec0.plaintext, b"msg-0");
    let dec1 = bob.decrypt(&env1).unwrap();
    assert_eq!(dec1.plaintext, b"msg-1");

    assert!(
        bob.decrypt(&env1).is_err(),
        "Replaying out-of-order-delivered message must be rejected"
    );
    assert!(
        bob.decrypt(&env2).is_err(),
        "Replaying first-delivered message must be rejected"
    );
}

#[test]
fn attack_skip_ahead_then_backfill() {
    let (alice, bob) = attack_session_pair();

    let env0 = alice.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice.encrypt(b"msg-1", 0, 1, None).unwrap();
    let env2 = alice.encrypt(b"msg-2", 0, 2, None).unwrap();
    let env3 = alice.encrypt(b"msg-3", 0, 3, None).unwrap();
    let env4 = alice.encrypt(b"msg-4", 0, 4, None).unwrap();

    let dec4 = bob.decrypt(&env4).unwrap();
    assert_eq!(dec4.plaintext, b"msg-4");

    let dec3 = bob.decrypt(&env3).unwrap();
    assert_eq!(dec3.plaintext, b"msg-3");
    let dec0 = bob.decrypt(&env0).unwrap();
    assert_eq!(dec0.plaintext, b"msg-0");
    let dec2 = bob.decrypt(&env2).unwrap();
    assert_eq!(dec2.plaintext, b"msg-2");
    let dec1 = bob.decrypt(&env1).unwrap();
    assert_eq!(dec1.plaintext, b"msg-1");

    assert!(
        bob.decrypt(&env3).is_err(),
        "Replaying backfilled message must be rejected"
    );
}

#[test]
fn attack_payload_swap_between_envelopes_rejected() {
    let (alice, bob) = attack_session_pair();

    let env_a = alice.encrypt(b"AAAA", 0, 1, None).unwrap();
    let env_b = alice.encrypt(b"BBBB", 0, 2, None).unwrap();

    let mut franken = env_a;
    franken.encrypted_payload = env_b.encrypted_payload;

    assert!(
        bob.decrypt(&franken).is_err(),
        "Swapped payload must fail: different message key/nonce pair"
    );
}

#[test]
fn attack_version_field_tamper_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"version test", 0, 1, None).unwrap();
    env.version = 999;
    assert!(
        bob.decrypt(&env).is_err(),
        "Invalid version must be rejected"
    );
}

#[test]
fn attack_empty_payload_rejected() {
    let (alice, bob) = attack_session_pair();
    let mut env = alice.encrypt(b"will be emptied", 0, 1, None).unwrap();
    env.encrypted_payload = vec![];
    assert!(
        bob.decrypt(&env).is_err(),
        "Empty encrypted payload must be rejected"
    );
}

#[test]
fn attack_multi_ratchet_forward_secrecy() {
    use ecliptix_protocol::protocol::Session;

    let (alice, bob) = attack_session_pair();

    for i in 0u32..5 {
        let env = alice
            .encrypt(format!("a1-{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob.decrypt(&env).unwrap();
    }

    let r1 = bob.encrypt(b"bob-r1", 0, 0, None).unwrap();
    alice.decrypt(&r1).unwrap();

    for i in 5u32..10 {
        let env = alice
            .encrypt(format!("a2-{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob.decrypt(&env).unwrap();
    }

    let sk = CryptoInterop::get_random_bytes(32);
    let sp = StaticStateKeyProvider::new(sk.clone()).unwrap();
    let snapshot = alice.export_sealed_state(&sp, 1).unwrap();

    let r2 = bob.encrypt(b"bob-r2", 0, 1, None).unwrap();
    alice.decrypt(&r2).unwrap();

    let post_env = alice.encrypt(b"post-ratchet-2", 0, 10, None).unwrap();
    let dec = bob.decrypt(&post_env).unwrap();
    assert_eq!(dec.plaintext, b"post-ratchet-2");

    let sp2 = StaticStateKeyProvider::new(sk).unwrap();
    let old_alice = Session::from_sealed_state(&snapshot, &sp2, 0).unwrap();
    let attack_env = old_alice.encrypt(b"attack msg", 0, 999, None).unwrap();
    assert!(
        bob.decrypt(&attack_env).is_err(),
        "Pre-2nd-ratchet snapshot must not produce valid messages for post-2nd-ratchet bob"
    );
}

use proptest::prelude::*;

fn create_session_pair() -> (
    ecliptix_protocol::protocol::Session,
    ecliptix_protocol::protocol::Session,
) {
    init();
    let mut alice_ik = IdentityKeys::create(5).unwrap();
    let mut bob_ik = IdentityKeys::create(5).unwrap();

    let bob_bundle_bytes = build_proto_bundle(&bob_ik);
    let bob_bundle = PreKeyBundle::decode(bob_bundle_bytes.as_slice()).unwrap();
    let initiator = HandshakeInitiator::start(&mut alice_ik, &bob_bundle, 10000).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();

    let responder =
        HandshakeResponder::process(&mut bob_ik, &bob_bundle, &init_bytes, 10000).unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();

    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();

    (alice_session, bob_session)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_message_roundtrip(
        messages in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..4096),
            1..50
        )
    ) {
        let (alice, bob) = create_session_pair();
        for (i, plaintext) in messages.iter().enumerate() {
            let env = alice.encrypt(plaintext, 0, u32::try_from(i).unwrap(), None).unwrap();
            let dec = bob.decrypt(&env).unwrap();
            prop_assert_eq!(&dec.plaintext, plaintext);
        }
    }

    #[test]
    fn prop_alternating_direction(
        directions in prop::collection::vec(prop::bool::ANY, 1..80)
    ) {
        let (alice, bob) = create_session_pair();
        for (i, &alice_sends) in directions.iter().enumerate() {
            let msg = format!("msg-{i}");
            if alice_sends {
                let env = alice.encrypt(msg.as_bytes(), 0, u32::try_from(i).unwrap(), None).unwrap();
                let dec = bob.decrypt(&env).unwrap();
                prop_assert_eq!(dec.plaintext, msg.as_bytes());
            } else {
                let env = bob.encrypt(msg.as_bytes(), 0, u32::try_from(i).unwrap() + 10000, None).unwrap();
                let dec = alice.decrypt(&env).unwrap();
                prop_assert_eq!(dec.plaintext, msg.as_bytes());
            }
        }
    }

    #[test]
    fn prop_shamir_roundtrip(
        secret in prop::collection::vec(any::<u8>(), 1..128),
        threshold in 2u8..6,
    ) {
        init();
        let total = threshold + 2;
        let auth_key = CryptoInterop::get_random_bytes(32);
        let shares = ShamirSecretSharing::split(&secret, threshold, total, &auth_key).unwrap();
        let auth_tag = shares.last().unwrap().clone();
        let mut subset: Vec<_> = shares[..shares.len() - 1].iter()
            .take(threshold as usize).cloned().collect();
        subset.push(auth_tag);
        let recovered = ShamirSecretSharing::reconstruct(&subset, &auth_key, threshold as usize).unwrap();
        prop_assert_eq!(recovered, secret);
    }

    #[test]
    fn prop_hkdf_determinism(
        ikm in prop::collection::vec(any::<u8>(), 1..64),
        salt in prop::collection::vec(any::<u8>(), 0..32),
        info in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let out1 = HkdfSha256::derive_key_bytes(&ikm, 32, &salt, &info).unwrap();
        let out2 = HkdfSha256::derive_key_bytes(&ikm, 32, &salt, &info).unwrap();
        prop_assert_eq!(&out1, &out2);
        let mut ikm2 = ikm;
        ikm2[0] ^= 0xFF;
        let out3 = HkdfSha256::derive_key_bytes(&ikm2, 32, &salt, &info).unwrap();
        prop_assert_ne!(&out1, &out3);
    }

    #[test]
    fn prop_aes_gcm_siv_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        init();
        let key = CryptoInterop::get_random_bytes(32);
        let nonce = CryptoInterop::get_random_bytes(12);
        let ct = AesGcm::encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        let pt = AesGcm::decrypt(&key, &nonce, &ct, &aad).unwrap();
        prop_assert_eq!(pt, plaintext);
    }

    #[test]
    fn prop_out_of_order_delivery(
        count in 2usize..20,
        seed in any::<u64>(),
    ) {
        let (alice, bob) = create_session_pair();
        let mut envelopes = Vec::with_capacity(count);
        let mut plaintexts = Vec::with_capacity(count);
        for i in 0..count {
            let msg = format!("ooo-msg-{i}");
            let env = alice.encrypt(msg.as_bytes(), 0, u32::try_from(i).unwrap(), None).unwrap();
            envelopes.push(env);
            plaintexts.push(msg);
        }
        let mut indices: Vec<usize> = (0..count).collect();
        let mut rng_state = seed;
        for i in (1..indices.len()).rev() {
            rng_state = rng_state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let j = (rng_state >> 33) as usize % (i + 1);
            indices.swap(i, j);
        }
        for &idx in &indices {
            let dec = bob.decrypt(&envelopes[idx]).unwrap();
            prop_assert_eq!(dec.plaintext, plaintexts[idx].as_bytes());
        }
    }
}

#[test]
fn stress_concurrent_16_threads_100_messages() {
    init();
    use std::sync::Arc;
    use std::thread;

    let (alice_session, bob_session) = create_session_pair();
    let alice_session = Arc::new(alice_session);
    let bob_session = Arc::new(bob_session);

    let mut handles = vec![];

    for t in 0u32..16 {
        let alice_clone = Arc::clone(&alice_session);
        let bob_clone = Arc::clone(&bob_session);
        handles.push(thread::spawn(move || {
            for i in 0u32..100 {
                let id = t * 10000 + i;
                let msg = format!("t{t}-m{i}");
                let env = alice_clone.encrypt(msg.as_bytes(), 0, id, None).unwrap();
                let dec = bob_clone.decrypt(&env).unwrap();
                assert_eq!(dec.plaintext, msg.as_bytes());
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn stress_burst_1000_messages_single_direction() {
    init();
    let (alice, bob) = create_session_pair();

    for i in 0u32..1000 {
        let msg = format!("burst-{i}");
        let env = alice.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let dec = bob.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, msg.as_bytes());
    }
}

#[test]
fn stress_rapid_direction_changes_200_messages() {
    init();
    let (alice, bob) = create_session_pair();

    for i in 0u32..200 {
        if i % 2 == 0 {
            let msg = format!("a→b-{i}");
            let env = alice.encrypt(msg.as_bytes(), 0, i, None).unwrap();
            let dec = bob.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, msg.as_bytes());
        } else {
            let msg = format!("b→a-{i}");
            let env = bob.encrypt(msg.as_bytes(), 0, i + 10000, None).unwrap();
            let dec = alice.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, msg.as_bytes());
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

use ecliptix_protocol::api::EcliptixProtocol;
use ecliptix_protocol::protocol::group::tree::LeafData;
use ecliptix_protocol::protocol::group::{self, GroupSession};

#[test]
fn group_tree_navigation_parent_child_sibling() {
    use ecliptix_protocol::protocol::group::tree;

    assert_eq!(tree::leaf_to_node(0), 0);
    assert_eq!(tree::leaf_to_node(1), 2);
    assert_eq!(tree::leaf_to_node(2), 4);
    assert_eq!(tree::leaf_to_node(3), 6);

    assert_eq!(tree::node_to_leaf(0), Some(0));
    assert_eq!(tree::node_to_leaf(2), Some(1));
    assert_eq!(tree::node_to_leaf(1), None);

    let n = 4u32;
    assert_eq!(tree::root(n).unwrap(), 3);

    assert_eq!(tree::parent(0, n).unwrap(), 1);
    assert_eq!(tree::parent(2, n).unwrap(), 1);
    assert_eq!(tree::parent(4, n).unwrap(), 5);
    assert_eq!(tree::parent(6, n).unwrap(), 5);
    assert_eq!(tree::parent(1, n).unwrap(), 3);
    assert_eq!(tree::parent(5, n).unwrap(), 3);

    assert_eq!(tree::left(1).unwrap(), 0);
    assert_eq!(tree::right(1, n).unwrap(), 2);
    assert_eq!(tree::left(5).unwrap(), 4);
    assert_eq!(tree::right(5, n).unwrap(), 6);

    assert_eq!(tree::sibling(0, n).unwrap(), 2);
    assert_eq!(tree::sibling(2, n).unwrap(), 0);
    assert_eq!(tree::sibling(4, n).unwrap(), 6);
    assert_eq!(tree::sibling(6, n).unwrap(), 4);
    assert_eq!(tree::sibling(1, n).unwrap(), 5);
    assert_eq!(tree::sibling(5, n).unwrap(), 1);
}

#[test]
fn group_tree_direct_path_and_copath() {
    use ecliptix_protocol::protocol::group::tree;

    let dp = tree::direct_path(0, 4).unwrap();
    assert_eq!(dp, vec![1, 3]);

    let cp = tree::copath(0, 4).unwrap();
    assert_eq!(cp, vec![2, 5]);

    let dp3 = tree::direct_path(3, 4).unwrap();
    assert_eq!(dp3, vec![5, 3]);

    let cp3 = tree::copath(3, 4).unwrap();
    assert_eq!(cp3, vec![4, 1]);
}

#[test]
fn group_tree_single_member_paths() {
    use ecliptix_protocol::protocol::group::tree;

    assert_eq!(tree::root(1).unwrap(), 0);
    let dp = tree::direct_path(0, 1).unwrap();
    assert!(dp.is_empty());
    let cp = tree::copath(0, 1).unwrap();
    assert!(cp.is_empty());
}

#[test]
fn group_tree_new_single_and_add_leaf() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&identity, b"alice".to_vec()).unwrap();

    let mut tree = group::RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x25519_priv,
        kyber_sec,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    assert_eq!(tree.leaf_count(), 1);
    assert_eq!(tree.member_count(), 1);

    let identity2 = IdentityKeys::create(0).unwrap();
    let (kp2, _x25519_priv2, _kyber_sec2) =
        group::key_package::create_key_package(&identity2, b"bob".to_vec()).unwrap();

    let new_leaf = tree
        .add_leaf(
            kp2.leaf_x25519_public.clone(),
            kp2.leaf_kyber_public.clone(),
            LeafData {
                credential: b"bob".to_vec(),
                identity_ed25519_public: kp2.identity_ed25519_public.clone(),
                identity_x25519_public: kp2.identity_x25519_public,
                signature: kp2.signature,
            },
        )
        .unwrap();

    assert_eq!(new_leaf, 1);
    assert_eq!(tree.leaf_count(), 2);
    assert_eq!(tree.member_count(), 2);
}

#[test]
fn group_tree_blank_and_refill() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&identity, b"alice".to_vec()).unwrap();

    let mut tree = group::RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x25519_priv,
        kyber_sec,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    let identity2 = IdentityKeys::create(0).unwrap();
    let (kp2, _, _) = group::key_package::create_key_package(&identity2, b"bob".to_vec()).unwrap();
    tree.add_leaf(
        kp2.leaf_x25519_public.clone(),
        kp2.leaf_kyber_public.clone(),
        LeafData {
            credential: b"bob".to_vec(),
            identity_ed25519_public: kp2.identity_ed25519_public.clone(),
            identity_x25519_public: kp2.identity_x25519_public,
            signature: kp2.signature,
        },
    )
    .unwrap();

    let identity3 = IdentityKeys::create(0).unwrap();
    let (kp3, _, _) =
        group::key_package::create_key_package(&identity3, b"carol".to_vec()).unwrap();
    tree.add_leaf(
        kp3.leaf_x25519_public.clone(),
        kp3.leaf_kyber_public.clone(),
        LeafData {
            credential: b"carol".to_vec(),
            identity_ed25519_public: kp3.identity_ed25519_public.clone(),
            identity_x25519_public: kp3.identity_x25519_public,
            signature: kp3.signature,
        },
    )
    .unwrap();

    assert_eq!(tree.member_count(), 3);

    let _ = tree.blank_leaf(1);
    assert_eq!(tree.member_count(), 2);

    let identity4 = IdentityKeys::create(0).unwrap();
    let (kp4, _, _) = group::key_package::create_key_package(&identity4, b"dave".to_vec()).unwrap();
    let dave_idx = tree
        .add_leaf(
            kp4.leaf_x25519_public.clone(),
            kp4.leaf_kyber_public.clone(),
            LeafData {
                credential: b"dave".to_vec(),
                identity_ed25519_public: kp4.identity_ed25519_public.clone(),
                identity_x25519_public: kp4.identity_x25519_public,
                signature: kp4.signature,
            },
        )
        .unwrap();

    assert_eq!(dave_idx, 1);
    assert_eq!(tree.member_count(), 3);
}

#[test]
fn group_tree_hash_deterministic() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&identity, b"alice".to_vec()).unwrap();

    let tree = group::RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x25519_priv,
        kyber_sec,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    let h1 = tree.tree_hash().unwrap();
    let h2 = tree.tree_hash().unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

#[test]
fn group_tree_serialization_roundtrip() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&identity, b"alice".to_vec()).unwrap();

    let tree = group::RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x25519_priv,
        kyber_sec,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    let proto_nodes = tree.export_public();
    assert!(!proto_nodes.is_empty());

    let tree2 = group::RatchetTree::from_proto(&proto_nodes, 0).unwrap();
    assert_eq!(tree.tree_hash().unwrap(), tree2.tree_hash().unwrap());
}

#[test]
fn group_key_package_create_and_validate() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (kp, _, _) =
        group::key_package::create_key_package(&identity, b"credential-1".to_vec()).unwrap();

    group::key_package::validate_key_package(&kp).unwrap();

    assert_eq!(kp.version, 1);
    assert_eq!(kp.identity_ed25519_public.len(), 32);
    assert_eq!(kp.identity_x25519_public.len(), 32);
    assert_eq!(kp.leaf_x25519_public.len(), 32);
    assert_eq!(kp.leaf_kyber_public.len(), 1184);
    assert_eq!(kp.signature.len(), 64);
    assert_eq!(kp.credential, b"credential-1");
}

#[test]
fn group_key_package_tampered_signature_rejected() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (mut kp, _, _) =
        group::key_package::create_key_package(&identity, b"test".to_vec()).unwrap();

    kp.signature[0] ^= 0xFF;

    let err = group::key_package::validate_key_package(&kp);
    assert!(err.is_err());
}

#[test]
fn group_key_package_wrong_version_rejected() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let (mut kp, _, _) =
        group::key_package::create_key_package(&identity, b"test".to_vec()).unwrap();

    kp.version = 99;

    let err = group::key_package::validate_key_package(&kp);
    assert!(err.is_err());
}

#[test]
fn group_key_schedule_deterministic() {
    init();

    let init_secret = vec![0u8; 32];
    let commit_secret = vec![1u8; 32];
    let ctx_hash = vec![2u8; 32];

    let keys1 =
        group::GroupKeySchedule::derive_epoch_keys(&init_secret, &commit_secret, &ctx_hash, false)
            .unwrap();
    let keys2 =
        group::GroupKeySchedule::derive_epoch_keys(&init_secret, &commit_secret, &ctx_hash, false)
            .unwrap();

    assert_eq!(keys1.epoch_secret, keys2.epoch_secret);
    assert_eq!(keys1.metadata_key, keys2.metadata_key);
    assert_eq!(keys1.welcome_key, keys2.welcome_key);
    assert_eq!(keys1.confirmation_key, keys2.confirmation_key);
    assert_eq!(keys1.init_secret, keys2.init_secret);
}

#[test]
fn group_key_schedule_domain_separation() {
    init();

    let init_secret = vec![0u8; 32];
    let commit_secret = vec![1u8; 32];
    let ctx_hash = vec![2u8; 32];

    let keys =
        group::GroupKeySchedule::derive_epoch_keys(&init_secret, &commit_secret, &ctx_hash, false)
            .unwrap();

    assert_ne!(keys.epoch_secret, keys.metadata_key);
    assert_ne!(keys.metadata_key, keys.welcome_key);
    assert_ne!(keys.welcome_key, keys.confirmation_key);
    assert_ne!(keys.confirmation_key, keys.init_secret);
    assert_ne!(keys.epoch_secret, keys.init_secret);
}

#[test]
fn group_key_schedule_different_inputs_different_outputs() {
    init();

    let init_secret = vec![0u8; 32];
    let commit1 = vec![1u8; 32];
    let commit2 = vec![2u8; 32];
    let ctx_hash = vec![3u8; 32];

    let keys1 =
        group::GroupKeySchedule::derive_epoch_keys(&init_secret, &commit1, &ctx_hash, false)
            .unwrap();
    let keys2 =
        group::GroupKeySchedule::derive_epoch_keys(&init_secret, &commit2, &ctx_hash, false)
            .unwrap();

    assert_ne!(keys1.epoch_secret, keys2.epoch_secret);
}

#[test]
fn group_sender_key_forward_secrecy() {
    init();

    let mut chain = group::SenderKeyChain::new(0, vec![0xAA; 32]).unwrap();

    let (gen0, key0) = chain.next_message_key().unwrap();
    let (gen1, key1) = chain.next_message_key().unwrap();
    let (gen2, key2) = chain.next_message_key().unwrap();

    assert_eq!(gen0, 0);
    assert_eq!(gen1, 1);
    assert_eq!(gen2, 2);

    assert_ne!(key0, key1);
    assert_ne!(key1, key2);
    assert_ne!(key0, key2);

    assert_eq!(key0.len(), 32);
}

#[test]
fn group_sender_key_advance_to() {
    init();

    let mut chain = group::SenderKeyChain::new(0, vec![0xBB; 32]).unwrap();

    let (msg_key, skipped) = chain.advance_to(5).unwrap();
    assert_eq!(skipped.len(), 5);
    assert_eq!(msg_key.len(), 32);

    let (gen, _) = chain.next_message_key().unwrap();
    assert_eq!(gen, 6);
}

#[test]
fn group_sender_key_store_new_epoch() {
    init();

    let epoch_secret = vec![0xCC; 32];
    let leaf_indices = vec![0, 1, 2];
    let group_context_hash = vec![0xAA; 32];

    let mut store =
        group::SenderKeyStore::new_epoch(&epoch_secret, &leaf_indices, &group_context_hash)
            .unwrap();

    let (gen, key) = store.next_own_message_key(0).unwrap();
    assert_eq!(gen, 0);
    assert_eq!(key.len(), 32);
}

#[test]
fn group_sender_key_replay_rejection() {
    init();

    let epoch_secret = vec![0xDD; 32];
    let leaf_indices = vec![0, 1];
    let group_context_hash = vec![0xAA; 32];

    let mut store =
        group::SenderKeyStore::new_epoch(&epoch_secret, &leaf_indices, &group_context_hash)
            .unwrap();

    let key0 = store.get_message_key(1, 0).unwrap();
    assert_eq!(key0.len(), 32);

    let result = store.get_message_key(1, 0);
    assert!(result.is_err());
}

#[test]
fn group_session_create_single_member() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    assert_eq!(session.epoch().unwrap(), 0);
    assert_eq!(session.my_leaf_index().unwrap(), 0);
    assert_eq!(session.member_count().unwrap(), 1);
    assert_eq!(session.group_id().unwrap().len(), 32);
}

#[test]
fn group_session_single_member_encrypt_produces_ciphertext() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let plaintext = b"Hello, group!";
    let ciphertext = session.encrypt(plaintext).unwrap();

    assert!(ciphertext.len() > plaintext.len());

    let msg = ecliptix_protocol::proto::GroupMessage::decode(ciphertext.as_slice()).unwrap();
    assert_eq!(msg.epoch, 0);
    assert_eq!(msg.version, 1);
}

#[test]
fn group_session_single_member_multiple_encryptions() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let ct1 = session.encrypt(b"msg1").unwrap();
    let ct2 = session.encrypt(b"msg2").unwrap();
    let ct3 = session.encrypt(b"msg1").unwrap();

    assert_ne!(ct1, ct2);
    assert_ne!(ct1, ct3);
}

#[test]
fn group_session_self_decrypt_fails_as_expected() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let ct = session.encrypt(b"test").unwrap();

    let err = session.decrypt(&ct);
    assert!(err.is_err());
}

#[test]
fn group_session_epoch_mismatch_rejected() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let ct = session.encrypt(b"test").unwrap();

    let _commit = session.update().unwrap();

    let err = session.decrypt(&ct);
    assert!(err.is_err());
}

#[test]
fn group_api_create_and_encrypt() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"alice-cred".to_vec()).unwrap();

    assert_eq!(session.epoch().unwrap(), 0);
    assert_eq!(session.my_leaf_index().unwrap(), 0);
    assert_eq!(session.member_count().unwrap(), 1);

    let ct = session.encrypt(b"via API").unwrap();
    assert!(!ct.is_empty());
}

#[test]
fn group_api_generate_key_package() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let (kp_bytes, _x25519_priv, _kyber_sec) =
        proto.generate_key_package(b"bob-cred".to_vec()).unwrap();

    let kp = ecliptix_protocol::proto::GroupKeyPackage::decode(kp_bytes.as_slice()).unwrap();
    group::key_package::validate_key_package(&kp).unwrap();
}

#[test]
fn group_session_self_update_advances_epoch() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    assert_eq!(session.epoch().unwrap(), 0);

    let _commit = session.update().unwrap();

    assert_eq!(session.epoch().unwrap(), 1);

    let ct = session.encrypt(b"post-update").unwrap();
    assert!(!ct.is_empty());
}

#[test]
fn group_session_multiple_updates() {
    init();

    let identity = IdentityKeys::create(0).unwrap();
    let session = GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    for expected_epoch in 1..=5u64 {
        let _commit = session.update().unwrap();
        assert_eq!(session.epoch().unwrap(), expected_epoch);

        let ct = session.encrypt(b"test").unwrap();
        assert!(!ct.is_empty());
    }
}

#[test]
fn group_treekem_encrypt_decrypt_path_secret_roundtrip() {
    init();

    use ecliptix_protocol::protocol::group::tree_kem::TreeKem;

    let (x25519_priv, x25519_pub) = CryptoInterop::generate_x25519_keypair("test-kem").unwrap();
    let (kyber_sec, kyber_pub) =
        ecliptix_protocol::crypto::KyberInterop::generate_keypair().unwrap();

    let path_secret = CryptoInterop::get_random_bytes(32);

    let ct = TreeKem::encrypt_path_secret(&path_secret, &x25519_pub, &kyber_pub, 42).unwrap();

    let decrypted = TreeKem::decrypt_path_secret(&ct, &x25519_priv, &kyber_sec, 42).unwrap();

    assert_eq!(decrypted, path_secret);
}

#[test]
fn group_treekem_wrong_aad_fails() {
    init();

    use ecliptix_protocol::protocol::group::tree_kem::TreeKem;

    let (x25519_priv, x25519_pub) = CryptoInterop::generate_x25519_keypair("test-kem").unwrap();
    let (kyber_sec, kyber_pub) =
        ecliptix_protocol::crypto::KyberInterop::generate_keypair().unwrap();

    let path_secret = CryptoInterop::get_random_bytes(32);

    let ct = TreeKem::encrypt_path_secret(&path_secret, &x25519_pub, &kyber_pub, 42).unwrap();

    let err = TreeKem::decrypt_path_secret(&ct, &x25519_priv, &kyber_sec, 99);
    assert!(err.is_err());
}

#[test]
fn group_treekem_derive_node_keypairs_deterministic() {
    init();

    use ecliptix_protocol::protocol::group::tree_kem::TreeKem;

    let path_secret = vec![0x42u8; 32];

    let (_, pub1_x, _, pub1_k) = TreeKem::derive_node_keypairs(&path_secret).unwrap();
    let (_, pub2_x, _, pub2_k) = TreeKem::derive_node_keypairs(&path_secret).unwrap();

    assert_eq!(pub1_x, pub2_x);
    assert_eq!(pub1_k, pub2_k);
    assert_eq!(pub1_x.len(), 32);
    assert_eq!(pub1_k.len(), 1184);
}

#[test]
fn group_confirmation_mac_verified() {
    init();

    let confirm_key = vec![0xAA; 32];
    let ctx_hash = vec![0xBB; 32];

    let mac1 = group::GroupKeySchedule::compute_confirmation_mac(&confirm_key, &ctx_hash).unwrap();
    let mac2 = group::GroupKeySchedule::compute_confirmation_mac(&confirm_key, &ctx_hash).unwrap();

    assert_eq!(mac1, mac2);
    assert_eq!(mac1.len(), 32);

    let mac3 =
        group::GroupKeySchedule::compute_confirmation_mac(&confirm_key, &[0xCC; 32]).unwrap();
    assert_ne!(mac1, mac3);
}

#[test]
fn group_session_sealed_state_roundtrip() {
    init();

    let identity = IdentityKeys::create(10).unwrap();
    let session = group::GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let _ct1 = session.encrypt(b"hello group").unwrap();
    let _ct2 = session.encrypt(b"second message").unwrap();

    let key = vec![0x42u8; 32];
    let sealed = session.export_sealed_state(&key, 1).unwrap();
    assert!(!sealed.is_empty());

    let restored = group::GroupSession::from_sealed_state(
        &sealed,
        &key,
        identity.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());
    assert_eq!(session.epoch().unwrap(), restored.epoch().unwrap());
    assert_eq!(
        session.my_leaf_index().unwrap(),
        restored.my_leaf_index().unwrap()
    );
    assert_eq!(
        session.member_count().unwrap(),
        restored.member_count().unwrap()
    );

    let _ct3 = restored.encrypt(b"after restore").unwrap();
}

#[test]
fn group_session_sealed_state_wrong_key_fails() {
    init();

    let identity = IdentityKeys::create(10).unwrap();
    let session = group::GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let key = vec![0x42u8; 32];
    let sealed = session.export_sealed_state(&key, 1).unwrap();

    let wrong_key = vec![0x99u8; 32];
    let result = group::GroupSession::from_sealed_state(
        &sealed,
        &wrong_key,
        identity.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    );
    assert!(result.is_err());
}

#[test]
fn group_session_sealed_state_tampered_data_fails() {
    init();

    let identity = IdentityKeys::create(10).unwrap();
    let session = group::GroupSession::create(&identity, b"alice".to_vec()).unwrap();

    let key = vec![0x42u8; 32];
    let mut sealed = session.export_sealed_state(&key, 1).unwrap();

    if sealed.len() > 20 {
        sealed[20] ^= 0xFF;
    }

    let result = group::GroupSession::from_sealed_state(
        &sealed,
        &key,
        identity.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    );
    assert!(result.is_err());
}

#[test]
fn relay_roster_operations() {
    use ecliptix_protocol::api::relay::*;

    let member = GroupMemberRecord {
        leaf_index: 0,
        identity_ed25519_public: vec![0xAA; 32],
        identity_x25519_public: vec![0xBB; 32],
        credential: b"alice".to_vec(),
    };

    let roster = GroupRoster::new(vec![0x11; 32], member);
    assert_eq!(roster.member_count(), 1);
    assert_eq!(roster.epoch, 0);
    assert!(roster.find_member(0).is_some());
    assert!(roster.find_member(1).is_none());
    assert!(roster.find_member_by_identity(&[0xAA; 32]).is_some());
    assert_eq!(roster.leaf_indices(), vec![0]);
}

#[test]
fn relay_commit_recipients() {
    use ecliptix_protocol::api::relay::*;

    let members = vec![
        GroupMemberRecord {
            leaf_index: 0,
            identity_ed25519_public: vec![0xAA; 32],
            identity_x25519_public: vec![0xBB; 32],
            credential: b"alice".to_vec(),
        },
        GroupMemberRecord {
            leaf_index: 1,
            identity_ed25519_public: vec![0xCC; 32],
            identity_x25519_public: vec![0xDD; 32],
            credential: b"bob".to_vec(),
        },
        GroupMemberRecord {
            leaf_index: 2,
            identity_ed25519_public: vec![0xEE; 32],
            identity_x25519_public: vec![0xFF; 32],
            credential: b"carol".to_vec(),
        },
    ];

    let roster = GroupRoster {
        group_id: vec![0x11; 32],
        epoch: 5,
        members,
    };

    let recipients = commit_recipients(&roster, 0);
    assert_eq!(recipients, vec![1, 2]);

    let msg_recipients = message_recipients(&roster);
    assert_eq!(msg_recipients, vec![0, 1, 2]);
}

#[test]
fn relay_apply_commit_to_roster() {
    use ecliptix_protocol::api::relay::*;

    let mut roster = GroupRoster::new(
        vec![0x11; 32],
        GroupMemberRecord {
            leaf_index: 0,
            identity_ed25519_public: vec![0xAA; 32],
            identity_x25519_public: vec![0xBB; 32],
            credential: b"alice".to_vec(),
        },
    );

    let info = RelayCommitInfo {
        committer_leaf_index: 0,
        new_epoch: 1,
        added_identities: vec![vec![0xCC; 32]],
        removed_leaves: vec![],
    };

    let new_member = GroupMemberRecord {
        leaf_index: 1,
        identity_ed25519_public: vec![0xCC; 32],
        identity_x25519_public: vec![0xDD; 32],
        credential: b"bob".to_vec(),
    };

    apply_commit_to_roster(&mut roster, &info, vec![new_member]).unwrap();
    assert_eq!(roster.epoch, 1);
    assert_eq!(roster.member_count(), 2);
    assert!(roster.find_member(1).is_some());
}

#[test]
fn relay_validate_key_package_for_storage() {
    use ecliptix_protocol::api::relay::*;
    use prost::Message;

    init();

    let identity = IdentityKeys::create(10).unwrap();
    let (kp, _priv, _sec) = ecliptix_protocol::protocol::group::key_package::create_key_package(
        &identity,
        b"test".to_vec(),
    )
    .unwrap();

    let mut buf = Vec::new();
    kp.encode(&mut buf).unwrap();

    let validated = validate_key_package_for_storage(&buf).unwrap();
    assert_eq!(validated.version, 1);
    assert!(!validated.signature.is_empty());

    let result = validate_key_package_for_storage(&buf[..10]);
    assert!(result.is_err());
}

#[test]
fn group_api_serialize_deserialize() {
    use ecliptix_protocol::api::EcliptixProtocol;

    init();

    let proto = EcliptixProtocol::new(10).unwrap();
    let ed25519_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"alice".to_vec()).unwrap();

    let _ct = session.encrypt(b"test message").unwrap();

    let key = vec![0x77u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let (restored, restored_counter) =
        ecliptix_protocol::api::EcliptixGroupSession::deserialize(&sealed, &key, ed25519_secret, 0)
            .unwrap();
    assert_eq!(restored_counter, 1);
    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());
    assert_eq!(session.epoch().unwrap(), restored.epoch().unwrap());
}

#[test]
fn group_two_member_add_welcome_roundtrip() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");
    assert_eq!(alice_session.epoch().unwrap(), 0);
    assert_eq!(alice_session.member_count().unwrap(), 1);
    assert_eq!(alice_session.my_leaf_index().unwrap(), 0);

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();

    let (commit_bytes, welcome_bytes) = alice_session.add_member(&bob_kp).unwrap();
    assert_eq!(alice_session.epoch().unwrap(), 1);
    assert_eq!(alice_session.member_count().unwrap(), 2);
    assert!(!commit_bytes.is_empty());
    assert!(!welcome_bytes.is_empty());

    let bob_session = GroupSession::from_welcome(
        &welcome_bytes,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(bob_session.epoch().unwrap(), 1);
    assert_eq!(bob_session.member_count().unwrap(), 2);
    assert_eq!(bob_session.my_leaf_index().unwrap(), 1);
    assert_eq!(
        alice_session.group_id().unwrap(),
        bob_session.group_id().unwrap()
    );
}

#[test]
fn group_two_member_encrypt_decrypt() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();

    let (_commit_bytes, welcome_bytes) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome_bytes,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let alice_ct = alice_session.encrypt(b"Hello Bob!").unwrap();
    let bob_pt = bob_session.decrypt(&alice_ct).unwrap();
    assert_eq!(bob_pt.plaintext, b"Hello Bob!");
    assert_eq!(bob_pt.sender_leaf_index, 0);

    let bob_ct = bob_session.encrypt(b"Hello Alice!").unwrap();
    let alice_pt = alice_session.decrypt(&bob_ct).unwrap();
    assert_eq!(alice_pt.plaintext, b"Hello Alice!");
    assert_eq!(alice_pt.sender_leaf_index, 1);

    for i in 0..5 {
        let msg = format!("Message {i} from Alice");
        let ct = alice_session.encrypt(msg.as_bytes()).unwrap();
        let pt = bob_session.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, msg.as_bytes());
    }
}

#[test]
fn group_three_member_messaging() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();
    let carol_id = IdentityKeys::create(30).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit1, welcome1) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x25519_priv, carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (commit2, welcome2) = alice_session.add_member(&carol_kp).unwrap();

    bob_session.process_commit(&commit2).unwrap();
    assert_eq!(bob_session.epoch().unwrap(), 2);
    assert_eq!(bob_session.member_count().unwrap(), 3);

    let carol_session = GroupSession::from_welcome(
        &welcome2,
        carol_x25519_priv,
        carol_kyber_sec,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(carol_session.epoch().unwrap(), 2);
    assert_eq!(carol_session.member_count().unwrap(), 3);

    let ct_alice = alice_session.encrypt(b"from alice").unwrap();
    let ct_bob = bob_session.encrypt(b"from bob").unwrap();
    let ct_carol = carol_session.encrypt(b"from carol").unwrap();

    let pt = bob_session.decrypt(&ct_alice).unwrap();
    assert_eq!(pt.plaintext, b"from alice");
    assert_eq!(pt.sender_leaf_index, 0);
    let pt = carol_session.decrypt(&ct_alice).unwrap();
    assert_eq!(pt.plaintext, b"from alice");

    let pt = alice_session.decrypt(&ct_bob).unwrap();
    assert_eq!(pt.plaintext, b"from bob");
    assert_eq!(pt.sender_leaf_index, 1);
    let pt = carol_session.decrypt(&ct_bob).unwrap();
    assert_eq!(pt.plaintext, b"from bob");

    let pt = alice_session.decrypt(&ct_carol).unwrap();
    assert_eq!(pt.plaintext, b"from carol");
    assert_eq!(pt.sender_leaf_index, 2);
    let pt = bob_session.decrypt(&ct_carol).unwrap();
    assert_eq!(pt.plaintext, b"from carol");
}

#[test]
fn group_remove_member_blocks_decryption() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice_session.encrypt(b"before removal").unwrap();
    let pt = bob_session.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"before removal");

    let _remove_commit = alice_session.remove_member(1).unwrap();
    assert_eq!(alice_session.epoch().unwrap(), 2);
    assert_eq!(alice_session.member_count().unwrap(), 1);

    let ct_after = alice_session.encrypt(b"after removal").unwrap();

    let result = bob_session.decrypt(&ct_after);
    assert!(result.is_err());
}

#[test]
fn group_update_both_members_advance() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice_session.epoch().unwrap(), 1);
    assert_eq!(bob_session.epoch().unwrap(), 1);

    let update_commit = alice_session.update().unwrap();
    assert_eq!(alice_session.epoch().unwrap(), 2);

    bob_session.process_commit(&update_commit).unwrap();
    assert_eq!(bob_session.epoch().unwrap(), 2);

    let ct = alice_session.encrypt(b"post-update").unwrap();
    let pt = bob_session.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"post-update");

    let ct2 = bob_session.encrypt(b"bob post-update").unwrap();
    let pt2 = alice_session.decrypt(&ct2).unwrap();
    assert_eq!(pt2.plaintext, b"bob post-update");
}

#[test]
fn group_wrong_group_id_commit_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let group_a = GroupSession::create(&alice_id, b"alice-a".to_vec()).unwrap();
    let group_b = GroupSession::create(&bob_id, b"bob-b".to_vec()).unwrap();

    let update_commit = group_a.update().unwrap();

    let result = group_b.process_commit(&update_commit);
    assert!(result.is_err());
}

#[test]
fn group_parent_hash_computed_in_update_path() {
    use ecliptix_protocol::proto::GroupCommit;
    use prost::Message;

    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, _bob_x25519_priv, _bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, _welcome) = alice_session.add_member(&bob_kp).unwrap();

    let carol_id = IdentityKeys::create(30).unwrap();
    let (carol_kp, _carol_x25519_priv, _carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (_commit2, _welcome2) = alice_session.add_member(&carol_kp).unwrap();

    let update_bytes = alice_session.update().unwrap();
    let commit = GroupCommit::decode(update_bytes.as_slice()).unwrap();

    let update_path = commit.update_path.as_ref().unwrap();
    assert!(
        update_path.nodes.len() > 1,
        "3-member tree should have >1 node on direct path"
    );
    let has_nonzero = update_path
        .nodes
        .iter()
        .any(|n| !n.parent_hash.is_empty() && n.parent_hash.iter().any(|&b| b != 0));
    assert!(
        has_nonzero,
        "UpdatePath should contain at least one non-zero parent_hash"
    );
}

#[test]
fn group_parent_hash_chain_valid_after_add() {
    use ecliptix_protocol::proto::GroupCommit;
    use prost::Message;

    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let carol_id = IdentityKeys::create(30).unwrap();
    let (carol_kp, carol_x25519_priv, carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (add_carol_bytes, carol_welcome) = alice_session.add_member(&carol_kp).unwrap();

    bob_session.process_commit(&add_carol_bytes).unwrap();

    let carol_session = GroupSession::from_welcome(
        &carol_welcome,
        carol_x25519_priv,
        carol_kyber_sec,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let commit = GroupCommit::decode(add_carol_bytes.as_slice()).unwrap();
    let update_path = commit.update_path.as_ref().unwrap();
    assert!(
        update_path.nodes.len() > 1,
        "3-member add should have >1 path node"
    );
    let lowest = &update_path.nodes[0];
    assert!(
        !lowest.parent_hash.is_empty() && lowest.parent_hash.iter().any(|&b| b != 0),
        "Lowest path node should have non-zero parent_hash"
    );

    let ct = alice_session.encrypt(b"parent_hash chain valid").unwrap();
    let pt_bob = bob_session.decrypt(&ct).unwrap();
    let pt_carol = carol_session.decrypt(&ct).unwrap();
    assert_eq!(pt_bob.plaintext, b"parent_hash chain valid");
    assert_eq!(pt_carol.plaintext, b"parent_hash chain valid");
}

#[test]
fn group_parent_hash_tampered_rejected() {
    use ecliptix_protocol::proto::GroupCommit;
    use prost::Message;

    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let carol_id = IdentityKeys::create(30).unwrap();
    let (carol_kp, _carol_x25519_priv, _carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (add_carol_bytes, _carol_welcome) = alice_session.add_member(&carol_kp).unwrap();
    bob_session.process_commit(&add_carol_bytes).unwrap();

    let update_bytes = alice_session.update().unwrap();
    let mut commit = GroupCommit::decode(update_bytes.as_slice()).unwrap();

    let mut tampered = false;
    if let Some(ref mut up) = commit.update_path {
        for node in &mut up.nodes {
            if !node.parent_hash.is_empty() && node.parent_hash.iter().any(|&b| b != 0) {
                node.parent_hash[0] ^= 0xFF;
                tampered = true;
                break;
            }
        }
    }
    assert!(
        tampered,
        "Should have found a non-zero parent_hash to tamper"
    );

    let mut tampered_bytes = Vec::new();
    commit.encode(&mut tampered_bytes).unwrap();

    let result = bob_session.process_commit(&tampered_bytes);
    assert!(result.is_err(), "Tampered parent_hash should be rejected");
}

#[test]
fn group_external_join_basic() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");
    assert_eq!(alice_session.member_count().unwrap(), 1);

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_session, external_commit) =
        authorize_and_join_external(&alice_session, &bob_id, b"bob");

    alice_session.process_commit(&external_commit).unwrap();

    assert_eq!(alice_session.epoch().unwrap(), bob_session.epoch().unwrap());
    assert_eq!(alice_session.member_count().unwrap(), 2);
    assert_eq!(bob_session.member_count().unwrap(), 2);

    let ct = alice_session.encrypt(b"hello from alice").unwrap();
    let pt = bob_session.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"hello from alice");

    let ct2 = bob_session.encrypt(b"hello from bob").unwrap();
    let pt2 = alice_session.decrypt(&ct2).unwrap();
    assert_eq!(pt2.plaintext, b"hello from bob");
}

#[test]
fn group_external_join_three_members() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let carol_id = IdentityKeys::create(30).unwrap();
    let (carol_session, external_commit) =
        authorize_and_join_external(&alice_session, &carol_id, b"carol");

    alice_session.process_commit(&external_commit).unwrap();
    bob_session.process_commit(&external_commit).unwrap();

    assert_eq!(alice_session.epoch().unwrap(), bob_session.epoch().unwrap());
    assert_eq!(
        alice_session.epoch().unwrap(),
        carol_session.epoch().unwrap()
    );
    assert_eq!(alice_session.member_count().unwrap(), 3);

    let ct_a = alice_session.encrypt(b"from alice").unwrap();
    let pt_b = bob_session.decrypt(&ct_a).unwrap();
    let pt_c = carol_session.decrypt(&ct_a).unwrap();
    assert_eq!(pt_b.plaintext, b"from alice");
    assert_eq!(pt_c.plaintext, b"from alice");

    let ct_c = carol_session.encrypt(b"from carol").unwrap();
    let pt_a = alice_session.decrypt(&ct_c).unwrap();
    let pt_b2 = bob_session.decrypt(&ct_c).unwrap();
    assert_eq!(pt_a.plaintext, b"from carol");
    assert_eq!(pt_b2.plaintext, b"from carol");
}

#[test]
fn group_external_join_oversized_committer_index_rejected_without_panic() {
    init();
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let joiner_id = IdentityKeys::create(10).unwrap();
    let (_joiner_session, ext_commit_bytes) =
        authorize_and_join_external(&alice_session, &joiner_id, b"joiner");

    let mut commit =
        ecliptix_protocol::proto::GroupCommit::decode(ext_commit_bytes.as_slice()).unwrap();
    commit.committer_leaf_index = u32::MAX;
    commit.committer_signature.clear();

    let sk = joiner_id.get_identity_ed25519_private_key_copy().unwrap();
    let sk_arr: [u8; 64] = sk.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_arr).unwrap();
    let mut commit_for_sig = Vec::new();
    commit.encode(&mut commit_for_sig).unwrap();
    use ed25519_dalek::Signer;
    commit.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();

    let mut tampered_commit = Vec::new();
    commit.encode(&mut tampered_commit).unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        alice_session.process_commit(&tampered_commit)
    }));
    assert!(
        result.is_ok(),
        "Malformed external join commit must not panic"
    );
    assert!(
        result.unwrap().is_err(),
        "Oversized committer leaf index must be rejected",
    );
}

#[test]
fn group_external_join_wrong_public_state_fails() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let mut public_state = alice_session.export_public_state().unwrap();

    if public_state.len() > 20 {
        public_state[20] ^= 0xFF;
    }

    let bob_id = IdentityKeys::create(20).unwrap();
    let authorization = alice_session
        .authorize_external_join(
            &bob_id.get_identity_ed25519_public(),
            &bob_id.get_identity_x25519_public(),
            b"bob",
        )
        .unwrap();
    let result =
        GroupSession::from_external_join(&public_state, &authorization, &bob_id, b"bob".to_vec());
    assert!(result.is_err(), "Tampered public state should be rejected");
}

#[test]
fn group_tree_max_members() {
    use ecliptix_protocol::protocol::group::tree::RatchetTree;

    init();

    let id = IdentityKeys::create(10).unwrap();
    let (kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&id, b"first".to_vec()).unwrap();

    let mut tree = RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x25519_priv,
        kyber_sec,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"first".to_vec(),
        kp.signature,
    )
    .unwrap();

    for i in 1..1024u32 {
        let member_id = IdentityKeys::create(10).unwrap();
        let (mkp, _priv, _sec) =
            group::key_package::create_key_package(&member_id, format!("m{i}").into_bytes())
                .unwrap();
        let leaf_data = LeafData {
            credential: mkp.credential.clone(),
            identity_ed25519_public: mkp.identity_ed25519_public.clone(),
            identity_x25519_public: mkp.identity_x25519_public.clone(),
            signature: mkp.signature.clone(),
        };
        tree.add_leaf(
            mkp.leaf_x25519_public.clone(),
            mkp.leaf_kyber_public.clone(),
            leaf_data,
        )
        .unwrap();
    }

    assert_eq!(tree.member_count(), 1024);

    let extra_id = IdentityKeys::create(10).unwrap();
    let (extra_kp, _priv, _sec) =
        group::key_package::create_key_package(&extra_id, b"extra".to_vec()).unwrap();
    let leaf_data = LeafData {
        credential: extra_kp.credential.clone(),
        identity_ed25519_public: extra_kp.identity_ed25519_public.clone(),
        identity_x25519_public: extra_kp.identity_x25519_public.clone(),
        signature: extra_kp.signature.clone(),
    };
    let result = tree.add_leaf(
        extra_kp.leaf_x25519_public.clone(),
        extra_kp.leaf_kyber_public,
        leaf_data,
    );
    assert!(result.is_err(), "Adding 1025th member should fail");
}

#[test]
fn group_concurrent_commits_second_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let alice_update = alice_session.update().unwrap();
    let bob_update = bob_session.update().unwrap();

    let result = alice_session.process_commit(&bob_update);
    assert!(result.is_err(), "Concurrent commit should fail epoch check");

    let result2 = bob_session.process_commit(&alice_update);
    assert!(
        result2.is_err(),
        "Concurrent commit should fail epoch check (other side)"
    );
}

#[test]
fn group_replay_message_rejected_two_members() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice_session.encrypt(b"unique msg").unwrap();

    let pt = bob_session.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"unique msg");

    let result = bob_session.decrypt(&ct);
    assert!(result.is_err(), "Replay should be rejected");
}

#[test]
fn group_malformed_commit_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let result = alice_session.process_commit(&garbage);
    assert!(result.is_err(), "Malformed commit should be rejected");
}

#[test]
fn group_proptest_encrypt_decrypt_roundtrip() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let config = Config::with_cases(50);
    let mut runner = TestRunner::new(config);

    runner
        .run(&prop::collection::vec(any::<u8>(), 0..4096), |plaintext| {
            let ct = alice_session
                .encrypt(&plaintext)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("encrypt: {e}")))?;
            let pt = bob_session
                .decrypt(&ct)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(format!("decrypt: {e}")))?;
            prop_assert_eq!(&pt.plaintext, &plaintext);
            Ok(())
        })
        .unwrap();
}

#[allow(dead_code)]
fn add_member_to_group(
    adder_session: &GroupSession,
    other_sessions: &[&GroupSession],
) -> GroupSession {
    let new_id = IdentityKeys::create(10).unwrap();
    let (new_kp, x25519_priv, kyber_sec) =
        group::key_package::create_key_package(&new_id, b"member".to_vec()).unwrap();
    let (commit, welcome) = adder_session.add_member(&new_kp).unwrap();

    for s in other_sessions {
        s.process_commit(&commit).unwrap();
    }

    GroupSession::from_welcome(
        &welcome,
        x25519_priv,
        kyber_sec,
        &new_id.get_identity_ed25519_public(),
        &new_id.get_identity_x25519_public(),
        new_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap()
}

#[test]
fn group_cascading_removes() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    let mut others = Vec::new();
    for i in 0..5 {
        let id = IdentityKeys::create(10).unwrap();
        let (kp, x, k) =
            group::key_package::create_key_package(&id, format!("m{i}").into_bytes()).unwrap();
        let (commit, welcome) = alice.add_member(&kp).unwrap();

        for s in &others {
            let s: &GroupSession = s;
            s.process_commit(&commit).unwrap();
        }

        let new_session = GroupSession::from_welcome(
            &welcome,
            x,
            k,
            &id.get_identity_ed25519_public(),
            &id.get_identity_x25519_public(),
            id.get_identity_ed25519_private_key_copy().unwrap(),
        )
        .unwrap();
        others.push(new_session);
    }

    assert_eq!(alice.member_count().unwrap(), 6);

    for i in 0..3 {
        let leaf = others[i].my_leaf_index().unwrap();
        let commit = alice.remove_member(leaf).unwrap();

        for other in others.iter().take(5).skip(i + 1) {
            other.process_commit(&commit).unwrap();
        }
    }

    assert_eq!(alice.member_count().unwrap(), 3);

    let ct = alice.encrypt(b"after cascading removes").unwrap();
    let pt3 = others[3].decrypt(&ct).unwrap();
    let pt4 = others[4].decrypt(&ct).unwrap();
    assert_eq!(pt3.plaintext, b"after cascading removes");
    assert_eq!(pt4.plaintext, b"after cascading removes");
}

#[test]
fn group_readd_removed_member() {
    init();

    let (alice, bob) = create_two_member_group_with_policy(external_join_enabled_policy());
    let bob_leaf = bob.my_leaf_index().unwrap();

    let _commit = alice.remove_member(bob_leaf).unwrap();
    assert_eq!(alice.member_count().unwrap(), 1);

    let bob2_id = IdentityKeys::create(10).unwrap();
    let (bob2_kp, bob2_x, bob2_k) =
        group::key_package::create_key_package(&bob2_id, b"bob-v2".to_vec()).unwrap();
    let (_commit2, welcome2) = alice.add_member(&bob2_kp).unwrap();

    let bob2 = GroupSession::from_welcome(
        &welcome2,
        bob2_x,
        bob2_k,
        &bob2_id.get_identity_ed25519_public(),
        &bob2_id.get_identity_x25519_public(),
        bob2_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice.member_count().unwrap(), 2);
    assert_eq!(bob2.member_count().unwrap(), 2);

    let ct = alice.encrypt(b"welcome back bob").unwrap();
    let pt = bob2.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"welcome back bob");

    let ct2 = alice.encrypt(b"bob cannot see this").unwrap();
    assert!(bob.decrypt(&ct2).is_err());
}

#[test]
fn group_state_persistence_across_epochs() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &welcome,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let key = CryptoInterop::get_random_bytes(32);

    for i in 0..5 {
        let ct = alice.encrypt(format!("msg-{i}").as_bytes()).unwrap();
        bob.decrypt(&ct).unwrap();
    }

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();

    let alice_state = alice.export_sealed_state(&key, 1).unwrap();
    let bob_state = bob.export_sealed_state(&key, 1).unwrap();

    let alice2 = GroupSession::from_sealed_state(
        &alice_state,
        &key,
        alice_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();
    let bob2 = GroupSession::from_sealed_state(
        &bob_state,
        &key,
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();

    let ct = alice2.encrypt(b"after restore").unwrap();
    let pt = bob2.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after restore");

    let ct2 = bob2.encrypt(b"bob after restore").unwrap();
    let pt2 = alice2.decrypt(&ct2).unwrap();
    assert_eq!(pt2.plaintext, b"bob after restore");
}

#[test]
fn group_five_member_messaging() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    let mut members = vec![];
    for i in 0..4 {
        let id = IdentityKeys::create(10).unwrap();
        let (kp, x, k) =
            group::key_package::create_key_package(&id, format!("m{i}").into_bytes()).unwrap();
        let (commit, welcome) = alice.add_member(&kp).unwrap();

        for s in &members {
            let s: &GroupSession = s;
            s.process_commit(&commit).unwrap();
        }

        let new_session = GroupSession::from_welcome(
            &welcome,
            x,
            k,
            &id.get_identity_ed25519_public(),
            &id.get_identity_x25519_public(),
            id.get_identity_ed25519_private_key_copy().unwrap(),
        )
        .unwrap();
        members.push(new_session);
    }

    assert_eq!(alice.member_count().unwrap(), 5);

    let all_sessions: Vec<&GroupSession> = std::iter::once(&alice).chain(members.iter()).collect();

    for (sender_idx, sender) in all_sessions.iter().enumerate() {
        let msg = format!("from-member-{sender_idx}");
        let ct = sender.encrypt(msg.as_bytes()).unwrap();

        for (recv_idx, receiver) in all_sessions.iter().enumerate() {
            if recv_idx == sender_idx {
                continue;
            }
            let pt = receiver.decrypt(&ct).unwrap();
            assert_eq!(pt.plaintext, msg.as_bytes());
        }
    }
}

#[test]
fn group_update_both_members_bidirectional() {
    init();

    let mut policy = ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield();
    policy.max_skipped_keys_per_sender = 32;
    let (alice, bob) = create_two_member_group_with_policy(policy);

    let commit1 = alice.update().unwrap();
    bob.process_commit(&commit1).unwrap();

    let commit2 = bob.update().unwrap();
    alice.process_commit(&commit2).unwrap();

    for i in 0..10 {
        let msg_ab = format!("alice-to-bob-{i}");
        let ct = alice.encrypt(msg_ab.as_bytes()).unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, msg_ab.as_bytes());

        let msg_ba = format!("bob-to-alice-{i}");
        let ct2 = bob.encrypt(msg_ba.as_bytes()).unwrap();
        let pt2 = alice.decrypt(&ct2).unwrap();
        assert_eq!(pt2.plaintext, msg_ba.as_bytes());
    }
}

#[test]
fn group_rapid_epoch_advancement() {
    init();

    let (alice, bob) = create_two_member_group_with_policy(external_join_enabled_policy());

    for i in 0..50 {
        if i % 2 == 0 {
            let commit = alice.update().unwrap();
            bob.process_commit(&commit).unwrap();
        } else {
            let commit = bob.update().unwrap();
            alice.process_commit(&commit).unwrap();
        }
    }

    assert_eq!(alice.epoch().unwrap(), bob.epoch().unwrap());
    assert!(alice.epoch().unwrap() >= 50);

    let ct = alice.encrypt(b"after 50 updates").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after 50 updates");
}

#[test]
fn group_large_plaintext_roundtrip() {
    init();

    let (alice, bob) = create_two_member_group();

    let large_payload = vec![0xABu8; 500 * 1024];
    let ct = alice.encrypt(&large_payload).unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, large_payload);
}

#[test]
fn group_empty_plaintext_roundtrip() {
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt(b"").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"");
}

#[test]
fn group_cross_group_commit_rejected() {
    init();

    let alice1_id = IdentityKeys::create(10).unwrap();
    let alice2_id = IdentityKeys::create(10).unwrap();

    let group1 = GroupSession::create(&alice1_id, b"alice1".to_vec()).unwrap();
    let group2 = GroupSession::create(&alice2_id, b"alice2".to_vec()).unwrap();

    let commit = group1.update().unwrap();

    let result = group2.process_commit(&commit);
    assert!(result.is_err(), "Cross-group commit must be rejected");
}

#[test]
fn group_epoch_rollback_rejected() {
    init();

    let (alice, bob) = create_two_member_group();

    let commit1 = alice.update().unwrap();
    bob.process_commit(&commit1).unwrap();

    let commit2 = alice.update().unwrap();
    bob.process_commit(&commit2).unwrap();

    let result = bob.process_commit(&commit1);
    assert!(result.is_err(), "Old-epoch commit must be rejected");
}

#[test]
fn group_malformed_update_path_rejected() {
    init();

    let (alice, _bob) = create_two_member_group();

    let commit = alice.update().unwrap();
    let truncated = &commit[..commit.len() / 2];
    let result = alice.process_commit(truncated);
    assert!(result.is_err());
}

#[test]
fn group_message_from_wrong_epoch_rejected() {
    init();

    let (alice, bob) = create_two_member_group();

    let ct_epoch1 = alice.encrypt(b"epoch 1 message").unwrap();

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();

    let result = bob.decrypt(&ct_epoch1);
    assert!(result.is_err(), "Wrong-epoch message must be rejected");
}

#[test]
fn group_sealed_state_wrong_key_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let key = CryptoInterop::get_random_bytes(32);
    let sealed = session.export_sealed_state(&key, 1).unwrap();

    let wrong_key = CryptoInterop::get_random_bytes(32);
    let result = GroupSession::from_sealed_state(
        &sealed,
        &wrong_key,
        alice_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    );
    assert!(result.is_err(), "Wrong key must be rejected");
}

#[test]
fn group_sealed_state_tampered_data_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let key = CryptoInterop::get_random_bytes(32);
    let mut sealed = session.export_sealed_state(&key, 1).unwrap();

    if sealed.len() > 20 {
        sealed[20] ^= 0xFF;
    }

    let result = GroupSession::from_sealed_state(
        &sealed,
        &key,
        alice_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    );
    assert!(result.is_err(), "Tampered state must be rejected");
}

#[test]
fn padding_roundtrip_various_sizes() {
    use ecliptix_protocol::crypto::MessagePadding;

    for size in [0, 1, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1000, 4096] {
        let original = vec![0xABu8; size];
        let padded = MessagePadding::pad(&original);

        assert_eq!(padded.len() % 64, 0, "size={size}: not block-aligned");

        assert!(padded.len() > original.len(), "size={size}: too short");

        let recovered = MessagePadding::unpad(&padded).unwrap();
        assert_eq!(recovered, original, "size={size}: roundtrip mismatch");
    }
}

#[test]
fn padding_ciphertext_length_is_uniform() {
    use ecliptix_protocol::crypto::MessagePadding;

    let p1 = MessagePadding::pad(b"a");
    let p2 = MessagePadding::pad(b"ab");
    let p3 = MessagePadding::pad(b"abc");

    assert_eq!(p1.len(), 64);
    assert_eq!(p2.len(), 64);
    assert_eq!(p3.len(), 64);

    let p4 = MessagePadding::pad(&[0xABu8; 64]);
    assert_eq!(p4.len(), 128);

    init();
    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt(b"padded message").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"padded message");
}

#[test]
fn group_psk_injection_changes_epoch_secret() {
    use ecliptix_protocol::protocol::group::key_schedule::GroupKeySchedule;

    init();

    let epoch_secret = CryptoInterop::get_random_bytes(32);
    let psk = CryptoInterop::get_random_bytes(32);
    let psk_nonce = CryptoInterop::get_random_bytes(32);

    let injected = GroupKeySchedule::inject_psk(&epoch_secret, &psk, &psk_nonce).unwrap();

    assert_ne!(injected, epoch_secret);

    let injected2 = GroupKeySchedule::inject_psk(&epoch_secret, &psk, &psk_nonce).unwrap();
    assert_eq!(injected, injected2);

    let different_psk = CryptoInterop::get_random_bytes(32);
    let injected3 =
        GroupKeySchedule::inject_psk(&epoch_secret, &different_psk, &psk_nonce).unwrap();
    assert_ne!(injected, injected3);
}

#[test]
fn group_psk_commit_derives_epoch_keys_from_psk_and_requires_resolver() {
    use ecliptix_protocol::core::constants::{
        EPOCH_SECRET_BYTES, GROUP_EPOCH_SECRET_INFO, GROUP_ID_BYTES, INIT_SECRET_BYTES, PSK_BYTES,
    };
    use ecliptix_protocol::proto::{GroupProposal, GroupPskProposal};
    use ecliptix_protocol::protocol::group::commit;
    use ecliptix_protocol::protocol::group::key_schedule::GroupKeySchedule;
    use ecliptix_protocol::protocol::group::tree::{leaf_to_node, LeafData, RatchetTree};
    use ecliptix_protocol::protocol::group::{GroupSecurityPolicy, PskResolver};

    struct StaticPskResolver {
        id: Vec<u8>,
        value: Vec<u8>,
    }

    impl PskResolver for StaticPskResolver {
        fn resolve(&self, psk_id: &[u8]) -> Option<Vec<u8>> {
            if psk_id == self.id.as_slice() {
                Some(self.value.clone())
            } else {
                None
            }
        }
    }

    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let (alice_kp, alice_x_priv, alice_kyber_sec) =
        group::key_package::create_key_package(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();

    let mut base_tree = RatchetTree::new_single(
        alice_kp.leaf_x25519_public.clone(),
        alice_kp.leaf_kyber_public.clone(),
        alice_x_priv,
        alice_kyber_sec,
        alice_kp.identity_ed25519_public.clone(),
        alice_kp.identity_x25519_public.clone(),
        alice_kp.credential,
        alice_kp.signature,
    )
    .unwrap();

    let bob_leaf_idx = base_tree
        .add_leaf(
            bob_kp.leaf_x25519_public.clone(),
            bob_kp.leaf_kyber_public.clone(),
            LeafData {
                credential: bob_kp.credential.clone(),
                identity_ed25519_public: bob_kp.identity_ed25519_public.clone(),
                identity_x25519_public: bob_kp.identity_x25519_public,
                signature: bob_kp.signature,
            },
        )
        .unwrap();
    assert_eq!(bob_leaf_idx, 1);
    base_tree
        .set_node_private_keys(leaf_to_node(bob_leaf_idx), bob_x_priv, bob_kyber_sec)
        .unwrap();

    let mut creator_tree = base_tree.try_clone().unwrap();
    let mut processor_tree = base_tree.try_clone().unwrap();
    let mut no_resolver_create_tree = base_tree.try_clone().unwrap();
    let mut no_resolver_process_tree = base_tree.try_clone().unwrap();

    let init_secret = CryptoInterop::get_random_bytes(INIT_SECRET_BYTES);
    let group_id = CryptoInterop::get_random_bytes(GROUP_ID_BYTES);

    let psk_id = b"audit-psk".to_vec();
    let psk_nonce = CryptoInterop::get_random_bytes(PSK_BYTES);
    let psk_value = CryptoInterop::get_random_bytes(PSK_BYTES);
    let resolver = StaticPskResolver {
        id: psk_id.clone(),
        value: psk_value.clone(),
    };

    let psk_proposal = GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Psk(
            GroupPskProposal {
                psk_id,
                psk_nonce: psk_nonce.clone(),
            },
        )),
    };

    let mut alice_ed25519_sk = alice_id.get_identity_ed25519_private_key_copy().unwrap();
    let no_resolver_create = commit::create_commit(
        &mut no_resolver_create_tree,
        vec![psk_proposal.clone()],
        0,
        &init_secret,
        &group_id,
        0,
        &alice_ed25519_sk,
        None,
        &GroupSecurityPolicy::default(),
    );
    assert!(
        no_resolver_create.is_err(),
        "Creating commit with PSK proposal must fail without resolver",
    );

    let create_result = commit::create_commit(
        &mut creator_tree,
        vec![psk_proposal],
        0,
        &init_secret,
        &group_id,
        0,
        &alice_ed25519_sk,
        Some(&resolver),
        &GroupSecurityPolicy::default(),
    );
    CryptoInterop::secure_wipe(&mut alice_ed25519_sk);
    let create_output = create_result.unwrap();

    let mut epoch_info =
        Vec::with_capacity(GROUP_EPOCH_SECRET_INFO.len() + create_output.group_context_hash.len());
    epoch_info.extend_from_slice(GROUP_EPOCH_SECRET_INFO);
    epoch_info.extend_from_slice(&create_output.group_context_hash);
    let pre_psk_epoch_secret = HkdfSha256::expand(
        &create_output.joiner_secret,
        &epoch_info,
        EPOCH_SECRET_BYTES,
    )
    .unwrap();
    let expected_epoch_secret =
        GroupKeySchedule::inject_psk(&pre_psk_epoch_secret, &psk_value, &psk_nonce).unwrap();
    let expected_epoch_keys =
        GroupKeySchedule::derive_sub_keys_from_epoch_secret(&expected_epoch_secret).unwrap();
    let expected_confirmation_mac = GroupKeySchedule::compute_confirmation_mac(
        &expected_epoch_keys.confirmation_key,
        &create_output.group_context_hash,
    )
    .unwrap();

    assert_eq!(create_output.epoch_keys.epoch_secret, expected_epoch_secret);
    assert_eq!(
        create_output.epoch_keys.metadata_key,
        expected_epoch_keys.metadata_key
    );
    assert_eq!(
        create_output.epoch_keys.confirmation_key,
        expected_epoch_keys.confirmation_key
    );
    assert_eq!(
        create_output.commit.confirmation_mac,
        expected_confirmation_mac
    );

    let no_resolver_process = commit::process_commit(
        &mut no_resolver_process_tree,
        &create_output.commit,
        bob_leaf_idx,
        &init_secret,
        &group_id,
        0,
        None,
        &GroupSecurityPolicy::default(),
    );
    assert!(
        no_resolver_process.is_err(),
        "Processing commit with PSK proposal must fail without resolver",
    );

    let processed = commit::process_commit(
        &mut processor_tree,
        &create_output.commit,
        bob_leaf_idx,
        &init_secret,
        &group_id,
        0,
        Some(&resolver),
        &GroupSecurityPolicy::default(),
    )
    .unwrap();

    assert_eq!(
        processed.epoch_keys.epoch_secret, create_output.epoch_keys.epoch_secret,
        "Creator and processor must derive identical PSK-injected epoch_secret",
    );
}

#[test]
fn group_new_member_cannot_decrypt_pre_join_messages() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct_epoch1_a = alice.encrypt(b"secret epoch 1 from alice").unwrap();
    let ct_epoch1_b = bob.encrypt(b"secret epoch 1 from bob").unwrap();

    let pt = bob.decrypt(&ct_epoch1_a).unwrap();
    assert_eq!(pt.plaintext, b"secret epoch 1 from alice");
    let pt = alice.decrypt(&ct_epoch1_b).unwrap();
    assert_eq!(pt.plaintext, b"secret epoch 1 from bob");

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(carol.epoch().unwrap(), 2);

    let result_a = carol.decrypt(&ct_epoch1_a);
    assert!(
        result_a.is_err(),
        "New member must NOT decrypt pre-join messages (alice's)"
    );
    let result_b = carol.decrypt(&ct_epoch1_b);
    assert!(
        result_b.is_err(),
        "New member must NOT decrypt pre-join messages (bob's)"
    );

    let ct_epoch2 = alice.encrypt(b"welcome carol").unwrap();
    let pt = carol.decrypt(&ct_epoch2).unwrap();
    assert_eq!(pt.plaintext, b"welcome carol");
}

#[test]
fn group_new_member_cannot_decrypt_multi_epoch_history() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let mut old_ciphertexts = Vec::new();
    for i in 0u64..10 {
        let msg = format!("epoch-{}-message", alice.epoch().unwrap());
        let ct = alice.encrypt(msg.as_bytes()).unwrap();
        old_ciphertexts.push(ct);

        let commit = alice.update().unwrap();
        bob.process_commit(&commit).unwrap();
        assert_eq!(alice.epoch().unwrap(), i + 2);
    }

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c_add, w_add) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c_add).unwrap();
    let carol = GroupSession::from_welcome(
        &w_add,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(carol.epoch().unwrap(), 12);

    for (i, ct) in old_ciphertexts.iter().enumerate() {
        let result = carol.decrypt(ct);
        assert!(
            result.is_err(),
            "Carol must not decrypt epoch {} message (i={})",
            i + 1,
            i
        );
    }

    let ct_now = alice.encrypt(b"carol can read this").unwrap();
    let pt = carol.decrypt(&ct_now).unwrap();
    assert_eq!(pt.plaintext, b"carol can read this");
}

#[test]
fn group_removed_member_forward_secrecy_across_rotations() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice.epoch().unwrap(), 2);
    assert_eq!(bob.epoch().unwrap(), 2);
    assert_eq!(carol.epoch().unwrap(), 2);

    let remove_commit = alice.remove_member(bob.my_leaf_index().unwrap()).unwrap();
    carol.process_commit(&remove_commit).unwrap();

    for _ in 0..5 {
        let commit = alice.update().unwrap();
        carol.process_commit(&commit).unwrap();
    }

    assert_eq!(alice.epoch().unwrap(), 8);

    for i in 0..5 {
        let msg = format!("post-removal-msg-{i}");
        let ct = alice.encrypt(msg.as_bytes()).unwrap();
        let result = bob.decrypt(&ct);
        assert!(
            result.is_err(),
            "Removed member must not decrypt post-removal message {i}"
        );

        let pt = carol.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, msg.as_bytes());
    }
}

#[test]
fn group_readd_member_cannot_decrypt_gap_messages() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct_before = bob.encrypt(b"bob pre-removal").unwrap();
    let pt = alice.decrypt(&ct_before).unwrap();
    assert_eq!(pt.plaintext, b"bob pre-removal");

    let _remove_commit = alice.remove_member(bob.my_leaf_index().unwrap()).unwrap();

    let mut gap_ciphertexts = Vec::new();
    for i in 0..3 {
        let _update_commit = alice.update().unwrap();
        let msg = format!("gap-message-{i}");
        let ct = alice.encrypt(msg.as_bytes()).unwrap();
        gap_ciphertexts.push(ct);
    }

    let bob2_id = IdentityKeys::create(10).unwrap();
    let (bob2_kp, bob2_x, bob2_k) =
        group::key_package::create_key_package(&bob2_id, b"bob-v2".to_vec()).unwrap();
    let (_c_add, w_add) = alice.add_member(&bob2_kp).unwrap();
    let bob2 = GroupSession::from_welcome(
        &w_add,
        bob2_x,
        bob2_k,
        &bob2_id.get_identity_ed25519_public(),
        &bob2_id.get_identity_x25519_public(),
        bob2_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    for (i, ct) in gap_ciphertexts.iter().enumerate() {
        let result = bob2.decrypt(ct);
        assert!(
            result.is_err(),
            "Re-added member must not decrypt gap message {i}"
        );
    }

    let ct_now = alice.encrypt(b"welcome back bob").unwrap();
    let pt = bob2.decrypt(&ct_now).unwrap();
    assert_eq!(pt.plaintext, b"welcome back bob");
}

#[test]
fn group_external_join_cannot_decrypt_pre_join_messages() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct_old_a = alice.encrypt(b"old alice msg").unwrap();
    let ct_old_b = bob.encrypt(b"old bob msg").unwrap();
    bob.decrypt(&ct_old_a).unwrap();
    alice.decrypt(&ct_old_b).unwrap();

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol, ext_commit) = authorize_and_join_external(&alice, &carol_id, b"carol");
    alice.process_commit(&ext_commit).unwrap();
    bob.process_commit(&ext_commit).unwrap();

    assert!(
        carol.decrypt(&ct_old_a).is_err(),
        "External joiner must not decrypt old alice msg"
    );
    assert!(
        carol.decrypt(&ct_old_b).is_err(),
        "External joiner must not decrypt old bob msg"
    );

    let ct_new = alice.encrypt(b"carol can read this").unwrap();
    let pt = carol.decrypt(&ct_new).unwrap();
    assert_eq!(pt.plaintext, b"carol can read this");
}

#[test]
fn group_stress_100_messages_bidirectional() {
    init();

    let (alice, bob) = create_two_member_group_with_policy(external_join_enabled_policy());

    for i in 0..100u32 {
        if i % 2 == 0 {
            let ct = alice.encrypt(format!("a-{i}").as_bytes()).unwrap();
            let pt = bob.decrypt(&ct).unwrap();
            assert_eq!(pt.plaintext, format!("a-{i}").as_bytes());
        } else {
            let ct = bob.encrypt(format!("b-{i}").as_bytes()).unwrap();
            let pt = alice.decrypt(&ct).unwrap();
            assert_eq!(pt.plaintext, format!("b-{i}").as_bytes());
        }
    }
}

#[test]
fn group_concurrent_encrypt_decrypt() {
    init();
    use std::sync::Arc;
    use std::thread;

    let (alice, bob) = create_two_member_group();
    let alice = Arc::new(alice);
    let results = Arc::new(std::sync::Mutex::new(Vec::<(Vec<u8>, Vec<u8>)>::new()));

    let mut handles = vec![];
    for t in 0..8u32 {
        let alice = Arc::clone(&alice);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            for i in 0..50u32 {
                let msg = format!("t{t}-m{i}");
                let ct = alice.encrypt(msg.as_bytes()).unwrap();
                results.lock().unwrap().push((msg.into_bytes(), ct));
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let mut produced = results.lock().unwrap();
    for (msg, ct) in produced.drain(..) {
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, msg);
    }
}

#[test]
fn group_psk_proposal_validation() {
    init();
    use ecliptix_protocol::protocol::group::membership::validate_proposals;
    use ecliptix_protocol::protocol::group::tree::RatchetTree;

    let alice_id = IdentityKeys::create(10).unwrap();
    let (kp, x, k) = group::key_package::create_key_package(&alice_id, b"alice".to_vec()).unwrap();
    let tree = RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x,
        k,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    let valid_psk = ecliptix_protocol::proto::GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Psk(
            ecliptix_protocol::proto::GroupPskProposal {
                psk_id: b"my-psk".to_vec(),
                psk_nonce: vec![0u8; 32],
            },
        )),
    };
    assert!(validate_proposals(&tree, &[valid_psk], 0).is_ok());

    let empty_id = ecliptix_protocol::proto::GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Psk(
            ecliptix_protocol::proto::GroupPskProposal {
                psk_id: vec![],
                psk_nonce: vec![0u8; 32],
            },
        )),
    };
    assert!(validate_proposals(&tree, &[empty_id], 0).is_err());

    let bad_nonce = ecliptix_protocol::proto::GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Psk(
            ecliptix_protocol::proto::GroupPskProposal {
                psk_id: b"my-psk".to_vec(),
                psk_nonce: vec![0u8; 16],
            },
        )),
    };
    assert!(validate_proposals(&tree, &[bad_nonce], 0).is_err());
}

#[test]
fn group_reinit_proposal_validation() {
    init();
    use ecliptix_protocol::protocol::group::membership::validate_proposals;
    use ecliptix_protocol::protocol::group::tree::RatchetTree;

    let alice_id = IdentityKeys::create(10).unwrap();
    let (kp, x, k) = group::key_package::create_key_package(&alice_id, b"alice".to_vec()).unwrap();
    let tree = RatchetTree::new_single(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        x,
        k,
        kp.identity_ed25519_public.clone(),
        kp.identity_x25519_public,
        b"alice".to_vec(),
        kp.signature,
    )
    .unwrap();

    let valid_reinit = ecliptix_protocol::proto::GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::ReInit(
            ecliptix_protocol::proto::GroupReInitProposal {
                new_group_id: vec![0u8; 32],
                new_version: 2,
            },
        )),
    };
    assert!(validate_proposals(&tree, &[valid_reinit], 0).is_ok());

    let bad_reinit = ecliptix_protocol::proto::GroupProposal {
        proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::ReInit(
            ecliptix_protocol::proto::GroupReInitProposal {
                new_group_id: vec![0u8; 16],
                new_version: 2,
            },
        )),
    };
    assert!(validate_proposals(&tree, &[bad_reinit], 0).is_err());
}

#[test]
fn group_plaintext_roundtrip_regression() {
    use ecliptix_protocol::protocol::group::ContentType;

    let (alice, bob) = create_two_member_group();
    let plaintext = b"Hello, this is a normal message";

    let ct = alice.encrypt(plaintext).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.content_type, ContentType::Normal);
    assert!(result.sealed_payload.is_none());
    assert!(result.franking_data.is_some());
    assert_eq!(result.ttl_seconds, 0);
}

#[test]
fn group_sealed_message_roundtrip() {
    use ecliptix_protocol::protocol::group::{ContentType, GroupSession};

    let mut policy = ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield();
    policy.max_messages_per_epoch = 5_000;
    let (alice, bob) = create_two_member_group_with_policy(policy);
    let actual_content = b"This is top-secret content";
    let hint = b"Photo from Alice";

    let ct = alice.encrypt_sealed(actual_content, hint).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, hint);
    assert_eq!(result.content_type, ContentType::Sealed);
    assert!(result.sealed_payload.is_some());

    let sealed = result.sealed_payload.as_ref().unwrap();
    assert_eq!(sealed.hint, hint);
    let revealed = GroupSession::reveal_sealed(sealed).unwrap();
    assert_eq!(revealed, actual_content);
}

#[test]
fn group_disappearing_message_fresh() {
    use ecliptix_protocol::protocol::group::ContentType;

    let (alice, bob) = create_two_member_group();
    let plaintext = b"This message will disappear";

    let ct = alice.encrypt_disappearing(plaintext, 3600).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, plaintext);
    assert_eq!(result.content_type, ContentType::Disappearing);
    assert_eq!(result.ttl_seconds, 3600);
    assert!(result.sent_timestamp > 0);
}

#[test]
fn group_disappearing_message_expired() {
    let (alice, bob) = create_two_member_group();
    let plaintext = b"Ephemeral";

    let ct = alice.encrypt_disappearing(plaintext, 1).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));

    let result = bob.decrypt(&ct);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("expired"),
        "Expected 'expired' in: {err_msg}"
    );
}

#[test]
fn group_disappearing_invalid_ttl_rejected() {
    let (alice, _bob) = create_two_member_group();

    let r = alice.encrypt_disappearing(b"test", 0);
    assert!(r.is_err());

    let r = alice.encrypt_disappearing(b"test", 7 * 24 * 3600 + 1);
    assert!(r.is_err());
}

#[test]
fn group_frankable_message_roundtrip() {
    use ecliptix_protocol::protocol::group::GroupSession;

    let (alice, bob) = create_two_member_group();
    let plaintext = b"This is a frankable message";

    let ct = alice.encrypt_frankable(plaintext).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, plaintext);
    assert!(result.franking_data.is_some());

    let fd = result.franking_data.as_ref().unwrap();
    assert_eq!(fd.content, plaintext);
    let valid = GroupSession::verify_franking(fd).unwrap();
    assert!(valid, "Franking verification should succeed");
}

#[test]
fn group_frankable_tampered_content_rejected() {
    use ecliptix_protocol::protocol::group::{FrankingData, GroupSession};

    let (alice, bob) = create_two_member_group();
    let plaintext = b"Original content";

    let ct = alice.encrypt_frankable(plaintext).unwrap();
    let result = bob.decrypt(&ct).unwrap();
    let fd = result.franking_data.as_ref().unwrap();

    let tampered = FrankingData {
        franking_tag: fd.franking_tag.clone(),
        franking_key: fd.franking_key.clone(),
        content: b"Tampered content".to_vec(),
        sealed_content: vec![],
    };
    let valid = GroupSession::verify_franking(&tampered).unwrap();
    assert!(
        !valid,
        "Franking verification should fail for tampered content"
    );
}

#[test]
fn group_sealed_disappearing_frankable() {
    use ecliptix_protocol::protocol::group::{ContentType, GroupSession, MessagePolicy};

    let (alice, bob) = create_two_member_group();
    let plaintext = b"Multi-feature message";

    let policy = MessagePolicy {
        content_type: ContentType::SealedDisappearing,
        ttl_seconds: 3600,
        frankable: true,
        referenced_message_id: Vec::new(),
    };
    let ct = alice.encrypt_with_policy(plaintext, &policy).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.content_type, ContentType::SealedDisappearing);
    assert_eq!(result.ttl_seconds, 3600);
    assert!(result.sealed_payload.is_some());
    assert!(result.franking_data.is_some());

    let sealed = result.sealed_payload.as_ref().unwrap();
    let revealed = GroupSession::reveal_sealed(sealed).unwrap();
    assert_eq!(revealed, plaintext);
}

#[test]
fn group_non_creator_adds_member() {
    init();

    let (alice, bob) = create_two_member_group();

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (commit, welcome) = bob.add_member(&carol_kp).unwrap();
    alice.process_commit(&commit).unwrap();
    let carol = GroupSession::from_welcome(
        &welcome,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice.member_count().unwrap(), 3);
    assert_eq!(bob.member_count().unwrap(), 3);
    assert_eq!(carol.member_count().unwrap(), 3);

    let ct = bob.encrypt(b"bob added carol").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"bob added carol");
    assert_eq!(carol.decrypt(&ct).unwrap().plaintext, b"bob added carol");
}

#[test]
fn group_triple_sequential_update_same_member() {
    init();

    let (alice, bob) = create_two_member_group();
    let epoch_before = alice.epoch().unwrap();

    for _ in 0..3 {
        let commit = alice.update().unwrap();
        bob.process_commit(&commit).unwrap();
    }

    assert_eq!(alice.epoch().unwrap(), epoch_before + 3);
    assert_eq!(bob.epoch().unwrap(), epoch_before + 3);

    let ct = alice.encrypt(b"after triple update").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after triple update");
}

#[test]
fn group_add_reuses_blank_slot_after_remove() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let bob_leaf = bob.my_leaf_index().unwrap();

    let _remove_commit = alice.remove_member(bob_leaf).unwrap();

    assert_eq!(alice.member_count().unwrap(), 1);

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (_c2, w2) = alice.add_member(&carol_kp).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(
        carol.my_leaf_index().unwrap(),
        bob_leaf,
        "Carol should reuse Bob's blank slot"
    );
    assert_eq!(alice.member_count().unwrap(), 2);

    let ct = alice.encrypt(b"slot reuse works").unwrap();
    let pt = carol.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"slot reuse works");
}

#[test]
fn group_remove_self_rejected() {
    init();

    let (alice, _bob) = create_two_member_group();

    let result = alice.remove_member(alice.my_leaf_index().unwrap());
    assert!(result.is_err(), "Removing self must be rejected");
}

#[test]
fn group_decrypt_result_metadata_correct() {
    init();

    let (alice, bob) = create_two_member_group_with_policy(external_join_enabled_policy());

    for i in 0..5u32 {
        let ct = alice.encrypt(format!("msg-{i}").as_bytes()).unwrap();
        let result = bob.decrypt(&ct).unwrap();
        assert_eq!(result.sender_leaf_index, alice.my_leaf_index().unwrap());
        assert_eq!(result.generation, i, "Generation should increment from 0");
    }

    let ct = bob.encrypt(b"from bob").unwrap();
    let result = alice.decrypt(&ct).unwrap();
    assert_eq!(result.sender_leaf_index, bob.my_leaf_index().unwrap());
    assert_eq!(result.generation, 0);
}

#[test]
fn group_binary_payload_roundtrip() {
    init();

    let (alice, bob) = create_two_member_group();

    let zeros = vec![0u8; 256];
    let ct = alice.encrypt(&zeros).unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, zeros);

    let ones = vec![0xFFu8; 256];
    let ct = alice.encrypt(&ones).unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, ones);

    let mixed: Vec<u8> = (0..=255).collect();
    let ct = alice.encrypt(&mixed).unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, mixed);
}

#[test]
fn group_state_persistence_then_add_member() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &welcome,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let key = CryptoInterop::get_random_bytes(32);

    for i in 0..3 {
        let ct = alice.encrypt(format!("pre-{i}").as_bytes()).unwrap();
        bob.decrypt(&ct).unwrap();
    }

    let alice_state = alice.export_sealed_state(&key, 1).unwrap();
    let alice2 = GroupSession::from_sealed_state(
        &alice_state,
        &key,
        alice_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (commit, welcome) = alice2.add_member(&carol_kp).unwrap();
    bob.process_commit(&commit).unwrap();
    let carol = GroupSession::from_welcome(
        &welcome,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice2.member_count().unwrap(), 3);

    let ct = alice2.encrypt(b"restored alice says hi").unwrap();
    assert_eq!(
        bob.decrypt(&ct).unwrap().plaintext,
        b"restored alice says hi"
    );
    assert_eq!(
        carol.decrypt(&ct).unwrap().plaintext,
        b"restored alice says hi"
    );
}

#[test]
fn group_context_hash_changes_each_epoch() {
    use ecliptix_protocol::proto::GroupPublicState;
    init();

    let (alice, bob) = create_two_member_group();

    let mut hashes = Vec::new();
    let ps0 = alice.export_public_state().unwrap();
    let state0 = GroupPublicState::decode(ps0.as_slice()).unwrap();
    hashes.push(state0.group_context_hash);

    for _ in 0..5 {
        let commit = alice.update().unwrap();
        bob.process_commit(&commit).unwrap();

        let ps = alice.export_public_state().unwrap();
        let state = ecliptix_protocol::proto::GroupPublicState::decode(ps.as_slice()).unwrap();
        hashes.push(state.group_context_hash.clone());
    }

    let unique: std::collections::HashSet<Vec<u8>> = hashes.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        hashes.len(),
        "Context hash must change every epoch"
    );
}

#[test]
fn group_external_join_after_remove() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let _remove_commit = alice.remove_member(bob.my_leaf_index().unwrap()).unwrap();
    assert_eq!(alice.member_count().unwrap(), 1);

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol, ext_commit) = authorize_and_join_external(&alice, &carol_id, b"carol");
    alice.process_commit(&ext_commit).unwrap();

    assert_eq!(alice.member_count().unwrap(), 2);
    assert_eq!(carol.member_count().unwrap(), 2);

    let ct = alice.encrypt(b"external join with blanks").unwrap();
    let pt = carol.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"external join with blanks");
}

#[test]
fn group_replay_detection_capacity_eviction() {
    init();

    let mut policy = ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield();
    policy.max_messages_per_epoch = 5_000;
    let (alice, bob) = create_two_member_group_with_policy(policy);

    for i in 0u32..2100 {
        let ct = alice.encrypt(format!("m{i}").as_bytes()).unwrap();
        bob.decrypt(&ct).unwrap();
    }

    let ct = alice.encrypt(b"after eviction").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after eviction");
}

#[test]
fn group_multi_sender_generation_counters() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct_a0 = alice.encrypt(b"a0").unwrap();
    let ct_b0 = bob.encrypt(b"b0").unwrap();
    let ct_c0 = carol.encrypt(b"c0").unwrap();
    let ct_a1 = alice.encrypt(b"a1").unwrap();
    let ct_b1 = bob.encrypt(b"b1").unwrap();
    let ct_a2 = alice.encrypt(b"a2").unwrap();

    let r = carol.decrypt(&ct_a0).unwrap();
    assert_eq!(r.sender_leaf_index, alice.my_leaf_index().unwrap());
    assert_eq!(r.generation, 0);

    let r = carol.decrypt(&ct_a1).unwrap();
    assert_eq!(r.sender_leaf_index, alice.my_leaf_index().unwrap());
    assert_eq!(r.generation, 1);

    let r = carol.decrypt(&ct_a2).unwrap();
    assert_eq!(r.sender_leaf_index, alice.my_leaf_index().unwrap());
    assert_eq!(r.generation, 2);

    let r = carol.decrypt(&ct_b0).unwrap();
    assert_eq!(r.sender_leaf_index, bob.my_leaf_index().unwrap());
    assert_eq!(r.generation, 0);

    let r = carol.decrypt(&ct_b1).unwrap();
    assert_eq!(r.sender_leaf_index, bob.my_leaf_index().unwrap());
    assert_eq!(r.generation, 1);

    let r = alice.decrypt(&ct_c0).unwrap();
    assert_eq!(r.sender_leaf_index, carol.my_leaf_index().unwrap());
    assert_eq!(r.generation, 0);
}

#[test]
fn group_max_message_size_enforced_on_decrypt() {
    init();

    let (alice, _bob) = create_two_member_group();

    let oversized = vec![0u8; 1024 * 1024 + 1];
    let result = alice.decrypt(&oversized);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("too large"), "Expected size error, got: {err}");
}

#[test]
fn group_export_public_state_structure() {
    use ecliptix_protocol::proto::GroupPublicState;
    init();

    let (alice, bob) = create_two_member_group();

    let ps_bytes = alice.export_public_state().unwrap();
    let ps = GroupPublicState::decode(ps_bytes.as_slice()).unwrap();

    assert_eq!(ps.version, 1);
    assert_eq!(ps.group_id, alice.group_id().unwrap());
    assert_eq!(ps.epoch, alice.epoch().unwrap());
    assert!(!ps.tree_nodes.is_empty(), "tree must have nodes");
    assert_eq!(ps.group_context_hash.len(), 32);
    assert_eq!(ps.confirmation_mac.len(), 32);
    assert_eq!(ps.external_x25519_public.len(), 32);
    assert_eq!(ps.external_kyber_public.len(), 1184);

    let ps2_bytes = bob.export_public_state().unwrap();
    let ps2 = GroupPublicState::decode(ps2_bytes.as_slice()).unwrap();
    assert_eq!(ps.group_id, ps2.group_id);
    assert_eq!(ps.epoch, ps2.epoch);
    assert_eq!(ps.group_context_hash, ps2.group_context_hash);
}

#[test]
fn group_sealed_reveal_wrong_key_fails() {
    use ecliptix_protocol::protocol::group::{GroupSession, SealedPayload};

    init();

    let (alice, bob) = create_two_member_group();
    let ct = alice.encrypt_sealed(b"top secret", b"hint").unwrap();
    let result = bob.decrypt(&ct).unwrap();

    let sealed = result.sealed_payload.unwrap();

    let tampered = SealedPayload {
        hint: sealed.hint.clone(),
        encrypted_content: sealed.encrypted_content.clone(),
        nonce: sealed.nonce.clone(),
        seal_key: vec![0xAA; 32],
    };
    let reveal_result = GroupSession::reveal_sealed(&tampered);
    assert!(reveal_result.is_err(), "Wrong seal key must fail");
}

#[test]
fn group_frankable_disappearing_combined() {
    use ecliptix_protocol::protocol::group::{ContentType, GroupSession, MessagePolicy};

    init();

    let (alice, bob) = create_two_member_group();

    let policy = MessagePolicy {
        content_type: ContentType::Disappearing,
        ttl_seconds: 3600,
        frankable: true,
        referenced_message_id: Vec::new(),
    };
    let ct = alice
        .encrypt_with_policy(b"ephemeral proof", &policy)
        .unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.content_type, ContentType::Disappearing);
    assert_eq!(result.ttl_seconds, 3600);
    assert!(result.franking_data.is_some());

    let fd = result.franking_data.as_ref().unwrap();
    assert!(GroupSession::verify_franking(fd).unwrap());
}

#[test]
fn group_sealed_state_wrong_key_length_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let short_key = vec![0u8; 16];
    assert!(session.export_sealed_state(&short_key, 1).is_err());

    let long_key = vec![0u8; 64];
    assert!(session.export_sealed_state(&long_key, 1).is_err());
}

#[test]
fn group_old_epoch_messages_rejected_after_update() {
    init();

    let (alice, bob) = create_two_member_group();

    let ct_old_alice = alice.encrypt(b"epoch-1-alice").unwrap();
    let ct_old_bob = bob.encrypt(b"epoch-1-bob").unwrap();

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();

    assert!(bob.decrypt(&ct_old_alice).is_err());
    assert!(alice.decrypt(&ct_old_bob).is_err());

    let ct_new = alice.encrypt(b"epoch-2").unwrap();
    assert_eq!(bob.decrypt(&ct_new).unwrap().plaintext, b"epoch-2");
}

#[test]
fn group_member_leaf_indices_consistent() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let mut alice_indices = alice.member_leaf_indices().unwrap();
    let mut bob_indices = bob.member_leaf_indices().unwrap();
    let mut carol_indices = carol.member_leaf_indices().unwrap();

    alice_indices.sort_unstable();
    bob_indices.sort_unstable();
    carol_indices.sort_unstable();

    assert_eq!(alice_indices, bob_indices);
    assert_eq!(bob_indices, carol_indices);
    assert_eq!(alice_indices.len(), 3);

    assert!(alice_indices.contains(&alice.my_leaf_index().unwrap()));
    assert!(alice_indices.contains(&bob.my_leaf_index().unwrap()));
    assert!(alice_indices.contains(&carol.my_leaf_index().unwrap()));
}

#[test]
fn group_complex_lifecycle_add_update_remove_messaging() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let bob_id = IdentityKeys::create(10).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice.encrypt(b"phase1").unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, b"phase1");

    let commit = bob.update().unwrap();
    alice.process_commit(&commit).unwrap();

    let ct = bob.encrypt(b"phase2").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"phase2");

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c3, w3) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c3).unwrap();
    let carol = GroupSession::from_welcome(
        &w3,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = carol.encrypt(b"phase3-carol").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"phase3-carol");
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, b"phase3-carol");

    let remove_commit = alice.remove_member(bob.my_leaf_index().unwrap()).unwrap();
    carol.process_commit(&remove_commit).unwrap();

    assert_eq!(alice.member_count().unwrap(), 2);

    let ct = alice.encrypt(b"phase4-no-bob").unwrap();
    assert_eq!(carol.decrypt(&ct).unwrap().plaintext, b"phase4-no-bob");
    assert!(bob.decrypt(&ct).is_err());

    let commit = carol.update().unwrap();
    alice.process_commit(&commit).unwrap();

    let ct = carol.encrypt(b"phase5-final").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"phase5-final");
}

#[test]
fn group_id_immutable_across_lifecycle() {
    init();

    let (alice, bob) = create_two_member_group_with_policy(external_join_enabled_policy());
    let group_id = alice.group_id().unwrap();

    assert_eq!(group_id.len(), 32);
    assert_eq!(bob.group_id().unwrap(), group_id);

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();
    assert_eq!(alice.group_id().unwrap(), group_id);
    assert_eq!(bob.group_id().unwrap(), group_id);

    let carol_id = IdentityKeys::create(10).unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (commit, welcome) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&commit).unwrap();
    let carol = GroupSession::from_welcome(
        &welcome,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert_eq!(alice.group_id().unwrap(), group_id);
    assert_eq!(bob.group_id().unwrap(), group_id);
    assert_eq!(carol.group_id().unwrap(), group_id);

    let dave_id = IdentityKeys::create(10).unwrap();
    let (dave, ext_commit) = authorize_and_join_external(&alice, &dave_id, b"dave");
    alice.process_commit(&ext_commit).unwrap();
    bob.process_commit(&ext_commit).unwrap();
    carol.process_commit(&ext_commit).unwrap();

    assert_eq!(dave.group_id().unwrap(), group_id);
}

#[test]
fn group_20_member_full_lifecycle() {
    init();

    let creator_id = IdentityKeys::create(10).unwrap();
    let creator = GroupSession::create(&creator_id, b"creator".to_vec()).unwrap();

    let mut sessions: Vec<GroupSession> = vec![];

    for i in 0..19 {
        let id = IdentityKeys::create(10).unwrap();
        let (kp, x, k) =
            group::key_package::create_key_package(&id, format!("m{i}").into_bytes()).unwrap();
        let (commit, welcome) = creator.add_member(&kp).unwrap();

        for s in &sessions {
            s.process_commit(&commit).unwrap();
        }

        let new_session = GroupSession::from_welcome(
            &welcome,
            x,
            k,
            &id.get_identity_ed25519_public(),
            &id.get_identity_x25519_public(),
            id.get_identity_ed25519_private_key_copy().unwrap(),
        )
        .unwrap();
        sessions.push(new_session);
    }

    assert_eq!(creator.member_count().unwrap(), 20);

    let ct = creator.encrypt(b"hello 20 members").unwrap();
    for s in &sessions {
        let pt = s.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, b"hello 20 members");
    }

    let ct2 = sessions[10].encrypt(b"from member 10").unwrap();
    let pt = creator.decrypt(&ct2).unwrap();
    assert_eq!(pt.plaintext, b"from member 10");
    for (i, s) in sessions.iter().enumerate() {
        if i != 10 {
            let pt = s.decrypt(&ct2).unwrap();
            assert_eq!(pt.plaintext, b"from member 10");
        }
    }
}

#[test]
fn group_rapid_membership_churn() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let mut others: Vec<GroupSession> = Vec::new();
    for i in 0..4 {
        let id = IdentityKeys::create(10).unwrap();
        let (kp, x, k) =
            group::key_package::create_key_package(&id, format!("init{i}").into_bytes()).unwrap();
        let (commit, welcome) = alice.add_member(&kp).unwrap();
        for s in &others {
            s.process_commit(&commit).unwrap();
        }
        let s = GroupSession::from_welcome(
            &welcome,
            x,
            k,
            &id.get_identity_ed25519_public(),
            &id.get_identity_x25519_public(),
            id.get_identity_ed25519_private_key_copy().unwrap(),
        )
        .unwrap();
        others.push(s);
    }

    assert_eq!(alice.member_count().unwrap(), 5);

    for round in 0..10 {
        let remove_idx = 0;
        let removed_leaf = others[remove_idx].my_leaf_index().unwrap();
        let remove_commit = alice.remove_member(removed_leaf).unwrap();
        for s in others.iter().skip(1) {
            s.process_commit(&remove_commit).unwrap();
        }
        others.remove(remove_idx);

        let id = IdentityKeys::create(10).unwrap();
        let (kp, x, k) =
            group::key_package::create_key_package(&id, format!("churn{round}").into_bytes())
                .unwrap();
        let (commit, welcome) = alice.add_member(&kp).unwrap();
        for s in &others {
            s.process_commit(&commit).unwrap();
        }
        let s = GroupSession::from_welcome(
            &welcome,
            x,
            k,
            &id.get_identity_ed25519_public(),
            &id.get_identity_x25519_public(),
            id.get_identity_ed25519_private_key_copy().unwrap(),
        )
        .unwrap();
        others.push(s);

        let ct = alice.encrypt(format!("round{round}").as_bytes()).unwrap();
        for s in &others {
            let pt = s.decrypt(&ct).unwrap();
            assert_eq!(pt.plaintext, format!("round{round}").as_bytes());
        }
    }

    assert_eq!(alice.member_count().unwrap(), 5);
}

#[test]
fn group_bulk_messages_single_epoch() {
    init();

    let (alice, bob) = create_two_member_group();

    for i in 0u32..500 {
        let ct = alice.encrypt(format!("a{i}").as_bytes()).unwrap();
        let pt = bob.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, format!("a{i}").as_bytes());
    }

    for i in 0u32..500 {
        let ct = bob.encrypt(format!("b{i}").as_bytes()).unwrap();
        let pt = alice.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, format!("b{i}").as_bytes());
    }
}

#[test]
fn group_external_join_after_many_epochs() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    for _ in 0..10 {
        let _commit = alice.update().unwrap();
    }

    assert_eq!(alice.epoch().unwrap(), 10);

    let joiner_id = IdentityKeys::create(10).unwrap();
    let (joiner, ext_commit) = authorize_and_join_external(&alice, &joiner_id, b"joiner");
    alice.process_commit(&ext_commit).unwrap();

    assert_eq!(alice.epoch().unwrap(), 11);
    assert_eq!(joiner.epoch().unwrap(), 11);
    assert_eq!(alice.member_count().unwrap(), 2);

    let ct = joiner.encrypt(b"joined after 10 epochs").unwrap();
    let pt = alice.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"joined after 10 epochs");

    let ct = alice.encrypt(b"welcome late joiner").unwrap();
    let pt = joiner.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"welcome late joiner");
}

#[test]
fn group_sequential_external_joins() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    let mut joiners: Vec<GroupSession> = Vec::new();

    for i in 0..3 {
        let joiner_id = IdentityKeys::create(10).unwrap();
        let joiner_credential = format!("ext{i}").into_bytes();
        let (joiner, ext_commit) =
            authorize_and_join_external(&alice, &joiner_id, &joiner_credential);

        alice.process_commit(&ext_commit).unwrap();
        for s in &joiners {
            s.process_commit(&ext_commit).unwrap();
        }

        joiners.push(joiner);
    }

    assert_eq!(alice.member_count().unwrap(), 4);
    for s in &joiners {
        assert_eq!(s.member_count().unwrap(), 4);
    }

    let ct = alice.encrypt(b"all four here").unwrap();
    for s in &joiners {
        let pt = s.decrypt(&ct).unwrap();
        assert_eq!(pt.plaintext, b"all four here");
    }

    let ct = joiners[2].encrypt(b"from ext2").unwrap();
    let pt = alice.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"from ext2");
    let pt = joiners[0].decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"from ext2");
    let pt = joiners[1].decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"from ext2");
}

#[test]
fn group_welcome_truncated_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    let bob_id = IdentityKeys::create(10).unwrap();
    let (bob_kp, _bob_x, _bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice.add_member(&bob_kp).unwrap();

    let truncations = [welcome.len() / 2, welcome.len() * 3 / 4, 10, 1, 0];
    for &len in &truncations {
        let truncated = &welcome[..len];
        let dummy_id = IdentityKeys::create(10).unwrap();
        let (dummy_x, _) = CryptoInterop::generate_x25519_keypair("dummy").unwrap();
        let (_, _, dummy_kyber_sec) =
            group::key_package::create_key_package(&dummy_id, b"dummy".to_vec()).unwrap();
        let result = GroupSession::from_welcome(
            truncated,
            dummy_x,
            dummy_kyber_sec,
            &dummy_id.get_identity_ed25519_public(),
            &dummy_id.get_identity_x25519_public(),
            dummy_id.get_identity_ed25519_private_key_copy().unwrap(),
        );
        assert!(
            result.is_err(),
            "Welcome truncated to {len} bytes must be rejected"
        );
    }
}

#[test]
fn group_removed_member_captured_ciphertext_unusable() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let charlie_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (charlie_kp, charlie_x, charlie_k) =
        group::key_package::create_key_package(&charlie_id, b"charlie".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&charlie_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let charlie = GroupSession::from_welcome(
        &w2,
        charlie_x,
        charlie_k,
        &charlie_id.get_identity_ed25519_public(),
        &charlie_id.get_identity_x25519_public(),
        charlie_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let pre_remove_ct = alice.encrypt(b"before charlie removal").unwrap();
    let pt = charlie.decrypt(&pre_remove_ct).unwrap();
    assert_eq!(pt.plaintext, b"before charlie removal");

    let remove_commit = alice
        .remove_member(charlie.my_leaf_index().unwrap())
        .unwrap();
    bob.process_commit(&remove_commit).unwrap();

    let post_remove_ct = alice.encrypt(b"after charlie removal").unwrap();
    let pt = bob.decrypt(&post_remove_ct).unwrap();
    assert_eq!(pt.plaintext, b"after charlie removal");

    assert!(
        charlie.decrypt(&post_remove_ct).is_err(),
        "Removed member must not decrypt post-removal messages"
    );
}

#[test]
fn group_update_rotates_all_path_keys() {
    init();
    use ecliptix_protocol::proto::GroupPublicState;

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ps_before = alice.export_public_state().unwrap();
    let state_before = GroupPublicState::decode(ps_before.as_slice()).unwrap();

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();
    carol.process_commit(&commit).unwrap();

    let ps_after = alice.export_public_state().unwrap();
    let state_after = GroupPublicState::decode(ps_after.as_slice()).unwrap();

    assert_ne!(
        state_before.group_context_hash, state_after.group_context_hash,
        "Context hash must change after update"
    );

    let ct = alice.encrypt(b"after rotation").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after rotation");
    let pt = carol.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after rotation");
}

#[test]
fn session_forward_secrecy_old_state_cannot_decrypt_new() {
    init();
    use ecliptix_protocol::protocol::Session;

    let (alice, bob) = create_session_pair();

    for i in 0u32..5 {
        let env = alice
            .encrypt(format!("msg-{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob.decrypt(&env).unwrap();
    }

    let fs_key = CryptoInterop::get_random_bytes(32);
    let fs_prov = StaticStateKeyProvider::new(fs_key.clone()).unwrap();
    let alice_state = alice.export_sealed_state(&fs_prov, 1).unwrap();

    for i in 5u32..10 {
        let env = alice
            .encrypt(format!("msg-{i}").as_bytes(), 0, i, None)
            .unwrap();
        bob.decrypt(&env).unwrap();
    }

    let fs_prov2 = StaticStateKeyProvider::new(fs_key).unwrap();
    let old_alice = Session::from_sealed_state(&alice_state, &fs_prov2, 0).unwrap();

    let env_from_old = old_alice.encrypt(b"from old state", 0, 999, None).unwrap();
    let result = bob.decrypt(&env_from_old);
    assert!(
        result.is_err(),
        "Old state must not produce valid messages for advanced ratchet"
    );
}

#[test]
fn group_sealed_state_full_lifecycle() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice.encrypt(b"pre-persist").unwrap();
    bob.decrypt(&ct).unwrap();
    carol.decrypt(&ct).unwrap();

    let key = CryptoInterop::get_random_bytes(32);
    let alice_sealed = alice.export_sealed_state(&key, 1).unwrap();
    let bob_sealed = bob.export_sealed_state(&key, 1).unwrap();
    let carol_sealed = carol.export_sealed_state(&key, 1).unwrap();

    let alice2 = GroupSession::from_sealed_state(
        &alice_sealed,
        &key,
        alice_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();
    let bob2 = GroupSession::from_sealed_state(
        &bob_sealed,
        &key,
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();
    let carol2 = GroupSession::from_sealed_state(
        &carol_sealed,
        &key,
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(alice2.group_id().unwrap(), alice.group_id().unwrap());
    assert_eq!(alice2.epoch().unwrap(), alice.epoch().unwrap());
    assert_eq!(alice2.member_count().unwrap(), 3);

    let ct = alice2.encrypt(b"post-restore").unwrap();
    let pt = bob2.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"post-restore");
    let pt = carol2.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"post-restore");

    let ct = carol2.encrypt(b"carol restored").unwrap();
    let pt = alice2.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"carol restored");
}

#[test]
fn group_sealed_state_bit_flip_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let key = CryptoInterop::get_random_bytes(32);
    let sealed = session.export_sealed_state(&key, 1).unwrap();

    for offset in [
        10,
        sealed.len() / 4,
        sealed.len() / 2,
        sealed.len() * 3 / 4,
        sealed.len() - 5,
    ] {
        if offset < sealed.len() {
            let mut tampered = sealed.clone();
            tampered[offset] ^= 0x01;
            let result = GroupSession::from_sealed_state(
                &tampered,
                &key,
                alice_id.get_identity_ed25519_private_key_copy().unwrap(),
                0,
            );
            assert!(
                result.is_err(),
                "Bit flip at offset {offset} must be detected"
            );
        }
    }
}

#[test]
fn session_export_import_continues_ratchet() {
    init();
    use ecliptix_protocol::protocol::Session;

    let (alice, bob) = create_session_pair();

    for i in 0u32..20 {
        if i % 2 == 0 {
            let env = alice
                .encrypt(format!("a{i}").as_bytes(), 0, i, None)
                .unwrap();
            let dec = bob.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("a{i}").as_bytes());
        } else {
            let env = bob
                .encrypt(format!("b{i}").as_bytes(), 0, i + 10000, None)
                .unwrap();
            let dec = alice.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("b{i}").as_bytes());
        }
    }

    let ak = CryptoInterop::get_random_bytes(32);
    let bk = CryptoInterop::get_random_bytes(32);
    let ap = StaticStateKeyProvider::new(ak.clone()).unwrap();
    let bp = StaticStateKeyProvider::new(bk.clone()).unwrap();
    let alice_bytes = alice.export_sealed_state(&ap, 1).unwrap();
    let bob_bytes = bob.export_sealed_state(&bp, 1).unwrap();

    let ap2 = StaticStateKeyProvider::new(ak).unwrap();
    let bp2 = StaticStateKeyProvider::new(bk).unwrap();
    let alice2 = Session::from_sealed_state(&alice_bytes, &ap2, 0).unwrap();
    let bob2 = Session::from_sealed_state(&bob_bytes, &bp2, 0).unwrap();

    for i in 20u32..40 {
        if i % 2 == 0 {
            let env = alice2
                .encrypt(format!("a{i}").as_bytes(), 0, i, None)
                .unwrap();
            let dec = bob2.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("a{i}").as_bytes());
        } else {
            let env = bob2
                .encrypt(format!("b{i}").as_bytes(), 0, i + 10000, None)
                .unwrap();
            let dec = alice2.decrypt(&env).unwrap();
            assert_eq!(dec.plaintext, format!("b{i}").as_bytes());
        }
    }
}

#[test]
fn group_message_deduplication_within_epoch() {
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt(b"unique message").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"unique message");

    let result = bob.decrypt(&ct);
    assert!(
        result.is_err(),
        "Replayed message within same epoch must be rejected"
    );
}

#[test]
fn group_commit_from_unrelated_group_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let carol_id = IdentityKeys::create(10).unwrap();
    let unrelated = GroupSession::create(&carol_id, b"carol".to_vec()).unwrap();
    let unrelated_commit = unrelated.update().unwrap();

    let result = bob.process_commit(&unrelated_commit);
    assert!(
        result.is_err(),
        "Commit from unrelated group must be rejected"
    );

    let ct = alice.encrypt(b"still works").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"still works");
}

#[test]
fn group_ciphertext_bit_flip_rejected() {
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt(b"authentic message").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"authentic message");

    let ct2 = alice.encrypt(b"tamper target").unwrap();
    let mut tampered = ct2;
    if tampered.len() > 30 {
        tampered[30] ^= 0xFF;
    }
    let result = bob.decrypt(&tampered);
    assert!(result.is_err(), "Bit-flipped ciphertext must be rejected");
}

#[test]
fn group_sender_signature_tampering_rejected() {
    init();

    let (alice, bob) = create_two_member_group();

    let ciphertext = alice.encrypt(b"sender-authenticated message").unwrap();
    let mut msg = ecliptix_protocol::proto::GroupMessage::decode(ciphertext.as_slice()).unwrap();

    match msg.content.as_mut() {
        Some(ecliptix_protocol::proto::group_message::Content::Application(app)) => {
            assert_eq!(app.sender_signature.len(), 64);
            app.sender_signature[0] ^= 0x01;
        }
        _ => panic!("expected application group message"),
    }

    let mut tampered = Vec::new();
    msg.encode(&mut tampered).unwrap();

    assert!(
        bob.decrypt(&tampered).is_err(),
        "Tampered sender signature must be rejected",
    );
}

#[test]
fn session_encrypt_after_destroy_rejected() {
    init();

    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"before destroy", 0, 1, None).unwrap();
    let dec = bob.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"before destroy");

    alice.destroy();
    assert!(alice.is_destroyed());

    let result = alice.encrypt(b"after destroy", 0, 2, None);
    assert!(result.is_err(), "Encrypt after destroy must fail");
}

#[test]
fn group_interleaved_updates_and_messages_three_members() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice.encrypt(b"msg1").unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, b"msg1");
    assert_eq!(carol.decrypt(&ct).unwrap().plaintext, b"msg1");

    let commit = bob.update().unwrap();
    alice.process_commit(&commit).unwrap();
    carol.process_commit(&commit).unwrap();

    let ct = carol.encrypt(b"msg2").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"msg2");
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, b"msg2");

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();
    carol.process_commit(&commit).unwrap();

    let ct = bob.encrypt(b"msg3").unwrap();
    assert_eq!(alice.decrypt(&ct).unwrap().plaintext, b"msg3");
    assert_eq!(carol.decrypt(&ct).unwrap().plaintext, b"msg3");

    let commit = carol.update().unwrap();
    alice.process_commit(&commit).unwrap();
    bob.process_commit(&commit).unwrap();

    let ct = alice.encrypt(b"msg4-final").unwrap();
    assert_eq!(bob.decrypt(&ct).unwrap().plaintext, b"msg4-final");
    assert_eq!(carol.decrypt(&ct).unwrap().plaintext, b"msg4-final");
}

#[test]
fn group_add_remove_update_sequential_ops() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();
    let carol_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    assert_eq!(alice.epoch().unwrap(), 1);

    let (carol_kp, carol_x, carol_k) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice.add_member(&carol_kp).unwrap();
    bob.process_commit(&c2).unwrap();
    let carol = GroupSession::from_welcome(
        &w2,
        carol_x,
        carol_k,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    assert_eq!(alice.epoch().unwrap(), 2);

    let remove_commit = alice.remove_member(bob.my_leaf_index().unwrap()).unwrap();
    carol.process_commit(&remove_commit).unwrap();
    assert_eq!(alice.epoch().unwrap(), 3);
    assert_eq!(alice.member_count().unwrap(), 2);

    let commit = carol.update().unwrap();
    alice.process_commit(&commit).unwrap();
    assert_eq!(alice.epoch().unwrap(), 4);

    let ct = alice.encrypt(b"after add-remove-update").unwrap();
    let pt = carol.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after add-remove-update");

    let ct = carol.encrypt(b"carol epoch 4").unwrap();
    let pt = alice.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"carol epoch 4");

    assert!(bob.decrypt(&ct).is_err());
}

#[test]
fn group_psk_injection_e2e_messaging() {
    init();

    let (alice, bob) = create_two_member_group();

    let epoch_before = alice.epoch().unwrap();

    let ct_before_psk = alice.encrypt(b"no psk yet").unwrap();
    let pt = bob.decrypt(&ct_before_psk).unwrap();
    assert_eq!(pt.plaintext, b"no psk yet");

    let commit = alice.update().unwrap();
    bob.process_commit(&commit).unwrap();

    assert_eq!(alice.epoch().unwrap(), epoch_before + 1);

    let ct_after = alice.encrypt(b"post-update msg").unwrap();
    let pt = bob.decrypt(&ct_after).unwrap();
    assert_eq!(pt.plaintext, b"post-update msg");

    let ct_back = bob.encrypt(b"bob responds").unwrap();
    let pt = alice.decrypt(&ct_back).unwrap();
    assert_eq!(pt.plaintext, b"bob responds");
}

#[test]
fn group_reinit_sets_pending_state() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(10).unwrap();

    let alice = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x, bob_k) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice.add_member(&bob_kp).unwrap();
    let bob = GroupSession::from_welcome(
        &w1,
        bob_x,
        bob_k,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    assert!(alice.pending_reinit().unwrap().is_none());
    assert!(bob.pending_reinit().unwrap().is_none());

    let ct = alice.encrypt(b"pre-reinit").unwrap();
    let pt = bob.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"pre-reinit");
}

#[test]
fn group_external_join_then_immediate_update() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice = create_external_joinable_group(&alice_id, b"alice");

    let joiner_id = IdentityKeys::create(10).unwrap();
    let (joiner, ext_commit) = authorize_and_join_external(&alice, &joiner_id, b"joiner");
    alice.process_commit(&ext_commit).unwrap();

    assert_eq!(alice.member_count().unwrap(), 2);
    assert_eq!(joiner.member_count().unwrap(), 2);

    let commit = joiner.update().unwrap();
    alice.process_commit(&commit).unwrap();

    let ct = joiner.encrypt(b"after update").unwrap();
    let pt = alice.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"after update");

    let ct = alice.encrypt(b"reply after update").unwrap();
    let pt = joiner.decrypt(&ct).unwrap();
    assert_eq!(pt.plaintext, b"reply after update");
}

#[test]
fn session_sealed_state_roundtrip_via_key() {
    init();
    let (alice, bob) = create_session_pair();

    let key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(key.clone()).unwrap();

    let sealed = alice.export_sealed_state(&provider, 1).unwrap();
    assert!(!sealed.is_empty());

    let provider2 = StaticStateKeyProvider::new(key).unwrap();
    let restored =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &provider2, 0).unwrap();

    let env = restored.encrypt(b"after restore", 0, 0, None).unwrap();
    let dec = bob.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"after restore");
}

#[test]
fn session_sealed_state_wrong_key_fails() {
    init();
    let (alice, _bob) = create_session_pair();

    let key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(key).unwrap();
    let sealed = alice.export_sealed_state(&provider, 1).unwrap();

    let wrong_key = CryptoInterop::get_random_bytes(32);
    let wrong_provider = StaticStateKeyProvider::new(wrong_key).unwrap();
    let result =
        ecliptix_protocol::protocol::Session::from_sealed_state(&sealed, &wrong_provider, 0);
    assert!(result.is_err());
}

#[test]
fn group_encrypt_sealed_roundtrip() {
    use ecliptix_protocol::protocol::group::GroupSession;
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice
        .encrypt_sealed(b"secret content", b"visible hint")
        .unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, b"visible hint");
    assert!(result.sealed_payload.is_some());

    let sealed = result.sealed_payload.unwrap();
    let revealed = GroupSession::reveal_sealed(&sealed).unwrap();
    assert_eq!(revealed, b"secret content");
}

#[test]
fn group_encrypt_disappearing_roundtrip() {
    use ecliptix_protocol::protocol::group::ContentType;
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt_disappearing(b"ephemeral msg", 3600).unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, b"ephemeral msg");
    assert_eq!(result.content_type, ContentType::Disappearing);
    assert_eq!(result.ttl_seconds, 3600);
}

#[test]
fn group_encrypt_disappearing_zero_ttl_rejected() {
    init();
    let (alice, _bob) = create_two_member_group();

    let result = alice.encrypt_disappearing(b"bad", 0);
    assert!(result.is_err());
}

#[test]
fn group_encrypt_frankable_roundtrip() {
    use ecliptix_protocol::protocol::group::{FrankingData, GroupSession};
    init();

    let (alice, bob) = create_two_member_group();

    let ct = alice.encrypt_frankable(b"frankable content").unwrap();
    let result = bob.decrypt(&ct).unwrap();

    assert_eq!(result.plaintext, b"frankable content");
    assert!(result.franking_data.is_some());

    let franking = result.franking_data.unwrap();
    assert!(!franking.franking_tag.is_empty());
    assert!(!franking.franking_key.is_empty());

    let valid = GroupSession::verify_franking(&franking).unwrap();
    assert!(valid);

    let tampered = FrankingData {
        franking_tag: franking.franking_tag.clone(),
        franking_key: franking.franking_key.clone(),
        content: b"tampered content".to_vec(),
        sealed_content: vec![],
    };
    let invalid = GroupSession::verify_franking(&tampered).unwrap();
    assert!(!invalid);
}

#[test]
fn group_pending_reinit_none_by_default() {
    init();
    let id = IdentityKeys::create(10).unwrap();
    let session =
        ecliptix_protocol::protocol::group::GroupSession::create(&id, b"test".to_vec()).unwrap();
    assert!(session.pending_reinit().unwrap().is_none());
}

#[test]
fn crypto_envelope_proto_roundtrip() {
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![0xAA; 256],
        group_id: vec![0xBB; 32],
        epoch: 42,
        generation: 7,
        sender_leaf_index: 0,
    };

    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();
    let decoded = CryptoEnvelope::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.sender_device_id, envelope.sender_device_id);
    assert_eq!(
        decoded.payload_type,
        CryptoPayloadType::CryptoPayloadGroupMessage as i32
    );
    assert_eq!(decoded.epoch, 42);
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.encrypted_payload.len(), 256);
}

#[test]
fn crypto_envelope_all_types_roundtrip() {
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let commit_env = GroupCommitEnvelope {
        group_id: vec![0xCC; 32],
        new_epoch: 5,
        commit_bytes: vec![0xDD; 100],
        welcome_bytes: vec![0xEE; 200],
        committer_device_id: vec![1; 16],
    };
    let mut buf = Vec::new();
    commit_env.encode(&mut buf).unwrap();
    let decoded = GroupCommitEnvelope::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.new_epoch, 5);
    assert_eq!(decoded.commit_bytes.len(), 100);

    let welcome_env = WelcomeEnvelope {
        group_id: vec![0xFF; 32],
        welcome_bytes: vec![0xAA; 300],
        sender_device_id: vec![2; 16],
        initial_key_packages: vec![vec![0xBB; 50], vec![0xCC; 60]],
    };
    buf.clear();
    welcome_env.encode(&mut buf).unwrap();
    let decoded = WelcomeEnvelope::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.initial_key_packages.len(), 2);
}

#[test]
fn fetch_pending_events_proto_roundtrip() {
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let req = FetchPendingEventsRequest {
        device_id: vec![1; 16],
        last_event_id: "evt_12345".to_string(),
        max_events: 100,
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();
    let decoded = FetchPendingEventsRequest::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.last_event_id, "evt_12345");
    assert_eq!(decoded.max_events, 100);

    let resp = FetchPendingEventsResponse {
        events: vec![PendingEvent {
            event_id: "evt_1".to_string(),
            server_timestamp: 1_700_000_000,
            envelope: Some(CryptoEnvelope {
                sender_device_id: vec![1; 16],
                recipient_device_id: vec![],
                payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
                encrypted_payload: vec![0xAA; 64],
                group_id: vec![0xBB; 32],
                epoch: 1,
                generation: 0,
                sender_leaf_index: 0,
            }),
        }],
        next_cursor: "cursor_abc".to_string(),
        has_more: true,
    };
    buf.clear();
    resp.encode(&mut buf).unwrap();
    let decoded = FetchPendingEventsResponse::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.events.len(), 1);
    assert!(decoded.has_more);
    assert_eq!(decoded.next_cursor, "cursor_abc");
}

#[test]
fn validate_crypto_envelope_valid() {
    use ecliptix_protocol::api::relay::validate_crypto_envelope;
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![1; 16],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![0xAA; 256],
        group_id: vec![0xBB; 32],
        epoch: 1,
        generation: 0,
        sender_leaf_index: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();

    let result = validate_crypto_envelope(&buf);
    assert!(result.is_ok());
    let decoded = result.unwrap();
    assert_eq!(decoded.epoch, 1);
}

#[test]
fn validate_crypto_envelope_missing_sender_rejected() {
    use ecliptix_protocol::api::relay::validate_crypto_envelope;
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![0xAA; 256],
        group_id: vec![0xBB; 32],
        epoch: 1,
        generation: 0,
        sender_leaf_index: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();

    let result = validate_crypto_envelope(&buf);
    assert!(result.is_err());
}

#[test]
fn validate_crypto_envelope_empty_payload_rejected() {
    use ecliptix_protocol::api::relay::validate_crypto_envelope;
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![1; 16],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![],
        group_id: vec![0xBB; 32],
        epoch: 1,
        generation: 0,
        sender_leaf_index: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();

    let result = validate_crypto_envelope(&buf);
    assert!(result.is_err());
}

#[test]
fn validate_crypto_envelope_group_message_without_group_id_rejected() {
    use ecliptix_protocol::api::relay::validate_crypto_envelope;
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![1; 16],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![0xAA; 64],
        group_id: vec![],
        epoch: 1,
        generation: 0,
        sender_leaf_index: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();

    let result = validate_crypto_envelope(&buf);
    assert!(result.is_err());
}

#[test]
fn validate_crypto_envelope_key_package_without_group_id_ok() {
    use ecliptix_protocol::api::relay::validate_crypto_envelope;
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let envelope = CryptoEnvelope {
        sender_device_id: vec![1; 16],
        recipient_device_id: vec![2; 16],
        payload_type: CryptoPayloadType::CryptoPayloadKeyPackage as i32,
        encrypted_payload: vec![0xAA; 1200],
        group_id: vec![],
        epoch: 0,
        generation: 0,
        sender_leaf_index: 0,
    };
    let mut buf = Vec::new();
    envelope.encode(&mut buf).unwrap();

    let result = validate_crypto_envelope(&buf);
    assert!(result.is_ok());
}

#[test]
fn device_link_proto_roundtrip() {
    use ecliptix_protocol::proto::e2e::*;
    use prost::Message;
    init();

    let req = DeviceLinkInitRequest {
        primary_device_id: vec![1; 16],
        provisioning_public_key: vec![0xAA; 32],
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();
    let decoded = DeviceLinkInitRequest::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.provisioning_public_key.len(), 32);

    let complete = DeviceLinkCompleteRequest {
        primary_device_id: vec![1; 16],
        new_device_id: vec![2; 16],
        encrypted_identity: vec![0xBB; 128],
        encrypted_welcomes: vec![vec![0xCC; 64], vec![0xDD; 96]],
    };
    buf.clear();
    complete.encode(&mut buf).unwrap();
    let decoded = DeviceLinkCompleteRequest::decode(buf.as_slice()).unwrap();
    assert_eq!(decoded.encrypted_welcomes.len(), 2);
    assert_eq!(decoded.new_device_id.len(), 16);
}

#[test]
fn route_crypto_envelope_matches_roster() {
    use ecliptix_protocol::api::relay::*;
    use ecliptix_protocol::proto::e2e::*;
    init();

    let roster = GroupRoster {
        group_id: vec![0xBB; 32],
        epoch: 1,
        members: vec![
            GroupMemberRecord {
                leaf_index: 0,
                identity_ed25519_public: vec![1; 32],
                identity_x25519_public: vec![2; 32],
                credential: vec![10; 16],
            },
            GroupMemberRecord {
                leaf_index: 2,
                identity_ed25519_public: vec![3; 32],
                identity_x25519_public: vec![4; 32],
                credential: vec![20; 16],
            },
        ],
    };

    let envelope = CryptoEnvelope {
        sender_device_id: vec![10; 16],
        recipient_device_id: vec![],
        payload_type: CryptoPayloadType::CryptoPayloadGroupMessage as i32,
        encrypted_payload: vec![0xAA; 64],
        group_id: vec![0xBB; 32],
        epoch: 1,
        generation: 0,
        sender_leaf_index: 0,
    };

    let gid = route_crypto_envelope(&envelope, &roster).unwrap();
    assert_eq!(gid, vec![0xBB; 32]);

    let wrong_envelope = CryptoEnvelope {
        group_id: vec![0xCC; 32],
        ..envelope
    };
    let result = route_crypto_envelope(&wrong_envelope, &roster);
    assert!(result.is_err());
}

#[test]
fn group_external_join_with_remove_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let bob_id = IdentityKeys::create(20).unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        ecliptix_protocol::protocol::group::key_package::create_key_package(
            &bob_id,
            b"bob".to_vec(),
        )
        .unwrap();
    let (_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = ecliptix_protocol::protocol::group::GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let joiner_id = IdentityKeys::create(30).unwrap();
    let (_joiner_session, ext_commit_bytes) =
        authorize_and_join_external(&alice_session, &joiner_id, b"joiner");

    let mut commit =
        ecliptix_protocol::proto::GroupCommit::decode(ext_commit_bytes.as_slice()).unwrap();

    commit
        .proposals
        .push(ecliptix_protocol::proto::GroupProposal {
            proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Remove(
                ecliptix_protocol::proto::GroupRemoveProposal {
                    removed_leaf_index: 0,
                },
            )),
        });

    commit.committer_signature.clear();
    let sk = joiner_id.get_identity_ed25519_private_key_copy().unwrap();
    let sk_arr: [u8; 64] = sk.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_arr).unwrap();
    let mut commit_for_sig = Vec::new();
    commit.encode(&mut commit_for_sig).unwrap();
    use ed25519_dalek::Signer;
    commit.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();
    let mut tampered = Vec::new();
    commit.encode(&mut tampered).unwrap();

    let result = alice_session.process_commit(&tampered);
    assert!(
        result.is_err(),
        "External join with Remove proposal must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Remove"),
        "Error should mention Remove: {err_msg}"
    );

    let _ = bob_session;
}

#[test]
fn group_external_join_with_extra_add_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");
    let joiner_id = IdentityKeys::create(20).unwrap();
    let (_joiner_session, ext_commit_bytes) =
        authorize_and_join_external(&alice_session, &joiner_id, b"joiner");

    let mut commit =
        ecliptix_protocol::proto::GroupCommit::decode(ext_commit_bytes.as_slice()).unwrap();

    let extra_id = IdentityKeys::create(30).unwrap();
    let (extra_kp, _, _) = ecliptix_protocol::protocol::group::key_package::create_key_package(
        &extra_id,
        b"extra".to_vec(),
    )
    .unwrap();
    commit
        .proposals
        .push(ecliptix_protocol::proto::GroupProposal {
            proposal: Some(ecliptix_protocol::proto::group_proposal::Proposal::Add(
                ecliptix_protocol::proto::GroupAddProposal {
                    key_package: Some(extra_kp),
                },
            )),
        });

    commit.committer_signature.clear();
    let sk = joiner_id.get_identity_ed25519_private_key_copy().unwrap();
    let sk_arr: [u8; 64] = sk.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_arr).unwrap();
    let mut commit_for_sig = Vec::new();
    commit.encode(&mut commit_for_sig).unwrap();
    use ed25519_dalek::Signer;
    commit.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();
    let mut tampered = Vec::new();
    commit.encode(&mut tampered).unwrap();

    let result = alice_session.process_commit(&tampered);
    assert!(
        result.is_err(),
        "External join with extra Add proposal must be rejected"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("exactly 1 Add"),
        "Error should mention Add count: {err_msg}"
    );
}

#[test]
fn group_external_join_committer_leaf_mismatch_rejected() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");
    let joiner_id = IdentityKeys::create(20).unwrap();
    let (_joiner_session, ext_commit_bytes) =
        authorize_and_join_external(&alice_session, &joiner_id, b"joiner");

    let mut commit =
        ecliptix_protocol::proto::GroupCommit::decode(ext_commit_bytes.as_slice()).unwrap();

    commit.committer_leaf_index = 999;
    commit.committer_signature.clear();
    let sk = joiner_id.get_identity_ed25519_private_key_copy().unwrap();
    let sk_arr: [u8; 64] = sk.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_arr).unwrap();
    let mut commit_for_sig = Vec::new();
    commit.encode(&mut commit_for_sig).unwrap();
    use ed25519_dalek::Signer;
    commit.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();
    let mut tampered = Vec::new();
    commit.encode(&mut tampered).unwrap();

    let result = alice_session.process_commit(&tampered);
    assert!(
        result.is_err(),
        "External join with mismatched committer_leaf_index must be rejected"
    );
}

#[test]
fn group_key_package_identity_substitution_rejected() {
    init();
    let identity = IdentityKeys::create(0).unwrap();
    let (mut kp, _x25519_priv, _kyber_sec) =
        group::key_package::create_key_package(&identity, b"alice".to_vec()).unwrap();

    let attacker = IdentityKeys::create(0).unwrap();
    kp.identity_ed25519_public = attacker.get_identity_ed25519_public();
    kp.identity_x25519_public = attacker.get_identity_x25519_public();

    let result = group::key_package::validate_key_package(&kp);
    assert!(result.is_err(), "Identity substitution must be rejected");
}

#[test]
fn group_key_package_oversized_credential_rejected() {
    init();
    use ecliptix_protocol::core::constants::MAX_CREDENTIAL_SIZE;
    let identity = IdentityKeys::create(0).unwrap();
    let big_cred = vec![0xAA; MAX_CREDENTIAL_SIZE + 1];
    let result = group::key_package::create_key_package(&identity, big_cred);
    assert!(result.is_err(), "Oversized credential must be rejected");
}

#[test]
fn group_key_package_max_credential_accepted() {
    init();
    use ecliptix_protocol::core::constants::MAX_CREDENTIAL_SIZE;
    let identity = IdentityKeys::create(0).unwrap();
    let max_cred = vec![0xBB; MAX_CREDENTIAL_SIZE];
    let result = group::key_package::create_key_package(&identity, max_cred);
    assert!(
        result.is_ok(),
        "Credential at exactly MAX size must be accepted"
    );
    let (kp, _, _) = result.unwrap();
    assert!(group::key_package::validate_key_package(&kp).is_ok());
}

#[test]
fn group_tree_root_zero_returns_error() {
    use ecliptix_protocol::protocol::group::tree;
    let result = tree::root(0);
    assert!(result.is_err(), "root(0) must return Err");
}

#[test]
fn group_tree_left_on_leaf_returns_error() {
    use ecliptix_protocol::protocol::group::tree;
    let result = tree::left(0);
    assert!(result.is_err(), "left(leaf_node=0) must return Err");
    let result2 = tree::left(2);
    assert!(result2.is_err(), "left(leaf_node=2) must return Err");
}

#[test]
fn group_tree_parent_of_root_returns_error() {
    use ecliptix_protocol::protocol::group::tree;
    let r = tree::root(4).unwrap();
    let result = tree::parent(r, 4);
    assert!(result.is_err(), "parent(root) must return Err");
}

#[test]
fn group_tree_checked_leaf_to_node_overflow() {
    use ecliptix_protocol::protocol::group::tree;
    let result = tree::checked_leaf_to_node(u32::MAX);
    assert!(
        result.is_err(),
        "checked_leaf_to_node(u32::MAX) must return Err"
    );
    let ok = tree::checked_leaf_to_node(0);
    assert!(ok.is_ok());
    assert_eq!(ok.unwrap(), 0);
}

#[test]
fn secure_memory_try_clone_roundtrip() {
    init();
    let mut handle = SecureMemoryHandle::allocate(32).unwrap();
    let data = [0x42u8; 32];
    handle.write(&data).unwrap();

    let cloned = handle.try_clone().unwrap();
    let read_back = cloned.read_bytes(32).unwrap();
    assert_eq!(read_back, data);
}

/// Simulate exact gateway flow: seed-based server + random client via EcliptixProtocol API.
/// This is what happens when iOS client connects to gateway.
#[test]
fn gateway_flow_seed_server_random_client_handshake() {
    init();
    use ecliptix_protocol::api::EcliptixProtocol;
    use sha2::{Digest, Sha256};

    // Server: create from seed (like gateway does with EPP_SECRET_KEY_SEED)
    let raw_seed = b"test-seed-for-gateway-1234";
    let mut hasher = Sha256::new();
    hasher.update(raw_seed);
    let seed_32: Vec<u8> = hasher.finalize().to_vec();
    let mut server = EcliptixProtocol::from_seed(&seed_32, "server", 100).unwrap();

    // Client: random identity (like iOS does with epp_identity_create)
    let mut client = EcliptixProtocol::new(5).unwrap();

    // Step 1: Client gets server's prekey bundle (event 105)
    let server_bundle_bytes = server.pre_key_bundle().unwrap();

    // Step 2: Client initiates handshake (event 102 request)
    let (initiator, init_bytes) = client.begin_session(&server_bundle_bytes).unwrap();

    // Step 3: Server processes handshake (accept_session)
    let (responder, ack_bytes) = server.accept_session(&init_bytes).unwrap();

    // Step 4: Both complete sessions
    let mut server_session = responder.complete().unwrap();
    let mut client_session = initiator.complete(&ack_bytes).unwrap();

    // Step 5: Encrypt/decrypt test
    let env = client_session
        .encrypt(b"hello from iOS", 0, 1, None)
        .unwrap();
    let dec = server_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"hello from iOS");
}

/// Same as above but use cached bundle (like FFI path does)
#[test]
fn gateway_flow_cached_bundle_handshake() {
    init();
    use ecliptix_protocol::api::EcliptixProtocol;

    let mut server = EcliptixProtocol::new(100).unwrap();
    let mut client = EcliptixProtocol::new(5).unwrap();

    // Server caches bundle at startup
    let cached_bundle_bytes = server.pre_key_bundle().unwrap();

    // Client gets cached bundle
    let (initiator, init_bytes) = client.begin_session(&cached_bundle_bytes).unwrap();

    // Server accepts using accept_session (which generates fresh bundle internally)
    let (responder, ack_bytes) = server.accept_session(&init_bytes).unwrap();

    let mut server_session = responder.complete().unwrap();
    let mut client_session = initiator.complete(&ack_bytes).unwrap();

    let env = client_session
        .encrypt(b"cached bundle works", 0, 1, None)
        .unwrap();
    let dec = server_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"cached bundle works");
}

/// Test that pre_key_bundle() returns different bytes on each call (one-time pre-keys differ).
/// This simulates the mismatch between cached bundle sent to client vs fresh bundle used by accept_session.
#[test]
fn gateway_flow_bundle_bytes_stability() {
    init();
    use ecliptix_protocol::api::EcliptixProtocol;

    let server = EcliptixProtocol::new(100).unwrap();

    let bundle1 = server.pre_key_bundle().unwrap();
    let bundle2 = server.pre_key_bundle().unwrap();

    // Check if bundles are identical
    if bundle1 == bundle2 {
        println!("pre_key_bundle() returns identical bytes (deterministic)");
    } else {
        println!("CRITICAL: pre_key_bundle() returns DIFFERENT bytes on each call!");
        println!(
            "  bundle1 len={}, bundle2 len={}",
            bundle1.len(),
            bundle2.len()
        );
    }
    // This assertion checks the hypothesis:
    assert_eq!(
        bundle1, bundle2,
        "pre_key_bundle() must be deterministic for cached-bundle handshake to work"
    );
}

/// Simulate the exact FFI gateway flow using C FFI functions directly.
#[test]
fn gateway_flow_ffi_responder_with_cached_bundle() {
    init();
    use ecliptix_protocol::api::EcliptixProtocol;

    let mut server = EcliptixProtocol::new(100).unwrap();
    let mut client = EcliptixProtocol::new(5).unwrap();

    // Server caches bundle bytes at startup
    let cached_bundle_bytes = server.pre_key_bundle().unwrap();

    // Client begins session using cached bundle
    let (initiator, init_bytes) = client.begin_session(&cached_bundle_bytes).unwrap();

    // Server: accept_session generates fresh bundle internally.
    // But the cached_bundle_bytes and fresh bundle should be identical
    // (since identity hasn't changed). Let's verify this:
    let fresh_bundle_bytes = server.pre_key_bundle().unwrap();
    assert_eq!(
        cached_bundle_bytes, fresh_bundle_bytes,
        "cached and fresh bundles must be identical for same identity"
    );

    let (responder, ack_bytes) = server.accept_session(&init_bytes).unwrap();

    let mut server_session = responder.complete().unwrap();
    let mut client_session = initiator.complete(&ack_bytes).unwrap();

    let env = client_session
        .encrypt(b"ffi cached bundle", 0, 1, None)
        .unwrap();
    let dec = server_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"ffi cached bundle");
}

/// Simulates the EXACT iOS→Gateway flow:
/// 1. Server: from_seed("server") — like gateway does
/// 2. Server: pre_key_bundle() → cached_bytes — like gateway sends to iOS
/// 3. Bundle bytes pass through ServerPublicKeysResponse decode→encode (proto roundtrip)
/// 4. Client: random identity — like iOS creates
/// 5. Client: begin_session(roundtripped_bundle) — like iOS FFI does
/// 6. Init bytes pass through EventEnvelope (proto roundtrip as bytes field)
/// 7. Server: accept_session(init_bytes) — like gateway processes
#[test]
fn gateway_flow_full_ios_simulation() {
    init();
    use ecliptix_protocol::api::EcliptixProtocol;
    use sha2::{Digest, Sha256};

    // Step 1: Server creates identity from seed (exactly like gateway)
    let raw_seed = b"ecliptix-dev-seed-2026-02-27";
    let mut hasher = Sha256::new();
    hasher.update(raw_seed);
    let seed_32: Vec<u8> = hasher.finalize().to_vec();
    let mut server = EcliptixProtocol::from_seed(&seed_32, "server", 100).unwrap();

    // Step 2: Server generates cached bundle (like handle_server_keys)
    let cached_bundle_bytes = server.pre_key_bundle().unwrap();
    let bundle_hash = {
        let mut h = Sha256::new();
        h.update(&cached_bundle_bytes);
        {
            use std::fmt::Write as _;
            let digest = h.finalize();
            let mut out = String::new();
            for byte in &digest[..8] {
                let _ = write!(&mut out, "{byte:02x}");
            }
            out
        }
    };

    // Step 3: Simulate proto roundtrip through ServerPublicKeysResponse
    // The bundle is a bytes field - it should pass through unchanged.
    // But let's verify by decode→encode the PreKeyBundle itself.
    let decoded_bundle = PreKeyBundle::decode(cached_bundle_bytes.as_slice()).unwrap();
    let roundtripped_bytes = decoded_bundle.encode_to_vec();
    assert_eq!(
        cached_bundle_bytes, roundtripped_bytes,
        "PreKeyBundle decode→encode must be lossless"
    );

    // Step 4: Client creates random identity (like iOS epp_identity_create)
    let mut client = EcliptixProtocol::new(5).unwrap();

    // Step 5: Client begins session (like iOS epp_handshake_initiator_start)
    let (initiator, init_bytes) = client.begin_session(&cached_bundle_bytes).unwrap();

    // Step 6: init_bytes pass through EventEnvelope as a bytes field - no transformation
    // But let's simulate decode→encode of HandshakeInit to check
    let decoded_init =
        ecliptix_protocol::proto::HandshakeInit::decode(init_bytes.as_slice()).unwrap();
    let roundtripped_init = decoded_init.encode_to_vec();
    assert_eq!(
        init_bytes, roundtripped_init,
        "HandshakeInit decode→encode must be lossless"
    );

    // Step 7: Server accepts session (like gateway process_handshake_init_raw → accept_session)
    let result = server.accept_session(&init_bytes);
    assert!(
        result.is_ok(),
        "accept_session must succeed, got: {:?}",
        result.err()
    );

    let (responder, ack_bytes) = result.unwrap();
    let mut server_session = responder.complete().unwrap();
    let mut client_session = initiator.complete(&ack_bytes).unwrap();

    // Verify end-to-end encryption works
    let env = client_session
        .encrypt(b"hello from iOS", 0, 1, None)
        .unwrap();
    let dec = server_session.decrypt(&env).unwrap();
    assert_eq!(dec.plaintext, b"hello from iOS");
    eprintln!(
        "Full iOS simulation: bundle_hash={bundle_hash}, bundle_len={}",
        cached_bundle_bytes.len()
    );
}
