// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use ecliptix_protocol::api::{EcliptixGroupSession, EcliptixProtocol};
use ecliptix_protocol::core::constants::{
    HMAC_BYTES, MAX_BUFFER_SIZE, MAX_ENVELOPE_MESSAGE_SIZE, MAX_INFLIGHT_HANDSHAKE_INITS,
    MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE, MAX_PROTOBUF_MESSAGE_SIZE,
};
use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::proto::{OneTimePreKey, PreKeyBundle};
use ecliptix_protocol::protocol::GroupSecurityPolicy;
use prost::Message;
use std::sync::Once;

static INIT_ONCE: Once = Once::new();

fn init() {
    INIT_ONCE.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });
}

const fn permissive_group_policy() -> GroupSecurityPolicy {
    GroupSecurityPolicy {
        max_messages_per_epoch: 1_000,
        max_skipped_keys_per_sender: 4,
        block_external_join: false,
        enhanced_key_schedule: false,
        mandatory_franking: false,
    }
}

fn authorize_external_join_api(
    group: &EcliptixGroupSession,
    joiner: &EcliptixProtocol,
    credential: &[u8],
) -> Vec<u8> {
    group
        .authorize_external_join(
            &joiner.identity_ed25519_public(),
            &joiner.identity_x25519_public(),
            credential,
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// EcliptixProtocol construction
// ---------------------------------------------------------------------------

#[test]
fn api_protocol_new_creates_instance() {
    init();
    let proto = EcliptixProtocol::new(5).unwrap();
    let bundle = proto.pre_key_bundle().unwrap();
    assert!(!bundle.is_empty());
}

#[test]
fn api_protocol_from_seed_is_deterministic() {
    init();
    let seed = vec![0xABu8; 32];
    let p1 = EcliptixProtocol::from_seed(&seed, "user-1", 2).unwrap();
    let p2 = EcliptixProtocol::from_seed(&seed, "user-1", 2).unwrap();

    let b1 = p1.pre_key_bundle().unwrap();
    let b2 = p2.pre_key_bundle().unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn api_protocol_different_seeds_produce_different_bundles() {
    init();
    let p1 = EcliptixProtocol::from_seed(&[0x11u8; 32], "a", 2).unwrap();
    let p2 = EcliptixProtocol::from_seed(&[0x22u8; 32], "a", 2).unwrap();

    assert_ne!(p1.pre_key_bundle().unwrap(), p2.pre_key_bundle().unwrap());
}

// ---------------------------------------------------------------------------
// P2P Session — full handshake + encrypt/decrypt via API
// ---------------------------------------------------------------------------

#[test]
fn api_p2p_full_handshake_encrypt_decrypt() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();

    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let ct = alice_session.encrypt(b"hello bob", 0, 1, None).unwrap();
    let result = bob_session.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"hello bob");
    assert!(!result.metadata.is_empty());
}

#[test]
fn api_p2p_bidirectional_messaging() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    for i in 0..10u32 {
        let msg = format!("alice-{i}");
        let ct = alice_session.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let r = bob_session.decrypt(&ct).unwrap();
        assert_eq!(r.plaintext, msg.as_bytes());

        let msg2 = format!("bob-{i}");
        let ct2 = bob_session.encrypt(msg2.as_bytes(), 1, i, None).unwrap();
        let r2 = alice_session.decrypt(&ct2).unwrap();
        assert_eq!(r2.plaintext, msg2.as_bytes());
    }
}

#[test]
fn api_p2p_with_correlation_id() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let ct = alice_session
        .encrypt(b"correlated", 0, 42, Some("req-abc-123"))
        .unwrap();
    let result = bob_session.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"correlated");
}

#[test]
fn api_p2p_session_serialize_deserialize() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let ct1 = alice_session.encrypt(b"before", 0, 1, None).unwrap();
    let _ = bob_session.decrypt(&ct1).unwrap();

    let key = vec![0x55u8; 32];
    let sealed = alice_session.serialize(&key, 1).unwrap();

    let counter =
        ecliptix_protocol::api::EcliptixSession::sealed_external_counter(&sealed).unwrap();
    assert_eq!(counter, 1);

    let (mut restored, restored_counter) =
        ecliptix_protocol::api::EcliptixSession::deserialize(&sealed, &key, 0).unwrap();
    assert_eq!(restored_counter, 1);

    let ct2 = restored.encrypt(b"after restore", 0, 2, None).unwrap();
    let result = bob_session.decrypt(&ct2).unwrap();
    assert_eq!(result.plaintext, b"after restore");
}

#[test]
fn api_p2p_session_serialize_wrong_key_fails() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let alice_session = initiator.complete(&ack_msg).unwrap();
    let _bob_session = responder.complete().unwrap();

    let key = vec![0x55u8; 32];
    let sealed = alice_session.serialize(&key, 1).unwrap();

    let wrong_key = vec![0xAAu8; 32];
    let result = ecliptix_protocol::api::EcliptixSession::deserialize(&sealed, &wrong_key, 0);
    assert!(result.is_err());
}

#[test]
fn api_p2p_begin_session_with_invalid_bundle_fails() {
    init();
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let result = alice.begin_session(b"garbage");
    assert!(result.is_err());
}

#[test]
fn api_p2p_accept_session_with_invalid_init_fails() {
    init();
    let mut bob = EcliptixProtocol::new(5).unwrap();
    let result = bob.accept_session(b"garbage");
    assert!(result.is_err());
}

#[test]
fn api_p2p_decrypt_with_oversized_envelope_fails() {
    init();
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();
    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();
    let _alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let oversized = vec![0u8; MAX_ENVELOPE_MESSAGE_SIZE + 1];
    let result = bob_session.decrypt(&oversized);
    assert!(result.is_err());
}

#[test]
fn api_p2p_encrypt_with_oversized_plaintext_fails() {
    init();
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();
    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (_responder, ack_msg) = bob.accept_session(&init_msg).unwrap();
    let mut alice_session = initiator.complete(&ack_msg).unwrap();

    let oversized = vec![0u8; MAX_BUFFER_SIZE + 1];
    let result = alice_session.encrypt(&oversized, 0, 1, None);
    assert!(result.is_err());
}

#[test]
fn api_p2p_begin_session_with_oversized_bundle_fails() {
    init();
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let oversized = vec![0u8; MAX_PROTOBUF_MESSAGE_SIZE + 1];
    let result = alice.begin_session(&oversized);
    assert!(result.is_err());
}

#[test]
fn api_p2p_begin_session_rejects_bundle_with_too_many_opks() {
    init();
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let bob = EcliptixProtocol::new(5).unwrap();
    let bundle_bytes = bob.pre_key_bundle().unwrap();
    let mut bundle = PreKeyBundle::decode(bundle_bytes.as_slice()).unwrap();

    let mut opks = Vec::new();
    for i in 0..(MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE + 1) {
        opks.push(OneTimePreKey {
            one_time_pre_key_id: i as u32 + 1,
            public_key: bundle.signed_pre_key_public.clone(),
        });
    }
    bundle.one_time_pre_keys = opks;

    let mut encoded = Vec::new();
    bundle.encode(&mut encoded).unwrap();
    let result = alice.begin_session(&encoded);
    assert!(result.is_err());
}

#[test]
fn identity_reserve_handshake_init_fingerprint_respects_inflight_limit() {
    init();
    let id = IdentityKeys::create(1).unwrap();
    for i in 0..MAX_INFLIGHT_HANDSHAKE_INITS {
        let mut fp = vec![0u8; HMAC_BYTES];
        fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let accepted = id.reserve_handshake_init_fingerprint(&fp).unwrap();
        assert!(accepted);
    }
    let mut overflow_fp = vec![0u8; HMAC_BYTES];
    overflow_fp[..8].copy_from_slice(&(MAX_INFLIGHT_HANDSHAKE_INITS as u64).to_le_bytes());
    let result = id.reserve_handshake_init_fingerprint(&overflow_fp);
    assert!(result.is_err());
}

#[test]
fn identity_reserve_handshake_init_duplicate_returns_false() {
    init();
    let id = IdentityKeys::create(1).unwrap();
    let fp = vec![0xAB; HMAC_BYTES];
    let first = id.reserve_handshake_init_fingerprint(&fp).unwrap();
    let second = id.reserve_handshake_init_fingerprint(&fp).unwrap();
    assert!(first);
    assert!(!second);
}

#[test]
fn identity_reserve_handshake_init_release_restores_capacity() {
    init();
    let id = IdentityKeys::create(1).unwrap();
    for i in 0..MAX_INFLIGHT_HANDSHAKE_INITS {
        let mut fp = vec![0u8; HMAC_BYTES];
        fp[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let accepted = id.reserve_handshake_init_fingerprint(&fp).unwrap();
        assert!(accepted);
    }

    let mut released_fp = vec![0u8; HMAC_BYTES];
    released_fp[..8].copy_from_slice(&0u64.to_le_bytes());
    id.release_handshake_init_fingerprint(&released_fp);

    let mut replacement_fp = vec![0u8; HMAC_BYTES];
    replacement_fp[..8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    let accepted = id
        .reserve_handshake_init_fingerprint(&replacement_fp)
        .unwrap();
    assert!(accepted);
}

#[test]
fn api_p2p_decrypt_wrong_session_fails() {
    init();

    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();
    let mut charlie = EcliptixProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let charlie_bundle = charlie.pre_key_bundle().unwrap();

    let (init_ab, init_msg_ab) = alice.begin_session(&bob_bundle).unwrap();
    let (resp_ab, ack_ab) = bob.accept_session(&init_msg_ab).unwrap();

    let (init_ac, init_msg_ac) = alice.begin_session(&charlie_bundle).unwrap();
    let (resp_ac, ack_ac) = charlie.accept_session(&init_msg_ac).unwrap();

    let mut alice_bob = init_ab.complete(&ack_ab).unwrap();
    let mut _bob_session = resp_ab.complete().unwrap();
    let _alice_charlie = init_ac.complete(&ack_ac).unwrap();
    let mut charlie_session = resp_ac.complete().unwrap();

    let ct = alice_bob.encrypt(b"for bob only", 0, 1, None).unwrap();
    let result = charlie_session.decrypt(&ct);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Group Session via API
// ---------------------------------------------------------------------------

#[test]
fn api_group_two_member_lifecycle() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    assert_eq!(alice_group.epoch().unwrap(), 0);
    assert_eq!(alice_group.member_count().unwrap(), 1);

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    assert!(!commit.is_empty());
    assert!(!welcome.is_empty());
    assert_eq!(alice_group.epoch().unwrap(), 1);
    assert_eq!(alice_group.member_count().unwrap(), 2);

    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();
    assert_eq!(bob_group.epoch().unwrap(), 1);
    assert_eq!(bob_group.member_count().unwrap(), 2);

    let ct = alice_group.encrypt(b"hello group").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"hello group");

    let ct2 = bob_group.encrypt(b"bob says hi").unwrap();
    let result2 = alice_group.decrypt(&ct2).unwrap();
    assert_eq!(result2.plaintext, b"bob says hi");
}

#[test]
fn api_group_update_advances_epoch() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    assert_eq!(session.epoch().unwrap(), 0);

    let commit = session.update().unwrap();
    assert!(!commit.is_empty());
    assert_eq!(session.epoch().unwrap(), 1);
}

#[test]
fn api_group_remove_member() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (_commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();
    let bob_leaf = bob_group.my_leaf_index().unwrap();

    let remove_commit = alice_group.remove_member(bob_leaf).unwrap();
    assert!(!remove_commit.is_empty());
    assert_eq!(alice_group.member_count().unwrap(), 1);

    let post_remove_ct = alice_group.encrypt(b"after remove").unwrap();
    let result = bob_group.decrypt(&post_remove_ct);
    assert!(result.is_err());
}

#[test]
fn api_group_external_join() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();

    let public_state = alice_group.export_public_state().unwrap();
    assert!(!public_state.is_empty());

    let charlie_proto = EcliptixProtocol::new(5).unwrap();
    let authorization = authorize_external_join_api(&alice_group, &charlie_proto, b"charlie");
    let (charlie_group, ext_commit) = charlie_proto
        .join_group_external(&public_state, &authorization, b"charlie".to_vec())
        .unwrap();
    assert!(!ext_commit.is_empty());

    alice_group.process_commit(&ext_commit).unwrap();

    assert_eq!(alice_group.member_count().unwrap(), 2);
    assert_eq!(charlie_group.member_count().unwrap(), 2);

    let ct = alice_group.encrypt(b"welcome charlie").unwrap();
    let r = charlie_group.decrypt(&ct).unwrap();
    assert_eq!(r.plaintext, b"welcome charlie");
}

#[test]
fn api_group_serialize_deserialize() {
    init();

    let proto = EcliptixProtocol::new(5).unwrap();
    let ed_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let _ct = session.encrypt(b"test").unwrap();

    let key = vec![0x99u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let counter = EcliptixGroupSession::sealed_external_counter(&sealed).unwrap();
    assert_eq!(counter, 1);

    let (restored, restored_counter) =
        EcliptixGroupSession::deserialize(&sealed, &key, ed_secret, 0).unwrap();
    assert_eq!(restored_counter, 1);
    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());
    assert_eq!(session.epoch().unwrap(), restored.epoch().unwrap());
    assert_eq!(
        session.my_leaf_index().unwrap(),
        restored.my_leaf_index().unwrap()
    );
}

#[test]
fn api_group_serialize_wrong_key_fails() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let ed_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let key = vec![0x99u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let wrong_key = vec![0xFFu8; 32];
    let result = EcliptixGroupSession::deserialize(&sealed, &wrong_key, ed_secret, 0);
    assert!(result.is_err());
}

#[test]
fn api_group_member_leaf_indices() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let _bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let indices = alice_group.member_leaf_indices().unwrap();
    assert_eq!(indices.len(), 2);
    assert!(indices.contains(&0));
}

#[test]
fn api_group_encrypt_sealed_roundtrip() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group
        .encrypt_sealed(b"secret content", b"hint")
        .unwrap();
    let result = bob_group.decrypt(&ct).unwrap();

    if let Some(sealed) = &result.sealed_payload {
        let revealed = EcliptixGroupSession::reveal_sealed(sealed).unwrap();
        assert_eq!(revealed, b"secret content");
    } else {
        assert_eq!(result.plaintext, b"secret content");
    }
}

#[test]
fn api_group_encrypt_frankable_roundtrip() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group.encrypt_frankable(b"frankable msg").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"frankable msg");

    if let Some(franking) = &result.franking_data {
        let valid = EcliptixGroupSession::verify_franking(franking).unwrap();
        assert!(valid);
    }
}

#[test]
fn api_group_encrypt_disappearing_roundtrip() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();

    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group
        .encrypt_disappearing(b"ephemeral", 3600)
        .unwrap();
    let result = bob_group.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"ephemeral");
}

#[test]
fn api_group_process_commit_invalid_data_fails() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.process_commit(b"not a valid commit");
    assert!(result.is_err());
}

#[test]
fn api_group_decrypt_invalid_data_fails() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.decrypt(b"not a valid message");
    assert!(result.is_err());
}

#[test]
fn api_group_add_member_invalid_key_package_fails() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.add_member(b"invalid key package");
    assert!(result.is_err());
}

#[test]
fn api_group_join_external_invalid_state_fails() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let result = proto.join_group_external(b"garbage", b"invalid-auth", b"cred".to_vec());
    assert!(result.is_err());
}

#[test]
fn api_group_pending_reinit_none_by_default() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let reinit = session.pending_reinit().unwrap();
    assert!(reinit.is_none());
}

#[test]
fn api_group_id_stable_across_epochs() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let gid1 = session.group_id().unwrap();
    let _ = session.update().unwrap();
    let gid2 = session.group_id().unwrap();
    let _ = session.update().unwrap();
    let gid3 = session.group_id().unwrap();

    assert_eq!(gid1, gid2);
    assert_eq!(gid2, gid3);
}

// ---------------------------------------------------------------------------
// Message Edit/Delete
// ---------------------------------------------------------------------------

#[test]
fn api_compute_message_id_deterministic() {
    let id1 = EcliptixGroupSession::compute_message_id(b"group-1", 0, 0, 0);
    let id2 = EcliptixGroupSession::compute_message_id(b"group-1", 0, 0, 0);
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 32);

    let id3 = EcliptixGroupSession::compute_message_id(b"group-1", 0, 0, 1);
    assert_ne!(id1, id3);

    let id4 = EcliptixGroupSession::compute_message_id(b"group-2", 0, 0, 0);
    assert_ne!(id1, id4);
}

#[test]
fn api_group_edit_roundtrip() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct_original = alice_group.encrypt(b"original message").unwrap();
    let original_result = bob_group.decrypt(&ct_original).unwrap();
    assert!(!original_result.message_id.is_empty());
    assert!(original_result.referenced_message_id.is_empty());

    let edit_ct = alice_group
        .encrypt_edit(b"edited message", &original_result.message_id)
        .unwrap();
    let edit_result = bob_group.decrypt(&edit_ct).unwrap();

    assert_eq!(edit_result.plaintext, b"edited message");
    assert_eq!(
        edit_result.content_type,
        ecliptix_protocol::protocol::group::ContentType::Edit
    );
    assert_eq!(
        edit_result.referenced_message_id,
        original_result.message_id
    );
    assert!(!edit_result.message_id.is_empty());
    assert_ne!(edit_result.message_id, original_result.message_id);
}

#[test]
fn api_group_delete_roundtrip() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct_original = alice_group.encrypt(b"to be deleted").unwrap();
    let original_result = bob_group.decrypt(&ct_original).unwrap();

    let delete_ct = alice_group
        .encrypt_delete(&original_result.message_id)
        .unwrap();
    let delete_result = bob_group.decrypt(&delete_ct).unwrap();

    assert!(delete_result.plaintext.is_empty());
    assert_eq!(
        delete_result.content_type,
        ecliptix_protocol::protocol::group::ContentType::Delete
    );
    assert_eq!(
        delete_result.referenced_message_id,
        original_result.message_id
    );
}

#[test]
fn api_group_edit_requires_valid_message_id() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.encrypt_edit(b"new content", b"too-short");
    assert!(result.is_err());

    let result = session.encrypt_edit(b"new content", b"");
    assert!(result.is_err());
}

#[test]
fn api_group_delete_requires_valid_message_id() {
    init();

    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.encrypt_delete(b"too-short");
    assert!(result.is_err());

    let result = session.encrypt_delete(b"");
    assert!(result.is_err());
}

#[test]
fn api_group_normal_message_has_empty_referenced_id() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group.encrypt(b"normal msg").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();

    assert!(result.referenced_message_id.is_empty());
    assert_eq!(
        result.content_type,
        ecliptix_protocol::protocol::group::ContentType::Normal
    );
}

#[test]
fn api_group_decrypt_always_returns_message_id() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let mut seen_ids = std::collections::HashSet::new();
    for _ in 0..5 {
        let ct = alice_group.encrypt(b"test").unwrap();
        let result = bob_group.decrypt(&ct).unwrap();
        assert_eq!(result.message_id.len(), 32);
        assert!(seen_ids.insert(result.message_id.clone()));
    }
}

#[test]
fn api_group_message_id_matches_compute() {
    init();

    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group.encrypt(b"test").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();

    let computed = EcliptixGroupSession::compute_message_id(
        &bob_group.group_id().unwrap(),
        bob_group.epoch().unwrap(),
        result.sender_leaf_index,
        result.generation,
    );
    assert_eq!(result.message_id, computed);
}

// ---------------------------------------------------------------------------
// Shield Mode tests
// ---------------------------------------------------------------------------

#[test]
fn shield_mode_creation() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_shielded_group(b"cred".to_vec()).unwrap();
    assert!(session.is_shielded().unwrap());
    let policy = session.security_policy().unwrap();
    assert!(policy.enhanced_key_schedule);
    assert!(policy.mandatory_franking);
    assert!(policy.block_external_join);
    assert_eq!(policy.max_messages_per_epoch, 1_000);
    assert_eq!(policy.max_skipped_keys_per_sender, 4);
}

#[test]
fn shield_blocks_external_join() {
    init();
    let creator = EcliptixProtocol::new(0).unwrap();
    let session = creator.create_shielded_group(b"cred".to_vec()).unwrap();
    let public_state = session.export_public_state().unwrap();

    let joiner = EcliptixProtocol::new(0).unwrap();
    let result = joiner.join_group_external(&public_state, b"invalid-auth", b"join".to_vec());
    assert!(
        result.is_err(),
        "External join should be blocked by shield policy"
    );
}

#[test]
fn shield_forces_rotation() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let mut policy = GroupSecurityPolicy::shield();
    policy.max_messages_per_epoch = 10;
    policy.block_external_join = false;
    let session = proto
        .create_group_with_policy(b"cred".to_vec(), policy)
        .unwrap();

    for _ in 0..10 {
        session.encrypt(b"msg").unwrap();
    }
    let result = session.encrypt(b"msg");
    assert!(result.is_err(), "Should fail after max_messages_per_epoch");
}

#[test]
fn shield_after_rotation_can_continue() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let mut policy = GroupSecurityPolicy::shield();
    policy.max_messages_per_epoch = 10;
    policy.block_external_join = false;
    let session = proto
        .create_group_with_policy(b"cred".to_vec(), policy)
        .unwrap();

    for _ in 0..10 {
        session.encrypt(b"msg").unwrap();
    }
    assert!(session.encrypt(b"msg").is_err());

    let _commit = session.update().unwrap();
    session.encrypt(b"after rotation").unwrap();
}

#[test]
fn shield_enhanced_keys_differ() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let default_session = proto.create_group(b"cred".to_vec()).unwrap();
    let shield_session = proto.create_shielded_group(b"cred".to_vec()).unwrap();

    let ct_default = default_session.encrypt(b"test").unwrap();
    let ct_shield = shield_session.encrypt(b"test").unwrap();
    assert_ne!(ct_default, ct_shield);
}

#[test]
fn shield_policy_bound_in_context_hash() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();

    let default_session = proto.create_group(b"cred".to_vec()).unwrap();
    let shield_session = proto.create_shielded_group(b"cred".to_vec()).unwrap();

    let default_policy = default_session.security_policy().unwrap();
    let shield_policy = shield_session.security_policy().unwrap();

    assert_eq!(default_policy.policy_bytes(), shield_policy.policy_bytes());
}

#[test]
fn shield_policy_survives_serialization() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_shielded_group(b"cred".to_vec()).unwrap();
    let ed25519_sk = proto.get_identity_ed25519_private_key_copy().unwrap();

    let key = vec![0xABu8; 32];
    let data = session.serialize(&key, 42).unwrap();
    let (restored, restored_counter) =
        EcliptixGroupSession::deserialize(&data, &key, ed25519_sk, 0).unwrap();
    assert_eq!(restored_counter, 42);

    assert!(restored.is_shielded().unwrap());
    let policy = restored.security_policy().unwrap();
    assert!(policy.enhanced_key_schedule);
    assert!(policy.mandatory_franking);
    assert!(policy.block_external_join);
    assert_eq!(policy.max_messages_per_epoch, 1_000);
}

#[test]
fn shield_reduced_skip_window() {
    init();
    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let mut policy = GroupSecurityPolicy::shield();
    policy.max_skipped_keys_per_sender = 2;
    policy.block_external_join = false;

    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), policy)
        .unwrap();

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    for _ in 0..5 {
        alice_group.encrypt(b"skip me").unwrap();
    }
    let last_ct = alice_group.encrypt(b"catch this").unwrap();
    let result = bob_group.decrypt(&last_ct);
    assert!(
        result.is_err(),
        "Should fail: too many skipped generations for shield policy"
    );
}

#[test]
fn shield_mandatory_franking() {
    init();
    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto
        .create_shielded_group(b"alice".to_vec())
        .unwrap();

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group.encrypt(b"hello shield").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();
    assert_eq!(result.plaintext, b"hello shield");
    assert!(
        result.franking_data.is_some(),
        "Shield mode must always include franking data"
    );
}

#[test]
fn default_policy_is_shielded() {
    init();
    let proto = EcliptixProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();
    assert!(session.is_shielded().unwrap());

    let policy = session.security_policy().unwrap();
    assert_eq!(policy.max_messages_per_epoch, 1_000);
    assert!(policy.enhanced_key_schedule);
    assert!(policy.mandatory_franking);
    assert!(policy.block_external_join);
}

#[test]
fn shield_welcome_carries_policy() {
    init();
    let alice_proto = EcliptixProtocol::new(5).unwrap();
    let bob_proto = EcliptixProtocol::new(5).unwrap();

    let alice_group = alice_proto
        .create_shielded_group(b"alice".to_vec())
        .unwrap();

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    assert!(bob_group.is_shielded().unwrap());
    let bob_policy = bob_group.security_policy().unwrap();
    assert!(bob_policy.enhanced_key_schedule);
    assert!(bob_policy.mandatory_franking);
    assert!(bob_policy.block_external_join);
    assert_eq!(bob_policy.max_messages_per_epoch, 1_000);
}
