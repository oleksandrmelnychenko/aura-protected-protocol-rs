// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use aura_protected_protocol::api::{
    AuraGroupSession, AuraProtocol, AuraSession, AuraVoipSession, SealedStateCounterTracker,
    SealedStateSlot,
};
use aura_protected_protocol::core::constants::{
    HMAC_BYTES, MAX_BUFFER_SIZE, MAX_ENVELOPE_MESSAGE_SIZE, MAX_GROUP_MESSAGE_SIZE,
    MAX_INFLIGHT_HANDSHAKE_INITS, MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE, MAX_PROTOBUF_MESSAGE_SIZE,
};
use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::{
    GroupCommit, GroupExternalJoinAuthorization, OneTimePreKey, PreKeyBundle,
};
use aura_protected_protocol::protocol::GroupSecurityPolicy;
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
        enhanced_key_schedule: true,
        mandatory_franking: false,
    }
}

fn authorize_external_join_api(
    group: &AuraGroupSession,
    joiner: &AuraProtocol,
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

fn resign_external_join_authorization_for_api_test(
    authorization: &mut GroupExternalJoinAuthorization,
    signer_secret: &[u8],
) -> Vec<u8> {
    authorization.authorizer_signature.clear();

    let mut auth_for_sig = Vec::new();
    authorization.encode(&mut auth_for_sig).unwrap();

    let signer_secret: [u8; 64] = signer_secret.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&signer_secret).unwrap();
    use ed25519_dalek::Signer;
    authorization.authorizer_signature = signing_key.sign(&auth_for_sig).to_bytes().to_vec();

    let mut signed = Vec::new();
    authorization.encode(&mut signed).unwrap();
    signed
}

fn resign_group_commit_for_api_test(commit: &mut GroupCommit, signer_secret: &[u8]) -> Vec<u8> {
    commit.committer_signature.clear();

    let mut commit_for_sig = Vec::new();
    commit.encode(&mut commit_for_sig).unwrap();

    let signer_secret: [u8; 64] = signer_secret.try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&signer_secret).unwrap();
    use ed25519_dalek::Signer;
    commit.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();

    let mut signed = Vec::new();
    commit.encode(&mut signed).unwrap();
    signed
}

fn extract_voip_peer_material(bundle_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let bundle = PreKeyBundle::decode(bundle_bytes).unwrap();
    (bundle.kyber_public, bundle.identity_ed25519_public)
}

fn create_api_voip_session_pair() -> (
    AuraProtocol,
    AuraProtocol,
    AuraVoipSession,
    AuraVoipSession,
    Vec<u8>,
    Vec<u8>,
) {
    let alice = AuraProtocol::new(5).unwrap();
    let bob = AuraProtocol::new(5).unwrap();
    let (alice_kyber, alice_ed25519) = extract_voip_peer_material(&alice.pre_key_bundle().unwrap());
    let (bob_kyber, bob_ed25519) = extract_voip_peer_material(&bob.pre_key_bundle().unwrap());
    let (initiator, call_init) = alice.initiate_call(&bob_kyber, false, 512, 60).unwrap();
    let (bob_session, call_accept) = bob.accept_call(&call_init, &alice_kyber).unwrap();
    let alice_session = alice.complete_call(initiator, &call_accept).unwrap();
    (
        alice,
        bob,
        alice_session,
        bob_session,
        alice_ed25519,
        bob_ed25519,
    )
}

// ---------------------------------------------------------------------------
// AuraProtocol construction
// ---------------------------------------------------------------------------

#[test]
fn api_protocol_new_creates_instance() {
    init();
    let proto = AuraProtocol::new(5).unwrap();
    let bundle = proto.pre_key_bundle().unwrap();
    assert!(!bundle.is_empty());
}

#[test]
fn api_protocol_from_seed_is_deterministic() {
    init();
    let seed = vec![0xABu8; 32];
    let p1 = AuraProtocol::from_seed(&seed, "user-1", 2).unwrap();
    let p2 = AuraProtocol::from_seed(&seed, "user-1", 2).unwrap();

    let b1 = p1.pre_key_bundle().unwrap();
    let b2 = p2.pre_key_bundle().unwrap();
    assert_eq!(b1, b2);
}

#[test]
fn api_protocol_different_seeds_produce_different_bundles() {
    init();
    let p1 = AuraProtocol::from_seed(&[0x11u8; 32], "a", 2).unwrap();
    let p2 = AuraProtocol::from_seed(&[0x22u8; 32], "a", 2).unwrap();

    assert_ne!(p1.pre_key_bundle().unwrap(), p2.pre_key_bundle().unwrap());
}

// ---------------------------------------------------------------------------
// P2P Session — full handshake + encrypt/decrypt via API
// ---------------------------------------------------------------------------

#[test]
fn api_p2p_full_handshake_encrypt_decrypt() {
    init();

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

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

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

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

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

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

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

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
        aura_protected_protocol::api::AuraSession::sealed_external_counter(&sealed).unwrap();
    assert_eq!(counter, 1);

    let (mut restored, restored_counter) =
        aura_protected_protocol::api::AuraSession::deserialize(&sealed, &key, 0).unwrap();
    assert_eq!(restored_counter, 1);

    let ct2 = restored.encrypt(b"after restore", 0, 2, None).unwrap();
    let result = bob_session.decrypt(&ct2).unwrap();
    assert_eq!(result.plaintext, b"after restore");
}

#[test]
fn api_sealed_state_counter_tracker_serialization_roundtrip() {
    let mut tracker = SealedStateCounterTracker::new();
    assert_eq!(tracker.next_export_counter().unwrap(), 1);
    tracker.note_successful_export(1).unwrap();
    tracker.note_successful_restore(1).unwrap();
    assert_eq!(tracker.max_restored_counter(), 1);
    assert_eq!(tracker.latest_issued_counter(), 1);

    let encoded = tracker.serialize();
    let decoded = SealedStateCounterTracker::deserialize(&encoded).unwrap();
    assert_eq!(decoded, tracker);
}

#[test]
fn api_sealed_state_slot_serialization_roundtrip() {
    let mut slot = SealedStateSlot::new();
    slot.note_successful_export(1, vec![1, 2, 3, 4]).unwrap();
    slot.note_successful_restore(1).unwrap();

    let encoded = slot.serialize().unwrap();
    let decoded = SealedStateSlot::deserialize(&encoded).unwrap();
    assert_eq!(decoded, slot);
    assert_eq!(decoded.max_restored_counter(), 1);
    assert_eq!(decoded.latest_issued_counter(), 1);
    assert_eq!(decoded.sealed_state(), &[1, 2, 3, 4]);
}

#[test]
fn api_p2p_session_counter_tracker_restores_latest_and_rejects_rollback() {
    init();

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let ct1 = alice_session.encrypt(b"before", 0, 1, None).unwrap();
    let _ = bob_session.decrypt(&ct1).unwrap();

    let key = vec![0x44u8; 32];
    let mut tracker = SealedStateCounterTracker::new();
    let sealed1 = alice_session
        .serialize_with_counter_tracker(&key, &mut tracker)
        .unwrap();
    let tracker_bytes = tracker.serialize();

    let mut restart_tracker = SealedStateCounterTracker::deserialize(&tracker_bytes).unwrap();
    let mut restored =
        AuraSession::deserialize_with_counter_tracker(&sealed1, &key, &mut restart_tracker)
            .unwrap();
    assert_eq!(restart_tracker.max_restored_counter(), 1);
    assert_eq!(restart_tracker.latest_issued_counter(), 1);

    let ct2 = restored
        .encrypt(b"after managed restore", 0, 2, None)
        .unwrap();
    let result = bob_session.decrypt(&ct2).unwrap();
    assert_eq!(result.plaintext, b"after managed restore");

    let sealed2 = restored
        .serialize_with_counter_tracker(&key, &mut restart_tracker)
        .unwrap();
    assert_eq!(restart_tracker.max_restored_counter(), 1);
    assert_eq!(restart_tracker.latest_issued_counter(), 2);

    let tracker_after_export = restart_tracker.serialize();
    let mut next_restart = SealedStateCounterTracker::deserialize(&tracker_after_export).unwrap();
    assert!(
        AuraSession::deserialize_with_counter_tracker(&sealed1, &key, &mut next_restart).is_err()
    );
    let mut latest =
        AuraSession::deserialize_with_counter_tracker(&sealed2, &key, &mut next_restart).unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);

    let ct3 = latest.encrypt(b"latest only", 0, 3, None).unwrap();
    let result = bob_session.decrypt(&ct3).unwrap();
    assert_eq!(result.plaintext, b"latest only");
}

#[test]
fn api_p2p_session_slot_roundtrip() {
    init();

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let mut alice_session = initiator.complete(&ack_msg).unwrap();
    let mut bob_session = responder.complete().unwrap();

    let ct1 = alice_session.encrypt(b"before", 0, 1, None).unwrap();
    let _ = bob_session.decrypt(&ct1).unwrap();

    let key = vec![0x24u8; 32];
    let mut slot = SealedStateSlot::new();
    alice_session.export_to_slot(&key, &mut slot).unwrap();
    let slot_bytes = slot.serialize().unwrap();

    let mut restart_slot = SealedStateSlot::deserialize(&slot_bytes).unwrap();
    let mut restored = AuraSession::restore_from_slot(&mut restart_slot, &key).unwrap();
    assert_eq!(restart_slot.max_restored_counter(), 1);
    assert_eq!(restart_slot.latest_issued_counter(), 1);

    let ct2 = restored.encrypt(b"after slot restore", 0, 2, None).unwrap();
    let result = bob_session.decrypt(&ct2).unwrap();
    assert_eq!(result.plaintext, b"after slot restore");

    restored.export_to_slot(&key, &mut restart_slot).unwrap();
    let next_slot_bytes = restart_slot.serialize().unwrap();
    let mut next_restart = SealedStateSlot::deserialize(&next_slot_bytes).unwrap();
    let mut latest = AuraSession::restore_from_slot(&mut next_restart, &key).unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);

    let ct3 = latest.encrypt(b"latest slot only", 0, 3, None).unwrap();
    let result = bob_session.decrypt(&ct3).unwrap();
    assert_eq!(result.plaintext, b"latest slot only");
}

#[test]
fn api_p2p_session_serialize_wrong_key_fails() {
    init();

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();

    let alice_session = initiator.complete(&ack_msg).unwrap();
    let _bob_session = responder.complete().unwrap();

    let key = vec![0x55u8; 32];
    let sealed = alice_session.serialize(&key, 1).unwrap();

    let wrong_key = vec![0xAAu8; 32];
    let result = aura_protected_protocol::api::AuraSession::deserialize(&sealed, &wrong_key, 0);
    assert!(result.is_err());
}

#[test]
fn api_p2p_begin_session_with_invalid_bundle_fails() {
    init();
    let mut alice = AuraProtocol::new(5).unwrap();
    let result = alice.begin_session(b"garbage");
    assert!(result.is_err());
}

#[test]
fn api_p2p_accept_session_with_invalid_init_fails() {
    init();
    let mut bob = AuraProtocol::new(5).unwrap();
    let result = bob.accept_session(b"garbage");
    assert!(result.is_err());
}

#[test]
fn api_p2p_decrypt_with_oversized_envelope_fails() {
    init();
    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();
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
    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();
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
    let mut alice = AuraProtocol::new(5).unwrap();
    let oversized = vec![0u8; MAX_PROTOBUF_MESSAGE_SIZE + 1];
    let result = alice.begin_session(&oversized);
    assert!(result.is_err());
}

#[test]
fn api_p2p_begin_session_rejects_bundle_with_too_many_opks() {
    init();
    let mut alice = AuraProtocol::new(5).unwrap();
    let bob = AuraProtocol::new(5).unwrap();
    let bundle_bytes = bob.pre_key_bundle().unwrap();
    let mut bundle = PreKeyBundle::decode(bundle_bytes.as_slice()).unwrap();

    let mut opks = Vec::new();
    for i in 0..=MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE {
        opks.push(OneTimePreKey {
            one_time_pre_key_id: u32::try_from(i).unwrap() + 1,
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

    let mut alice = AuraProtocol::new(5).unwrap();
    let mut bob = AuraProtocol::new(5).unwrap();
    let mut charlie = AuraProtocol::new(5).unwrap();

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

#[test]
fn api_voip_signed_recording_consent_and_metadata_wrappers() {
    init();

    let (alice, bob, alice_session, bob_session, alice_ed25519, bob_ed25519) =
        create_api_voip_session_pair();

    alice_session
        .set_screen_share_meta(1920, 1080, 30, Some("H264"))
        .unwrap();
    assert_eq!(
        alice_session.get_screen_share_meta().unwrap(),
        Some((1920, 1080, 30, Some("H264".to_string())))
    );

    let encrypted = alice_session
        .encrypt_frame(111, alice_session.ssrc(), 160, 1, b"opus-frame")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"opus-frame");

    let alice_stats = alice_session.get_call_statistics().unwrap();
    assert_eq!(alice_stats.frames_sent, 1);
    let bob_stats = bob_session.get_call_statistics().unwrap();
    assert_eq!(bob_stats.frames_received, 1);

    let alice_consent = alice
        .build_call_recording_consent_message(&alice_session, 1, 1_700_000_000)
        .unwrap();
    assert_eq!(alice_session.get_local_recording_consent().unwrap(), 1);
    bob.process_call_recording_consent_message(&bob_session, &alice_consent, &alice_ed25519)
        .unwrap();
    assert_eq!(bob_session.get_remote_recording_consent().unwrap(), 1);
    assert!(!bob_session.both_consented_to_recording().unwrap());

    let bob_consent = bob
        .build_call_recording_consent_message(&bob_session, 1, 1_700_000_001)
        .unwrap();
    assert_eq!(bob_session.get_local_recording_consent().unwrap(), 1);
    alice
        .process_call_recording_consent_message(&alice_session, &bob_consent, &bob_ed25519)
        .unwrap();
    assert_eq!(alice_session.get_remote_recording_consent().unwrap(), 1);
    assert!(alice_session.both_consented_to_recording().unwrap());
    assert!(bob_session.both_consented_to_recording().unwrap());

    alice_session.clear_screen_share_meta().unwrap();
    assert_eq!(alice_session.get_screen_share_meta().unwrap(), None);
}

#[test]
fn api_voip_counter_tracker_restores_latest_and_rejects_rollback() {
    init();

    let (alice, _bob, alice_session, bob_session, _alice_ed25519, _bob_ed25519) =
        create_api_voip_session_pair();

    let state_key = vec![0x61u8; 32];
    let mut tracker = SealedStateCounterTracker::new();
    let sealed1 = alice_session
        .export_sealed_state_with_counter_tracker(&state_key, &mut tracker)
        .unwrap();
    let tracker_bytes = tracker.serialize();

    let mut restart_tracker = SealedStateCounterTracker::deserialize(&tracker_bytes).unwrap();
    let restored = alice
        .import_call_state_with_counter_tracker(&sealed1, &state_key, &mut restart_tracker)
        .unwrap();
    assert_eq!(restart_tracker.max_restored_counter(), 1);
    assert_eq!(restart_tracker.latest_issued_counter(), 1);

    let encrypted = restored
        .encrypt_frame(111, restored.ssrc(), 160, 1, b"managed-voip")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"managed-voip");

    let sealed2 = restored
        .export_sealed_state_with_counter_tracker(&state_key, &mut restart_tracker)
        .unwrap();
    let tracker_after_export = restart_tracker.serialize();

    let mut next_restart = SealedStateCounterTracker::deserialize(&tracker_after_export).unwrap();
    assert!(AuraVoipSession::from_sealed_state_with_counter_tracker(
        &sealed1,
        &state_key,
        &mut next_restart,
    )
    .is_err());
    let latest = AuraVoipSession::from_sealed_state_with_counter_tracker(
        &sealed2,
        &state_key,
        &mut next_restart,
    )
    .unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);

    let encrypted = latest
        .encrypt_frame(111, latest.ssrc(), 320, 2, b"latest-voip")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"latest-voip");
}

#[test]
fn api_voip_slot_roundtrip() {
    init();

    let (alice, _bob, alice_session, bob_session, _alice_ed25519, _bob_ed25519) =
        create_api_voip_session_pair();

    let state_key = vec![0x62u8; 32];
    let mut slot = SealedStateSlot::new();
    alice_session.export_to_slot(&state_key, &mut slot).unwrap();
    let slot_bytes = slot.serialize().unwrap();

    let mut restart_slot = SealedStateSlot::deserialize(&slot_bytes).unwrap();
    let restored = alice
        .import_call_state_from_slot(&mut restart_slot, &state_key)
        .unwrap();
    assert_eq!(restart_slot.max_restored_counter(), 1);
    assert_eq!(restart_slot.latest_issued_counter(), 1);

    let encrypted = restored
        .encrypt_frame(111, restored.ssrc(), 160, 1, b"slot-voip")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"slot-voip");

    restored
        .export_to_slot(&state_key, &mut restart_slot)
        .unwrap();
    let next_slot_bytes = restart_slot.serialize().unwrap();
    let mut next_restart = SealedStateSlot::deserialize(&next_slot_bytes).unwrap();
    let latest = AuraVoipSession::restore_from_slot(&mut next_restart, &state_key).unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);

    let encrypted = latest
        .encrypt_frame(111, latest.ssrc(), 320, 2, b"latest-slot-voip")
        .unwrap();
    let decrypted = bob_session.decrypt_frame(&encrypted).unwrap();
    assert_eq!(decrypted.payload, b"latest-slot-voip");
}

// ---------------------------------------------------------------------------
// Group Session via API
// ---------------------------------------------------------------------------

#[test]
fn api_group_two_member_lifecycle() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    assert_eq!(session.epoch().unwrap(), 0);

    let commit = session.update().unwrap();
    assert!(!commit.is_empty());
    assert_eq!(session.epoch().unwrap(), 1);
}

#[test]
fn api_group_remove_member() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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

    let alice_proto = AuraProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();

    let public_state = alice_group.export_public_state().unwrap();
    assert!(!public_state.is_empty());

    let charlie_proto = AuraProtocol::new(5).unwrap();
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
fn api_group_external_join_rejects_stale_authorization() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();

    let charlie_proto = AuraProtocol::new(5).unwrap();
    let authorization = authorize_external_join_api(&alice_group, &charlie_proto, b"charlie");

    let _commit = alice_group.update().unwrap();
    let public_state = alice_group.export_public_state().unwrap();

    let result =
        charlie_proto.join_group_external(&public_state, &authorization, b"charlie".to_vec());
    assert!(result.is_err());
}

#[test]
fn api_group_external_join_rejects_expired_authorization() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();
    let public_state = alice_group.export_public_state().unwrap();

    let charlie_proto = AuraProtocol::new(5).unwrap();
    let mut authorization = GroupExternalJoinAuthorization::decode(
        authorize_external_join_api(&alice_group, &charlie_proto, b"charlie").as_slice(),
    )
    .unwrap();
    authorization.issued_at_unix = 1;
    authorization.expires_at_unix = 2;

    let alice_secret = alice_proto.get_identity_ed25519_private_key_copy().unwrap();
    let expired_authorization = resign_external_join_authorization_for_api_test(
        &mut authorization,
        alice_secret.as_slice(),
    );

    let result = charlie_proto.join_group_external(
        &public_state,
        &expired_authorization,
        b"charlie".to_vec(),
    );
    assert!(result.is_err());
}

#[test]
fn api_group_external_join_rejects_unsupported_authorization_format() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();
    let public_state = alice_group.export_public_state().unwrap();

    let charlie_proto = AuraProtocol::new(5).unwrap();
    let mut authorization = GroupExternalJoinAuthorization::decode(
        authorize_external_join_api(&alice_group, &charlie_proto, b"charlie").as_slice(),
    )
    .unwrap();
    authorization.auth_format_version = 0;

    let alice_secret = alice_proto.get_identity_ed25519_private_key_copy().unwrap();
    let tampered_authorization = resign_external_join_authorization_for_api_test(
        &mut authorization,
        alice_secret.as_slice(),
    );

    let result = charlie_proto.join_group_external(
        &public_state,
        &tampered_authorization,
        b"charlie".to_vec(),
    );
    assert!(result.is_err());
}

#[test]
fn api_group_external_join_commit_accepts_delayed_apply_after_authorization_expiry() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();
    let carol_proto = AuraProtocol::new(5).unwrap();

    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();

    let (bob_kp_bytes, bob_x25519, bob_kyber) =
        bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp_bytes).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let state_key = vec![0xA5; 32];
    let bob_sealed = bob_group.serialize(&state_key, 1).unwrap();

    let authorization = authorize_external_join_api(&alice_group, &carol_proto, b"carol");
    let public_state = alice_group.export_public_state().unwrap();
    let (carol_group, ext_commit) = carol_proto
        .join_group_external(&public_state, &authorization, b"carol".to_vec())
        .unwrap();

    let mut commit = GroupCommit::decode(ext_commit.as_slice()).unwrap();
    let external_init = commit
        .proposals
        .iter_mut()
        .find_map(|proposal| match proposal.proposal.as_mut() {
            Some(aura_protected_protocol::proto::group_proposal::Proposal::ExternalInit(ext)) => {
                Some(ext)
            }
            _ => None,
        })
        .unwrap();

    let mut auth =
        GroupExternalJoinAuthorization::decode(external_init.authorization.as_slice()).unwrap();
    auth.issued_at_unix = 1;
    auth.expires_at_unix = 2;

    let alice_secret = alice_proto.get_identity_ed25519_private_key_copy().unwrap();
    external_init.authorization =
        resign_external_join_authorization_for_api_test(&mut auth, alice_secret.as_slice());

    let carol_secret = carol_proto.get_identity_ed25519_private_key_copy().unwrap();
    let expired_commit = resign_group_commit_for_api_test(&mut commit, carol_secret.as_slice());

    alice_group.process_commit(&expired_commit).unwrap();

    let bob_secret = bob_proto.get_identity_ed25519_private_key_copy().unwrap();
    let (bob_restored, restored_counter) =
        AuraGroupSession::deserialize(&bob_sealed, &state_key, bob_secret, 0).unwrap();
    assert_eq!(restored_counter, 1);
    bob_restored.process_commit(&expired_commit).unwrap();

    let ct = carol_group
        .encrypt(b"carol after delayed api external join")
        .unwrap();
    let pt_alice = alice_group.decrypt(&ct).unwrap();
    let pt_bob = bob_restored.decrypt(&ct).unwrap();
    assert_eq!(pt_alice.plaintext, b"carol after delayed api external join");
    assert_eq!(pt_bob.plaintext, b"carol after delayed api external join");
}

#[test]
fn api_group_serialize_deserialize() {
    init();

    let proto = AuraProtocol::new(5).unwrap();
    let ed_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let _ct = session.encrypt(b"test").unwrap();

    let key = vec![0x99u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let counter = AuraGroupSession::sealed_external_counter(&sealed).unwrap();
    assert_eq!(counter, 1);

    let (restored, restored_counter) =
        AuraGroupSession::deserialize(&sealed, &key, ed_secret, 0).unwrap();
    assert_eq!(restored_counter, 1);
    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());
    assert_eq!(session.epoch().unwrap(), restored.epoch().unwrap());
    assert_eq!(
        session.my_leaf_index().unwrap(),
        restored.my_leaf_index().unwrap()
    );
}

#[test]
fn api_group_counter_tracker_restores_latest_and_rejects_rollback() {
    init();

    let proto = AuraProtocol::new(5).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();
    let key = vec![0x77u8; 32];
    let mut tracker = SealedStateCounterTracker::new();

    let sealed1 = session
        .serialize_with_counter_tracker(&key, &mut tracker)
        .unwrap();
    let tracker_bytes = tracker.serialize();

    let mut restart_tracker = SealedStateCounterTracker::deserialize(&tracker_bytes).unwrap();
    let restored = AuraGroupSession::deserialize_with_counter_tracker(
        &sealed1,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
        &mut restart_tracker,
    )
    .unwrap();
    assert_eq!(restart_tracker.max_restored_counter(), 1);
    assert_eq!(restart_tracker.latest_issued_counter(), 1);
    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());

    let sealed2 = restored
        .serialize_with_counter_tracker(&key, &mut restart_tracker)
        .unwrap();
    let tracker_after_export = restart_tracker.serialize();

    let mut next_restart = SealedStateCounterTracker::deserialize(&tracker_after_export).unwrap();
    assert!(AuraGroupSession::deserialize_with_counter_tracker(
        &sealed1,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
        &mut next_restart,
    )
    .is_err());
    let latest = AuraGroupSession::deserialize_with_counter_tracker(
        &sealed2,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
        &mut next_restart,
    )
    .unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);
    assert_eq!(session.group_id().unwrap(), latest.group_id().unwrap());
}

/// Regression test for the iOS cold-start reload bug: a sealed group blob must
/// be loadable any number of times when no state changes have occurred since
/// the last persist. The original code rejected counter == watermark as
/// "rollback", which made the iOS app unable to deserialize its own freshly
/// persisted MLS state on the very next launch and surfaced as
/// `groupDeserialize FFI code 16` (AuraErrorInvalidState).
#[test]
fn api_group_counter_tracker_idempotent_reload_after_cold_start() {
    init();

    let proto = AuraProtocol::new(5).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();
    let key = vec![0xAAu8; 32];
    let mut tracker = SealedStateCounterTracker::new();

    let sealed = session
        .serialize_with_counter_tracker(&key, &mut tracker)
        .unwrap();
    let tracker_bytes = tracker.serialize();

    // Cold-start cycle 1: load tracker from disk, deserialize sealed blob.
    // Tracker advances max_restored from 0 to 1.
    let mut tracker_cold1 = SealedStateCounterTracker::deserialize(&tracker_bytes).unwrap();
    let _restored1 = AuraGroupSession::deserialize_with_counter_tracker(
        &sealed,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
        &mut tracker_cold1,
    )
    .unwrap();
    assert_eq!(tracker_cold1.max_restored_counter(), 1);

    // Persist the advanced tracker back to disk.
    let tracker_after_cold1 = tracker_cold1.serialize();

    // Cold-start cycle 2: same sealed blob (no changes were exported), tracker
    // already shows max_restored=1. Pre-fix this rejected with InvalidState
    // because the load check was `<=`. Post-fix, it must succeed — the blob
    // is at the watermark, not below it, so there is no rollback.
    let mut tracker_cold2 = SealedStateCounterTracker::deserialize(&tracker_after_cold1).unwrap();
    let _restored2 = AuraGroupSession::deserialize_with_counter_tracker(
        &sealed,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
        &mut tracker_cold2,
    )
    .expect("idempotent reload of unchanged sealed state must succeed");
    assert_eq!(
        tracker_cold2.max_restored_counter(),
        1,
        "watermark stays put when reloading the same counter — only advances on strict-greater"
    );
}

#[test]
fn api_group_slot_roundtrip() {
    init();

    let proto = AuraProtocol::new(5).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();
    let key = vec![0x87u8; 32];
    let mut slot = SealedStateSlot::new();

    session.export_to_slot(&key, &mut slot).unwrap();
    let slot_bytes = slot.serialize().unwrap();

    let mut restart_slot = SealedStateSlot::deserialize(&slot_bytes).unwrap();
    let restored = AuraGroupSession::restore_from_slot(
        &mut restart_slot,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    assert_eq!(restart_slot.max_restored_counter(), 1);
    assert_eq!(restart_slot.latest_issued_counter(), 1);
    assert_eq!(session.group_id().unwrap(), restored.group_id().unwrap());

    restored.export_to_slot(&key, &mut restart_slot).unwrap();
    let next_slot_bytes = restart_slot.serialize().unwrap();
    let mut next_restart = SealedStateSlot::deserialize(&next_slot_bytes).unwrap();
    let latest = AuraGroupSession::restore_from_slot(
        &mut next_restart,
        &key,
        proto.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    assert_eq!(next_restart.max_restored_counter(), 2);
    assert_eq!(next_restart.latest_issued_counter(), 2);
    assert_eq!(session.group_id().unwrap(), latest.group_id().unwrap());
}

#[test]
fn api_group_serialize_wrong_key_fails() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let ed_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let key = vec![0x99u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let wrong_key = vec![0xFFu8; 32];
    let result = AuraGroupSession::deserialize(&sealed, &wrong_key, ed_secret, 0);
    assert!(result.is_err());
}

#[test]
fn api_group_deserialize_wrong_identity_secret_rejected() {
    init();

    let alice_proto = AuraProtocol::new(0).unwrap();
    let mallory_proto = AuraProtocol::new(0).unwrap();
    let session = alice_proto.create_group(b"cred".to_vec()).unwrap();

    let key = vec![0x99u8; 32];
    let sealed = session.serialize(&key, 1).unwrap();

    let wrong_secret = mallory_proto
        .get_identity_ed25519_private_key_copy()
        .unwrap();
    let result = AuraGroupSession::deserialize(&sealed, &key, wrong_secret, 0);
    let Err(err) = result else {
        panic!("Mismatched identity secret must be rejected");
    };
    let err = err.to_string();
    assert!(
        err.contains("does not match sealed group state"),
        "unexpected error: {err}"
    );
}

#[test]
fn api_group_member_leaf_indices() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
        let revealed = AuraGroupSession::reveal_sealed(sealed).unwrap();
        assert_eq!(revealed, b"secret content");
    } else {
        assert_eq!(result.plaintext, b"secret content");
    }
}

#[test]
fn api_group_encrypt_frankable_roundtrip() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
        let valid = AuraGroupSession::verify_franking(franking).unwrap();
        assert!(valid);
    }
}

#[test]
fn api_group_encrypt_disappearing_roundtrip() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.process_commit(b"not a valid commit");
    assert!(result.is_err());
}

#[test]
fn api_group_decrypt_invalid_data_fails() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.decrypt(b"not a valid message");
    assert!(result.is_err());
}

#[test]
fn api_group_add_member_invalid_key_package_fails() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.add_member(b"invalid key package");
    assert!(result.is_err());
}

#[test]
fn api_group_add_member_oversized_key_package_fails() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let oversized = vec![0xAB; MAX_GROUP_MESSAGE_SIZE + 1];
    let result = session.add_member(&oversized);
    assert!(result.is_err());
}

#[test]
fn api_group_join_external_invalid_state_fails() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let result = proto.join_group_external(b"garbage", b"invalid-auth", b"cred".to_vec());
    assert!(result.is_err());
}

#[test]
fn api_group_join_external_oversized_authorization_fails() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let alice_group = alice_proto
        .create_group_with_policy(b"alice".to_vec(), permissive_group_policy())
        .unwrap();
    let public_state = alice_group.export_public_state().unwrap();

    let joiner = AuraProtocol::new(5).unwrap();
    let oversized_auth = vec![0xCD; MAX_GROUP_MESSAGE_SIZE + 1];
    let result = joiner.join_group_external(&public_state, &oversized_auth, b"join".to_vec());
    assert!(result.is_err());
}

#[test]
fn api_group_join_rejects_oversized_welcome() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();

    let mut oversized_welcome = welcome;
    oversized_welcome.resize(MAX_GROUP_MESSAGE_SIZE + 1, 0x00);

    let result = bob_proto.join_group(&oversized_welcome, bob_x25519, bob_kyber);
    assert!(result.is_err());
}

#[test]
fn api_group_pending_reinit_none_by_default() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let reinit = session.pending_reinit().unwrap();
    assert!(reinit.is_none());
}

#[test]
fn api_group_id_stable_across_epochs() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
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
    let id1 = AuraGroupSession::compute_message_id(b"group-1", 0, 0, 0);
    let id2 = AuraGroupSession::compute_message_id(b"group-1", 0, 0, 0);
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 32);

    let id3 = AuraGroupSession::compute_message_id(b"group-1", 0, 0, 1);
    assert_ne!(id1, id3);

    let id4 = AuraGroupSession::compute_message_id(b"group-2", 0, 0, 0);
    assert_ne!(id1, id4);
}

#[test]
fn api_group_edit_roundtrip() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
        aura_protected_protocol::protocol::group::ContentType::Edit
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

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
        aura_protected_protocol::protocol::group::ContentType::Delete
    );
    assert_eq!(
        delete_result.referenced_message_id,
        original_result.message_id
    );
}

#[test]
fn api_group_edit_requires_valid_message_id() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.encrypt_edit(b"new content", b"too-short");
    assert!(result.is_err());

    let result = session.encrypt_edit(b"new content", b"");
    assert!(result.is_err());
}

#[test]
fn api_group_delete_requires_valid_message_id() {
    init();

    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();

    let result = session.encrypt_delete(b"too-short");
    assert!(result.is_err());

    let result = session.encrypt_delete(b"");
    assert!(result.is_err());
}

#[test]
fn api_group_normal_message_has_empty_referenced_id() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
        aura_protected_protocol::protocol::group::ContentType::Normal
    );
}

#[test]
fn api_group_decrypt_always_returns_message_id() {
    init();

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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

    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

    let alice_group = alice_proto.create_group(b"alice".to_vec()).unwrap();
    let (bob_kp, bob_x25519, bob_kyber) = bob_proto.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob_proto
        .join_group(&welcome, bob_x25519, bob_kyber)
        .unwrap();

    let ct = alice_group.encrypt(b"test").unwrap();
    let result = bob_group.decrypt(&ct).unwrap();

    let computed = AuraGroupSession::compute_message_id(
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
    let proto = AuraProtocol::new(0).unwrap();
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
    let creator = AuraProtocol::new(0).unwrap();
    let session = creator.create_shielded_group(b"cred".to_vec()).unwrap();
    let public_state = session.export_public_state().unwrap();

    let joiner = AuraProtocol::new(0).unwrap();
    let result = joiner.join_group_external(&public_state, b"invalid-auth", b"join".to_vec());
    assert!(
        result.is_err(),
        "External join should be blocked by shield policy"
    );
}

#[test]
fn shield_forces_rotation() {
    init();
    let proto = AuraProtocol::new(0).unwrap();
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
    let proto = AuraProtocol::new(0).unwrap();
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
    let proto = AuraProtocol::new(0).unwrap();
    let default_session = proto.create_group(b"cred".to_vec()).unwrap();
    let shield_session = proto.create_shielded_group(b"cred".to_vec()).unwrap();

    let ct_default = default_session.encrypt(b"test").unwrap();
    let ct_shield = shield_session.encrypt(b"test").unwrap();
    assert_ne!(ct_default, ct_shield);
}

#[test]
fn shield_policy_bound_in_context_hash() {
    init();
    let proto = AuraProtocol::new(0).unwrap();

    let default_session = proto.create_group(b"cred".to_vec()).unwrap();
    let shield_session = proto.create_shielded_group(b"cred".to_vec()).unwrap();

    let default_policy = default_session.security_policy().unwrap();
    let shield_policy = shield_session.security_policy().unwrap();

    assert_eq!(default_policy.policy_bytes(), shield_policy.policy_bytes());
}

#[test]
fn shield_policy_survives_serialization() {
    init();
    let proto = AuraProtocol::new(0).unwrap();
    let session = proto.create_shielded_group(b"cred".to_vec()).unwrap();
    let ed25519_sk = proto.get_identity_ed25519_private_key_copy().unwrap();

    let key = vec![0xABu8; 32];
    let data = session.serialize(&key, 42).unwrap();
    let (restored, restored_counter) =
        AuraGroupSession::deserialize(&data, &key, ed25519_sk, 0).unwrap();
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
    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
    let proto = AuraProtocol::new(0).unwrap();
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
    let alice_proto = AuraProtocol::new(5).unwrap();
    let bob_proto = AuraProtocol::new(5).unwrap();

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
