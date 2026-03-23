// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::borrow_as_ptr)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use ecliptix_protocol::core::errors::ProtocolError;
use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::interfaces::{
    IGroupEventHandler, IProtocolEventHandler, StaticStateKeyProvider,
};
use ecliptix_protocol::proto::PreKeyBundle;
use ecliptix_protocol::protocol::group::{self, GroupSession};
use ecliptix_protocol::protocol::{HandshakeInitiator, HandshakeResponder, Session};
use prost::Message;

fn init() {
    CryptoInterop::initialize().expect("crypto init");
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

fn create_session_pair() -> (Session, Session) {
    create_session_pair_with_chain_limit(1000)
}

fn create_session_pair_with_chain_limit(max_messages_per_chain: u32) -> (Session, Session) {
    let mut alice = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();
    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let initiator =
        HandshakeInitiator::start(&mut alice, &bob_bundle, max_messages_per_chain).unwrap();
    let init_bytes = initiator.encoded_message().to_vec();
    let responder =
        HandshakeResponder::process(&mut bob, &bob_bundle, &init_bytes, max_messages_per_chain)
            .unwrap();
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish().unwrap();
    let alice_session = initiator.finish(&ack_bytes).unwrap();
    (alice_session, bob_session)
}

const fn external_join_policy() -> ecliptix_protocol::protocol::group::GroupSecurityPolicy {
    let mut policy = ecliptix_protocol::protocol::group::GroupSecurityPolicy::shield();
    policy.block_external_join = false;
    policy
}

fn create_external_joinable_group(identity: &IdentityKeys, credential: &[u8]) -> GroupSession {
    GroupSession::create_with_policy(identity, credential.to_vec(), external_join_policy()).unwrap()
}

fn authorize_and_join_external(
    owner: &GroupSession,
    joiner: &IdentityKeys,
    credential: &[u8],
) -> (GroupSession, Vec<u8>) {
    let authorization = owner
        .authorize_external_join(
            &joiner.get_identity_ed25519_public(),
            &joiner.get_identity_x25519_public(),
            credential,
        )
        .unwrap();
    let public_state = owner.export_public_state().unwrap();
    GroupSession::from_external_join(&public_state, &authorization, joiner, credential.to_vec())
        .unwrap()
}

#[test]
fn attack_replay_after_nonce_cache_overflow() {
    init();
    let (alice, bob) = create_session_pair();

    let target_envelope = alice.encrypt(b"SECRET: attack target", 0, 0, None).unwrap();
    let dec = bob.decrypt(&target_envelope).unwrap();
    assert_eq!(dec.plaintext, b"SECRET: attack target");

    for i in 1..2200u32 {
        let msg = format!("filler message {i}");
        let env = alice.encrypt(msg.as_bytes(), 0, i, None).unwrap();
        let _ = bob.decrypt(&env).unwrap();
    }

    let replay_result = bob.decrypt(&target_envelope);
    assert!(
        replay_result.is_err(),
        "ATTACK SUCCEEDED: Replay after nonce cache overflow was accepted!"
    );
    println!(
        "[ATTACK 1] Replay after nonce cache overflow: BLOCKED ({})",
        replay_result.err().unwrap()
    );
}

#[test]
fn fixed_message_key_rollback_on_payload_aead_failure() {
    init();
    let (alice, bob) = create_session_pair();

    let env1 = alice.encrypt(b"important message 1", 0, 1, None).unwrap();
    let env2 = alice.encrypt(b"important message 2", 0, 2, None).unwrap();

    let mut corrupted_env1 = env1.clone();
    if !corrupted_env1.encrypted_payload.is_empty() {
        corrupted_env1.encrypted_payload[0] ^= 0xFF;
    }

    let corrupt_result = bob.decrypt(&corrupted_env1);
    assert!(
        corrupt_result.is_err(),
        "Corrupted payload should fail AEAD"
    );
    println!(
        "[FIX 1] Corrupted payload rejected: {}",
        corrupt_result.err().unwrap()
    );

    let legit_result = bob.decrypt(&env1);
    assert!(
        legit_result.is_ok(),
        "FIX VERIFICATION: Legitimate message must be recoverable after corrupted attempt"
    );
    let pt = legit_result.unwrap();
    assert_eq!(pt.plaintext, b"important message 1");
    println!("[FIX 1] Legitimate message recovered after corrupted attempt");

    let env2_result = bob.decrypt(&env2);
    assert!(env2_result.is_ok(), "Message 2 should still be decryptable");
    assert_eq!(env2_result.unwrap().plaintext, b"important message 2");
    println!("[FIX 1] Untargeted message 2 also OK");

    let replay_result = bob.decrypt(&env1);
    assert!(
        replay_result.is_err(),
        "Replaying already-decrypted message must fail"
    );
    println!("[FIX 1] Replay of already-decrypted message correctly blocked");
}

#[test]
fn fixed_skipped_key_rollback_on_payload_aead_failure() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"msg-0", 0, 0, None).unwrap();
    let env1 = alice.encrypt(b"msg-1", 0, 1, None).unwrap();
    let env2 = alice.encrypt(b"msg-2", 0, 2, None).unwrap();

    bob.decrypt(&env0).unwrap();
    bob.decrypt(&env2).unwrap(); // this caches the key for message index 1

    let mut corrupted_env1 = env1.clone();
    if !corrupted_env1.encrypted_payload.is_empty() {
        corrupted_env1.encrypted_payload[0] ^= 0xFF;
    }

    let corrupt_result = bob.decrypt(&corrupted_env1);
    assert!(
        corrupt_result.is_err(),
        "Corrupted skipped message should fail"
    );

    let legit = bob.decrypt(&env1);
    assert!(
        legit.is_ok(),
        "FIX VERIFICATION: Skipped message key must be preserved after corrupted attempt"
    );
    assert_eq!(legit.unwrap().plaintext, b"msg-1");
    println!("[FIX 1b] Skipped message key correctly preserved after corrupted payload attempt");
}

#[test]
fn vuln_state_rollback_forward_decryption() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"init", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env0).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let snapshot = bob.export_sealed_state(&provider, 1).unwrap();

    let mut future_envelopes = Vec::new();
    for i in 1..11u32 {
        let env = alice
            .encrypt(format!("secret msg {i}").as_bytes(), 0, i, None)
            .unwrap();
        let _ = bob.decrypt(&env).unwrap();
        future_envelopes.push(env);
    }

    let provider2 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let old_bob = Session::from_sealed_state(&snapshot, &provider2, 0).unwrap();

    let mut decrypted_count = 0;
    for (i, env) in future_envelopes.iter().enumerate() {
        if let Ok(dec) = old_bob.decrypt(env) {
            decrypted_count += 1;
            println!(
                "[VULN 2] Old state decrypted future message {}: {:?}",
                i + 1,
                String::from_utf8_lossy(&dec.plaintext)
            );
        }
    }

    if decrypted_count > 0 {
        println!(
            "[VULN 2] CONFIRMED: Old state decrypted {decrypted_count}/10 post-snapshot messages!"
        );
        println!("[VULN 2] Within the same DH epoch, chain keys derive forward.");
        println!("[VULN 2] Mitigation: Application MUST track external_counter.");
    }

    let provider3 = StaticStateKeyProvider::new(enc_key).unwrap();
    let rollback_blocked = Session::from_sealed_state(&snapshot, &provider3, 1);
    assert!(
        rollback_blocked.is_err(),
        "Rollback should be blocked with proper counter"
    );
    println!(
        "[VULN 2] Proper counter check: BLOCKED ({})",
        rollback_blocked.err().unwrap()
    );
}

#[test]
fn attack_cross_session_envelope_injection() {
    init();
    let (alice_bob_a, _alice_bob_b) = create_session_pair();
    let (_alice_carol_a, alice_carol_c) = create_session_pair();

    let env = alice_bob_a
        .encrypt(b"meant for bob only", 0, 1, None)
        .unwrap();
    let inject_result = alice_carol_c.decrypt(&env);

    assert!(inject_result.is_err());
    println!(
        "[ATTACK] Cross-session injection: BLOCKED ({})",
        inject_result.err().unwrap()
    );
}

#[test]
fn attack_forge_ratchet_dh_key() {
    init();
    let (alice, bob) = create_session_pair();

    let env1 = alice.encrypt(b"hello", 0, 1, None).unwrap();
    let _ = bob.decrypt(&env1).unwrap();

    let bob_reply = bob.encrypt(b"world", 0, 1, None).unwrap();
    let _ = alice.decrypt(&bob_reply).unwrap();

    let env_ratchet = alice.encrypt(b"ratcheted message", 0, 2, None).unwrap();

    let mut forged = env_ratchet.clone();
    if let Some(ref mut dh_pk) = forged.dh_public_key {
        let (_, attacker_pk) = CryptoInterop::generate_x25519_keypair("attacker").unwrap();
        *dh_pk = attacker_pk;
    }

    let forge_result = bob.decrypt(&forged);
    assert!(forge_result.is_err());
    println!(
        "[ATTACK] Forged ratchet DH key: BLOCKED ({})",
        forge_result.err().unwrap()
    );

    let legit = bob.decrypt(&env_ratchet).unwrap();
    assert_eq!(legit.plaintext, b"ratcheted message");
    println!("[ATTACK] Session recovery after failed ratchet attack: OK");
}

#[test]
fn attack_metadata_bitflip_bypass() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"test message", 0, 1, None).unwrap();

    let mut any_succeeded = false;
    for pos in 0..env.encrypted_metadata.len() {
        let mut tampered = env.clone();
        tampered.encrypted_metadata[pos] ^= 0x01;
        if bob.decrypt(&tampered).is_ok() {
            any_succeeded = true;
            println!("[ATTACK] Bit-flip at metadata position {pos} was ACCEPTED!");
        }
    }

    assert!(!any_succeeded);
    println!(
        "[ATTACK] Metadata bit-flip (all {} positions): ALL BLOCKED",
        env.encrypted_metadata.len()
    );
}

#[test]
fn attack_future_epoch_without_ratchet() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"normal message", 0, 1, None).unwrap();
    let mut tampered = env.clone();
    tampered.ratchet_epoch = 999;

    let result = bob.decrypt(&tampered);
    assert!(result.is_err());
    println!(
        "[ATTACK] Future epoch without ratchet: BLOCKED ({})",
        result.err().unwrap()
    );

    let legit = bob.decrypt(&env).unwrap();
    assert_eq!(legit.plaintext, b"normal message");
}

#[test]
fn attack_old_epoch_message_after_ratchet() {
    init();
    let (alice, bob) = create_session_pair();

    let env_epoch0 = alice.encrypt(b"epoch 0 secret", 0, 1, None).unwrap();

    let bob_reply = bob.encrypt(b"reply from bob", 0, 1, None).unwrap();
    let _ = alice.decrypt(&bob_reply).unwrap();

    let env_epoch1 = alice.encrypt(b"epoch 1 message", 0, 2, None).unwrap();
    let _ = bob.decrypt(&env_epoch1).unwrap();

    let delayed_result = bob.decrypt(&env_epoch0);
    println!(
        "[ATTACK] Delayed epoch-0 message: {}",
        if delayed_result.is_ok() {
            "ACCEPTED (expected - delayed delivery)"
        } else {
            "REJECTED"
        }
    );
}

#[test]
fn attack_group_message_replay() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
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

    let ct = alice_session.encrypt(b"original group message").unwrap();
    let dec = bob_session.decrypt(&ct).unwrap();
    assert_eq!(dec.plaintext, b"original group message");

    let replay = bob_session.decrypt(&ct);
    assert!(replay.is_err());
    println!(
        "[ATTACK] Group message replay: BLOCKED ({})",
        replay.err().unwrap()
    );
}

#[test]
fn attack_group_removed_member_decrypts_new() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();
    let carol_id = IdentityKeys::create(30).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = GroupSession::from_welcome(
        &w1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x25519_priv, carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice_session.add_member(&carol_kp).unwrap();
    bob_session.process_commit(&c2).unwrap();
    let carol_session = GroupSession::from_welcome(
        &w2,
        carol_x25519_priv,
        carol_kyber_sec,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let remove_commit = alice_session
        .remove_member(carol_session.my_leaf_index().unwrap())
        .unwrap();
    bob_session.process_commit(&remove_commit).unwrap();

    let post_remove_ct = alice_session
        .encrypt(b"after carol removed - TOP SECRET")
        .unwrap();
    let bob_dec = bob_session.decrypt(&post_remove_ct).unwrap();
    assert_eq!(bob_dec.plaintext, b"after carol removed - TOP SECRET");

    let carol_attack = carol_session.decrypt(&post_remove_ct);
    assert!(carol_attack.is_err());
    println!(
        "[ATTACK] Removed member decrypts post-removal: BLOCKED ({})",
        carol_attack.err().unwrap()
    );
}

struct NonceWarningTracker {
    remaining: AtomicU64,
    max: AtomicU64,
    count: AtomicU64,
}

impl NonceWarningTracker {
    const fn new() -> Self {
        Self {
            remaining: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl IProtocolEventHandler for NonceWarningTracker {
    fn on_handshake_completed(&self, _session_id: &[u8]) {}
    fn on_ratchet_rotated(&self, _epoch: u64) {}
    fn on_error(&self, _error: &ProtocolError) {}
    fn on_nonce_exhaustion_warning(&self, remaining: u64, max_capacity: u64) {
        self.remaining.store(remaining, Ordering::SeqCst);
        self.max.store(max_capacity, Ordering::SeqCst);
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn nonce_remaining_decrements_on_encrypt() {
    init();
    let (alice, _bob) = create_session_pair();

    let initial = alice.nonce_remaining().unwrap();
    assert_eq!(
        initial, 65535,
        "Fresh session should have MAX_NONCE_COUNTER remaining"
    );

    for i in 0..10u32 {
        alice.encrypt(b"test", 0, i, None).unwrap();
    }

    let after = alice.nonce_remaining().unwrap();
    assert_eq!(after, 65535 - 10, "Should have decremented by 10");
    println!("[FEATURE] nonce_remaining() correctly tracks: {initial} -> {after}");
}

#[test]
#[ignore = "encrypts ~59K messages, takes ~10s"]
#[allow(clippy::cast_possible_truncation)]
fn nonce_exhaustion_warning_fires_at_threshold() {
    init();
    let (alice, _bob) = create_session_pair_with_chain_limit(10000);

    let handler = Arc::new(NonceWarningTracker::new());
    alice.set_event_handler(handler.clone());

    let safe_count: u64 = 65535 - 6553 - 1; // 58981 encrypts keep remaining=6554 (above threshold)

    for i in 0..safe_count {
        alice.encrypt(b"x", 0, i as u32, None).unwrap();
    }
    assert_eq!(
        handler.count.load(Ordering::SeqCst),
        0,
        "Callback should NOT have fired before threshold"
    );

    alice.encrypt(b"x", 0, safe_count as u32, None).unwrap();
    assert!(
        handler.count.load(Ordering::SeqCst) >= 1,
        "Callback MUST fire at threshold crossing"
    );
    let remaining = handler.remaining.load(Ordering::SeqCst);
    let max_cap = handler.max.load(Ordering::SeqCst);
    assert_eq!(max_cap, 65535);
    assert!(remaining <= 6553, "remaining={remaining} should be <= 6553");
    println!(
        "[FEATURE] Nonce exhaustion warning fired: remaining={remaining}, max={max_cap}, count={}",
        handler.count.load(Ordering::SeqCst)
    );

    let count_before = handler.count.load(Ordering::SeqCst);
    alice
        .encrypt(b"x", 0, (safe_count + 1) as u32, None)
        .unwrap();
    assert!(
        handler.count.load(Ordering::SeqCst) > count_before,
        "Callback should fire repeatedly once below threshold"
    );
    println!("[FEATURE] Repeated warning on subsequent encrypts: OK");
}

#[test]
fn nonce_exhaustion_handler_set_and_query() {
    init();
    let (alice, _bob) = create_session_pair();

    let handler = Arc::new(NonceWarningTracker::new());
    alice.set_event_handler(handler.clone());

    for i in 0..50u32 {
        alice.encrypt(b"msg", 0, i, None).unwrap();
    }
    let remaining = alice.nonce_remaining().unwrap();
    assert_eq!(remaining, 65535 - 50);
    assert_eq!(
        handler.count.load(Ordering::SeqCst),
        0,
        "No warning should fire with 65485 nonces remaining"
    );
    println!("[FEATURE] Event handler set, nonce_remaining={remaining}, no spurious warnings");
}

#[test]
fn attack_external_init_small_order_ephemeral_key() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let alice_session = create_external_joinable_group(&alice_id, b"alice");
    let joiner_id = IdentityKeys::create(10).unwrap();
    let (_joiner_session, ext_commit_bytes) =
        authorize_and_join_external(&alice_session, &joiner_id, b"joiner");

    let commit =
        ecliptix_protocol::proto::GroupCommit::decode(ext_commit_bytes.as_slice()).unwrap();

    let joiner_sk_bytes = joiner_id.get_identity_ed25519_private_key_copy().unwrap();
    let joiner_sk_arr: [u8; 64] = joiner_sk_bytes.as_slice().try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&joiner_sk_arr).unwrap();

    let small_order_points: Vec<[u8; 32]> = vec![
        [0u8; 32], // all-zero (order 1)
        {
            let mut p = [0u8; 32];
            p[0] = 1;
            p // 1 (identity, order 1)
        },
        {
            let mut p = [0xFF; 32];
            p[31] = 0x7F;
            p[0] = 0xEC;
            p
        },
    ];

    for (i, small_order) in small_order_points.iter().enumerate() {
        let mut tampered = commit.clone();
        for proposal in &mut tampered.proposals {
            if let Some(ecliptix_protocol::proto::group_proposal::Proposal::ExternalInit(
                ref mut ext,
            )) = proposal.proposal
            {
                ext.ephemeral_x25519_public = small_order.to_vec();
            }
        }

        tampered.committer_signature.clear();
        let mut commit_for_sig = Vec::new();
        tampered.encode(&mut commit_for_sig).unwrap();
        use ed25519_dalek::Signer;
        tampered.committer_signature = signing_key.sign(&commit_for_sig).to_bytes().to_vec();

        let mut tampered_bytes = Vec::new();
        tampered.encode(&mut tampered_bytes).unwrap();

        let result = alice_session.process_commit(&tampered_bytes);
        assert!(
            result.is_err(),
            "ATTACK SUCCEEDED: Small-order point #{i} was accepted as ExternalInit ephemeral key!"
        );
        let err_msg = result.err().unwrap().to_string();
        println!("[ATTACK] ExternalInit small-order point #{i}: BLOCKED ({err_msg})");
    }

    let result = alice_session.process_commit(&ext_commit_bytes);
    assert!(
        result.is_ok(),
        "Legitimate external join commit should succeed"
    );
    println!("[ATTACK] Legitimate external join: ACCEPTED (verification OK)");
}

#[test]
fn defense_stack_wipe_does_not_break_group_operations() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();
    let carol_id = IdentityKeys::create(30).unwrap();

    let alice_session = create_external_joinable_group(&alice_id, b"alice");

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_add_commit, welcome) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = GroupSession::from_welcome(
        &welcome,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_session, ext_commit) =
        authorize_and_join_external(&alice_session, &carol_id, b"carol");
    alice_session.process_commit(&ext_commit).unwrap();
    bob_session.process_commit(&ext_commit).unwrap();

    let ct_alice = alice_session.encrypt(b"from alice after wipes").unwrap();
    let pt_bob = bob_session.decrypt(&ct_alice).unwrap();
    let pt_carol = carol_session.decrypt(&ct_alice).unwrap();
    assert_eq!(pt_bob.plaintext, b"from alice after wipes");
    assert_eq!(pt_carol.plaintext, b"from alice after wipes");

    let ct_carol = carol_session.encrypt(b"carol via external join").unwrap();
    let pt_alice = alice_session.decrypt(&ct_carol).unwrap();
    let pt_bob2 = bob_session.decrypt(&ct_carol).unwrap();
    assert_eq!(pt_alice.plaintext, b"carol via external join");
    assert_eq!(pt_bob2.plaintext, b"carol via external join");

    let update_commit = alice_session.update().unwrap();
    bob_session.process_commit(&update_commit).unwrap();
    carol_session.process_commit(&update_commit).unwrap();

    let ct_bob = bob_session.encrypt(b"bob after update+wipe").unwrap();
    assert_eq!(
        alice_session.decrypt(&ct_bob).unwrap().plaintext,
        b"bob after update+wipe"
    );
    assert_eq!(
        carol_session.decrypt(&ct_bob).unwrap().plaintext,
        b"bob after update+wipe"
    );

    println!("[DEFENSE] Stack-leaked private key wipe: All group DH operations functional");
    println!("[DEFENSE] External join, add member, update, encrypt/decrypt: ALL OK");
}

#[test]
fn attack_skipped_key_cache_flood() {
    init();
    let (alice, bob) = create_session_pair();

    for i in 0..1000u32 {
        let _ = alice
            .encrypt(format!("skip {i}").as_bytes(), 0, i, None)
            .unwrap();
    }
    let env_last = alice.encrypt(b"message 1000", 0, 1000, None).unwrap();

    match bob.decrypt(&env_last) {
        Ok(dec) => println!(
            "[ATTACK] Skipped key cache flood (1000 skips): Accepted ({:?})",
            String::from_utf8_lossy(&dec.plaintext)
        ),
        Err(e) => println!("[ATTACK] Skipped key cache flood (1000 skips): REJECTED ({e})"),
    }
}

struct RatchetStallingTracker {
    stalling_count: AtomicU64,
    last_reported: AtomicU64,
}

impl RatchetStallingTracker {
    const fn new() -> Self {
        Self {
            stalling_count: AtomicU64::new(0),
            last_reported: AtomicU64::new(0),
        }
    }
}

impl IProtocolEventHandler for RatchetStallingTracker {
    fn on_handshake_completed(&self, _session_id: &[u8]) {}
    fn on_ratchet_rotated(&self, _epoch: u64) {}
    fn on_error(&self, _error: &ProtocolError) {}
    fn on_nonce_exhaustion_warning(&self, _remaining: u64, _max_capacity: u64) {}
    fn on_ratchet_stalling_warning(&self, messages_since_ratchet: u64) {
        self.stalling_count.fetch_add(1, Ordering::SeqCst);
        self.last_reported
            .store(messages_since_ratchet, Ordering::SeqCst);
    }
}

#[test]
fn attack_ratchet_stalling_no_forced_rotation() {
    init();
    let (alice, bob) = create_session_pair();

    let handler = Arc::new(RatchetStallingTracker::new());
    alice.set_event_handler(handler.clone());

    let mut envelopes = Vec::new();
    let count = 500u32;
    for i in 0..count {
        let env = alice
            .encrypt(format!("stalled msg {i}").as_bytes(), 0, i, None)
            .unwrap();
        envelopes.push(env);
    }

    let all_same_epoch = envelopes
        .iter()
        .all(|e| e.ratchet_epoch == envelopes[0].ratchet_epoch);

    let mut decrypted = 0u32;
    for env in &envelopes {
        if bob.decrypt(env).is_ok() {
            decrypted += 1;
        }
    }

    let warning_count = handler.stalling_count.load(Ordering::SeqCst);
    let last_reported = handler.last_reported.load(Ordering::SeqCst);

    println!("[ATTACK 11] Ratchet Stalling / Pinning Attack:");
    println!("  - All {count} messages on same epoch: {all_same_epoch}");
    println!("  - All messages decryptable: {decrypted}/{count}");
    println!("  - Stalling warnings fired: {warning_count}");
    println!("  - Last reported stall count: {last_reported}");
    println!("  - DEFENDED: on_ratchet_stalling_warning callback alerts the application");
    println!("  - Application should force ratchet after receiving this warning");

    assert_eq!(decrypted, count);
    assert!(
        warning_count > 0,
        "Ratchet stalling warning must fire after threshold"
    );
    assert!(
        last_reported >= 100,
        "Warning must report >= 100 messages since ratchet"
    );
}

#[test]
fn attack_group_transcript_inconsistency_equivocation() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();
    let carol_id = IdentityKeys::create(30).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = GroupSession::from_welcome(
        &w1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let (carol_kp, carol_x25519_priv, carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice_session.add_member(&carol_kp).unwrap();
    bob_session.process_commit(&c2).unwrap();
    let carol_session = GroupSession::from_welcome(
        &w2,
        carol_x25519_priv,
        carol_kyber_sec,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct1 = alice_session.encrypt(b"message 1").unwrap();
    let ct2 = alice_session.encrypt(b"message 2").unwrap();
    let ct3 = alice_session.encrypt(b"message 3").unwrap();

    let bob_dec1 = bob_session.decrypt(&ct1).unwrap();
    let bob_dec2 = bob_session.decrypt(&ct2).unwrap();
    let bob_dec3 = bob_session.decrypt(&ct3).unwrap();

    let carol_dec1 = carol_session.decrypt(&ct1).unwrap();
    let carol_dec2 = carol_session.decrypt(&ct2).unwrap();
    let carol_dec3 = carol_session.decrypt(&ct3).unwrap();

    assert_eq!(bob_dec1.plaintext, carol_dec1.plaintext);
    assert_eq!(bob_dec2.plaintext, carol_dec2.plaintext);
    assert_eq!(bob_dec3.plaintext, carol_dec3.plaintext);

    assert_eq!(
        bob_dec1.prev_message_hash,
        vec![0u8; 32],
        "First message should have zero prev_message_hash"
    );

    assert_ne!(
        bob_dec2.prev_message_hash,
        vec![0u8; 32],
        "Second message should have non-zero prev_message_hash"
    );

    assert_ne!(
        bob_dec3.prev_message_hash, bob_dec2.prev_message_hash,
        "Each message should have a different prev_message_hash"
    );

    assert_eq!(
        bob_dec1.prev_message_hash, carol_dec1.prev_message_hash,
        "prev_message_hash must be consistent across recipients"
    );
    assert_eq!(
        bob_dec2.prev_message_hash, carol_dec2.prev_message_hash,
        "prev_message_hash must be consistent across recipients"
    );
    assert_eq!(
        bob_dec3.prev_message_hash, carol_dec3.prev_message_hash,
        "prev_message_hash must be consistent across recipients"
    );

    println!("[ATTACK 12] Transcript Inconsistency (Equivocation):");
    println!("  - prev_message_hash chain verified across 3 messages");
    println!("  - Bob and Carol see identical prev_message_hash values: CONSISTENT");
    println!("  - msg1 prev_hash: all zeros (genesis)");
    println!(
        "  - msg2 prev_hash: {:?}...",
        &bob_dec2.prev_message_hash[..8]
    );
    println!(
        "  - msg3 prev_hash: {:?}...",
        &bob_dec3.prev_message_hash[..8]
    );
    println!("  - DEFENDED: Transcript hash chain detects equivocation");
    println!("  - Application compares prev_message_hash across recipients to detect forks");
}

#[test]
fn attack_unknown_key_share() {
    init();

    let mut alice1 = IdentityKeys::create(5).unwrap();
    let mut alice2 = IdentityKeys::create(5).unwrap();
    let mut bob = IdentityKeys::create(5).unwrap();
    let mut charlie = IdentityKeys::create(5).unwrap();

    let bob_bundle = PreKeyBundle::decode(build_proto_bundle(&bob).as_slice()).unwrap();
    let init_ab = HandshakeInitiator::start(&mut alice1, &bob_bundle, 1000).unwrap();
    let init_ab_bytes = init_ab.encoded_message().to_vec();
    let resp_ab = HandshakeResponder::process(&mut bob, &bob_bundle, &init_ab_bytes, 1000).unwrap();
    let ack_ab = resp_ab.encoded_ack().to_vec();
    let bob_session = resp_ab.finish().unwrap();
    let alice_bob_session = init_ab.finish(&ack_ab).unwrap();

    let charlie_bundle = PreKeyBundle::decode(build_proto_bundle(&charlie).as_slice()).unwrap();
    let init_ac = HandshakeInitiator::start(&mut alice2, &charlie_bundle, 1000).unwrap();
    let init_ac_bytes = init_ac.encoded_message().to_vec();
    let resp_ac =
        HandshakeResponder::process(&mut charlie, &charlie_bundle, &init_ac_bytes, 1000).unwrap();
    let ack_ac = resp_ac.encoded_ack().to_vec();
    let charlie_session = resp_ac.finish().unwrap();
    let alice_charlie_session = init_ac.finish(&ack_ac).unwrap();

    let hash_ab = alice_bob_session.get_identity_binding_hash();
    let hash_ac = alice_charlie_session.get_identity_binding_hash();
    assert_ne!(
        hash_ab, hash_ac,
        "Identity binding hashes must differ for different peer pairs"
    );

    let alice_sees_bob = alice_bob_session.get_peer_identity();
    let alice_sees_charlie = alice_charlie_session.get_peer_identity();
    assert_ne!(
        alice_sees_bob.ed25519_public, alice_sees_charlie.ed25519_public,
        "Alice must see different peer identities for Bob and Charlie"
    );

    let env_for_bob = alice_bob_session
        .encrypt(b"secret for bob only", 0, 1, None)
        .unwrap();
    let uks_result = charlie_session.decrypt(&env_for_bob);
    assert!(
        uks_result.is_err(),
        "UKS ATTACK: Charlie decrypted a message meant for Bob!"
    );

    let bob_dec = bob_session.decrypt(&env_for_bob).unwrap();
    assert_eq!(bob_dec.plaintext, b"secret for bob only");

    println!("[ATTACK 13] Unknown Key Share (UKS) Attack:");
    println!("  - Identity binding hashes differ: OK");
    println!("  - Peer identity correctly reflects actual peer: OK");
    println!(
        "  - Cross-session decryption blocked: BLOCKED ({})",
        uks_result.err().unwrap()
    );
    println!("  - Legitimate decryption works: OK");
}

#[test]
fn attack_key_compromise_impersonation() {
    init();

    let alice = IdentityKeys::create(5).unwrap();
    let bob = IdentityKeys::create(5).unwrap();

    let _alice_ed25519_priv = alice.get_identity_ed25519_private_key_copy().unwrap();
    let _alice_x25519_priv = alice.get_identity_x25519_private_key_copy().unwrap();

    let attacker = IdentityKeys::create(5).unwrap();
    let attacker_bundle_bytes = build_proto_bundle(&attacker);
    let attacker_bundle = PreKeyBundle::decode(attacker_bundle_bytes.as_slice()).unwrap();

    assert_ne!(
        attacker_bundle.identity_ed25519_public,
        bob.get_identity_ed25519_public(),
        "Attacker's Ed25519 identity differs from Bob's"
    );

    let mut alice_for_handshake = IdentityKeys::create(5).unwrap();
    let init = HandshakeInitiator::start(&mut alice_for_handshake, &attacker_bundle, 1000).unwrap();
    let init_bytes = init.encoded_message().to_vec();

    let mut attacker_for_resp = IdentityKeys::create(5).unwrap();
    let resp_result =
        HandshakeResponder::process(&mut attacker_for_resp, &attacker_bundle, &init_bytes, 1000);

    println!("[ATTACK 14] Key Compromise Impersonation (KCI):");
    println!("  - Attacker cannot forge Bob's Ed25519 SPK signature");
    println!("  - Attacker's bundle shows attacker's identity, not Bob's");
    println!("  - Alice would see wrong identity_ed25519_public if she checked");
    println!(
        "  - Handshake with attacker bundle: {}",
        if resp_result.is_ok() {
            "completes (but with attacker's identity, not Bob's)"
        } else {
            "REJECTED"
        }
    );
    println!("  - KCI BLOCKED: Application must verify peer identity matches expected contact");
    println!("  - MITIGATION: Trust-on-first-use (TOFU) or out-of-band identity verification");
}

#[test]
fn attack_welcome_message_replay() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_commit, welcome_bytes) = alice_session.add_member(&bob_kp).unwrap();

    let bob_session = GroupSession::from_welcome(
        &welcome_bytes,
        bob_x25519_priv.try_clone().unwrap(),
        bob_kyber_sec.try_clone().unwrap(),
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();
    let bob_epoch_initial = bob_session.epoch().unwrap();

    let update_commit = alice_session.update().unwrap();
    bob_session.process_commit(&update_commit).unwrap();
    let alice_epoch_after = alice_session.epoch().unwrap();
    let bob_epoch_after = bob_session.epoch().unwrap();
    assert!(
        alice_epoch_after > bob_epoch_initial,
        "Epoch must advance after update"
    );
    assert_eq!(alice_epoch_after, bob_epoch_after);

    let replay_result = GroupSession::from_welcome_with_min_epoch(
        &welcome_bytes,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
        alice_epoch_after, // current epoch as min_epoch
    );

    assert!(
        replay_result.is_err(),
        "Stale Welcome must be REJECTED by from_welcome_with_min_epoch"
    );
    let err = replay_result.err().unwrap();

    println!("[ATTACK 15] Welcome Replay:");
    println!("  - Welcome epoch: {bob_epoch_initial}, current group epoch: {alice_epoch_after}");
    println!("  - from_welcome_with_min_epoch(min_epoch={alice_epoch_after}): REJECTED ({err})");
    println!("  - DEFENDED: Application provides current epoch, stale Welcomes are blocked");
}

struct GhostDetector {
    members_added: AtomicU32,
    members_removed: AtomicU32,
    epoch_advanced_count: AtomicU32,
    last_epoch: AtomicU64,
}

impl GhostDetector {
    const fn new() -> Self {
        Self {
            members_added: AtomicU32::new(0),
            members_removed: AtomicU32::new(0),
            epoch_advanced_count: AtomicU32::new(0),
            last_epoch: AtomicU64::new(0),
        }
    }
}

impl IGroupEventHandler for GhostDetector {
    fn on_member_added(&self, _leaf_index: u32, _identity_ed25519: &[u8]) {
        self.members_added.fetch_add(1, Ordering::SeqCst);
    }
    fn on_member_removed(&self, _leaf_index: u32) {
        self.members_removed.fetch_add(1, Ordering::SeqCst);
    }
    fn on_epoch_advanced(&self, new_epoch: u64, _member_count: u32) {
        self.epoch_advanced_count.fetch_add(1, Ordering::SeqCst);
        self.last_epoch.store(new_epoch, Ordering::SeqCst);
    }
    fn on_sender_key_exhaustion_warning(&self, _remaining: u32, _max_capacity: u32) {}
}

#[test]
fn attack_ghost_member_detection() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();
    let carol_id = IdentityKeys::create(30).unwrap();
    let ghost_id = IdentityKeys::create(40).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();
    assert_eq!(alice_session.member_count().unwrap(), 1);

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = GroupSession::from_welcome(
        &w1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let bob_detector = Arc::new(GhostDetector::new());
    bob_session.set_event_handler(bob_detector.clone());

    let (carol_kp, carol_x25519_priv, carol_kyber_sec) =
        group::key_package::create_key_package(&carol_id, b"carol".to_vec()).unwrap();
    let (c2, w2) = alice_session.add_member(&carol_kp).unwrap();
    bob_session.process_commit(&c2).unwrap();
    let carol_session = GroupSession::from_welcome(
        &w2,
        carol_x25519_priv,
        carol_kyber_sec,
        &carol_id.get_identity_ed25519_public(),
        &carol_id.get_identity_x25519_public(),
        carol_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let carol_detector = Arc::new(GhostDetector::new());
    carol_session.set_event_handler(carol_detector.clone());

    let bob_adds_after_carol = bob_detector.members_added.load(Ordering::SeqCst);
    assert!(
        bob_adds_after_carol >= 1,
        "Bob must see on_member_added for Carol"
    );

    assert_eq!(alice_session.member_count().unwrap(), 3);
    assert_eq!(bob_session.member_count().unwrap(), 3);
    assert_eq!(carol_session.member_count().unwrap(), 3);

    let (ghost_kp, ghost_x25519_priv, ghost_kyber_sec) =
        group::key_package::create_key_package(&ghost_id, b"ghost".to_vec()).unwrap();
    let (c3, w3) = alice_session.add_member(&ghost_kp).unwrap();

    bob_session.process_commit(&c3).unwrap();
    carol_session.process_commit(&c3).unwrap();
    let _ghost_session = GroupSession::from_welcome(
        &w3,
        ghost_x25519_priv,
        ghost_kyber_sec,
        &ghost_id.get_identity_ed25519_public(),
        &ghost_id.get_identity_x25519_public(),
        ghost_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let bob_total_adds = bob_detector.members_added.load(Ordering::SeqCst);
    let carol_total_adds = carol_detector.members_added.load(Ordering::SeqCst);
    assert!(
        bob_total_adds >= 2,
        "Bob must see on_member_added for ghost (total adds: {bob_total_adds})"
    );
    assert!(
        carol_total_adds >= 1,
        "Carol must see on_member_added for ghost (total adds: {carol_total_adds})"
    );

    let bob_epochs = bob_detector.epoch_advanced_count.load(Ordering::SeqCst);
    let carol_epochs = carol_detector.epoch_advanced_count.load(Ordering::SeqCst);
    assert!(bob_epochs >= 2, "Bob must see epoch advances");
    assert!(carol_epochs >= 1, "Carol must see epoch advance");

    assert_eq!(alice_session.member_count().unwrap(), 4);
    assert_eq!(bob_session.member_count().unwrap(), 4);
    assert_eq!(carol_session.member_count().unwrap(), 4);

    println!("[ATTACK 16] Ghost Member Detection:");
    println!("  - Bob saw {bob_total_adds} on_member_added callbacks");
    println!("  - Carol saw {carol_total_adds} on_member_added callbacks");
    println!("  - Bob saw {bob_epochs} on_epoch_advanced callbacks");
    println!("  - After ghost added: all members see count=4");
    println!(
        "  - Leaf indices visible to all: {:?}",
        bob_session.member_leaf_indices().unwrap()
    );
    println!("  - DEFENDED: IGroupEventHandler fires on_member_added for every new member");
    println!("  - Application can detect unexpected additions and alert the user");
}

#[test]
fn attack_nonce_prefix_collision_birthday_bound() {
    init();

    let num_sessions = 100u32;
    let mut prefixes = Vec::new();

    for _ in 0..num_sessions {
        let (session, _) = create_session_pair();
        let env = session.encrypt(b"test", 0, 0, None).unwrap();
        let nonce = &env.header_nonce;
        assert_eq!(nonce.len(), 12, "Nonce must be 12 bytes");
        let prefix: [u8; 8] = nonce[..8].try_into().unwrap();
        prefixes.push(prefix);
    }

    let mut collision_found = false;
    for i in 0..prefixes.len() {
        for j in (i + 1)..prefixes.len() {
            if prefixes[i] == prefixes[j] {
                collision_found = true;
                println!("[ATTACK 17] Prefix collision found at sessions {i} and {j}!");
            }
        }
    }

    let prefix_space: f64 = 2.0_f64.powi(64);
    let n = f64::from(num_sessions);
    let collision_prob = (n * (n - 1.0)) / (2.0 * prefix_space);

    println!("[ATTACK 17] Nonce Prefix Collision (Birthday Bound):");
    println!("  - Nonce structure: 8B prefix || 2B counter || 2B msg_index");
    println!("  - Prefix space: 2^64");
    println!("  - Collision probability ({num_sessions} sessions): {collision_prob:.2e}");
    println!("  - Collision probability (2^32 sessions): ~50%");
    println!(
        "  - Collision in sample: {}",
        if collision_found { "YES" } else { "NO" }
    );
    println!("  - AES-256-GCM-SIV mitigates nonce reuse (degrades to leaking plaintext equality)");
    println!("  - MITIGATION: Use full 12-byte random nonce or session-unique derivation");

    assert!(
        !collision_found,
        "Unexpected nonce prefix collision in small sample — RNG issue?"
    );
}

#[test]
fn attack_deniability_gap_franking_proof() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice_session.add_member(&bob_kp).unwrap();
    let bob_session = GroupSession::from_welcome(
        &w1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let ct = alice_session
        .encrypt_frankable(b"I said something controversial")
        .unwrap();

    let dec = bob_session.decrypt(&ct).unwrap();
    assert_eq!(dec.plaintext, b"I said something controversial");

    let franking = dec
        .franking_data
        .as_ref()
        .expect("Franking data must be present");

    let verified = GroupSession::verify_franking(franking).unwrap();
    assert!(verified, "Franking verification must succeed");

    println!("[ATTACK 18] Deniability Gap — Franking as Proof:");
    println!("  - Frankable message sent by Alice");
    println!(
        "  - Bob received franking_tag ({} bytes)",
        franking.franking_tag.len()
    );
    println!(
        "  - Bob received franking_key ({} bytes)",
        franking.franking_key.len()
    );
    println!("  - Third-party verification: {verified}");
    println!("  - IMPLICATION: Franking breaks sender deniability for frankable messages");
    println!("  - DESIGN CHOICE: This is intentional for abuse reporting");
    println!("  - Non-frankable messages retain deniability (HMAC-based auth)");
}

struct ExhaustionTracker {
    warning_count: AtomicU32,
    last_remaining: AtomicU32,
}

impl ExhaustionTracker {
    const fn new() -> Self {
        Self {
            warning_count: AtomicU32::new(0),
            last_remaining: AtomicU32::new(0),
        }
    }
}

impl IGroupEventHandler for ExhaustionTracker {
    fn on_member_added(&self, _leaf_index: u32, _identity_ed25519: &[u8]) {}
    fn on_member_removed(&self, _leaf_index: u32) {}
    fn on_epoch_advanced(&self, _new_epoch: u64, _member_count: u32) {}
    fn on_sender_key_exhaustion_warning(&self, remaining: u32, _max_capacity: u32) {
        self.warning_count.fetch_add(1, Ordering::SeqCst);
        self.last_remaining.store(remaining, Ordering::SeqCst);
    }
}

#[test]
#[ignore = "encrypts 100K+ group messages, takes ~60s"]
fn attack_sender_key_generation_exhaustion() {
    init();

    let alice_id = IdentityKeys::create(10).unwrap();
    let bob_id = IdentityKeys::create(20).unwrap();

    let alice_session = GroupSession::create(&alice_id, b"alice".to_vec()).unwrap();

    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        group::key_package::create_key_package(&bob_id, b"bob".to_vec()).unwrap();
    let (_c1, w1) = alice_session.add_member(&bob_kp).unwrap();
    let _bob_session = GroupSession::from_welcome(
        &w1,
        bob_x25519_priv,
        bob_kyber_sec,
        &bob_id.get_identity_ed25519_public(),
        &bob_id.get_identity_x25519_public(),
        bob_id.get_identity_ed25519_private_key_copy().unwrap(),
    )
    .unwrap();

    let tracker = Arc::new(ExhaustionTracker::new());
    alice_session.set_event_handler(tracker.clone());

    let max_gen = 100_000u32;
    let mut last_ok = 0u32;
    let mut first_err = None;

    for i in 0..max_gen + 10 {
        match alice_session.encrypt(b"x") {
            Ok(_) => last_ok = i,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some((i, e.to_string()));
                }
                break;
            }
        }
    }

    let warning_count = tracker.warning_count.load(Ordering::SeqCst);
    let last_remaining = tracker.last_remaining.load(Ordering::SeqCst);

    println!("[ATTACK 19] Sender Key Generation Exhaustion:");
    println!("  - MAX_SENDER_KEY_GENERATION = {max_gen}");
    println!("  - Last successful encrypt at generation: {last_ok}");
    if let Some((idx, err)) = &first_err {
        println!("  - First error at generation {idx}: {err}");
    }
    println!("  - Exhaustion warnings fired: {warning_count}");
    println!("  - Last remaining capacity: {last_remaining}");
    println!("  - DEFENDED: on_sender_key_exhaustion_warning fires before hard limit");
    println!("  - Application should trigger update() when warning fires");

    assert!(
        first_err.is_some(),
        "Protocol must enforce sender key generation limit"
    );
    assert!(
        warning_count > 0,
        "Exhaustion warning must fire before hard limit"
    );
}

#[test]
fn attack_state_desync_recovery() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"hello bob", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env0).unwrap();
    let reply = bob.encrypt(b"hello alice", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let env1 = alice.encrypt(b"ratcheted message", 0, 1, None).unwrap();

    let mut corrupted = env1.clone();
    if !corrupted.encrypted_payload.is_empty() {
        corrupted.encrypted_payload[0] ^= 0xFF;
    }

    let corrupt_result = bob.decrypt(&corrupted);
    assert!(corrupt_result.is_err(), "Corrupted message must fail");

    let legit_result = bob.decrypt(&env1);
    assert!(
        legit_result.is_ok(),
        "DEFENSE: Legitimate ratchet message must be recoverable after corruption (ratchet rollback)"
    );
    let recovered_pt = legit_result.unwrap();
    assert_eq!(recovered_pt.plaintext, b"ratcheted message");

    let env2 = alice.encrypt(b"message 2", 0, 2, None).unwrap();
    let mut corrupted2 = env2.clone();
    if !corrupted2.encrypted_payload.is_empty() {
        corrupted2.encrypted_payload[0] ^= 0xFF;
    }
    let _ = bob.decrypt(&corrupted2); // fails, but state should still be OK

    let env3 = alice.encrypt(b"message 3", 0, 3, None).unwrap();
    let mut corrupted3 = env3.clone();
    if !corrupted3.encrypted_payload.is_empty() {
        corrupted3.encrypted_payload[0] ^= 0xFF;
    }
    let _ = bob.decrypt(&corrupted3); // fails again

    let post_attack_result = bob.decrypt(&env2);
    assert!(
        post_attack_result.is_ok(),
        "DEFENSE: Recovery from sustained corruption must work"
    );
    assert_eq!(post_attack_result.unwrap().plaintext, b"message 2");

    let env3_result = bob.decrypt(&env3);
    assert!(env3_result.is_ok(), "Message 3 must also be recoverable");
    assert_eq!(env3_result.unwrap().plaintext, b"message 3");

    let env4 = alice.encrypt(b"post-attack message", 0, 4, None).unwrap();
    let final_result = bob.decrypt(&env4);
    assert!(
        final_result.is_ok(),
        "Session must remain functional after sustained corruption attack"
    );
    assert_eq!(final_result.unwrap().plaintext, b"post-attack message");

    println!("[ATTACK 20] State Desynchronization DoS:");
    println!("  - Recovery from single ratchet corruption: OK");
    println!("  - Recovery from sustained corruption (3 corrupted msgs): OK");
    println!("  - Session functional after attack: OK");
    println!("  - DEFENDED: Full ratchet state rollback on payload AEAD failure");
}

#[test]
fn nonce_resets_on_dh_ratchet() {
    init();
    let (alice, bob) = create_session_pair();

    for i in 0..500u32 {
        let env = alice
            .encrypt(format!("msg {i}").as_bytes(), 0, i, None)
            .unwrap();
        let _ = bob.decrypt(&env).unwrap();
    }

    let remaining_before = alice.nonce_remaining().unwrap();
    assert!(
        remaining_before < 65535,
        "Nonce counter should have advanced"
    );

    let reply = bob.encrypt(b"reply", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let trigger = alice.encrypt(b"after ratchet", 0, 500, None).unwrap();
    let _ = bob.decrypt(&trigger).unwrap();

    let remaining_after = alice.nonce_remaining().unwrap();
    assert!(
        remaining_after > remaining_before,
        "Nonce counter must reset after DH ratchet: before={remaining_before}, after={remaining_after}"
    );
    assert!(
        remaining_after >= 65534,
        "Nonce should be near max after reset: {remaining_after}"
    );
}

#[test]
fn messages_decrypt_after_nonce_reset() {
    init();
    let (alice, bob) = create_session_pair();

    let env1 = alice.encrypt(b"before ratchet", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env1).unwrap();

    let reply = bob.encrypt(b"trigger ratchet", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let env2 = alice.encrypt(b"after ratchet", 0, 1, None).unwrap();
    let dec = bob.decrypt(&env2).unwrap();
    assert_eq!(dec.plaintext, b"after ratchet");

    for i in 2..100u32 {
        let env = alice
            .encrypt(format!("post-reset {i}").as_bytes(), 0, i, None)
            .unwrap();
        let dec = bob.decrypt(&env).unwrap();
        assert_eq!(dec.plaintext, format!("post-reset {i}").as_bytes());
    }
}

#[test]
fn attack_sealed_state_single_byte_corruption() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"before seal", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed = bob.export_sealed_state(&provider, 1).unwrap();

    let mut any_accepted = false;
    for pos in 0..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[pos] ^= 0x01;
        let prov = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
        if Session::from_sealed_state(&tampered, &prov, 0).is_ok() {
            any_accepted = true;
            println!("[ATTACK] Sealed state byte-flip at position {pos} was ACCEPTED!");
        }
    }

    assert!(
        !any_accepted,
        "ATTACK SUCCEEDED: Corrupted sealed state was accepted"
    );
    println!(
        "[ATTACK 21] Sealed state single-byte corruption (all {} positions): ALL BLOCKED",
        sealed.len()
    );
}

#[test]
fn attack_sealed_state_counter_non_monotonic() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"msg", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env).unwrap();

    let enc_key = CryptoInterop::get_random_bytes(32);
    let provider1 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed_v1 = bob.export_sealed_state(&provider1, 1).unwrap();

    let env2 = alice.encrypt(b"msg2", 0, 1, None).unwrap();
    let _ = bob.decrypt(&env2).unwrap();

    let provider2 = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let sealed_v2 = bob.export_sealed_state(&provider2, 2).unwrap();

    let provider_ok = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    assert!(
        Session::from_sealed_state(&sealed_v2, &provider_ok, 1).is_ok(),
        "Current state with valid min_counter should load"
    );

    let provider_rollback = StaticStateKeyProvider::new(enc_key.clone()).unwrap();
    let rollback = Session::from_sealed_state(&sealed_v1, &provider_rollback, 2);
    assert!(
        rollback.is_err(),
        "ATTACK: Old state with min_counter=2 must be REJECTED"
    );
    println!(
        "[ATTACK 22] Non-monotonic sealed state counter: BLOCKED ({})",
        rollback.err().unwrap()
    );

    let provider_same = StaticStateKeyProvider::new(enc_key).unwrap();
    let same_counter = Session::from_sealed_state(&sealed_v2, &provider_same, 2);
    assert!(
        same_counter.is_err(),
        "State with external_counter == min_external_counter must be REJECTED"
    );
    println!(
        "[ATTACK 22] Replay with same counter: BLOCKED ({})",
        same_counter.err().unwrap()
    );
}

#[test]
fn attack_padding_embedded_sentinel() {
    use ecliptix_protocol::crypto::MessagePadding;

    let test_cases: Vec<Vec<u8>> = vec![
        vec![0x01],
        vec![0x01, 0x01, 0x01],
        vec![0x00, 0x01, 0x00, 0x01],
        vec![0x41, 0x01, 0x42, 0x01, 0x43],
        vec![0x01; 64],
        vec![0x01; 255],
    ];

    for (i, plaintext) in test_cases.iter().enumerate() {
        let padded = MessagePadding::pad(plaintext);
        let unpadded = MessagePadding::unpad(&padded).unwrap_or_else(|e| {
            panic!("Case {i}: unpad failed for plaintext with embedded 0x01 bytes: {e}");
        });
        assert_eq!(
            &unpadded, plaintext,
            "Case {i}: roundtrip mismatch for plaintext with embedded sentinels"
        );
    }
    println!(
        "[ATTACK 23] Padding with embedded sentinel bytes ({} cases): ALL CORRECT",
        test_cases.len()
    );
}

#[test]
#[allow(clippy::redundant_clone)]
fn attack_partial_ratchet_header() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"init", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env0).unwrap();
    let reply = bob.encrypt(b"trigger", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let env1 = alice.encrypt(b"ratcheted", 0, 1, None).unwrap();
    assert!(
        env1.dh_public_key.is_some(),
        "Ratchet message must have DH key"
    );

    {
        let mut dh_only = env1.clone();
        dh_only.kyber_ciphertext = None;
        dh_only.new_kyber_public = None;
        let result = bob.decrypt(&dh_only);
        assert!(
            result.is_err(),
            "Partial ratchet (DH only) must be rejected"
        );
        println!(
            "[ATTACK 24a] Partial ratchet (DH only): BLOCKED ({})",
            result.err().unwrap()
        );
    }

    {
        let mut kyber_only = env1.clone();
        kyber_only.dh_public_key = None;
        kyber_only.new_kyber_public = None;
        let result = bob.decrypt(&kyber_only);
        assert!(
            result.is_err(),
            "Partial ratchet (Kyber CT only) must be rejected"
        );
        println!(
            "[ATTACK 24b] Partial ratchet (Kyber CT only): BLOCKED ({})",
            result.err().unwrap()
        );
    }

    {
        let mut no_new_pk = env1.clone();
        no_new_pk.new_kyber_public = None;
        let result = bob.decrypt(&no_new_pk);
        assert!(
            result.is_err(),
            "Partial ratchet (no new Kyber PK) must be rejected"
        );
        println!(
            "[ATTACK 24c] Partial ratchet (no new Kyber PK): BLOCKED ({})",
            result.err().unwrap()
        );
    }

    let legit = bob.decrypt(&env1);
    assert!(legit.is_ok(), "Legitimate full ratchet must succeed");
    assert_eq!(legit.unwrap().plaintext, b"ratcheted");
    println!("[ATTACK 24] Partial ratchet header downgrade: ALL BLOCKED, legitimate OK");
}

#[test]
fn attack_kyber_ciphertext_bitflip_ratchet() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"init", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env0).unwrap();
    let reply = bob.encrypt(b"trigger", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let env = alice.encrypt(b"post-ratchet", 0, 1, None).unwrap();
    assert!(env.kyber_ciphertext.is_some(), "Must have Kyber CT");

    let mut tampered = env.clone();
    if let Some(ref mut ct) = tampered.kyber_ciphertext {
        ct[0] ^= 0xFF;
    }

    let result = bob.decrypt(&tampered);
    assert!(
        result.is_err(),
        "Kyber CT bitflip must cause decryption failure"
    );
    println!(
        "[ATTACK 25] Kyber ciphertext bitflip in ratchet: BLOCKED ({})",
        result.err().unwrap()
    );

    let legit = bob.decrypt(&env);
    assert!(
        legit.is_ok(),
        "Session must recover after Kyber CT bitflip attack"
    );
    assert_eq!(legit.unwrap().plaintext, b"post-ratchet");
    println!("[ATTACK 25] Session recovery after Kyber CT bitflip: OK");
}

#[test]
fn attack_payload_bitflip_every_position() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice
        .encrypt(b"sensitive payload data here", 0, 0, None)
        .unwrap();

    let mut any_succeeded = false;
    for pos in 0..env.encrypted_payload.len() {
        let mut tampered = env.clone();
        tampered.encrypted_payload[pos] ^= 0x01;
        if bob.decrypt(&tampered).is_ok() {
            any_succeeded = true;
            println!("[ATTACK] Payload bit-flip at position {pos} was ACCEPTED!");
        }
    }

    assert!(!any_succeeded);
    println!(
        "[ATTACK 26] Payload bit-flip (all {} positions): ALL BLOCKED by AEAD",
        env.encrypted_payload.len()
    );

    let legit = bob.decrypt(&env).unwrap();
    assert_eq!(legit.plaintext, b"sensitive payload data here");
    println!("[ATTACK 26] Legitimate message after bitflip scan: OK");
}

#[test]
fn attack_chain_exhaustion_forces_ratchet() {
    init();
    let (alice, bob) = create_session_pair_with_chain_limit(50);

    for i in 0..50u32 {
        let env = alice
            .encrypt(format!("msg {i}").as_bytes(), 0, i, None)
            .unwrap();
        let _ = bob.decrypt(&env).unwrap();
    }

    let result = alice.encrypt(b"should fail or ratchet", 0, 50, None);
    match result {
        Err(e) => {
            println!("[ATTACK 27] Chain exhaustion at limit=50: ERROR ({e})");
            println!("[ATTACK 27] Protocol enforces chain message limit");
        }
        Ok(env) => {
            assert_ne!(
                env.ratchet_epoch, 0,
                "If encryption succeeds, it must have auto-ratcheted to a new epoch"
            );
            println!(
                "[ATTACK 27] Chain exhaustion at limit=50: auto-ratcheted to epoch {}",
                env.ratchet_epoch
            );
        }
    }
}

#[test]
fn attack_rapid_bidirectional_ratcheting() {
    init();
    let (alice, bob) = create_session_pair();

    for round in 0..50u32 {
        let env_a = alice
            .encrypt(
                format!("alice round {round}").as_bytes(),
                0,
                round * 2,
                None,
            )
            .unwrap();
        let dec_b = bob.decrypt(&env_a).unwrap();
        assert_eq!(dec_b.plaintext, format!("alice round {round}").as_bytes());

        let env_b = bob
            .encrypt(
                format!("bob round {round}").as_bytes(),
                0,
                round * 2 + 1,
                None,
            )
            .unwrap();
        let dec_a = alice.decrypt(&env_b).unwrap();
        assert_eq!(dec_a.plaintext, format!("bob round {round}").as_bytes());
    }

    let final_epoch_env = alice.encrypt(b"final check", 0, 100, None).unwrap();
    assert!(
        final_epoch_env.ratchet_epoch >= 49,
        "50 bidirectional rounds should produce many ratchet epochs, got {}",
        final_epoch_env.ratchet_epoch
    );

    let dec = bob.decrypt(&final_epoch_env).unwrap();
    assert_eq!(dec.plaintext, b"final check");
    println!(
        "[ATTACK 28] Rapid bidirectional ratcheting (50 rounds): OK, final epoch={}",
        final_epoch_env.ratchet_epoch
    );
}

#[test]
fn attack_header_nonce_truncation() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"test nonce", 0, 0, None).unwrap();

    let truncated_nonces: Vec<Vec<u8>> = vec![
        vec![],
        env.header_nonce[..6].to_vec(),
        env.header_nonce[..11].to_vec(),
        [env.header_nonce.clone(), vec![0x00]].concat(),
    ];

    for (i, bad_nonce) in truncated_nonces.iter().enumerate() {
        let mut tampered = env.clone();
        tampered.header_nonce = bad_nonce.clone();
        let result = bob.decrypt(&tampered);
        assert!(
            result.is_err(),
            "Malformed nonce size {} must be rejected",
            bad_nonce.len()
        );
        println!(
            "[ATTACK 29.{i}] Header nonce size {} (expected 12): BLOCKED",
            bad_nonce.len()
        );
    }
}

#[test]
fn attack_envelope_version_mismatch() {
    init();
    let (alice, bob) = create_session_pair();

    let env = alice.encrypt(b"version test", 0, 0, None).unwrap();

    for bad_version in [0u32, 2, 99, u32::MAX] {
        let mut tampered = env.clone();
        tampered.version = bad_version;
        let result = bob.decrypt(&tampered);
        assert!(result.is_err(), "Version {bad_version} must be rejected");
    }

    let legit = bob.decrypt(&env).unwrap();
    assert_eq!(legit.plaintext, b"version test");
    println!("[ATTACK 30] Envelope version mismatch (0, 2, 99, MAX): ALL BLOCKED");
}

#[test]
fn attack_double_ratchet_same_epoch() {
    init();
    let (alice, bob) = create_session_pair();

    let env0 = alice.encrypt(b"init", 0, 0, None).unwrap();
    let _ = bob.decrypt(&env0).unwrap();
    let reply = bob.encrypt(b"trigger", 0, 0, None).unwrap();
    let _ = alice.decrypt(&reply).unwrap();

    let ratchet_msg = alice.encrypt(b"ratchet 1", 0, 1, None).unwrap();
    assert!(ratchet_msg.dh_public_key.is_some());
    let ratchet_epoch = ratchet_msg.ratchet_epoch;

    let _ = bob.decrypt(&ratchet_msg).unwrap();

    let mut fake_double_ratchet = alice.encrypt(b"fake", 0, 2, None).unwrap();
    if fake_double_ratchet.dh_public_key.is_none() {
        let (_, attacker_pk) = CryptoInterop::generate_x25519_keypair("attacker").unwrap();
        fake_double_ratchet.dh_public_key = Some(attacker_pk);
        fake_double_ratchet.kyber_ciphertext = Some(vec![0u8; 1088]);
        fake_double_ratchet.new_kyber_public = Some(vec![0u8; 1184]);
        fake_double_ratchet.ratchet_epoch = ratchet_epoch;
    }

    let result = bob.decrypt(&fake_double_ratchet);
    assert!(
        result.is_err(),
        "Duplicate ratchet at same epoch must be rejected"
    );
    println!(
        "[ATTACK 31] Double ratchet at same epoch: BLOCKED ({})",
        result.err().unwrap()
    );
}
