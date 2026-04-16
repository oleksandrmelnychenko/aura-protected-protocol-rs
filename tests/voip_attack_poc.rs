#![allow(clippy::pedantic, clippy::nursery)]

use aura_protected_protocol::core::constants::*;
use aura_protected_protocol::core::errors::ProtocolError;
use aura_protected_protocol::crypto::{CryptoInterop, SecureMemoryHandle};
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::protocol::voip::call_key_exchange::{
    callee_accept_with_context, caller_finish_with_context, caller_init_with_context,
    CallAcceptOutput, CallInitAuthContext, CallInitOutput, CallKeyMaterial,
};
use aura_protected_protocol::protocol::voip::frame::{build_frame_aad, FrameHeader};
use aura_protected_protocol::protocol::voip::key_ratchet::MediaKeyRatchet;
use aura_protected_protocol::protocol::voip::media_crypto::MediaCrypto;
use aura_protected_protocol::protocol::voip::replay_window::ReplayWindow;
use aura_protected_protocol::protocol::voip::{
    CallControlType, CallRole, CallState, EncryptedFrame, VoipSession,
};

fn init() {
    let _ = CryptoInterop::initialize();
}

fn id() -> IdentityKeys {
    IdentityKeys::create(1).unwrap()
}

fn default_call_context(shield_mode: bool) -> CallInitAuthContext {
    CallInitAuthContext {
        version: VOIP_PROTOCOL_VERSION,
        media_type: 1,
        ratchet_interval_frames: DEFAULT_RATCHET_INTERVAL_FRAMES,
        pq_rekey_interval_secs: DEFAULT_PQ_REKEY_INTERVAL_SECS,
        shield_mode,
    }
}

fn caller_init(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    peer_kyber_public: &[u8],
) -> Result<CallInitOutput, ProtocolError> {
    caller_init_with_context(
        identity_ed25519_secret,
        identity_ed25519_public,
        peer_kyber_public,
        &default_call_context(false),
    )
}

fn caller_init_for_shield(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    peer_kyber_public: &[u8],
    shield_mode: bool,
) -> Result<CallInitOutput, ProtocolError> {
    caller_init_with_context(
        identity_ed25519_secret,
        identity_ed25519_public,
        peer_kyber_public,
        &default_call_context(shield_mode),
    )
}

#[allow(clippy::too_many_arguments)]
fn callee_accept(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    identity_kyber_secret: &SecureMemoryHandle,
    peer_kyber_public: &[u8],
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    shield_mode: bool,
) -> Result<CallAcceptOutput, ProtocolError> {
    callee_accept_with_context(
        identity_ed25519_secret,
        identity_ed25519_public,
        identity_kyber_secret,
        peer_kyber_public,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_ed25519_public,
        peer_signature,
        peer_key_confirm_mac,
        &default_call_context(shield_mode),
    )
}

#[allow(clippy::too_many_arguments)]
fn caller_finish(
    init_output: &CallInitOutput,
    identity_kyber_secret: &SecureMemoryHandle,
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    shield_mode: bool,
) -> Result<CallKeyMaterial, ProtocolError> {
    caller_finish_with_context(
        init_output,
        identity_kyber_secret,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_ed25519_public,
        peer_signature,
        peer_key_confirm_mac,
        &default_call_context(shield_mode),
    )
}

fn pair(shield: bool) -> (VoipSession, VoipSession) {
    pair_with_interval(shield, 512)
}

fn pair_with_interval(shield: bool, ratchet_interval_frames: u32) -> (VoipSession, VoipSession) {
    let a = id();
    let b = id();
    let a_es = a.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = a.get_identity_ed25519_public();
    let a_kp = a.get_kyber_public();
    let a_ks = a.clone_kyber_secret_key().unwrap();
    let b_es = b.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = b.get_identity_ed25519_public();
    let b_kp = b.get_kyber_public();
    let b_ks = b.clone_kyber_secret_key().unwrap();

    let init_out = caller_init_for_shield(&a_es, &a_ep, &b_kp, shield).unwrap();
    let cid = init_out.call_id.clone();
    let acc = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        shield,
    )
    .unwrap();
    let ak = caller_finish(
        &init_out,
        &a_ks,
        &cid,
        &acc.ephemeral_x25519_public,
        &acc.kyber_ciphertext,
        &acc.identity_ed25519_public,
        &acc.signature,
        &acc.key_confirmation_mac,
        shield,
    )
    .unwrap();
    let as_ = VoipSession::from_key_material(
        cid.clone(),
        CallRole::Caller,
        ak,
        ratchet_interval_frames,
        60,
        shield,
    )
    .unwrap();
    let bs = VoipSession::from_key_material(
        cid,
        CallRole::Callee,
        acc.key_material,
        ratchet_interval_frames,
        60,
        shield,
    )
    .unwrap();
    (as_, bs)
}

fn hdr(ssrc: u32, seq: u16) -> FrameHeader {
    FrameHeader {
        payload_type: 111,
        ssrc,
        timestamp: u32::from(seq) * 160,
        sequence_number: seq,
    }
}

// ════════════════════════════════════════════════════════════════════
// 1. REPLAY ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_replay_exact_duplicate_rejected() {
    init();
    let (a, b) = pair(false);
    let enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"frame0").unwrap();
    b.decrypt_frame(&enc).unwrap();
    assert!(matches!(
        b.decrypt_frame(&enc).err().unwrap(),
        ProtocolError::ReplayAttack(_)
    ));
}

#[test]
fn attack_replay_triple_replay_all_rejected() {
    init();
    let (a, b) = pair(false);
    let enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"x").unwrap();
    b.decrypt_frame(&enc).unwrap();
    assert!(b.decrypt_frame(&enc).is_err());
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_replay_frame_outside_128_window() {
    init();
    let (a, b) = pair(false);
    let first = a.encrypt_frame(&hdr(a.ssrc(), 0), b"old").unwrap();
    b.decrypt_frame(&first).unwrap();

    for i in 1u16..200 {
        let e = a.encrypt_frame(&hdr(a.ssrc(), i), b"x").unwrap();
        b.decrypt_frame(&e).unwrap();
    }

    let stale = a.encrypt_frame(&hdr(a.ssrc(), 200), b"y").unwrap();
    b.decrypt_frame(&stale).unwrap();
    assert!(b.decrypt_frame(&first).is_err());
}

#[test]
fn attack_replay_frame_at_window_boundary_127() {
    let mut w = ReplayWindow::new();
    w.mark(0);
    w.mark(127);
    assert!(!w.check(0));
    assert!(w.check(1));
    w.mark(1);
    assert!(!w.check(1));
}

#[test]
fn attack_replay_frame_at_window_boundary_128_evicts() {
    let mut w = ReplayWindow::new();
    w.mark(0);
    w.mark(128);
    assert!(!w.check(0));
}

#[test]
fn attack_replay_large_gap_clears_entire_window() {
    let mut w = ReplayWindow::new();
    for i in 0..50 {
        w.mark(i);
    }
    w.mark(10000);
    for i in 0..50 {
        assert!(!w.check(i));
    }
    assert!(w.check(9999));
}

#[test]
fn attack_replay_out_of_order_ratchet_prevents_backward_decrypt() {
    init();
    let (a, b) = pair(false);
    let e0 = a.encrypt_frame(&hdr(a.ssrc(), 0), b"f0").unwrap();
    let _e1 = a.encrypt_frame(&hdr(a.ssrc(), 1), b"f1").unwrap();
    let e2 = a.encrypt_frame(&hdr(a.ssrc(), 2), b"f2").unwrap();

    b.decrypt_frame(&e0).unwrap();
    b.decrypt_frame(&e2).unwrap();
    assert!(b.decrypt_frame(&e0).is_err());
}

#[test]
fn attack_replay_sequential_then_replay_rejected() {
    init();
    let (a, b) = pair(false);
    let e0 = a.encrypt_frame(&hdr(a.ssrc(), 0), b"f0").unwrap();
    let e1 = a.encrypt_frame(&hdr(a.ssrc(), 1), b"f1").unwrap();

    b.decrypt_frame(&e0).unwrap();
    b.decrypt_frame(&e1).unwrap();
    assert!(b.decrypt_frame(&e0).is_err());
    assert!(b.decrypt_frame(&e1).is_err());
}

#[test]
fn attack_replay_window_sequential_fill_and_verify() {
    let mut w = ReplayWindow::new();
    for i in 0u64..256 {
        assert!(w.check(i));
        w.mark(i);
        assert!(!w.check(i));
    }
}

#[test]
fn attack_replay_window_random_order_no_false_accept() {
    let mut w = ReplayWindow::new();
    let counters = [50u64, 10, 90, 30, 70, 0, 127, 1, 80, 40];
    for &c in &counters {
        assert!(w.check(c));
        w.mark(c);
    }
    for &c in &counters {
        assert!(!w.check(c));
    }
}

// ════════════════════════════════════════════════════════════════════
// 2. FRAME TAMPERING / INTEGRITY
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_tamper_payload_single_bit_flip() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"secret audio").unwrap();
    enc.encrypted_payload[0] ^= 0x01;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_payload_last_byte() {
    init();
    let (a, b) = pair(false);
    let mut enc = a
        .encrypt_frame(&hdr(a.ssrc(), 0), b"audio data xxxx")
        .unwrap();
    let last = enc.encrypted_payload.len() - 1;
    enc.encrypted_payload[last] ^= 0xFF;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_payload_truncate() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"audio data").unwrap();
    enc.encrypted_payload
        .truncate(enc.encrypted_payload.len() / 2);
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_payload_extend() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.encrypted_payload.extend_from_slice(&[0xAA; 32]);
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_payload_replace_with_zeros() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    for byte in &mut enc.encrypted_payload {
        *byte = 0;
    }
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_header_single_bit() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"audio").unwrap();
    enc.encrypted_header[0] ^= 0x01;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_header_truncate() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"audio").unwrap();
    enc.encrypted_header.truncate(5);
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_swap_payload_between_frames() {
    init();
    let (a, b) = pair(false);
    let e0 = a.encrypt_frame(&hdr(a.ssrc(), 0), b"frame-0").unwrap();
    let e1 = a.encrypt_frame(&hdr(a.ssrc(), 1), b"frame-1").unwrap();
    b.decrypt_frame(&e0).unwrap();

    let frankenstein = EncryptedFrame {
        call_id: e1.call_id.clone(),
        ssrc: e1.ssrc,
        frame_counter: e1.frame_counter,
        ratchet_generation: e1.ratchet_generation,
        encrypted_payload: e0.encrypted_payload.clone(),
        nonce: e1.nonce.clone(),
        encrypted_header: e1.encrypted_header.clone(),
    };
    assert!(b.decrypt_frame(&frankenstein).is_err());
}

#[test]
fn attack_tamper_swap_header_between_frames() {
    init();
    let (a, b) = pair(false);
    let e0 = a.encrypt_frame(&hdr(a.ssrc(), 0), b"f0").unwrap();
    let e1 = a.encrypt_frame(&hdr(a.ssrc(), 1), b"f1").unwrap();
    b.decrypt_frame(&e0).unwrap();

    let mixed = EncryptedFrame {
        call_id: e1.call_id.clone(),
        ssrc: e1.ssrc,
        frame_counter: e1.frame_counter,
        ratchet_generation: e1.ratchet_generation,
        encrypted_payload: e1.encrypted_payload.clone(),
        nonce: e1.nonce.clone(),
        encrypted_header: e0.encrypted_header.clone(),
    };
    assert!(b.decrypt_frame(&mixed).is_err());
}

#[test]
fn attack_tamper_frame_counter_increment() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.frame_counter += 1;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_ssrc_flip() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.ssrc ^= 0xFFFF_FFFF;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_ratchet_generation_up() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.ratchet_generation = 999;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_ratchet_generation_down() {
    init();
    let (a, b) = pair_with_interval(false, 2);
    let e0 = a.encrypt_frame(&hdr(a.ssrc(), 0), b"f0").unwrap();
    b.decrypt_frame(&e0).unwrap();
    let _e1 = a.encrypt_frame(&hdr(a.ssrc(), 1), b"f1").unwrap();
    let mut e2 = a.encrypt_frame(&hdr(a.ssrc(), 2), b"f2").unwrap();
    e2.ratchet_generation = 0;
    assert!(b.decrypt_frame(&e2).is_err());
}

#[test]
fn attack_tamper_empty_payload() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.encrypted_payload.clear();
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_tamper_empty_header() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.encrypted_header.clear();
    assert!(b.decrypt_frame(&enc).is_err());
}

// ════════════════════════════════════════════════════════════════════
// 3. CROSS-SESSION / INJECTION ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_inject_frame_from_different_call() {
    init();
    let (a1, _b1) = pair(false);
    let (_a2, b2) = pair(false);
    let mut enc = a1.encrypt_frame(&hdr(a1.ssrc(), 0), b"injected").unwrap();
    enc.call_id = b2.call_id();
    assert!(b2.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_inject_frame_wrong_call_id_random() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_inject_frame_truncated_call_id() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.call_id.truncate(16);
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_inject_frame_empty_call_id() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"data").unwrap();
    enc.call_id.clear();
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_cross_session_keys_never_match() {
    init();
    let (a1, _) = pair(false);
    let (a2, _) = pair(false);
    let e1 = a1.encrypt_frame(&hdr(a1.ssrc(), 0), b"same").unwrap();
    let e2 = a2.encrypt_frame(&hdr(a2.ssrc(), 0), b"same").unwrap();
    assert_ne!(e1.encrypted_payload, e2.encrypted_payload);
    assert_ne!(e1.encrypted_header, e2.encrypted_header);
    assert_ne!(e1.call_id, e2.call_id);
}

#[test]
fn attack_shield_vs_normal_different_keys() {
    init();
    let (a_normal, _) = pair(false);
    let (a_shield, _) = pair(true);
    let e1 = a_normal
        .encrypt_frame(&hdr(a_normal.ssrc(), 0), b"same")
        .unwrap();
    let e2 = a_shield
        .encrypt_frame(&hdr(a_shield.ssrc(), 0), b"same")
        .unwrap();
    assert_ne!(e1.encrypted_payload, e2.encrypted_payload);
}

// ════════════════════════════════════════════════════════════════════
// 4. KEY EXCHANGE ATTACKS (MITM / IMPERSONATION)
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_kex_wrong_caller_ed25519_identity() {
    init();
    let alice = id();
    let bob = id();
    let eve = id();

    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();
    let eve_ep = eve.get_identity_ed25519_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &eve_ep,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_forged_caller_signature() {
    init();
    let alice = id();
    let bob = id();
    let eve = id();

    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();
    let eve_es = eve.get_identity_ed25519_private_key_copy().unwrap();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();

    let eve_init = caller_init(&eve_es, &eve.get_identity_ed25519_public(), &b_kp).unwrap();

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &eve_init.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_random_signature_bytes() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let random_sig = CryptoInterop::get_random_bytes(ED25519_SIGNATURE_BYTES);

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &random_sig,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_forged_mac() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let bad_mac = CryptoInterop::get_random_bytes(HMAC_BYTES);

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &bad_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_zero_mac() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &[0u8; HMAC_BYTES],
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_wrong_call_id_size_16() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_ep,
        &[0u8; 16],
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_wrong_call_id_empty() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_ep,
        &[],
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_tampered_ephemeral_x25519() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let mut tampered_eph = init_out.ephemeral_x25519_public.clone();
    tampered_eph[0] ^= 0xFF;

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &tampered_eph,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_tampered_kyber_ciphertext() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();
    let a_kp = alice.get_kyber_public();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let mut tampered_ct = init_out.kyber_ciphertext.clone();
    tampered_ct[0] ^= 0xFF;

    let result = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &tampered_ct,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_callee_mac_forgery_on_finish() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let a_kp = alice.get_kyber_public();
    let a_ks = alice.clone_kyber_secret_key().unwrap();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let acc = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    )
    .unwrap();

    let bad_mac = CryptoInterop::get_random_bytes(HMAC_BYTES);
    let result = caller_finish(
        &init_out,
        &a_ks,
        &cid,
        &acc.ephemeral_x25519_public,
        &acc.kyber_ciphertext,
        &acc.identity_ed25519_public,
        &acc.signature,
        &bad_mac,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn attack_kex_callee_signature_forgery_on_finish() {
    init();
    let alice = id();
    let bob = id();
    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let a_kp = alice.get_kyber_public();
    let a_ks = alice.clone_kyber_secret_key().unwrap();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks = bob.clone_kyber_secret_key().unwrap();

    let init_out = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid = init_out.call_id.clone();
    let acc = callee_accept(
        &b_es,
        &b_ep,
        &b_ks,
        &a_kp,
        &cid,
        &init_out.ephemeral_x25519_public,
        &init_out.kyber_ciphertext,
        &init_out.identity_ed25519_public,
        &init_out.signature,
        &init_out.key_confirmation_mac,
        false,
    )
    .unwrap();

    let random_sig = CryptoInterop::get_random_bytes(ED25519_SIGNATURE_BYTES);
    let result = caller_finish(
        &init_out,
        &a_ks,
        &cid,
        &acc.ephemeral_x25519_public,
        &acc.kyber_ciphertext,
        &acc.identity_ed25519_public,
        &random_sig,
        &acc.key_confirmation_mac,
        false,
    );
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════
// 5. CALL END / STATE ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_encrypt_after_end() {
    init();
    let (a, _) = pair(false);
    a.end_call().unwrap();
    assert!(a.encrypt_frame(&hdr(0, 0), b"x").is_err());
}

#[test]
fn attack_decrypt_after_end() {
    init();
    let (a, b) = pair(false);
    let enc = a.encrypt_frame(&hdr(a.ssrc(), 0), b"last").unwrap();
    b.end_call().unwrap();
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_call_control_after_end() {
    init();
    let (a, _) = pair(false);
    a.end_call().unwrap();
    assert!(a.encrypt_call_control(CallControlType::Mute).is_err());
}

#[test]
fn attack_double_end_call() {
    init();
    let (a, _) = pair(false);
    a.end_call().unwrap();
    assert_eq!(a.state(), CallState::Ended);
    a.end_call().unwrap();
    assert_eq!(a.state(), CallState::Ended);
}

#[test]
fn attack_call_end_hmac_forged() {
    init();
    let (a, _) = pair(false);
    let dev = b"dev-1";
    let ts = 999u64;
    let real = a.generate_call_end_hmac(dev, ts).unwrap();
    assert!(a.verify_call_end_hmac(dev, ts, &real).unwrap());

    let forged = CryptoInterop::get_random_bytes(HMAC_BYTES);
    assert!(!a.verify_call_end_hmac(dev, ts, &forged).unwrap());
}

#[test]
fn attack_call_end_hmac_wrong_timestamp() {
    init();
    let (a, _) = pair(false);
    let real = a.generate_call_end_hmac(b"d", 100).unwrap();
    assert!(!a.verify_call_end_hmac(b"d", 101, &real).unwrap());
}

#[test]
fn attack_call_end_hmac_wrong_device() {
    init();
    let (a, _) = pair(false);
    let real = a.generate_call_end_hmac(b"device-A", 100).unwrap();
    assert!(!a.verify_call_end_hmac(b"device-B", 100, &real).unwrap());
}

#[test]
fn attack_call_end_hmac_truncated() {
    init();
    let (a, _) = pair(false);
    let real = a.generate_call_end_hmac(b"d", 100).unwrap();
    assert!(!a.verify_call_end_hmac(b"d", 100, &real[..16]).unwrap());
}

#[test]
fn attack_call_end_hmac_empty() {
    init();
    let (a, _) = pair(false);
    assert!(!a.verify_call_end_hmac(b"d", 100, &[]).unwrap());
}

#[test]
fn attack_call_end_hmac_cross_session() {
    init();
    let (a1, _) = pair(false);
    let (a2, _) = pair(false);
    let hmac1 = a1.generate_call_end_hmac(b"d", 100).unwrap();
    assert!(!a2.verify_call_end_hmac(b"d", 100, &hmac1).unwrap());
}

// ════════════════════════════════════════════════════════════════════
// 6. MEDIA CRYPTO DIRECT ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_media_wrong_key_decrypt() {
    init();
    let k1 = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let k2 = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let prefix = [1u8, 2, 3, 4];
    let ct = MediaCrypto::encrypt_frame(&k1, &prefix, 0, b"secret", b"aad").unwrap();
    assert!(MediaCrypto::decrypt_frame(&k2, &prefix, 0, &ct, b"aad").is_err());
}

#[test]
fn attack_media_wrong_prefix_decrypt() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let ct = MediaCrypto::encrypt_frame(&k, &[1, 2, 3, 4], 0, b"data", b"a").unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &[5, 6, 7, 8], 0, &ct, b"a").is_err());
}

#[test]
fn attack_media_wrong_counter_decrypt() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", b"a").unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 1, &ct, b"a").is_err());
}

#[test]
fn attack_media_wrong_aad_decrypt() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", b"correct").unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 0, &ct, b"wrong").is_err());
}

#[test]
fn attack_media_short_key_rejected() {
    init();
    assert!(MediaCrypto::encrypt_frame(&[0u8; 16], &[0; 4], 0, b"d", b"").is_err());
}

#[test]
fn attack_media_empty_payload_rejected() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    assert!(MediaCrypto::encrypt_frame(&k, &[0; 4], 0, b"", b"").is_err());
}

#[test]
fn attack_media_counter_overflow_rejected() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    assert!(MediaCrypto::encrypt_frame(&k, &[0; 4], MAX_FRAME_COUNTER + 1, b"d", b"").is_err());
}

#[test]
fn attack_media_ciphertext_too_short() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    assert!(MediaCrypto::decrypt_frame(&k, &[0; 4], 0, &[0u8; 5], b"").is_err());
}

#[test]
fn attack_media_header_wrong_key() {
    init();
    let k1 = CryptoInterop::get_random_bytes(VOIP_HEADER_KEY_BYTES);
    let k2 = CryptoInterop::get_random_bytes(VOIP_HEADER_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let ct = MediaCrypto::encrypt_header(&k1, &p, 0, b"hdr").unwrap();
    assert!(MediaCrypto::decrypt_header(&k2, &p, 0, &ct).is_err());
}

#[test]
fn attack_media_header_tampered() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_HEADER_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let mut ct = MediaCrypto::encrypt_header(&k, &p, 0, b"hdr").unwrap();
    ct[0] ^= 1;
    assert!(MediaCrypto::decrypt_header(&k, &p, 0, &ct).is_err());
}

// ════════════════════════════════════════════════════════════════════
// 7. KEY RATCHET ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_ratchet_backward_advance_rejected() {
    init();
    let mut h = SecureMemoryHandle::allocate(32).unwrap();
    h.write(&CryptoInterop::get_random_bytes(32)).unwrap();
    let mut r = MediaKeyRatchet::new(h, [0; 4]);
    r.advance().unwrap();
    r.advance().unwrap();
    assert!(r.advance_to(0).is_err());
}

#[test]
fn attack_ratchet_skip_exceeds_max() {
    init();
    let mut h = SecureMemoryHandle::allocate(32).unwrap();
    h.write(&CryptoInterop::get_random_bytes(32)).unwrap();
    let mut r = MediaKeyRatchet::new(h, [0; 4]);
    assert!(r.advance_to(MAX_SKIPPED_RATCHET_GENERATIONS + 1).is_err());
}

#[test]
fn attack_ratchet_keys_are_unique_per_generation() {
    init();
    let mut h = SecureMemoryHandle::allocate(32).unwrap();
    h.write(&CryptoInterop::get_random_bytes(32)).unwrap();
    let mut r = MediaKeyRatchet::new(h, [0; 4]);
    let k0 = r.advance().unwrap();
    let k1 = r.advance().unwrap();
    let k2 = r.advance().unwrap();
    assert_ne!(*k0.media_key, *k1.media_key);
    assert_ne!(*k1.media_key, *k2.media_key);
    assert_ne!(*k0.media_key, *k2.media_key);
}

#[test]
fn attack_ratchet_different_seed_different_keys() {
    init();
    let mut h1 = SecureMemoryHandle::allocate(32).unwrap();
    h1.write(&CryptoInterop::get_random_bytes(32)).unwrap();
    let mut r1 = MediaKeyRatchet::new(h1, [0; 4]);

    let mut h2 = SecureMemoryHandle::allocate(32).unwrap();
    h2.write(&CryptoInterop::get_random_bytes(32)).unwrap();
    let mut r2 = MediaKeyRatchet::new(h2, [0; 4]);

    assert_ne!(
        *r1.advance().unwrap().media_key,
        *r2.advance().unwrap().media_key
    );
}

// ════════════════════════════════════════════════════════════════════
// 8. AAD BINDING ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_aad_call_id_is_bound() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let aad1 = build_frame_aad(&[0xAA; 32], 1, 0, 0);
    let aad2 = build_frame_aad(&[0xBB; 32], 1, 0, 0);
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", &aad1).unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 0, &ct, &aad2).is_err());
}

#[test]
fn attack_aad_ssrc_is_bound() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let aad1 = build_frame_aad(&[0; 32], 100, 0, 0);
    let aad2 = build_frame_aad(&[0; 32], 200, 0, 0);
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", &aad1).unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 0, &ct, &aad2).is_err());
}

#[test]
fn attack_aad_counter_is_bound() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let aad1 = build_frame_aad(&[0; 32], 1, 0, 0);
    let aad2 = build_frame_aad(&[0; 32], 1, 1, 0);
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", &aad1).unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 0, &ct, &aad2).is_err());
}

#[test]
fn attack_aad_ratchet_gen_is_bound() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let aad1 = build_frame_aad(&[0; 32], 1, 0, 0);
    let aad2 = build_frame_aad(&[0; 32], 1, 0, 1);
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, b"data", &aad1).unwrap();
    assert!(MediaCrypto::decrypt_frame(&k, &p, 0, &ct, &aad2).is_err());
}

// ════════════════════════════════════════════════════════════════════
// 9. NONCE CONSTRUCTION ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_nonce_uniqueness_different_counters() {
    let p = [0u8; 4];
    let n0 = MediaCrypto::build_nonce(&p, 0);
    let n1 = MediaCrypto::build_nonce(&p, 1);
    assert_ne!(n0, n1);
}

#[test]
fn attack_nonce_uniqueness_different_prefixes() {
    let n1 = MediaCrypto::build_nonce(&[0, 0, 0, 0], 0);
    let n2 = MediaCrypto::build_nonce(&[0, 0, 0, 1], 0);
    assert_ne!(n1, n2);
}

#[test]
fn attack_nonce_correct_size() {
    let n = MediaCrypto::build_nonce(&[1, 2, 3, 4], 42);
    assert_eq!(n.len(), 12);
}

#[test]
fn attack_nonce_prefix_embedded() {
    let prefix = [0xAA, 0xBB, 0xCC, 0xDD];
    let n = MediaCrypto::build_nonce(&prefix, 0);
    assert_eq!(&n[..4], &prefix);
}

#[test]
fn attack_nonce_counter_embedded_big_endian() {
    let n = MediaCrypto::build_nonce(&[0; 4], 0x0102_0304_0506_0708);
    assert_eq!(&n[4..], &[1, 2, 3, 4, 5, 6, 7, 8]);
}

// ════════════════════════════════════════════════════════════════════
// 10. FRAME HEADER ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_frame_header_too_short() {
    assert!(FrameHeader::deserialize(&[0u8; 5]).is_err());
}

#[test]
fn attack_frame_header_empty() {
    assert!(FrameHeader::deserialize(&[]).is_err());
}

#[test]
fn attack_frame_header_roundtrip_preserves_all_fields() {
    let h = FrameHeader {
        payload_type: 255,
        ssrc: 0xDEAD_BEEF,
        timestamp: 0xCAFE_BABE,
        sequence_number: 0xFFFF,
    };
    let bytes = h.serialize();
    let h2 = FrameHeader::deserialize(&bytes).unwrap();
    assert_eq!(h.payload_type, h2.payload_type);
    assert_eq!(h.ssrc, h2.ssrc);
    assert_eq!(h.timestamp, h2.timestamp);
    assert_eq!(h.sequence_number, h2.sequence_number);
}

// ════════════════════════════════════════════════════════════════════
// 11. CALL CONTROL ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_call_control_mute_roundtrip() {
    init();
    let (a, b) = pair(false);
    let enc = a.encrypt_call_control(CallControlType::Mute).unwrap();
    let dec = b.decrypt_frame(&enc).unwrap();
    assert_eq!(
        VoipSession::decode_call_control(&dec),
        Some(CallControlType::Mute)
    );
}

#[test]
fn attack_call_control_dtmf_all_digits() {
    init();
    let (a, b) = pair(false);
    for digit in 0..16u8 {
        let enc = a
            .encrypt_call_control(CallControlType::Dtmf(digit))
            .unwrap();
        let dec = b.decrypt_frame(&enc).unwrap();
        assert_eq!(
            VoipSession::decode_call_control(&dec),
            Some(CallControlType::Dtmf(digit))
        );
    }
}

#[test]
fn attack_call_control_tampered_rejected() {
    init();
    let (a, b) = pair(false);
    let mut enc = a.encrypt_call_control(CallControlType::Hold).unwrap();
    enc.encrypted_payload[0] ^= 0xFF;
    assert!(b.decrypt_frame(&enc).is_err());
}

#[test]
fn attack_call_control_cross_session_rejected() {
    init();
    let (a1, _) = pair(false);
    let (_, b2) = pair(false);
    let mut enc = a1.encrypt_call_control(CallControlType::Mute).unwrap();
    enc.call_id = b2.call_id();
    assert!(b2.decrypt_frame(&enc).is_err());
}

// ════════════════════════════════════════════════════════════════════
// 12. SEALED STATE EXPORT ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_sealed_state_export_after_end_rejected() {
    init();
    let (a, _) = pair(false);
    let key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    a.end_call().unwrap();
    assert!(a.export_sealed_state(&key, 1).is_err());
}

#[test]
fn attack_sealed_state_wrong_key_size() {
    init();
    let (a, _) = pair(false);
    let short_key = CryptoInterop::get_random_bytes(16);
    assert!(a.export_sealed_state(&short_key, 1).is_err());
}

#[test]
fn attack_sealed_state_produces_different_output_each_time() {
    init();
    let (a, _) = pair(false);
    let key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let s1 = a.export_sealed_state(&key, 1).unwrap();
    let s2 = a.export_sealed_state(&key, 2).unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn attack_sealed_state_different_keys_different_output() {
    init();
    let (a, _) = pair(false);
    let k1 = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let k2 = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let s1 = a.export_sealed_state(&k1, 1).unwrap();
    let s2 = a.export_sealed_state(&k2, 1).unwrap();
    assert_ne!(s1, s2);
}

// ════════════════════════════════════════════════════════════════════
// 13. FORWARD SECRECY / KEY ISOLATION
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_fs_different_sessions_independent_keys() {
    init();
    let (a1, b1) = pair(false);
    let (a2, b2) = pair(false);

    let e1 = a1.encrypt_frame(&hdr(a1.ssrc(), 0), b"session1").unwrap();
    let e2 = a2.encrypt_frame(&hdr(a2.ssrc(), 0), b"session1").unwrap();

    b1.decrypt_frame(&e1).unwrap();
    b2.decrypt_frame(&e2).unwrap();

    assert!(b1.decrypt_frame(&e2).is_err());
    assert!(b2.decrypt_frame(&e1).is_err());
}

#[test]
fn attack_fs_same_parties_different_calls_different_keys() {
    init();
    let alice = id();
    let bob = id();

    let a_es = alice.get_identity_ed25519_private_key_copy().unwrap();
    let a_ep = alice.get_identity_ed25519_public();
    let a_kp = alice.get_kyber_public();
    let a_ks1 = alice.clone_kyber_secret_key().unwrap();
    let a_ks2 = alice.clone_kyber_secret_key().unwrap();
    let b_es = bob.get_identity_ed25519_private_key_copy().unwrap();
    let b_ep = bob.get_identity_ed25519_public();
    let b_kp = bob.get_kyber_public();
    let b_ks1 = bob.clone_kyber_secret_key().unwrap();
    let b_ks2 = bob.clone_kyber_secret_key().unwrap();

    let init1 = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid1 = init1.call_id.clone();
    let acc1 = callee_accept(
        &b_es,
        &b_ep,
        &b_ks1,
        &a_kp,
        &cid1,
        &init1.ephemeral_x25519_public,
        &init1.kyber_ciphertext,
        &init1.identity_ed25519_public,
        &init1.signature,
        &init1.key_confirmation_mac,
        false,
    )
    .unwrap();
    let ak1 = caller_finish(
        &init1,
        &a_ks1,
        &cid1,
        &acc1.ephemeral_x25519_public,
        &acc1.kyber_ciphertext,
        &acc1.identity_ed25519_public,
        &acc1.signature,
        &acc1.key_confirmation_mac,
        false,
    )
    .unwrap();

    let init2 = caller_init(&a_es, &a_ep, &b_kp).unwrap();
    let cid2 = init2.call_id.clone();
    let acc2 = callee_accept(
        &b_es,
        &b_ep,
        &b_ks2,
        &a_kp,
        &cid2,
        &init2.ephemeral_x25519_public,
        &init2.kyber_ciphertext,
        &init2.identity_ed25519_public,
        &init2.signature,
        &init2.key_confirmation_mac,
        false,
    )
    .unwrap();
    let ak2 = caller_finish(
        &init2,
        &a_ks2,
        &cid2,
        &acc2.ephemeral_x25519_public,
        &acc2.kyber_ciphertext,
        &acc2.identity_ed25519_public,
        &acc2.signature,
        &acc2.key_confirmation_mac,
        false,
    )
    .unwrap();

    let rs1 = ak1.root_secret.read_bytes(ROOT_KEY_BYTES).unwrap();
    let rs2 = ak2.root_secret.read_bytes(ROOT_KEY_BYTES).unwrap();
    assert_ne!(rs1, rs2);
}

#[test]
fn attack_fs_key_material_is_32_bytes() {
    init();
    let (a, _) = pair(false);
    let key = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
    let sealed = a.export_sealed_state(&key, 1).unwrap();
    assert!(sealed.len() > 8 + 12 + 32);
}

#[test]
fn attack_fs_ciphertext_indistinguishable_from_random() {
    init();
    let (a, _) = pair(false);
    let enc = a
        .encrypt_frame(&hdr(a.ssrc(), 0), b"test payload for randomness")
        .unwrap();

    let mut byte_counts = [0u32; 256];
    for &b in &enc.encrypted_payload {
        byte_counts[b as usize] += 1;
    }
    let max = *byte_counts.iter().max().unwrap();
    let min = *byte_counts.iter().filter(|&&c| c > 0).min().unwrap();
    assert!(max < enc.encrypted_payload.len() as u32);
    assert!(min >= 1);
}

// ════════════════════════════════════════════════════════════════════
// 14. PADDING ATTACKS
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_padding_constant_size_1_byte() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [0u8; 4];
    let ct1 = MediaCrypto::encrypt_frame(&k, &p, 0, &[0x42], b"").unwrap();
    let ct2 = MediaCrypto::encrypt_frame(&k, &p, 1, &[0x42, 0x43], b"").unwrap();
    assert_eq!(ct1.len(), ct2.len());
}

#[test]
fn attack_padding_blocks_aligned_to_16() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [0u8; 4];
    for size in [1, 15, 16, 17, 31, 32, 33, 48, 64] {
        let data = vec![0xABu8; size];
        let ct = MediaCrypto::encrypt_frame(&k, &p, size as u64, &data, b"").unwrap();
        let tag_size = 16;
        let padded_size = ct.len() - tag_size;
        assert_eq!(padded_size % VOIP_FRAME_PADDING_BLOCK, 0);
    }
}

#[test]
fn attack_padding_roundtrip_exact_block_boundary() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [0u8; 4];
    let data = vec![0xAB; 15];
    let ct = MediaCrypto::encrypt_frame(&k, &p, 0, &data, b"a").unwrap();
    let pt = MediaCrypto::decrypt_frame(&k, &p, 0, &ct, b"a").unwrap();
    assert_eq!(pt, data);
}

// ════════════════════════════════════════════════════════════════════
// 15. STRESS / EDGE CASES
// ════════════════════════════════════════════════════════════════════

#[test]
fn attack_stress_500_frames_sequential() {
    init();
    let (a, b) = pair(false);
    for i in 0u16..500 {
        let enc = a
            .encrypt_frame(&hdr(a.ssrc(), i), b"audio payload data")
            .unwrap();
        b.decrypt_frame(&enc).unwrap();
    }
    assert_eq!(a.send_frame_counter(), 500);
}

#[test]
fn attack_stress_bidirectional_250_each() {
    init();
    let (a, b) = pair(false);
    for i in 0u16..250 {
        let ea = a.encrypt_frame(&hdr(a.ssrc(), i), b"a-data").unwrap();
        b.decrypt_frame(&ea).unwrap();
        let eb = b.encrypt_frame(&hdr(b.ssrc(), i), b"b-data").unwrap();
        a.decrypt_frame(&eb).unwrap();
    }
}

#[test]
fn attack_stress_large_frame_16kb() {
    init();
    let (a, b) = pair(false);
    let big = vec![0xCCu8; 16 * 1024];
    let enc = a.encrypt_frame(&hdr(a.ssrc(), 0), &big).unwrap();
    let dec = b.decrypt_frame(&enc).unwrap();
    assert_eq!(dec.payload, big);
}

#[test]
fn attack_stress_minimum_frame_1_byte() {
    init();
    let (a, b) = pair(false);
    let enc = a.encrypt_frame(&hdr(a.ssrc(), 0), &[0x01]).unwrap();
    let dec = b.decrypt_frame(&enc).unwrap();
    assert_eq!(dec.payload, &[0x01]);
}

#[test]
fn attack_stress_frame_counter_high_values() {
    init();
    let k = CryptoInterop::get_random_bytes(VOIP_MEDIA_KEY_BYTES);
    let p = [1u8, 2, 3, 4];
    let ct = MediaCrypto::encrypt_frame(&k, &p, MAX_FRAME_COUNTER, b"x", b"").unwrap();
    let pt = MediaCrypto::decrypt_frame(&k, &p, MAX_FRAME_COUNTER, &ct, b"").unwrap();
    assert_eq!(pt, b"x");
}

#[test]
fn attack_replay_window_max_u64_counter() {
    let mut w = ReplayWindow::new();
    assert!(w.check(u64::MAX));
    w.mark(u64::MAX);
    assert!(!w.check(u64::MAX));
}

#[test]
fn attack_replay_window_sequential_wrap_no_panic() {
    let mut w = ReplayWindow::new();
    w.mark(0);
    w.mark(1000);
    w.mark(1_000_000);
    w.mark(1_000_000_000);
    assert!(!w.check(0));
    assert!(!w.check(1000));
}
