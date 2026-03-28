// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::pedantic, clippy::nursery)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

use ecliptix_protocol::api::{
    EcliptixGroupSession, EcliptixProtocol, EcliptixSession, EcliptixVoipSession,
    SealedStateCounterTracker, SealedStateSlot,
};
use ecliptix_protocol::crypto::CryptoInterop;
use proptest::collection::vec;
use proptest::prelude::*;
use prost::Message;

static INIT_ONCE: Once = Once::new();

fn init() {
    INIT_ONCE.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });
}

fn mutate_bytes(base: &[u8], ops: &[u8]) -> Vec<u8> {
    let mut data = if base.is_empty() {
        vec![0xA5]
    } else {
        base.to_vec()
    };
    let max_len = base.len().saturating_add(16).max(2);

    for chunk in ops.chunks(3).take(8) {
        let op = chunk[0];
        let arg1 = *chunk.get(1).unwrap_or(&0);
        let arg2 = chunk.get(2).copied().unwrap_or(1).max(1);
        match op % 5 {
            0 => {
                let idx = usize::from(arg1) % data.len();
                data[idx] ^= arg2;
            }
            1 => {
                let idx = usize::from(arg1) % data.len();
                data[idx] = data[idx].wrapping_add(arg2);
            }
            2 => {
                if data.len() > 1 {
                    let idx = usize::from(arg1) % data.len();
                    data.remove(idx);
                } else {
                    data.push(arg2);
                }
            }
            3 => {
                if data.len() < max_len {
                    let idx = usize::from(arg1) % (data.len() + 1);
                    data.insert(idx, arg2);
                } else {
                    let idx = usize::from(arg1) % data.len();
                    data[idx] ^= arg2;
                }
            }
            _ => {
                if data.len() > 1 {
                    let new_len = 1 + (usize::from(arg1) % data.len());
                    data.truncate(new_len);
                } else {
                    data[0] ^= arg2;
                }
            }
        }
    }

    if data == base {
        if let Some(first) = data.first_mut() {
            *first ^= 0x80;
        } else {
            data.push(0x80);
        }
    }
    data
}

fn create_session_sealed_state() -> Vec<u8> {
    let mut alice = EcliptixProtocol::new(5).unwrap();
    let mut bob = EcliptixProtocol::new(5).unwrap();
    let bob_bundle = bob.pre_key_bundle().unwrap();
    let (initiator, init_msg) = alice.begin_session(&bob_bundle).unwrap();
    let (responder, ack_msg) = bob.accept_session(&init_msg).unwrap();
    let alice_session = initiator.complete(&ack_msg).unwrap();
    let _bob_session = responder.complete().unwrap();
    alice_session.serialize(&[0x11; 32], 1).unwrap()
}

fn create_group_sealed_state() -> (Vec<u8>, zeroize::Zeroizing<Vec<u8>>) {
    let proto = EcliptixProtocol::new(5).unwrap();
    let ed_secret = proto.get_identity_ed25519_private_key_copy().unwrap();
    let session = proto.create_group(b"cred".to_vec()).unwrap();
    let _ct = session.encrypt(b"group baseline").unwrap();
    let sealed = session.serialize(&[0x22; 32], 1).unwrap();
    (sealed, ed_secret)
}

fn extract_voip_peer_material(bundle_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let bundle = ecliptix_protocol::proto::PreKeyBundle::decode(bundle_bytes).unwrap();
    (bundle.kyber_public, bundle.identity_ed25519_public)
}

fn create_voip_sealed_state() -> Vec<u8> {
    let alice = EcliptixProtocol::new(5).unwrap();
    let bob = EcliptixProtocol::new(5).unwrap();
    let (alice_kyber, _alice_ed25519) =
        extract_voip_peer_material(&alice.pre_key_bundle().unwrap());
    let (bob_kyber, _bob_ed25519) = extract_voip_peer_material(&bob.pre_key_bundle().unwrap());
    let (initiator, call_init) = alice.initiate_call(&bob_kyber, false, 512, 60).unwrap();
    let (_bob_session, call_accept) = bob.accept_call(&call_init, &alice_kyber).unwrap();
    let alice_session = alice.complete_call(initiator, &call_accept).unwrap();
    alice_session.export_sealed_state(&[0x33; 32], 1).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn session_mutated_sealed_state_is_rejected_without_panic(ops in vec(any::<u8>(), 1..24)) {
        init();
        let sealed = create_session_sealed_state();
        let mutated = mutate_bytes(&sealed, &ops);
        prop_assert_ne!(mutated.as_slice(), sealed.as_slice());

        let result = catch_unwind(AssertUnwindSafe(|| {
            EcliptixSession::deserialize(&mutated, &[0x11; 32], 0)
        }));
        prop_assert!(result.is_ok());
        prop_assert!(result.unwrap().is_err());
    }

    #[test]
    fn group_mutated_sealed_state_is_rejected_without_panic(ops in vec(any::<u8>(), 1..24)) {
        init();
        let (sealed, ed_secret) = create_group_sealed_state();
        let mutated = mutate_bytes(&sealed, &ops);
        prop_assert_ne!(mutated.as_slice(), sealed.as_slice());

        let result = catch_unwind(AssertUnwindSafe(|| {
            EcliptixGroupSession::deserialize(&mutated, &[0x22; 32], ed_secret, 0)
        }));
        prop_assert!(result.is_ok());
        prop_assert!(result.unwrap().is_err());
    }

    #[test]
    fn voip_mutated_sealed_state_is_rejected_without_panic(ops in vec(any::<u8>(), 1..24)) {
        init();
        let sealed = create_voip_sealed_state();
        let mutated = mutate_bytes(&sealed, &ops);
        prop_assert_ne!(mutated.as_slice(), sealed.as_slice());

        let result = catch_unwind(AssertUnwindSafe(|| {
            EcliptixVoipSession::from_sealed_state(&mutated, &[0x33; 32], 0)
        }));
        prop_assert!(result.is_ok());
        prop_assert!(result.unwrap().is_err());
    }

    #[test]
    fn tracker_deserialize_random_bytes_never_panics(bytes in vec(any::<u8>(), 0..128)) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = SealedStateCounterTracker::deserialize(&bytes);
        }));
        prop_assert!(result.is_ok());
    }

    #[test]
    fn slot_deserialize_random_bytes_never_panics(bytes in vec(any::<u8>(), 0..256)) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = SealedStateSlot::deserialize(&bytes);
        }));
        prop_assert!(result.is_ok());
    }
}
