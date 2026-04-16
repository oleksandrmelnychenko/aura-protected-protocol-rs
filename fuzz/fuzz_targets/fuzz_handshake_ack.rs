#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::{OneTimePreKey, PreKeyBundle};
use aura_protected_protocol::protocol::HandshakeInitiator;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let mut alice = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };
    let bob = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };

    let bob_bundle = match build_bundle(&bob) {
        Some(b) => b,
        None => return,
    };

    let initiator = match HandshakeInitiator::start(&mut alice, &bob_bundle, 1000) {
        Ok(i) => i,
        Err(_) => return,
    };

    // Feed fuzz data as the ack — must never panic
    let _ = initiator.finish(data);
});

fn build_bundle(ik: &IdentityKeys) -> Option<PreKeyBundle> {
    let lb = ik.create_public_bundle().ok()?;
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
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: opks,
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
    };
    Some(pb)
}
