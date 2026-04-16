#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::core::errors::ProtocolError;
use aura_protected_protocol::crypto::{CryptoInterop, SecureMemoryHandle};
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::interfaces::IStateKeyProvider;
use aura_protected_protocol::proto::{OneTimePreKey, PreKeyBundle};
use aura_protected_protocol::protocol::{HandshakeInitiator, HandshakeResponder, Session};
use std::sync::Once;

static INIT: Once = Once::new();

struct DummyKeyProvider {
    key: [u8; 32],
}

impl IStateKeyProvider for DummyKeyProvider {
    fn get_state_encryption_key(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let mut handle = SecureMemoryHandle::allocate(32)?;
        handle.write(&self.key)?;
        Ok(handle)
    }
}

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let key_provider = DummyKeyProvider {
        key: [0x42u8; 32],
    };

    // Fuzz Session::from_sealed_state with arbitrary bytes — must never panic
    let _ = Session::from_sealed_state(data, &key_provider, 0);

    // Fuzz sealed_state_external_counter with arbitrary bytes
    let _ = Session::sealed_state_external_counter(data);

    // Roundtrip: create a real session, serialize, then deserialize fuzzed version
    if data.len() >= 16 {
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
        let mut bob_mut = bob;
        let init_bytes = initiator.encoded_message().to_vec();
        let responder =
            match HandshakeResponder::process(&mut bob_mut, &bob_bundle, &init_bytes, 1000) {
                Ok(r) => r,
                Err(_) => return,
            };
        let ack = responder.encoded_ack().to_vec();
        let _bob_session = match responder.finish() {
            Ok(s) => s,
            Err(_) => return,
        };
        let alice_session = match initiator.finish(&ack) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Serialize the real session, then try deserializing with some fuzz bytes mixed in
        if let Ok(sealed) = alice_session.export_sealed_state(&key_provider, 1) {
            // Valid roundtrip must work
            let _ = Session::from_sealed_state(&sealed, &key_provider, 0);

            // Corrupt the sealed state with fuzz data — must not panic
            let mut corrupted = sealed.clone();
            let offset = data[0] as usize % corrupted.len().max(1);
            let copy_len = data.len().min(corrupted.len() - offset);
            corrupted[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
            let _ = Session::from_sealed_state(&corrupted, &key_provider, 0);
        }
    }
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
    Some(PreKeyBundle {
        version: 1,
        identity_ed25519_public: lb.identity_ed25519_public().to_vec(),
        identity_x25519_public: lb.identity_x25519_public().to_vec(),
        signed_pre_key_id: lb.signed_pre_key_id(),
        signed_pre_key_public: lb.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: lb.signed_pre_key_signature().to_vec(),
        one_time_pre_keys: opks,
        kyber_public: lb.kyber_public().unwrap_or(&[]).to_vec(),
        identity_x25519_signature: lb.identity_x25519_signature().to_vec(),
    })
}
