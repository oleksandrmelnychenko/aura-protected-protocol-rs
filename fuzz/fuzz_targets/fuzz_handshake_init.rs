#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::PreKeyBundle;
use aura_protected_protocol::protocol::HandshakeResponder;
use prost::Message;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let mut bob_ik = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };
    let bundle_bytes = match build_bundle(&bob_ik) {
        Some(b) => b,
        None => return,
    };
    let bundle = match PreKeyBundle::decode(bundle_bytes.as_slice()) {
        Ok(b) => b,
        Err(_) => return,
    };

    let _ = HandshakeResponder::process(&mut bob_ik, &bundle, data, 1000);
});

fn build_bundle(ik: &IdentityKeys) -> Option<Vec<u8>> {
    let lb = ik.create_public_bundle().ok()?;
    let opks: Vec<aura_protected_protocol::proto::OneTimePreKey> = lb
        .one_time_pre_keys()
        .iter()
        .map(|o| aura_protected_protocol::proto::OneTimePreKey {
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
    let mut buf = Vec::new();
    pb.encode(&mut buf).ok()?;
    Some(buf)
}
