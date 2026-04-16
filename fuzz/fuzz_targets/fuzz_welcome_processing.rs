#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::{SecureMemoryHandle, CryptoInterop};
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::protocol::group::GroupSession;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let ik = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };
    let x25519_priv = match SecureMemoryHandle::allocate(32) {
        Ok(mut h) => {
            let _ = h.write(&[0u8; 32]);
            h
        }
        Err(_) => return,
    };
    let kyber_sec = match SecureMemoryHandle::allocate(2400) {
        Ok(mut h) => {
            let _ = h.write(&vec![0u8; 2400]);
            h
        }
        Err(_) => return,
    };

    let ed25519_sk = match ik.get_identity_ed25519_private_key_copy() {
        Ok(sk) => sk,
        Err(_) => return,
    };
    let _ = GroupSession::from_welcome(
        data,
        x25519_priv,
        kyber_sec,
        &ik.get_identity_ed25519_public(),
        &ik.get_identity_x25519_public(),
        ed25519_sk,
    );
});
