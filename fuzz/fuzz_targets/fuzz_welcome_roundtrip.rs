#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::core::constants::KYBER_SECRET_KEY_BYTES;
use aura_protected_protocol::crypto::{CryptoInterop, SecureMemoryHandle};
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::GroupWelcome;
use aura_protected_protocol::protocol::group::GroupSession;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    // Try decoding fuzz data as a GroupWelcome and process it
    if let Ok(welcome) = GroupWelcome::decode(data) {
        let ik = match IdentityKeys::create(2) {
            Ok(ik) => ik,
            Err(_) => return,
        };

        let x25519_priv = match SecureMemoryHandle::allocate(32) {
            Ok(mut h) => {
                let _ = h.write(&[0x42u8; 32]);
                h
            }
            Err(_) => return,
        };
        let kyber_sec = match SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES) {
            Ok(mut h) => {
                let _ = h.write(&vec![0u8; KYBER_SECRET_KEY_BYTES]);
                h
            }
            Err(_) => return,
        };

        let ed25519_sk = match ik.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(_) => return,
        };

        // Re-encode and process — must never panic
        let mut welcome_bytes = Vec::new();
        if welcome.encode(&mut welcome_bytes).is_ok() {
            let _ = GroupSession::from_welcome(
                &welcome_bytes,
                x25519_priv,
                kyber_sec,
                &ik.get_identity_ed25519_public(),
                &ik.get_identity_x25519_public(),
                ed25519_sk,
            );
        }
    }
});
