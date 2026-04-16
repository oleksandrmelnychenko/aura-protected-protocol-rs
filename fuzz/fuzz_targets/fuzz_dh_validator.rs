#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::security::DhValidator;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let _ = DhValidator::validate_x25519_public_key(data);

    if data.len() >= 32 {
        let _ = DhValidator::validate_x25519_public_key(&data[..32]);
    }

    let (_, public) = match CryptoInterop::generate_x25519_keypair("fuzz") {
        Ok(kp) => kp,
        Err(_) => return,
    };
    DhValidator::validate_x25519_public_key(&public)
        .expect("valid keypair must pass validation");
});
