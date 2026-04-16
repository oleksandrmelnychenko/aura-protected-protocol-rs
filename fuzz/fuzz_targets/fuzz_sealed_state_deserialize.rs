#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::protocol::group::GroupSession;
use std::sync::Once;
use zeroize::Zeroizing;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let key = [0x42u8; 32];
    let dummy_ed25519_secret = Zeroizing::new(vec![0u8; 64]);

    let _ = GroupSession::from_sealed_state(data, &key, dummy_ed25519_secret, 0);
});
