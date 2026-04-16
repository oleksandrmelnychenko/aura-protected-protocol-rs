#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
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
    let session = match GroupSession::create(&ik, b"fuzz".to_vec()) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = session.process_commit(data);
});
