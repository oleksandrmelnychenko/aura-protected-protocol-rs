#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::{CryptoInterop, KyberInterop};
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let _ = KyberInterop::validate_public_key(data);
    let _ = KyberInterop::validate_ciphertext(data);

    if data.len() >= 1184 {
        let _ = KyberInterop::encapsulate(&data[..1184]);
    }

    if data.len() >= 32 {
        let _ = KyberInterop::generate_keypair_from_seed(data);
    }

    let (sk_handle, pk) = match KyberInterop::generate_keypair() {
        Ok(kp) => kp,
        Err(_) => return,
    };
    KyberInterop::validate_public_key(&pk).expect("generated key must be valid");

    let (ct, ss_enc) = match KyberInterop::encapsulate(&pk) {
        Ok(v) => v,
        Err(_) => return,
    };
    KyberInterop::validate_ciphertext(&ct).expect("valid ciphertext must pass");

    let ss_dec = KyberInterop::decapsulate(&ct, &sk_handle)
        .expect("decapsulate must succeed with valid ct");
    let enc_bytes = ss_enc.read_bytes(32).expect("read enc ss");
    let dec_bytes = ss_dec.read_bytes(32).expect("read dec ss");
    assert_eq!(enc_bytes, dec_bytes, "shared secrets must match");
});
