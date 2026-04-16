#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::{CryptoInterop, MasterKeyDerivation};
use std::sync::Once;

static INIT: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct MkdInput {
    master_key: Vec<u8>,
    membership_id: String,
    out_len: u8,
}

fuzz_target!(|input: MkdInput| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let _ = MasterKeyDerivation::derive(
        &input.master_key,
        b"fuzz-context",
        input.membership_id.as_bytes(),
        input.out_len as usize,
    );

    let _ = MasterKeyDerivation::derive_ed25519_seed(&input.master_key, &input.membership_id);
    let _ = MasterKeyDerivation::derive_x25519_seed(&input.master_key, &input.membership_id);
    let _ = MasterKeyDerivation::derive_signed_pre_key_seed(&input.master_key, &input.membership_id);
    let _ = MasterKeyDerivation::derive_one_time_pre_key_seed(&input.master_key, &input.membership_id, 0);
    let _ = MasterKeyDerivation::derive_kyber_seed(&input.master_key, &input.membership_id);

    if input.master_key.len() >= 32 {
        let a = MasterKeyDerivation::derive_ed25519_seed(&input.master_key, &input.membership_id);
        let b = MasterKeyDerivation::derive_ed25519_seed(&input.master_key, &input.membership_id);
        if let (Ok(a), Ok(b)) = (a, b) {
            assert_eq!(*a, *b, "derivation must be deterministic");
        }
    }
});
