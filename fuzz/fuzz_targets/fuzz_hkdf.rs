#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::HkdfSha256;

#[derive(Arbitrary, Debug)]
struct HkdfInput<'a> {
    ikm: &'a [u8],
    salt: &'a [u8],
    info: &'a [u8],
    out_len: u16,
}

fuzz_target!(|input: HkdfInput| {
    let out_len = input.out_len as usize;

    // Fuzz derive_key_bytes — must never panic, only return errors
    let _ = HkdfSha256::derive_key_bytes(input.ikm, out_len, input.salt, input.info);

    // Fuzz extract + expand separately
    let prk = HkdfSha256::extract(input.salt, input.ikm);
    let _ = HkdfSha256::expand(&prk, input.info, out_len);

    // Determinism: same input must produce same output
    if out_len > 0 && out_len <= 255 * 32 {
        if let Ok(a) = HkdfSha256::derive_key_bytes(input.ikm, out_len, input.salt, input.info) {
            let b = HkdfSha256::derive_key_bytes(input.ikm, out_len, input.salt, input.info)
                .expect("second call must also succeed");
            assert_eq!(*a, *b, "HKDF must be deterministic");
        }
    }
});
