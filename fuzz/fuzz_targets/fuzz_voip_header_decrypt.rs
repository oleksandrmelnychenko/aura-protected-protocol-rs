#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::protocol::voip::media_crypto::MediaCrypto;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 4 + 16 {
        return;
    }

    let key = &data[..32];
    let prefix: [u8; 4] = data[32..36].try_into().unwrap();
    let ciphertext = &data[36..];

    let _ = MediaCrypto::decrypt_header(key, &prefix, 0, ciphertext);
});
