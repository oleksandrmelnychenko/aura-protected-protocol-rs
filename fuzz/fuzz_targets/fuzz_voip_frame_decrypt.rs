#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::protocol::voip::media_crypto::MediaCrypto;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 4 + 8 + 16 {
        return;
    }

    let key = &data[..32];
    let prefix: [u8; 4] = data[32..36].try_into().unwrap();
    let counter = u64::from_le_bytes(data[36..44].try_into().unwrap()) & 0xFFFF_FFFF_FFFF;
    let ciphertext = &data[44..];
    let aad = b"fuzz-aad";

    let _ = MediaCrypto::decrypt_frame(key, &prefix, counter, ciphertext, aad);
});
