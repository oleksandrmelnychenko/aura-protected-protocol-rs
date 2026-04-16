#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::AesGcm;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (key) + 12 (nonce) + 1 (ciphertext) bytes
    if data.len() < 45 {
        return;
    }

    let key = &data[..32];
    let nonce = &data[32..44];
    let ciphertext = &data[44..];
    let aad = b"fuzz-aad";

    // Fuzz decrypt with arbitrary ciphertext — must never panic
    let _ = AesGcm::decrypt(key, nonce, ciphertext, aad);

    // Roundtrip: encrypt then decrypt must recover original plaintext
    let plaintext = ciphertext;
    if let Ok(ct) = AesGcm::encrypt(key, nonce, plaintext, aad) {
        let recovered = AesGcm::decrypt(key, nonce, &ct, aad)
            .expect("roundtrip decrypt must succeed");
        assert_eq!(recovered, plaintext, "roundtrip mismatch");
    }
});
