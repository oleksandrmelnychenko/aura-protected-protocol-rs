#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::MessagePadding;

fuzz_target!(|data: &[u8]| {
    // Fuzz unpad with arbitrary bytes — must never panic
    let _ = MessagePadding::unpad(data);

    // Roundtrip: pad then unpad must recover original
    let padded = MessagePadding::pad(data);
    let recovered = MessagePadding::unpad(&padded)
        .expect("roundtrip unpad must succeed");
    assert_eq!(recovered, data, "pad/unpad roundtrip mismatch");
});
