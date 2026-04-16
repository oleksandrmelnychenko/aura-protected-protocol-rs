#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::protocol::{NonceGenerator, NonceState};
use std::sync::Once;

static INIT: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct NonceInput {
    prefix: [u8; 8],
    counter: u64,
    max_counter: u64,
    message_indices: Vec<u16>,
}

fuzz_target!(|input: NonceInput| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let _ = NonceState::new(input.prefix, input.counter);

    let state = match NonceState::new(input.prefix, input.counter) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut gen = match NonceGenerator::from_state_with_limit(state, input.max_counter) {
        Ok(g) => g,
        Err(_) => return,
    };

    let mut prev_counter = gen.export_state().counter();
    for idx in input.message_indices.iter().take(100) {
        match gen.next(u64::from(*idx)) {
            Ok(_nonce) => {
                let cur = gen.export_state().counter();
                assert!(cur > prev_counter, "counter must be monotonic");
                prev_counter = cur;
            }
            Err(_) => break,
        }
    }
});
