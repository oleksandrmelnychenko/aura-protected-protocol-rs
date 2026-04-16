#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::protocol::group::SenderKeyChain;
use std::sync::Once;

static INIT: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct SenderKeyInput {
    base: [u8; 32],
    leaf_index: u32,
    target_gen: u32,
    chain_key: [u8; 32],
    start_gen: u32,
}

fuzz_target!(|input: SenderKeyInput| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let mut chain = match SenderKeyChain::new(input.leaf_index, input.base.to_vec()) {
        Ok(c) => c,
        Err(_) => return,
    };

    assert_eq!(chain.generation(), 0);

    for _ in 0..std::cmp::min(input.target_gen, 10) {
        match chain.next_message_key() {
            Ok((gen, key)) => {
                assert_eq!(key.len(), 32);
                assert!(gen < 100);
            }
            Err(_) => break,
        }
    }

    let mut chain2 = match SenderKeyChain::from_state(
        input.leaf_index,
        input.chain_key.to_vec(),
        input.start_gen,
    ) {
        Ok(c) => c,
        Err(_) => return,
    };

    let target = input.start_gen.saturating_add(input.target_gen.min(50));
    let _ = chain2.advance_to(target);
});
