#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use ecliptix_protocol::crypto::{CryptoInterop, KyberInterop};
use ecliptix_protocol::proto::GroupProposal;
use ecliptix_protocol::protocol::group::membership;
use ecliptix_protocol::protocol::group::RatchetTree;
use std::sync::Once;

static INIT: Once = Once::new();

fn build_tree() -> Option<RatchetTree> {
    let (x_priv, x_pub) = CryptoInterop::generate_x25519_keypair("fuzz").ok()?;
    let (k_sec, k_pub) = KyberInterop::generate_keypair().ok()?;
    RatchetTree::new_single(
        x_pub,
        k_pub,
        x_priv,
        k_sec,
        vec![1u8; 32],
        vec![2u8; 32],
        b"fuzz".to_vec(),
        vec![],
    )
    .ok()
}

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let tree = match build_tree() {
        Some(t) => t,
        None => return,
    };

    let mut proposals = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        match GroupProposal::decode(&data[offset..]) {
            Ok(p) => {
                let len = p.encoded_len();
                offset += if len > 0 { len } else { 1 };
                proposals.push(p);
                if proposals.len() >= 16 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if !proposals.is_empty() {
        let _ = membership::validate_proposals(&tree, &proposals, 0);

        let mut tree_mut = match build_tree() {
            Some(t) => t,
            None => return,
        };
        let _ = membership::apply_proposals(&mut tree_mut, &proposals);
    }
});
