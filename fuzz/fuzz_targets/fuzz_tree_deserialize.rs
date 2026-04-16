#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::proto::GroupTreeNode;
use aura_protected_protocol::protocol::group::RatchetTree;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let mut nodes = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        match GroupTreeNode::decode(&data[offset..]) {
            Ok(node) => {
                offset += node.encoded_len();
                if offset == 0 {
                    break;
                }
                nodes.push(node);
                if nodes.len() >= 64 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if !nodes.is_empty() {
        if let Ok(tree) = RatchetTree::from_public_proto(&nodes) {
            let _ = tree.tree_hash();
            let _ = tree.leaf_count();
            let _ = tree.member_count();
            let exported = tree.export_public();
            if let Ok(tree2) = RatchetTree::from_public_proto(&exported) {
                assert_eq!(tree2.leaf_count(), tree.leaf_count(), "roundtrip leaf count mismatch");
            }
        }
    }
});
