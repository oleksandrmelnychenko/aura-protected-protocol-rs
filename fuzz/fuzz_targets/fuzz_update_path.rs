#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::proto::{GroupCommit, GroupUpdatePath};
use aura_protected_protocol::protocol::group::GroupSession;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    // Fuzz GroupUpdatePath decoding — must never panic
    let _ = GroupUpdatePath::decode(data);

    // Build a single-member group and feed it fuzzed commits that contain update paths
    let alice = match IdentityKeys::create(2) {
        Ok(ik) => ik,
        Err(_) => return,
    };

    let alice_session = match GroupSession::create(&alice, b"fuzz-up".to_vec()) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Try processing a fuzzed commit (which contains an update path)
    let _ = alice_session.process_commit(data);

    // Also try with a properly structured GroupCommit wrapping fuzzed update_path
    if let Ok(update_path) = GroupUpdatePath::decode(data) {
        let commit = GroupCommit {
            committer_leaf_index: 1,
            proposals: vec![],
            update_path: Some(update_path),
            confirmation_mac: vec![0u8; 32],
            epoch: 2,
            group_id: b"fuzz-up".to_vec(),
            committer_signature: vec![0u8; 64],
        };
        let mut commit_bytes = Vec::new();
        if commit.encode(&mut commit_bytes).is_ok() {
            let _ = alice_session.process_commit(&commit_bytes);
        }
    }
});
