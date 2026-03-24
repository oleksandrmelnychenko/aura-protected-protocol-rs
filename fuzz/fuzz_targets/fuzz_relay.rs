#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::api::relay::{
    self, GroupMemberRecord, GroupRoster,
};
use ecliptix_protocol::crypto::CryptoInterop;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    let roster = GroupRoster::new(
        b"fuzz-group".to_vec(),
        GroupMemberRecord {
            leaf_index: 0,
            identity_ed25519_public: vec![1u8; 32],
            identity_x25519_public: vec![2u8; 32],
            credential: b"fuzz".to_vec(),
        },
    );

    let _ = relay::validate_commit_for_relay_strict(data, &roster, &roster.members[0].identity_ed25519_public);
    let _ = relay::validate_group_message_for_relay_strict(
        data,
        &roster,
        0,
        &roster.members[0].identity_ed25519_public,
    );
    let _ = relay::validate_key_package_for_storage(data);
    let _ = relay::extract_welcome_target(data);
    let _ = relay::validate_crypto_envelope(data);
});
