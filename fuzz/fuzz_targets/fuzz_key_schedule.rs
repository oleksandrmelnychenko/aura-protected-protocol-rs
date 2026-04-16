#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::protocol::group::GroupKeySchedule;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    if data.len() < 32 {
        return;
    }

    let epoch_secret = &data[..32];
    let _ = GroupKeySchedule::derive_sub_keys_from_epoch_secret(epoch_secret);

    if data.len() >= 96 {
        let prev_init = &data[..32];
        let commit_secret = &data[32..64];
        let ctx_hash = &data[64..96];
        let _ = GroupKeySchedule::derive_epoch_keys(prev_init, commit_secret, ctx_hash, false);
        let _ = GroupKeySchedule::derive_epoch_keys(prev_init, commit_secret, ctx_hash, true);
        let _ = GroupKeySchedule::derive_sender_key_base(epoch_secret, 0, ctx_hash);
        let _ = GroupKeySchedule::compute_confirmation_mac(epoch_secret, ctx_hash);
    }

    let group_id = &data[..std::cmp::min(data.len(), 32)];
    let tree_hash = if data.len() >= 64 { &data[32..64] } else { epoch_secret };
    let _ = GroupKeySchedule::compute_group_context_hash(group_id, 0, tree_hash, &[]);

    if data.len() >= 96 {
        let psk = &data[32..64];
        let psk_nonce = &data[64..96];
        let _ = GroupKeySchedule::inject_psk(epoch_secret, psk, psk_nonce);
    }

    if data.len() >= 32 {
        let _ = GroupKeySchedule::derive_external_keypairs(epoch_secret);
    }

    if data.len() >= 64 {
        let a = GroupKeySchedule::derive_sub_keys_from_epoch_secret(epoch_secret);
        let b = GroupKeySchedule::derive_sub_keys_from_epoch_secret(epoch_secret);
        if let (Ok(a), Ok(b)) = (a, b) {
            assert_eq!(a.epoch_secret, b.epoch_secret, "key schedule must be deterministic");
        }
    }
});
