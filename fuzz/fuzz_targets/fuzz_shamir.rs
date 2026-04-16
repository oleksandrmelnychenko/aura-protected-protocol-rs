#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::{CryptoInterop, ShamirSecretSharing};
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    // --- Fuzz reconstruct with arbitrary share data ---
    // Try treating fuzz data as a single share + auth tag
    if data.len() >= 12 {
        let auth_key = [0x42u8; 32];
        let mid = data.len() / 2;
        let share1 = data[..mid].to_vec();
        let share2 = data[mid..].to_vec();
        let shares = vec![share1, share2];
        let _ = ShamirSecretSharing::reconstruct(&shares, &auth_key, 2);
    }

    // --- Fuzz reconstruct_serialized with arbitrary bytes ---
    if data.len() >= 10 {
        let auth_key = [0x42u8; 32];
        let share_len = 5 + 1; // magic(4) + x(1) + 1 byte secret
        let share_count = 3; // 2 data + 1 auth tag
        if data.len() >= share_len * share_count {
            let _ = ShamirSecretSharing::reconstruct_serialized(
                &data[..share_len * share_count],
                share_len,
                share_count,
                &auth_key,
                2,
            );
        }
    }

    // --- Roundtrip: split then reconstruct ---
    if !data.is_empty() && data.len() <= 256 {
        let auth_key = CryptoInterop::get_random_bytes(32);
        if let Ok(shares) = ShamirSecretSharing::split(data, 2, 3, &auth_key) {
            let recovered = ShamirSecretSharing::reconstruct(&shares, &auth_key, 2)
                .expect("roundtrip reconstruct must succeed");
            assert_eq!(recovered, data, "shamir roundtrip mismatch");
        }
    }
});
