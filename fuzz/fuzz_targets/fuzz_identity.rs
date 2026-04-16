#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    // Fuzz create_from_master_key with arbitrary seed and membership_id
    if data.len() >= 32 {
        let seed = &data[..32];
        let membership_id_bytes = &data[32..];
        let membership_id = String::from_utf8_lossy(membership_id_bytes);

        let _ = IdentityKeys::create_from_master_key(seed, &membership_id, 2);
    }

    // Fuzz verify_remote_spk_signature with arbitrary bytes
    if data.len() >= 128 {
        let identity_ed25519 = &data[..32];
        let spk_public = &data[32..64];
        let spk_signature = &data[64..128];
        let _ =
            IdentityKeys::verify_remote_spk_signature(identity_ed25519, spk_public, spk_signature);
    }

    // Fuzz verify_remote_identity_x25519_signature with arbitrary bytes
    if data.len() >= 128 {
        let identity_ed25519 = &data[..32];
        let x25519_public = &data[32..64];
        let x25519_signature = &data[64..128];
        let _ = IdentityKeys::verify_remote_identity_x25519_signature(
            identity_ed25519,
            x25519_public,
            x25519_signature,
        );
    }

    // Fuzz create + bundle generation with varying OPK counts
    if !data.is_empty() {
        let opk_count = (data[0] % 5) as u32;
        if let Ok(ik) = IdentityKeys::create(opk_count) {
            let _ = ik.create_public_bundle();

            // Fuzz OPK lookup with arbitrary IDs
            if data.len() >= 5 {
                let fuzz_id =
                    u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
                let _ = ik.find_one_time_pre_key_by_id(fuzz_id);
                let _ = ik.get_one_time_pre_key_private_by_id(fuzz_id);
                let _ = ik.consume_one_time_pre_key_by_id(fuzz_id);
            }

            // Fuzz decapsulate_kyber_ciphertext with arbitrary bytes
            if data.len() > 5 {
                let _ = ik.decapsulate_kyber_ciphertext(&data[5..]);
            }
        }
    }
});
