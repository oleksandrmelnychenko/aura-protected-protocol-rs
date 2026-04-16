#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::protocol::group::tree_kem::TreeKem;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        CryptoInterop::initialize().unwrap();
    });

    if data.len() < 32 {
        return;
    }

    let path_secret = &data[..32];
    let _ = TreeKem::derive_node_keypairs(path_secret);

    if let Ok((x25519_priv, x25519_pub, kyber_sec, kyber_pub)) =
        TreeKem::derive_node_keypairs(path_secret)
    {
        let node_index = if data.len() >= 36 {
            u32::from_le_bytes([data[32], data[33], data[34], data[35]])
        } else {
            0
        };

        if let Ok(ct) =
            TreeKem::encrypt_path_secret(path_secret, &x25519_pub, &kyber_pub, node_index)
        {
            let recovered =
                TreeKem::decrypt_path_secret(&ct, &x25519_priv, &kyber_sec, node_index)
                    .expect("roundtrip decrypt must succeed");
            assert_eq!(recovered, path_secret, "path secret roundtrip mismatch");
        }
    }
});
