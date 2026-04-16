#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::core::constants::*;
use aura_protected_protocol::crypto::CryptoInterop;
use aura_protected_protocol::identity::IdentityKeys;
use aura_protected_protocol::protocol::voip::call_key_exchange::{sign_rekey_material, verify_rekey_signature};

fn take_bytes(data: &[u8], offset: usize, max_len: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let len = usize::from(data[offset % data.len()]) % (max_len + 1);
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(data[(offset + 1 + i) % data.len()]);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let _ = CryptoInterop::initialize();
    let Ok(id) = IdentityKeys::create(333) else {
        return;
    };
    let Ok(secret) = id.get_identity_ed25519_private_key_copy() else {
        return;
    };
    let public = id.get_identity_ed25519_public();

    let call_id = take_bytes(data, 0, CALL_ID_BYTES * 2);
    let mut eph = take_bytes(data, 1, X25519_PUBLIC_KEY_BYTES * 2);
    let mut kyber_ct = take_bytes(data, 2, KYBER_CIPHERTEXT_BYTES * 2);
    let mut signature = take_bytes(data, 3, ED25519_SIGNATURE_BYTES * 2);

    if data.len() >= 8 {
        let gen_bytes = [data[4], data[5], data[6], data[7]];
        let generation = u32::from_le_bytes(gen_bytes);

        if data[0] & 1 == 0 {
            eph = vec![0xAB; X25519_PUBLIC_KEY_BYTES];
        }
        if data[1] & 1 == 0 {
            kyber_ct = vec![0xCD; KYBER_CIPHERTEXT_BYTES];
        }
        if data[2] & 1 == 0 {
            let resigned = sign_rekey_material(&secret, &call_id, generation, &eph, &kyber_ct);
            if let Ok(signed) = resigned {
                signature = signed;
            }
        }

        let _ = verify_rekey_signature(&public, &call_id, generation, &eph, &kyber_ct, &signature);
    }
});
