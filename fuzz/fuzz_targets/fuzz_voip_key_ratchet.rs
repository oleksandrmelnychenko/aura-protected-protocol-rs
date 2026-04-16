#![no_main]
use libfuzzer_sys::fuzz_target;

use aura_protected_protocol::crypto::SecureMemoryHandle;
use aura_protected_protocol::protocol::voip::key_ratchet::MediaKeyRatchet;

fuzz_target!(|data: &[u8]| {
    if data.len() < 36 {
        return;
    }

    let key_bytes = &data[..32];
    let prefix: [u8; 4] = data[32..36].try_into().unwrap();
    let ops = &data[36..];

    let mut handle = match SecureMemoryHandle::allocate(32) {
        Ok(h) => h,
        Err(_) => return,
    };
    if handle.write(key_bytes).is_err() {
        return;
    }

    let mut ratchet = MediaKeyRatchet::new(handle, prefix);

    for &op in ops {
        match op % 3 {
            0 => { let _ = ratchet.advance(); }
            1 => {
                let target = ratchet.generation().saturating_add(u32::from(op >> 2) % 5);
                let _ = ratchet.advance_to(target);
            }
            _ => {
                let new_bytes = vec![op; 32];
                if let Ok(mut h) = SecureMemoryHandle::allocate(32) {
                    if h.write(&new_bytes).is_ok() {
                        ratchet.reset(h, prefix);
                    }
                }
            }
        }
    }
});
