#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::proto::{CallInit, CallAccept, CallEnd, CallRekey, VoipEnvelope};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0] % 5;
    let payload = &data[1..];

    match selector {
        0 => { let _ = CallInit::decode(payload); }
        1 => { let _ = CallAccept::decode(payload); }
        2 => { let _ = CallEnd::decode(payload); }
        3 => { let _ = CallRekey::decode(payload); }
        4 => { let _ = VoipEnvelope::decode(payload); }
        _ => {}
    }
});
