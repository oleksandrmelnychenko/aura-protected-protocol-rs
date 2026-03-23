#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::api::relay::validate_voip_envelope;

fuzz_target!(|data: &[u8]| {
    let _ = validate_voip_envelope(data);
});
