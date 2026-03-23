#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::protocol::voip::replay_window::ReplayWindow;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let mut window = ReplayWindow::new();

    for chunk in data.chunks_exact(8) {
        let counter = u64::from_le_bytes(chunk.try_into().unwrap());
        let accepted = window.check(counter);
        if accepted {
            window.mark(counter);
            assert!(!window.check(counter), "marked frame must be rejected on re-check");
        }
    }
});
