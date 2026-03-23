#![no_main]
use libfuzzer_sys::fuzz_target;

use ecliptix_protocol::protocol::voip::frame::FrameHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = FrameHeader::deserialize(data) {
        let serialized = header.serialize();
        let roundtrip = FrameHeader::deserialize(&serialized).expect("roundtrip must succeed");
        assert_eq!(header.payload_type, roundtrip.payload_type);
        assert_eq!(header.ssrc, roundtrip.ssrc);
        assert_eq!(header.timestamp, roundtrip.timestamp);
        assert_eq!(header.sequence_number, roundtrip.sequence_number);
    }
});
