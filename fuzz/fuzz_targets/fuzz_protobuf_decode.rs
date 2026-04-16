#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::proto::{
    EnvelopeMetadata, GroupCommit, GroupKeyPackage, GroupMessage, GroupWelcome, HandshakeAck,
    HandshakeInit, PreKeyBundle, ProtocolState, SealedState, SecureEnvelope,
};

fuzz_target!(|data: &[u8]| {
    // Attempt to decode every protocol message type from raw fuzz bytes.
    // None of these should panic — they must return Ok or Err cleanly.

    let _ = PreKeyBundle::decode(data);
    let _ = SecureEnvelope::decode(data);
    let _ = EnvelopeMetadata::decode(data);
    let _ = HandshakeInit::decode(data);
    let _ = HandshakeAck::decode(data);
    let _ = SealedState::decode(data);
    let _ = ProtocolState::decode(data);

    // Group protocol messages
    let _ = GroupKeyPackage::decode(data);
    let _ = GroupWelcome::decode(data);
    let _ = GroupCommit::decode(data);
    let _ = GroupMessage::decode(data);

    // Roundtrip: if decode succeeds, re-encoding and decoding must match
    if let Ok(bundle) = PreKeyBundle::decode(data) {
        let mut buf = Vec::new();
        bundle.encode(&mut buf).expect("re-encode must succeed");
        let roundtrip = PreKeyBundle::decode(buf.as_slice())
            .expect("roundtrip decode must succeed");
        assert_eq!(bundle, roundtrip, "protobuf roundtrip mismatch");
    }

    if let Ok(envelope) = SecureEnvelope::decode(data) {
        let mut buf = Vec::new();
        envelope.encode(&mut buf).expect("re-encode must succeed");
        let roundtrip = SecureEnvelope::decode(buf.as_slice())
            .expect("roundtrip decode must succeed");
        assert_eq!(envelope, roundtrip, "protobuf roundtrip mismatch");
    }
});
