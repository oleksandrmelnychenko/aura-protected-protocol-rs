#![no_main]
use libfuzzer_sys::fuzz_target;
use prost::Message;

use aura_protected_protocol::proto::e2e::{
    AckEventsRequest, CryptoEnvelope, DeviceLinkCompleteRequest, DeviceLinkCompleteResponse,
    DeviceLinkInitRequest, FetchPendingEventsRequest, FetchPendingEventsResponse,
    GroupCommitEnvelope, KeyPackageFetchRequest, KeyPackageFetchResponse, KeyPackageUpload,
    PendingEvent, PreKeyBundleFetchRequest, PreKeyBundleFetchResponse, PreKeyBundleUpload,
    WelcomeEnvelope,
};

fuzz_target!(|data: &[u8]| {
    // Decode every E2E protobuf message type — none should panic
    let _ = CryptoEnvelope::decode(data);
    let _ = GroupCommitEnvelope::decode(data);
    let _ = WelcomeEnvelope::decode(data);
    let _ = FetchPendingEventsRequest::decode(data);
    let _ = FetchPendingEventsResponse::decode(data);
    let _ = PendingEvent::decode(data);
    let _ = AckEventsRequest::decode(data);
    let _ = KeyPackageUpload::decode(data);
    let _ = KeyPackageFetchRequest::decode(data);
    let _ = KeyPackageFetchResponse::decode(data);
    let _ = PreKeyBundleUpload::decode(data);
    let _ = PreKeyBundleFetchRequest::decode(data);
    let _ = PreKeyBundleFetchResponse::decode(data);
    let _ = DeviceLinkInitRequest::decode(data);
    let _ = DeviceLinkCompleteRequest::decode(data);
    let _ = DeviceLinkCompleteResponse::decode(data);

    // Roundtrip: if decode succeeds, re-encode and re-decode must match
    if let Ok(envelope) = CryptoEnvelope::decode(data) {
        let mut buf = Vec::new();
        envelope.encode(&mut buf).expect("re-encode must succeed");
        let rt = CryptoEnvelope::decode(buf.as_slice()).expect("roundtrip decode must succeed");
        assert_eq!(envelope, rt, "CryptoEnvelope roundtrip mismatch");
    }

    if let Ok(commit_env) = GroupCommitEnvelope::decode(data) {
        let mut buf = Vec::new();
        commit_env.encode(&mut buf).expect("re-encode must succeed");
        let rt =
            GroupCommitEnvelope::decode(buf.as_slice()).expect("roundtrip decode must succeed");
        assert_eq!(commit_env, rt, "GroupCommitEnvelope roundtrip mismatch");
    }

    if let Ok(welcome_env) = WelcomeEnvelope::decode(data) {
        let mut buf = Vec::new();
        welcome_env
            .encode(&mut buf)
            .expect("re-encode must succeed");
        let rt = WelcomeEnvelope::decode(buf.as_slice()).expect("roundtrip decode must succeed");
        assert_eq!(welcome_env, rt, "WelcomeEnvelope roundtrip mismatch");
    }
});
