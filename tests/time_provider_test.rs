// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(clippy::pedantic, clippy::nursery)]

use std::sync::{Arc, Mutex};

use ecliptix_protocol::api::EcliptixProtocol;
use ecliptix_protocol::core::constants::{
    EXTERNAL_JOIN_AUTH_VALIDITY_SECS, MAX_FUTURE_TIMESTAMP_SKEW_SECS,
};
use ecliptix_protocol::core::errors::ProtocolError;
use ecliptix_protocol::crypto::CryptoInterop;
use ecliptix_protocol::identity::IdentityKeys;
use ecliptix_protocol::interfaces::ITimeProvider;
use ecliptix_protocol::proto::{OneTimePreKey, PreKeyBundle};
use ecliptix_protocol::protocol::group::GroupSecurityPolicy;
use ecliptix_protocol::protocol::{HandshakeInitiator, HandshakeResponder, Session};
use prost::Message;

#[derive(Debug)]
struct TestTimeProvider {
    now_unix: Mutex<u64>,
}

impl TestTimeProvider {
    const fn new(now_unix: u64) -> Self {
        Self {
            now_unix: Mutex::new(now_unix),
        }
    }

    fn set(&self, now_unix: u64) {
        *self.now_unix.lock().unwrap() = now_unix;
    }

    fn get(&self) -> u64 {
        *self.now_unix.lock().unwrap()
    }
}

impl ITimeProvider for TestTimeProvider {
    fn now_unix_secs(&self) -> Result<u64, ProtocolError> {
        Ok(self.get())
    }
}

fn init() {
    CryptoInterop::initialize().expect("crypto init");
}

fn encode_pre_key_bundle(identity: &IdentityKeys) -> PreKeyBundle {
    let bundle = identity.create_public_bundle().unwrap();
    let one_time_pre_keys = bundle
        .one_time_pre_keys()
        .iter()
        .map(|opk| OneTimePreKey {
            one_time_pre_key_id: opk.id(),
            public_key: opk.public_key_vec(),
        })
        .collect();

    PreKeyBundle {
        version: ecliptix_protocol::core::constants::PROTOCOL_VERSION,
        identity_ed25519_public: bundle.identity_ed25519_public().to_vec(),
        identity_x25519_public: bundle.identity_x25519_public().to_vec(),
        identity_x25519_signature: bundle.identity_x25519_signature().to_vec(),
        signed_pre_key_id: bundle.signed_pre_key_id(),
        signed_pre_key_public: bundle.signed_pre_key_public().to_vec(),
        signed_pre_key_signature: bundle.signed_pre_key_signature().to_vec(),
        one_time_pre_keys,
        kyber_public: bundle.kyber_public().unwrap_or(&[]).to_vec(),
    }
}

fn create_session_pair(
    time_provider: Arc<TestTimeProvider>,
) -> Result<(Session, Session), ProtocolError> {
    let mut alice = IdentityKeys::create(8)?;
    let mut bob = IdentityKeys::create(8)?;
    let bob_bundle = encode_pre_key_bundle(&bob);

    let initiator = HandshakeInitiator::start_with_time_provider(
        &mut alice,
        &bob_bundle,
        1000,
        time_provider.clone(),
    )?;
    let init_bytes = initiator.encoded_message().to_vec();
    let responder = HandshakeResponder::process_with_replay_guard_and_time_provider(
        &mut bob,
        &bob_bundle,
        &init_bytes,
        1000,
        None,
        time_provider,
    )?;
    let ack_bytes = responder.encoded_ack().to_vec();
    let bob_session = responder.finish()?;
    let alice_session = initiator.finish(&ack_bytes)?;
    Ok((alice_session, bob_session))
}

fn create_two_member_group(
    time_provider: Arc<TestTimeProvider>,
) -> (
    EcliptixProtocol,
    EcliptixProtocol,
    ecliptix_protocol::api::EcliptixGroupSession,
    ecliptix_protocol::api::EcliptixGroupSession,
) {
    let alice = EcliptixProtocol::new_with_time_provider(8, time_provider.clone()).unwrap();
    let bob = EcliptixProtocol::new_with_time_provider(8, time_provider).unwrap();
    let alice_group = alice
        .create_group_with_policy(
            b"alice".to_vec(),
            GroupSecurityPolicy {
                block_external_join: false,
                ..GroupSecurityPolicy::shield()
            },
        )
        .unwrap();
    let (bob_kp, bob_x25519_priv, bob_kyber_sec) =
        bob.generate_key_package(b"bob".to_vec()).unwrap();
    let (_commit, welcome) = alice_group.add_member(&bob_kp).unwrap();
    let bob_group = bob
        .join_group(&welcome, bob_x25519_priv, bob_kyber_sec)
        .unwrap();
    (alice, bob, alice_group, bob_group)
}

fn extract_kyber_public(bundle_bytes: &[u8]) -> Vec<u8> {
    PreKeyBundle::decode(bundle_bytes).unwrap().kyber_public
}

#[test]
fn session_ttl_uses_injected_time_provider() {
    init();
    let time_provider = Arc::new(TestTimeProvider::new(1_700_000_000));
    let (alice_session, _bob_session) = create_session_pair(time_provider.clone()).unwrap();

    alice_session.set_session_ttl(Some(60)).unwrap();
    assert!(!alice_session.is_expired().unwrap());

    time_provider.set(1_700_000_061);
    assert!(alice_session.is_expired().unwrap());
    assert!(alice_session.encrypt(b"expired", 1, 1, None).is_err());
}

#[test]
fn group_external_join_uses_injected_time_provider() {
    init();
    let initial_now = 1_710_000_000;
    let time_provider = Arc::new(TestTimeProvider::new(initial_now));
    let (_alice, _bob, alice_group, _bob_group) = create_two_member_group(time_provider.clone());
    let carol = EcliptixProtocol::new_with_time_provider(8, time_provider.clone()).unwrap();

    let public_state = alice_group.export_public_state().unwrap();
    let authorization = alice_group
        .authorize_external_join(
            &carol.identity_ed25519_public(),
            &carol.identity_x25519_public(),
            b"carol",
        )
        .unwrap();

    time_provider.set(initial_now + EXTERNAL_JOIN_AUTH_VALIDITY_SECS + 1);
    let result = carol.join_group_external(&public_state, &authorization, b"carol".to_vec());
    assert!(result.is_err());
}

#[test]
fn group_disappearing_messages_use_injected_time_provider() {
    init();
    let initial_now = 1_720_000_000;
    let time_provider = Arc::new(TestTimeProvider::new(initial_now));
    let (_alice, _bob, alice_group, bob_group) = create_two_member_group(time_provider.clone());

    let message = alice_group.encrypt_disappearing(b"secret", 30).unwrap();
    time_provider.set(initial_now + 31);
    assert!(bob_group.decrypt(&message).is_err());
}

#[test]
fn voip_uses_injected_time_provider_for_duration_and_consent_freshness() {
    init();
    let initial_now = 1_730_000_000;
    let time_provider = Arc::new(TestTimeProvider::new(initial_now));
    let alice = EcliptixProtocol::new_with_time_provider(8, time_provider.clone()).unwrap();
    let bob = EcliptixProtocol::new_with_time_provider(8, time_provider.clone()).unwrap();

    let bob_bundle = bob.pre_key_bundle().unwrap();
    let alice_bundle = alice.pre_key_bundle().unwrap();
    let bob_kyber_public = extract_kyber_public(&bob_bundle);
    let alice_kyber_public = extract_kyber_public(&alice_bundle);

    let (initiator, call_init) = alice
        .initiate_call(&bob_kyber_public, false, 32, 60)
        .unwrap();
    let (bob_session, call_accept) = bob.accept_call(&call_init, &alice_kyber_public).unwrap();
    let alice_session = alice.complete_call(initiator, &call_accept).unwrap();

    time_provider.set(initial_now + 120);
    assert_eq!(
        alice_session
            .get_call_statistics()
            .unwrap()
            .call_duration_secs,
        120
    );
    assert_eq!(
        bob_session
            .get_call_statistics()
            .unwrap()
            .call_duration_secs,
        120
    );

    let too_future = time_provider.get() + MAX_FUTURE_TIMESTAMP_SKEW_SECS + 1;
    assert!(alice
        .build_call_recording_consent_message(&alice_session, 1, too_future)
        .is_err());
}
