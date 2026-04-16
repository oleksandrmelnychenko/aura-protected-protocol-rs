// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub mod relay;

use prost::Message;
use std::mem::size_of;
use zeroize::Zeroizing;

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, DEFAULT_MESSAGES_PER_CHAIN, MAX_BUFFER_SIZE,
    MAX_ENVELOPE_MESSAGE_SIZE, MAX_GROUP_MESSAGE_SIZE, MAX_HANDSHAKE_MESSAGE_SIZE,
    MAX_VOIP_SIGNAL_MESSAGE_SIZE, OPAQUE_ROOT_INFO, OPAQUE_SESSION_KEY_BYTES, PROTOCOL_VERSION,
};
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle, ShamirSecretSharing};
use crate::identity::IdentityKeys;
use crate::interfaces::{ITimeProvider, StaticStateKeyProvider, SystemTimeProvider};
use crate::proto::{GroupKeyPackage, OneTimePreKey, PreKeyBundle, SecureEnvelope};
use crate::protocol::group::{self, GroupSecurityPolicy, GroupSession};
use crate::protocol::{HandshakeInitReplayGuard, HandshakeInitiator, HandshakeResponder, Session};

pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub metadata: Vec<u8>,
}

pub struct SessionIdentity {
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

const SEALED_STATE_COUNTER_TRACKER_VERSION: u32 = 1;
const SEALED_STATE_SLOT_VERSION: u32 = 1;

/// Tracks sealed-state anti-rollback metadata for one persisted state slot.
///
/// The protocol's `external_counter` model needs two distinct values:
/// - `max_restored_counter`: highest sealed-state counter that has already been
///   accepted on restore/import. This is the value passed as
///   `min_external_counter` on the next restore.
/// - `latest_issued_counter`: highest counter already used for a local sealed
///   export. The next export must use `latest_issued_counter + 1`.
///
/// Persist this tracker alongside the sealed blob for the same slot. Using a
/// single counter is not enough to both restore the newest blob after restart
/// and reject rollback to an older blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealedStateCounterTracker {
    max_restored_counter: u64,
    latest_issued_counter: u64,
}

impl SealedStateCounterTracker {
    pub const SERIALIZED_LEN: usize = size_of::<u32>() + size_of::<u64>() * 2;

    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_restored_counter: 0,
            latest_issued_counter: 0,
        }
    }

    #[must_use]
    pub const fn max_restored_counter(&self) -> u64 {
        self.max_restored_counter
    }

    #[must_use]
    pub const fn latest_issued_counter(&self) -> u64 {
        self.latest_issued_counter
    }

    #[must_use]
    pub const fn min_import_counter(&self) -> u64 {
        self.max_restored_counter
    }

    pub fn next_export_counter(&self) -> Result<u64, ProtocolError> {
        self.latest_issued_counter
            .checked_add(1)
            .ok_or_else(|| ProtocolError::invalid_state("sealed-state counter overflow"))
    }

    pub fn note_successful_export(&mut self, counter: u64) -> Result<(), ProtocolError> {
        if counter == 0 {
            return Err(ProtocolError::invalid_input(
                "sealed-state counter must be > 0",
            ));
        }
        if counter <= self.latest_issued_counter {
            return Err(ProtocolError::invalid_state(format!(
                "sealed-state export counter regression: {counter} <= latest issued {}",
                self.latest_issued_counter
            )));
        }
        if counter < self.max_restored_counter {
            return Err(ProtocolError::invalid_state(format!(
                "sealed-state export counter {counter} is below restored watermark {}",
                self.max_restored_counter
            )));
        }
        self.latest_issued_counter = counter;
        Ok(())
    }

    pub fn note_successful_restore(&mut self, counter: u64) -> Result<(), ProtocolError> {
        if counter == 0 {
            return Err(ProtocolError::invalid_input(
                "sealed-state counter must be > 0",
            ));
        }
        if counter <= self.max_restored_counter {
            return Err(ProtocolError::replay_attack(format!(
                "sealed-state counter {counter} is not newer than restored watermark {}",
                self.max_restored_counter
            )));
        }
        self.max_restored_counter = counter;
        if self.latest_issued_counter < counter {
            self.latest_issued_counter = counter;
        }
        Ok(())
    }

    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&SEALED_STATE_COUNTER_TRACKER_VERSION.to_le_bytes());
        out.extend_from_slice(&self.max_restored_counter.to_le_bytes());
        out.extend_from_slice(&self.latest_issued_counter.to_le_bytes());
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() != Self::SERIALIZED_LEN {
            return Err(ProtocolError::decode(format!(
                "sealed-state counter tracker must be {} bytes, got {}",
                Self::SERIALIZED_LEN,
                data.len()
            )));
        }
        let version = u32::from_le_bytes(
            data[0..size_of::<u32>()]
                .try_into()
                .map_err(|_| ProtocolError::decode("counter tracker version missing"))?,
        );
        if version != SEALED_STATE_COUNTER_TRACKER_VERSION {
            return Err(ProtocolError::invalid_input(format!(
                "unsupported sealed-state counter tracker version {version}"
            )));
        }
        let max_restored_offset = size_of::<u32>();
        let latest_issued_offset = max_restored_offset + size_of::<u64>();
        let max_restored_counter = u64::from_le_bytes(
            data[max_restored_offset..latest_issued_offset]
                .try_into()
                .map_err(|_| ProtocolError::decode("counter tracker restored watermark missing"))?,
        );
        let latest_issued_counter = u64::from_le_bytes(
            data[latest_issued_offset..latest_issued_offset + size_of::<u64>()]
                .try_into()
                .map_err(|_| ProtocolError::decode("counter tracker latest counter missing"))?,
        );
        if latest_issued_counter < max_restored_counter {
            return Err(ProtocolError::invalid_state(format!(
                "sealed-state tracker invariant violated: latest issued {} < restored watermark {}",
                latest_issued_counter, max_restored_counter
            )));
        }
        Ok(Self {
            max_restored_counter,
            latest_issued_counter,
        })
    }
}

/// Atomically persisted sealed-state slot containing both anti-rollback
/// tracker state and the latest sealed blob for one storage slot.
///
/// Persist the serialized slot as a single record. After a successful restore,
/// re-serialize and persist the updated slot so the restore watermark is
/// advanced inside the same atomic record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedStateSlot {
    tracker: SealedStateCounterTracker,
    sealed_state: Vec<u8>,
}

impl SealedStateSlot {
    pub const HEADER_LEN: usize = size_of::<u32>() + SealedStateCounterTracker::SERIALIZED_LEN;

    #[must_use]
    pub fn new() -> Self {
        Self {
            tracker: SealedStateCounterTracker::new(),
            sealed_state: Vec::new(),
        }
    }

    #[must_use]
    pub const fn max_restored_counter(&self) -> u64 {
        self.tracker.max_restored_counter()
    }

    #[must_use]
    pub const fn latest_issued_counter(&self) -> u64 {
        self.tracker.latest_issued_counter()
    }

    #[must_use]
    pub const fn min_import_counter(&self) -> u64 {
        self.tracker.min_import_counter()
    }

    pub fn next_export_counter(&self) -> Result<u64, ProtocolError> {
        self.tracker.next_export_counter()
    }

    #[must_use]
    pub fn sealed_state(&self) -> &[u8] {
        &self.sealed_state
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sealed_state.is_empty()
    }

    pub fn note_successful_export(
        &mut self,
        counter: u64,
        sealed_state: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        if sealed_state.len() > MAX_BUFFER_SIZE {
            return Err(ProtocolError::invalid_input(
                "sealed-state slot payload too large",
            ));
        }
        self.tracker.note_successful_export(counter)?;
        self.sealed_state = sealed_state;
        Ok(())
    }

    pub fn note_successful_restore(&mut self, counter: u64) -> Result<(), ProtocolError> {
        self.tracker.note_successful_restore(counter)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.sealed_state.len() > MAX_BUFFER_SIZE {
            return Err(ProtocolError::invalid_input(
                "sealed-state slot payload too large",
            ));
        }
        let sealed_len = u32::try_from(self.sealed_state.len())
            .map_err(|_| ProtocolError::invalid_input("sealed-state slot payload too large"))?;
        let mut out =
            Vec::with_capacity(Self::HEADER_LEN + size_of::<u32>() + self.sealed_state.len());
        out.extend_from_slice(&SEALED_STATE_SLOT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.tracker.serialize());
        out.extend_from_slice(&sealed_len.to_le_bytes());
        out.extend_from_slice(&self.sealed_state);
        Ok(out)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        let min_len = Self::HEADER_LEN + size_of::<u32>();
        if data.len() < min_len {
            return Err(ProtocolError::decode(format!(
                "sealed-state slot must be at least {min_len} bytes, got {}",
                data.len()
            )));
        }
        let version = u32::from_le_bytes(
            data[0..size_of::<u32>()]
                .try_into()
                .map_err(|_| ProtocolError::decode("sealed-state slot version missing"))?,
        );
        if version != SEALED_STATE_SLOT_VERSION {
            return Err(ProtocolError::invalid_input(format!(
                "unsupported sealed-state slot version {version}"
            )));
        }
        let tracker_offset = size_of::<u32>();
        let tracker_end = tracker_offset + SealedStateCounterTracker::SERIALIZED_LEN;
        let tracker = SealedStateCounterTracker::deserialize(&data[tracker_offset..tracker_end])?;
        let sealed_len_offset = tracker_end;
        let sealed_len_end = sealed_len_offset + size_of::<u32>();
        let sealed_len = u32::from_le_bytes(
            data[sealed_len_offset..sealed_len_end]
                .try_into()
                .map_err(|_| ProtocolError::decode("sealed-state slot payload length missing"))?,
        ) as usize;
        if sealed_len > MAX_BUFFER_SIZE {
            return Err(ProtocolError::invalid_input(
                "sealed-state slot payload too large",
            ));
        }
        if data.len() != sealed_len_end + sealed_len {
            return Err(ProtocolError::decode(format!(
                "sealed-state slot length mismatch: declared {sealed_len} payload bytes, got {} total bytes",
                data.len()
            )));
        }
        Ok(Self {
            tracker,
            sealed_state: data[sealed_len_end..].to_vec(),
        })
    }
}

pub struct AuraSession(Session);

impl AuraSession {
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        envelope_type: i32,
        id: u32,
        correlation_id: Option<&str>,
    ) -> Result<Vec<u8>, ProtocolError> {
        let envelope = self
            .0
            .encrypt(plaintext, envelope_type, id, correlation_id)?;
        let mut buf = Vec::new();
        envelope
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode SecureEnvelope: {e}")))?;
        Ok(buf)
    }

    pub fn decrypt(&mut self, envelope_bytes: &[u8]) -> Result<DecryptResult, ProtocolError> {
        if envelope_bytes.len() > MAX_ENVELOPE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("SecureEnvelope too large"));
        }
        let envelope = SecureEnvelope::decode(envelope_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to decode SecureEnvelope: {e}")))?;
        let result = self.0.decrypt(&envelope)?;
        let mut meta_buf = Vec::new();
        result
            .metadata
            .encode(&mut meta_buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode metadata: {e}")))?;
        Ok(DecryptResult {
            plaintext: result.plaintext,
            metadata: meta_buf,
        })
    }

    pub fn serialize(&self, key: &[u8], external_counter: u64) -> Result<Vec<u8>, ProtocolError> {
        let provider = StaticStateKeyProvider::new(key.to_vec())?;
        self.0.export_sealed_state(&provider, external_counter)
    }

    pub fn serialize_with_counter_tracker(
        &self,
        key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Vec<u8>, ProtocolError> {
        let counter = tracker.next_export_counter()?;
        let sealed = self.serialize(key, counter)?;
        tracker.note_successful_export(counter)?;
        Ok(sealed)
    }

    pub fn export_to_slot(
        &self,
        key: &[u8],
        slot: &mut SealedStateSlot,
    ) -> Result<(), ProtocolError> {
        let counter = slot.next_export_counter()?;
        let sealed = self.serialize(key, counter)?;
        slot.note_successful_export(counter, sealed)
    }

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        Self::deserialize_with_time_provider(
            data,
            key,
            min_external_counter,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn deserialize_with_time_provider(
        data: &[u8],
        key: &[u8],
        min_external_counter: u64,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = Session::sealed_state_external_counter(data)?;
        let provider = StaticStateKeyProvider::new(key.to_vec())?;
        let session = Session::from_sealed_state_with_time_provider(
            data,
            &provider,
            min_external_counter,
            time_provider,
        )?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        Session::sealed_state_external_counter(data)
    }

    pub fn deserialize_with_counter_tracker(
        data: &[u8],
        key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Self, ProtocolError> {
        Self::deserialize_with_counter_tracker_and_time_provider(
            data,
            key,
            tracker,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn deserialize_with_counter_tracker_and_time_provider(
        data: &[u8],
        key: &[u8],
        tracker: &mut SealedStateCounterTracker,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        let (session, external_counter) = Self::deserialize_with_time_provider(
            data,
            key,
            tracker.min_import_counter(),
            time_provider,
        )?;
        tracker.note_successful_restore(external_counter)?;
        Ok(session)
    }

    pub fn restore_from_slot(
        slot: &mut SealedStateSlot,
        key: &[u8],
    ) -> Result<Self, ProtocolError> {
        Self::restore_from_slot_with_time_provider(slot, key, Arc::new(SystemTimeProvider))
    }

    pub fn restore_from_slot_with_time_provider(
        slot: &mut SealedStateSlot,
        key: &[u8],
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if slot.is_empty() {
            return Err(ProtocolError::invalid_input("sealed-state slot is empty"));
        }
        let (session, external_counter) = Self::deserialize_with_time_provider(
            slot.sealed_state(),
            key,
            slot.min_import_counter(),
            time_provider,
        )?;
        slot.note_successful_restore(external_counter)?;
        Ok(session)
    }

    pub fn nonce_remaining(&self) -> Result<u64, ProtocolError> {
        self.0.nonce_remaining()
    }

    pub fn session_id(&self) -> Vec<u8> {
        self.0.get_session_id()
    }

    pub fn peer_identity(&self) -> SessionIdentity {
        let peer = self.0.get_peer_identity();
        SessionIdentity {
            ed25519_public: peer.ed25519_public.clone(),
            x25519_public: peer.x25519_public.clone(),
        }
    }

    pub fn local_identity(&self) -> SessionIdentity {
        let local = self.0.get_local_identity();
        SessionIdentity {
            ed25519_public: local.ed25519_public.clone(),
            x25519_public: local.x25519_public.clone(),
        }
    }

    pub fn identity_binding_hash(&self) -> Vec<u8> {
        self.0.get_identity_binding_hash()
    }
}

pub struct AuraInitiator(HandshakeInitiator);

impl AuraInitiator {
    pub fn complete(self, ack_bytes: &[u8]) -> Result<AuraSession, ProtocolError> {
        let session = self.0.finish(ack_bytes)?;
        Ok(AuraSession(session))
    }
}

pub struct AuraResponder(HandshakeResponder);

impl AuraResponder {
    pub fn complete(self) -> Result<AuraSession, ProtocolError> {
        let session = self.0.finish()?;
        Ok(AuraSession(session))
    }
}

pub struct AuraProtocol {
    identity: IdentityKeys,
    max_messages: u32,
    time_provider: Arc<dyn ITimeProvider>,
}

impl AuraProtocol {
    pub fn new(opk_count: u32) -> Result<Self, ProtocolError> {
        Self::new_with_time_provider(opk_count, Arc::new(SystemTimeProvider))
    }

    pub fn new_with_time_provider(
        opk_count: u32,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create(opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
            time_provider,
        })
    }

    pub fn from_seed(
        seed: &[u8],
        membership_id: &str,
        opk_count: u32,
    ) -> Result<Self, ProtocolError> {
        Self::from_seed_with_time_provider(
            seed,
            membership_id,
            opk_count,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_seed_with_time_provider(
        seed: &[u8],
        membership_id: &str,
        opk_count: u32,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create_from_master_key(seed, membership_id, opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
            time_provider,
        })
    }

    pub fn get_identity_ed25519_private_key_copy(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        self.identity.get_identity_ed25519_private_key_copy()
    }

    pub fn identity_ed25519_public(&self) -> Vec<u8> {
        self.identity.get_identity_ed25519_public()
    }

    pub fn identity_x25519_public(&self) -> Vec<u8> {
        self.identity.get_identity_x25519_public()
    }

    pub fn pre_key_bundle(&self) -> Result<Vec<u8>, ProtocolError> {
        let bundle = self.identity.create_public_bundle()?;

        let opks: Vec<OneTimePreKey> = bundle
            .one_time_pre_keys()
            .iter()
            .map(|opk| OneTimePreKey {
                one_time_pre_key_id: opk.id(),
                public_key: opk.public_key_vec(),
            })
            .collect();

        let proto_bundle = PreKeyBundle {
            version: PROTOCOL_VERSION,
            identity_ed25519_public: bundle.identity_ed25519_public().to_vec(),
            identity_x25519_public: bundle.identity_x25519_public().to_vec(),
            identity_x25519_signature: bundle.identity_x25519_signature().to_vec(),
            signed_pre_key_id: bundle.signed_pre_key_id(),
            signed_pre_key_public: bundle.signed_pre_key_public().to_vec(),
            signed_pre_key_signature: bundle.signed_pre_key_signature().to_vec(),
            one_time_pre_keys: opks,
            kyber_public: bundle.kyber_public().unwrap_or(&[]).to_vec(),
        };

        let mut buf = Vec::new();
        proto_bundle
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("Failed to encode PreKeyBundle: {e}")))?;
        Ok(buf)
    }

    pub fn begin_session(
        &mut self,
        peer_bundle_bytes: &[u8],
    ) -> Result<(AuraInitiator, Vec<u8>), ProtocolError> {
        if peer_bundle_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("PreKeyBundle too large"));
        }
        let peer_bundle = PreKeyBundle::decode(peer_bundle_bytes).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode peer PreKeyBundle: {e}"))
        })?;

        let initiator = HandshakeInitiator::start_with_time_provider(
            &mut self.identity,
            &peer_bundle,
            self.max_messages,
            self.time_provider.clone(),
        )?;
        let init_bytes = initiator.encoded_message().to_vec();

        Ok((AuraInitiator(initiator), init_bytes))
    }

    pub fn accept_session(
        &mut self,
        init_bytes: &[u8],
    ) -> Result<(AuraResponder, Vec<u8>), ProtocolError> {
        self.accept_session_with_replay_guard(init_bytes, None)
    }

    pub fn accept_session_with_replay_guard(
        &mut self,
        init_bytes: &[u8],
        replay_guard: Option<&dyn HandshakeInitReplayGuard>,
    ) -> Result<(AuraResponder, Vec<u8>), ProtocolError> {
        let local_bundle_bytes = self.pre_key_bundle()?;
        let local_bundle = PreKeyBundle::decode(local_bundle_bytes.as_slice()).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode local PreKeyBundle: {e}"))
        })?;

        let responder = HandshakeResponder::process_with_replay_guard_and_time_provider(
            &mut self.identity,
            &local_bundle,
            init_bytes,
            self.max_messages,
            replay_guard,
            self.time_provider.clone(),
        )?;
        let ack_bytes = responder.encoded_ack().to_vec();

        Ok((AuraResponder(responder), ack_bytes))
    }

    pub fn generate_key_package(
        &self,
        credential: Vec<u8>,
    ) -> Result<(Vec<u8>, SecureMemoryHandle, SecureMemoryHandle), ProtocolError> {
        let (kp, x25519_priv, kyber_sec) =
            group::key_package::create_key_package(&self.identity, credential)?;
        let mut buf = Vec::new();
        kp.encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("KeyPackage encode: {e}")))?;
        Ok((buf, x25519_priv, kyber_sec))
    }

    pub fn create_group(&self, credential: Vec<u8>) -> Result<AuraGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy_and_time_provider(
            &self.identity,
            credential,
            GroupSecurityPolicy::shield(),
            self.time_provider.clone(),
        )?;
        Ok(AuraGroupSession(session))
    }

    pub fn create_shielded_group(
        &self,
        credential: Vec<u8>,
    ) -> Result<AuraGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy_and_time_provider(
            &self.identity,
            credential,
            GroupSecurityPolicy::shield(),
            self.time_provider.clone(),
        )?;
        Ok(AuraGroupSession(session))
    }

    pub fn create_group_with_policy(
        &self,
        credential: Vec<u8>,
        policy: GroupSecurityPolicy,
    ) -> Result<AuraGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy_and_time_provider(
            &self.identity,
            credential,
            policy,
            self.time_provider.clone(),
        )?;
        Ok(AuraGroupSession(session))
    }

    pub fn join_group(
        &self,
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
    ) -> Result<AuraGroupSession, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let session = GroupSession::from_welcome_with_time_provider(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            &self.identity.get_identity_ed25519_public(),
            &self.identity.get_identity_x25519_public(),
            ed25519_secret,
            self.time_provider.clone(),
        )?;
        Ok(AuraGroupSession(session))
    }

    pub fn join_group_external(
        &self,
        public_state_bytes: &[u8],
        authorization_bytes: &[u8],
        credential: Vec<u8>,
    ) -> Result<(AuraGroupSession, Vec<u8>), ProtocolError> {
        let (session, commit_bytes) = GroupSession::from_external_join_with_time_provider(
            public_state_bytes,
            authorization_bytes,
            &self.identity,
            credential,
            self.time_provider.clone(),
        )?;
        Ok((AuraGroupSession(session), commit_bytes))
    }

    pub fn validate_envelope(envelope_bytes: &[u8]) -> Result<(), ProtocolError> {
        if envelope_bytes.len() > MAX_ENVELOPE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Message too large"));
        }
        let envelope = SecureEnvelope::decode(envelope_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse envelope: {e}")))?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(ProtocolError::invalid_input("Invalid envelope version"));
        }
        if envelope.encrypted_metadata.len() <= AES_GCM_TAG_BYTES {
            return Err(ProtocolError::invalid_input("Encrypted metadata too small"));
        }
        if envelope.encrypted_payload.len() < AES_GCM_TAG_BYTES {
            return Err(ProtocolError::invalid_input("Encrypted payload too small"));
        }
        if envelope.header_nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid header nonce size"));
        }
        if envelope.header_nonce.iter().all(|&b| b == 0) {
            return Err(ProtocolError::invalid_input(
                "Header nonce must not be all zeros",
            ));
        }
        Ok(())
    }

    pub fn derive_root_key(
        opaque_session_key: &[u8],
        user_context: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if opaque_session_key.len() != OPAQUE_SESSION_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "OPAQUE session key must be 32 bytes",
            ));
        }
        if user_context.is_empty() || user_context.len() > MAX_BUFFER_SIZE {
            return Err(ProtocolError::invalid_input(
                "OPAQUE user context length invalid",
            ));
        }
        if output_length == 0 || output_length > 64 {
            return Err(ProtocolError::invalid_input(
                "OPAQUE output length must be in the range 1..=64",
            ));
        }
        let key = HkdfSha256::derive_key_bytes(
            opaque_session_key,
            output_length,
            user_context,
            OPAQUE_ROOT_INFO,
        )?;
        Ok(key.to_vec())
    }

    pub fn shamir_split(
        secret: &[u8],
        threshold: u8,
        share_count: u8,
        auth_key: &[u8],
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        ShamirSecretSharing::split(secret, threshold, share_count, auth_key)
    }

    pub fn shamir_reconstruct(
        shares: &[Vec<u8>],
        auth_key: &[u8],
        threshold: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        ShamirSecretSharing::reconstruct(shares, auth_key, threshold)
    }

    pub fn secure_wipe(data: &mut [u8]) {
        CryptoInterop::secure_wipe(data);
    }
}

// ── VoIP API ────────────────────────────────────────────────────────

use crate::core::constants::VOIP_PROTOCOL_VERSION;
use crate::protocol::voip::frame::FrameHeader;
use crate::protocol::voip::{
    self, CallControlType, CallRole, DecryptedFrame, EncryptedFrame, IVoipEventHandler, VoipSession,
};
use std::sync::Arc;

pub struct AuraVoipSession(VoipSession);
pub type AuraVoipScreenShareMeta = (u32, u32, u32, Option<String>);

impl AuraVoipSession {
    pub fn encrypt_frame(
        &self,
        payload_type: u8,
        ssrc: u32,
        timestamp: u32,
        sequence_number: u16,
        payload: &[u8],
    ) -> Result<EncryptedFrame, ProtocolError> {
        let header = FrameHeader {
            payload_type,
            ssrc,
            timestamp,
            sequence_number,
        };
        self.0.encrypt_frame(&header, payload)
    }

    pub fn decrypt_frame(
        &self,
        encrypted: &EncryptedFrame,
    ) -> Result<DecryptedFrame, ProtocolError> {
        self.0.decrypt_frame(encrypted)
    }

    pub fn call_id(&self) -> Vec<u8> {
        self.0.call_id()
    }

    pub fn ssrc(&self) -> u32 {
        self.0.ssrc()
    }

    pub fn is_caller(&self) -> bool {
        self.0.role() == CallRole::Caller
    }

    pub fn is_shield_mode(&self) -> bool {
        self.0.is_shield_mode()
    }

    pub fn send_frame_counter(&self) -> u64 {
        self.0.send_frame_counter()
    }

    pub fn recv_frame_counter(&self) -> u64 {
        self.0.recv_frame_counter()
    }

    pub fn needs_pq_rekey(&self, elapsed_secs: u64) -> bool {
        self.0.needs_pq_rekey(elapsed_secs)
    }

    pub fn apply_rekey(
        &self,
        new_keys: voip::call_key_exchange::CallKeyMaterial,
    ) -> Result<(), ProtocolError> {
        self.0.apply_rekey(new_keys)
    }

    pub fn end_call(&self) -> Result<(), ProtocolError> {
        self.0.end_call()
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IVoipEventHandler>) {
        self.0.set_event_handler(handler);
    }

    pub fn encrypt_call_control(
        &self,
        control: CallControlType,
    ) -> Result<EncryptedFrame, ProtocolError> {
        self.0.encrypt_call_control(control)
    }

    pub fn decode_call_control(decrypted: &DecryptedFrame) -> Option<CallControlType> {
        VoipSession::decode_call_control(decrypted)
    }

    pub fn generate_call_end_hmac(
        &self,
        device_id: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.generate_call_end_hmac(device_id, timestamp)
    }

    pub fn verify_call_end_hmac(
        &self,
        device_id: &[u8],
        timestamp: u64,
        hmac_value: &[u8],
    ) -> Result<bool, ProtocolError> {
        self.0
            .verify_call_end_hmac(device_id, timestamp, hmac_value)
    }

    pub fn export_sealed_state(
        &self,
        state_key: &[u8],
        external_counter: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.export_sealed_state(state_key, external_counter)
    }

    pub fn export_sealed_state_with_counter_tracker(
        &self,
        state_key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Vec<u8>, ProtocolError> {
        let counter = tracker.next_export_counter()?;
        let sealed = self.export_sealed_state(state_key, counter)?;
        tracker.note_successful_export(counter)?;
        Ok(sealed)
    }

    pub fn export_to_slot(
        &self,
        state_key: &[u8],
        slot: &mut SealedStateSlot,
    ) -> Result<(), ProtocolError> {
        let counter = slot.next_export_counter()?;
        let sealed = self.export_sealed_state(state_key, counter)?;
        slot.note_successful_export(counter, sealed)
    }

    pub fn build_call_end(
        &self,
        device_id: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.build_call_end(device_id, timestamp)
    }

    pub fn process_call_end(&self, call_end_bytes: &[u8]) -> Result<(), ProtocolError> {
        self.0.process_call_end(call_end_bytes)
    }

    pub fn initiate_rekey(
        &self,
        identity_ed25519_secret: &[u8],
        peer_kyber_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0
            .initiate_rekey(identity_ed25519_secret, peer_kyber_public)
    }

    pub fn process_rekey(
        &self,
        rekey_bytes: &[u8],
        peer_ed25519_public: &[u8],
        identity_kyber_secret: &SecureMemoryHandle,
        peer_kyber_public: &[u8],
        identity_ed25519_secret: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.process_rekey(
            rekey_bytes,
            peer_ed25519_public,
            identity_kyber_secret,
            peer_kyber_public,
            identity_ed25519_secret,
        )
    }

    pub fn process_rekey_ack(
        &self,
        ack_bytes: &[u8],
        peer_ed25519_public: &[u8],
        identity_kyber_secret: &SecureMemoryHandle,
    ) -> Result<(), ProtocolError> {
        self.0
            .process_rekey_ack(ack_bytes, peer_ed25519_public, identity_kyber_secret)
    }

    pub fn set_screen_share_meta(
        &self,
        width: u32,
        height: u32,
        frame_rate: u32,
        codec_hint: Option<&str>,
    ) -> Result<(), ProtocolError> {
        self.0
            .set_screen_share_meta(width, height, frame_rate, codec_hint)
    }

    pub fn get_screen_share_meta(
        &self,
    ) -> Result<Option<AuraVoipScreenShareMeta>, ProtocolError> {
        self.0.get_screen_share_meta()
    }

    pub fn clear_screen_share_meta(&self) -> Result<(), ProtocolError> {
        self.0.clear_screen_share_meta()
    }

    pub fn get_call_statistics(&self) -> Result<voip::CallStatistics, ProtocolError> {
        self.0.get_call_statistics()
    }

    pub fn set_recording_consent(&self, consent: i32) -> Result<(), ProtocolError> {
        self.0.set_recording_consent(consent)
    }

    pub fn get_local_recording_consent(&self) -> Result<i32, ProtocolError> {
        self.0.get_local_recording_consent()
    }

    pub fn set_remote_recording_consent(&self, consent: i32) -> Result<(), ProtocolError> {
        self.0.set_remote_recording_consent(consent)
    }

    pub fn get_remote_recording_consent(&self) -> Result<i32, ProtocolError> {
        self.0.get_remote_recording_consent()
    }

    pub fn both_consented_to_recording(&self) -> Result<bool, ProtocolError> {
        self.0.both_consented_to_recording()
    }

    pub fn build_recording_consent_message(
        &self,
        consent: i32,
        timestamp_unix: u64,
        identity_ed25519_secret: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0
            .build_recording_consent_message(consent, timestamp_unix, identity_ed25519_secret)
    }

    pub fn process_recording_consent_message(
        &self,
        message_bytes: &[u8],
        peer_ed25519_public: &[u8],
    ) -> Result<i32, ProtocolError> {
        self.0
            .process_recording_consent_message(message_bytes, peer_ed25519_public)
    }

    pub fn from_sealed_state(
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
    ) -> Result<Self, ProtocolError> {
        Self::from_sealed_state_with_time_provider(
            data,
            state_key,
            min_external_counter,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_sealed_state_with_time_provider(
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self(VoipSession::from_sealed_state_with_time_provider(
            data,
            state_key,
            min_external_counter,
            time_provider,
        )?))
    }

    pub fn sealed_state_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        VoipSession::sealed_state_external_counter(data)
    }

    pub fn from_sealed_state_with_counter_tracker(
        data: &[u8],
        state_key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Self, ProtocolError> {
        Self::from_sealed_state_with_counter_tracker_and_time_provider(
            data,
            state_key,
            tracker,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_sealed_state_with_counter_tracker_and_time_provider(
        data: &[u8],
        state_key: &[u8],
        tracker: &mut SealedStateCounterTracker,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        let session = Self::from_sealed_state_with_time_provider(
            data,
            state_key,
            tracker.min_import_counter(),
            time_provider,
        )?;
        let external_counter = Self::sealed_state_external_counter(data)?;
        tracker.note_successful_restore(external_counter)?;
        Ok(session)
    }

    pub fn restore_from_slot(
        slot: &mut SealedStateSlot,
        state_key: &[u8],
    ) -> Result<Self, ProtocolError> {
        Self::restore_from_slot_with_time_provider(slot, state_key, Arc::new(SystemTimeProvider))
    }

    pub fn restore_from_slot_with_time_provider(
        slot: &mut SealedStateSlot,
        state_key: &[u8],
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if slot.is_empty() {
            return Err(ProtocolError::invalid_input("sealed-state slot is empty"));
        }
        let session = Self::from_sealed_state_with_time_provider(
            slot.sealed_state(),
            state_key,
            slot.min_import_counter(),
            time_provider,
        )?;
        let external_counter = Self::sealed_state_external_counter(slot.sealed_state())?;
        slot.note_successful_restore(external_counter)?;
        Ok(session)
    }
}

pub struct AuraCallInitiator {
    pub init_output: voip::call_key_exchange::CallInitOutput,
    pub call_id: Vec<u8>,
    pub shield_mode: bool,
    pub ratchet_interval_frames: u32,
    pub pq_rekey_interval_secs: u32,
    time_provider: Arc<dyn ITimeProvider>,
}

impl AuraCallInitiator {
    pub fn complete(
        self,
        identity_kyber_secret: &SecureMemoryHandle,
        peer_eph_x25519_public: &[u8],
        peer_kyber_ct: &[u8],
        peer_ed25519_public: &[u8],
        peer_signature: &[u8],
        peer_key_confirm_mac: &[u8],
    ) -> Result<AuraVoipSession, ProtocolError> {
        let auth_context = voip::call_key_exchange::CallInitAuthContext {
            version: VOIP_PROTOCOL_VERSION,
            media_type: 1,
            ratchet_interval_frames: self.ratchet_interval_frames,
            pq_rekey_interval_secs: self.pq_rekey_interval_secs,
            shield_mode: self.shield_mode,
        };
        let key_material = voip::call_key_exchange::caller_finish_with_context(
            &self.init_output,
            identity_kyber_secret,
            &self.call_id,
            peer_eph_x25519_public,
            peer_kyber_ct,
            peer_ed25519_public,
            peer_signature,
            peer_key_confirm_mac,
            &auth_context,
        )?;
        let session = VoipSession::from_key_material_with_time_provider(
            self.call_id,
            CallRole::Caller,
            key_material,
            self.ratchet_interval_frames,
            self.pq_rekey_interval_secs,
            self.shield_mode,
            self.time_provider,
        )?;
        Ok(AuraVoipSession(session))
    }

    pub fn complete_from_accept(
        self,
        identity_kyber_secret: &SecureMemoryHandle,
        call_accept_bytes: &[u8],
    ) -> Result<AuraVoipSession, ProtocolError> {
        if call_accept_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_call("CallAccept too large"));
        }
        let call_accept = crate::proto::CallAccept::decode(call_accept_bytes)
            .map_err(|e| ProtocolError::decode(format!("CallAccept decode: {e}")))?;

        if call_accept.version != VOIP_PROTOCOL_VERSION {
            return Err(ProtocolError::voip_call(
                "unsupported VoIP protocol version",
            ));
        }
        if call_accept.call_id != self.call_id {
            return Err(ProtocolError::voip_call("CallAccept call_id mismatch"));
        }

        self.complete(
            identity_kyber_secret,
            &call_accept.ephemeral_x25519_public,
            &call_accept.kyber_ciphertext,
            &call_accept.identity_ed25519_public,
            &call_accept.signature,
            &call_accept.key_confirmation_mac,
        )
    }
}

impl AuraProtocol {
    pub fn initiate_call(
        &self,
        peer_kyber_public: &[u8],
        shield_mode: bool,
        ratchet_interval_frames: u32,
        pq_rekey_interval_secs: u32,
    ) -> Result<(AuraCallInitiator, Vec<u8>), ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let ed25519_public = self.identity.get_identity_ed25519_public();

        let auth_context = voip::call_key_exchange::CallInitAuthContext {
            version: VOIP_PROTOCOL_VERSION,
            media_type: 1,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode,
        };

        let init_output = voip::call_key_exchange::caller_init_with_context(
            &ed25519_secret,
            &ed25519_public,
            peer_kyber_public,
            &auth_context,
        )?;

        let call_id = init_output.call_id.clone();

        // Serialize CallInit protobuf
        let proto_init = crate::proto::CallInit {
            version: VOIP_PROTOCOL_VERSION,
            caller_device_id: Vec::new(), // set by caller
            call_id: call_id.clone(),
            ephemeral_x25519_public: init_output.ephemeral_x25519_public.clone(),
            kyber_ciphertext: init_output.kyber_ciphertext.clone(),
            identity_ed25519_public: init_output.identity_ed25519_public.clone(),
            signature: init_output.signature.clone(),
            key_confirmation_mac: init_output.key_confirmation_mac.clone(),
            media_type: 1,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode,
            screen_share: None,
        };

        let mut buf = Vec::new();
        proto_init
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallInit encode: {e}")))?;

        let initiator = AuraCallInitiator {
            init_output,
            call_id,
            shield_mode,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            time_provider: self.time_provider.clone(),
        };

        Ok((initiator, buf))
    }

    pub fn accept_call(
        &self,
        call_init_bytes: &[u8],
        peer_kyber_public: &[u8],
    ) -> Result<(AuraVoipSession, Vec<u8>), ProtocolError> {
        if call_init_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_call("CallInit too large"));
        }
        let call_init = crate::proto::CallInit::decode(call_init_bytes)
            .map_err(|e| ProtocolError::decode(format!("CallInit decode: {e}")))?;

        if call_init.version != VOIP_PROTOCOL_VERSION {
            return Err(ProtocolError::voip_call(
                "unsupported VoIP protocol version",
            ));
        }

        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let ed25519_public = self.identity.get_identity_ed25519_public();
        let kyber_secret = self.identity.clone_kyber_secret_key()?;

        let auth_context = voip::call_key_exchange::CallInitAuthContext {
            version: call_init.version,
            media_type: call_init.media_type,
            ratchet_interval_frames: call_init.ratchet_interval_frames,
            pq_rekey_interval_secs: call_init.pq_rekey_interval_secs,
            shield_mode: call_init.shield_mode,
        };

        let accept_output = voip::call_key_exchange::callee_accept_with_context(
            &ed25519_secret,
            &ed25519_public,
            &kyber_secret,
            peer_kyber_public,
            &call_init.call_id,
            &call_init.ephemeral_x25519_public,
            &call_init.kyber_ciphertext,
            &call_init.identity_ed25519_public,
            &call_init.signature,
            &call_init.key_confirmation_mac,
            &auth_context,
        )?;

        let proto_accept = crate::proto::CallAccept {
            version: VOIP_PROTOCOL_VERSION,
            callee_device_id: Vec::new(),
            call_id: call_init.call_id.clone(),
            ephemeral_x25519_public: accept_output.ephemeral_x25519_public,
            kyber_ciphertext: accept_output.kyber_ciphertext,
            identity_ed25519_public: accept_output.identity_ed25519_public,
            signature: accept_output.signature,
            key_confirmation_mac: accept_output.key_confirmation_mac,
            screen_share: None,
        };

        let mut buf = Vec::new();
        proto_accept
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallAccept encode: {e}")))?;

        let session = VoipSession::from_key_material_with_time_provider(
            call_init.call_id,
            CallRole::Callee,
            accept_output.key_material,
            call_init.ratchet_interval_frames,
            call_init.pq_rekey_interval_secs,
            call_init.shield_mode,
            self.time_provider.clone(),
        )?;

        Ok((AuraVoipSession(session), buf))
    }

    pub fn complete_call(
        &self,
        initiator: AuraCallInitiator,
        call_accept_bytes: &[u8],
    ) -> Result<AuraVoipSession, ProtocolError> {
        let kyber_secret = self.identity.clone_kyber_secret_key()?;
        initiator.complete_from_accept(&kyber_secret, call_accept_bytes)
    }

    pub fn initiate_call_rekey(
        &self,
        session: &AuraVoipSession,
        peer_kyber_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        session.initiate_rekey(&ed25519_secret, peer_kyber_public)
    }

    pub fn process_call_rekey(
        &self,
        session: &AuraVoipSession,
        rekey_bytes: &[u8],
        peer_ed25519_public: &[u8],
        peer_kyber_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if rekey_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_rekey("CallRekey too large"));
        }
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let kyber_secret = self.identity.clone_kyber_secret_key()?;
        session.process_rekey(
            rekey_bytes,
            peer_ed25519_public,
            &kyber_secret,
            peer_kyber_public,
            &ed25519_secret,
        )
    }

    pub fn process_call_rekey_ack(
        &self,
        session: &AuraVoipSession,
        ack_bytes: &[u8],
        peer_ed25519_public: &[u8],
    ) -> Result<(), ProtocolError> {
        if ack_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_rekey("CallRekeyAck too large"));
        }
        let kyber_secret = self.identity.clone_kyber_secret_key()?;
        session.process_rekey_ack(ack_bytes, peer_ed25519_public, &kyber_secret)
    }

    pub fn build_call_recording_consent_message(
        &self,
        session: &AuraVoipSession,
        consent: i32,
        timestamp_unix: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        session.build_recording_consent_message(consent, timestamp_unix, &ed25519_secret)
    }

    pub fn process_call_recording_consent_message(
        &self,
        session: &AuraVoipSession,
        message_bytes: &[u8],
        peer_ed25519_public: &[u8],
    ) -> Result<i32, ProtocolError> {
        session.process_recording_consent_message(message_bytes, peer_ed25519_public)
    }

    pub fn import_call_state(
        &self,
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
    ) -> Result<(AuraVoipSession, u64), ProtocolError> {
        let session = AuraVoipSession::from_sealed_state_with_time_provider(
            data,
            state_key,
            min_external_counter,
            self.time_provider.clone(),
        )?;
        let external_counter = AuraVoipSession::sealed_state_external_counter(data)?;
        Ok((session, external_counter))
    }

    pub fn import_call_state_with_counter_tracker(
        &self,
        data: &[u8],
        state_key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<AuraVoipSession, ProtocolError> {
        AuraVoipSession::from_sealed_state_with_counter_tracker_and_time_provider(
            data,
            state_key,
            tracker,
            self.time_provider.clone(),
        )
    }

    pub fn import_call_state_from_slot(
        &self,
        slot: &mut SealedStateSlot,
        state_key: &[u8],
    ) -> Result<AuraVoipSession, ProtocolError> {
        AuraVoipSession::restore_from_slot_with_time_provider(
            slot,
            state_key,
            self.time_provider.clone(),
        )
    }
}

pub struct AuraGroupSession(GroupSession);

impl AuraGroupSession {
    pub fn add_member(
        &self,
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        if key_package_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("KeyPackage too large"));
        }
        let kp = GroupKeyPackage::decode(key_package_bytes)
            .map_err(|e| ProtocolError::decode(format!("KeyPackage decode: {e}")))?;
        self.0.add_member(&kp)
    }

    pub fn remove_member(&self, leaf_index: u32) -> Result<Vec<u8>, ProtocolError> {
        self.0.remove_member(leaf_index)
    }

    pub fn update(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.update()
    }

    pub fn epoch_messages_remaining(&self) -> Result<u32, ProtocolError> {
        self.0.epoch_messages_remaining()
    }

    pub fn should_rotate_epoch(&self) -> Result<bool, ProtocolError> {
        self.0.should_rotate_epoch()
    }

    pub fn should_rotate_epoch_with_threshold(&self, percent: u32) -> Result<bool, ProtocolError> {
        self.0.should_rotate_epoch_with_threshold(percent)
    }

    pub fn rotate_epoch_if_needed(&self) -> Result<Option<Vec<u8>>, ProtocolError> {
        self.0.rotate_epoch_if_needed()
    }

    pub fn process_commit(&self, commit_bytes: &[u8]) -> Result<(), ProtocolError> {
        self.0.process_commit(commit_bytes)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt(plaintext)
    }

    pub fn encrypt_with_auto_rotate(
        &self,
        plaintext: &[u8],
    ) -> Result<(Option<Vec<u8>>, Vec<u8>), ProtocolError> {
        self.0.encrypt_with_auto_rotate(plaintext)
    }

    pub fn decrypt(
        &self,
        message_bytes: &[u8],
    ) -> Result<group::GroupDecryptResult, ProtocolError> {
        self.0.decrypt(message_bytes)
    }

    pub fn group_id(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.group_id()
    }

    pub fn epoch(&self) -> Result<u64, ProtocolError> {
        self.0.epoch()
    }

    pub fn my_leaf_index(&self) -> Result<u32, ProtocolError> {
        self.0.my_leaf_index()
    }

    pub fn member_count(&self) -> Result<u32, ProtocolError> {
        self.0.member_count()
    }

    pub fn member_leaf_indices(&self) -> Result<Vec<u32>, ProtocolError> {
        self.0.member_leaf_indices()
    }

    pub fn export_public_state(&self) -> Result<Vec<u8>, ProtocolError> {
        self.0.export_public_state()
    }

    pub fn authorize_external_join(
        &self,
        joiner_identity_ed25519_public: &[u8],
        joiner_identity_x25519_public: &[u8],
        joiner_credential: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.authorize_external_join(
            joiner_identity_ed25519_public,
            joiner_identity_x25519_public,
            joiner_credential,
        )
    }

    pub fn set_psk_resolver(
        &self,
        resolver: Box<dyn group::PskResolver>,
    ) -> Result<(), ProtocolError> {
        self.0.set_psk_resolver(resolver)
    }

    pub fn pending_reinit(&self) -> Result<Option<group::ReInitInfo>, ProtocolError> {
        self.0.pending_reinit()
    }

    pub fn encrypt_sealed(&self, plaintext: &[u8], hint: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_sealed(plaintext, hint)
    }

    pub fn encrypt_disappearing(
        &self,
        plaintext: &[u8],
        ttl_seconds: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_disappearing(plaintext, ttl_seconds)
    }

    pub fn encrypt_frankable(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_frankable(plaintext)
    }

    pub fn encrypt_with_policy(
        &self,
        plaintext: &[u8],
        policy: &group::MessagePolicy,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_with_policy(plaintext, policy)
    }

    pub fn encrypt_edit(
        &self,
        new_content: &[u8],
        target_message_id: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_edit(new_content, target_message_id)
    }

    pub fn encrypt_delete(&self, target_message_id: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt_delete(target_message_id)
    }

    pub fn compute_message_id(
        group_id: &[u8],
        epoch: u64,
        sender_leaf: u32,
        generation: u32,
    ) -> Vec<u8> {
        group::compute_message_id(group_id, epoch, sender_leaf, generation)
    }

    pub fn reveal_sealed(sealed: &group::SealedPayload) -> Result<Vec<u8>, ProtocolError> {
        GroupSession::reveal_sealed(sealed)
    }

    pub fn verify_franking(data: &group::FrankingData) -> Result<bool, ProtocolError> {
        GroupSession::verify_franking(data)
    }

    pub fn serialize(&self, key: &[u8], external_counter: u64) -> Result<Vec<u8>, ProtocolError> {
        self.0.export_sealed_state(key, external_counter)
    }

    pub fn serialize_with_counter_tracker(
        &self,
        key: &[u8],
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Vec<u8>, ProtocolError> {
        let counter = tracker.next_export_counter()?;
        let sealed = self.serialize(key, counter)?;
        tracker.note_successful_export(counter)?;
        Ok(sealed)
    }

    pub fn export_to_slot(
        &self,
        key: &[u8],
        slot: &mut SealedStateSlot,
    ) -> Result<(), ProtocolError> {
        let counter = slot.next_export_counter()?;
        let sealed = self.serialize(key, counter)?;
        slot.note_successful_export(counter, sealed)
    }

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        Self::deserialize_with_time_provider(
            data,
            key,
            ed25519_secret,
            min_external_counter,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn deserialize_with_time_provider(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = GroupSession::sealed_state_external_counter(data)?;
        let session = GroupSession::from_sealed_state_with_time_provider(
            data,
            key,
            ed25519_secret,
            min_external_counter,
            time_provider,
        )?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        GroupSession::sealed_state_external_counter(data)
    }

    pub fn deserialize_with_counter_tracker(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        tracker: &mut SealedStateCounterTracker,
    ) -> Result<Self, ProtocolError> {
        Self::deserialize_with_counter_tracker_and_time_provider(
            data,
            key,
            ed25519_secret,
            tracker,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn deserialize_with_counter_tracker_and_time_provider(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        tracker: &mut SealedStateCounterTracker,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        let (session, external_counter) = Self::deserialize_with_time_provider(
            data,
            key,
            ed25519_secret,
            tracker.min_import_counter(),
            time_provider,
        )?;
        tracker.note_successful_restore(external_counter)?;
        Ok(session)
    }

    pub fn restore_from_slot(
        slot: &mut SealedStateSlot,
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        Self::restore_from_slot_with_time_provider(
            slot,
            key,
            ed25519_secret,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn restore_from_slot_with_time_provider(
        slot: &mut SealedStateSlot,
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if slot.is_empty() {
            return Err(ProtocolError::invalid_input("sealed-state slot is empty"));
        }
        let (session, external_counter) = Self::deserialize_with_time_provider(
            slot.sealed_state(),
            key,
            ed25519_secret,
            slot.min_import_counter(),
            time_provider,
        )?;
        slot.note_successful_restore(external_counter)?;
        Ok(session)
    }

    pub fn is_shielded(&self) -> Result<bool, ProtocolError> {
        self.0.is_shielded()
    }

    pub fn security_policy(&self) -> Result<GroupSecurityPolicy, ProtocolError> {
        self.0.security_policy()
    }
}
