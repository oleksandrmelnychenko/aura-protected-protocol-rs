// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub mod relay;

use prost::Message;
use zeroize::Zeroizing;

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, DEFAULT_MESSAGES_PER_CHAIN, MAX_BUFFER_SIZE,
    MAX_ENVELOPE_MESSAGE_SIZE, MAX_VOIP_SIGNAL_MESSAGE_SIZE, OPAQUE_ROOT_INFO,
    OPAQUE_SESSION_KEY_BYTES, PROTOCOL_VERSION,
};
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle, ShamirSecretSharing};
use crate::identity::IdentityKeys;
use crate::interfaces::StaticStateKeyProvider;
use crate::proto::{GroupKeyPackage, OneTimePreKey, PreKeyBundle, SecureEnvelope};
use crate::protocol::group::{self, GroupSecurityPolicy, GroupSession};
use crate::protocol::{HandshakeInitiator, HandshakeResponder, Session};

pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub metadata: Vec<u8>,
}

pub struct SessionIdentity {
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

pub struct EcliptixSession(Session);

impl EcliptixSession {
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

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = Session::sealed_state_external_counter(data)?;
        let provider = StaticStateKeyProvider::new(key.to_vec())?;
        let session = Session::from_sealed_state(data, &provider, min_external_counter)?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        Session::sealed_state_external_counter(data)
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

pub struct EcliptixInitiator(HandshakeInitiator);

impl EcliptixInitiator {
    pub fn complete(self, ack_bytes: &[u8]) -> Result<EcliptixSession, ProtocolError> {
        let session = self.0.finish(ack_bytes)?;
        Ok(EcliptixSession(session))
    }
}

pub struct EcliptixResponder(HandshakeResponder);

impl EcliptixResponder {
    pub fn complete(self) -> Result<EcliptixSession, ProtocolError> {
        let session = self.0.finish()?;
        Ok(EcliptixSession(session))
    }
}

pub struct EcliptixProtocol {
    identity: IdentityKeys,
    max_messages: u32,
}

impl EcliptixProtocol {
    pub fn new(opk_count: u32) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create(opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
        })
    }

    pub fn from_seed(
        seed: &[u8],
        membership_id: &str,
        opk_count: u32,
    ) -> Result<Self, ProtocolError> {
        let identity = IdentityKeys::create_from_master_key(seed, membership_id, opk_count)?;
        #[allow(clippy::cast_possible_truncation)]
        let max_messages = DEFAULT_MESSAGES_PER_CHAIN as u32;
        Ok(Self {
            identity,
            max_messages,
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
    ) -> Result<(EcliptixInitiator, Vec<u8>), ProtocolError> {
        let peer_bundle = PreKeyBundle::decode(peer_bundle_bytes).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode peer PreKeyBundle: {e}"))
        })?;

        let initiator =
            HandshakeInitiator::start(&mut self.identity, &peer_bundle, self.max_messages)?;
        let init_bytes = initiator.encoded_message().to_vec();

        Ok((EcliptixInitiator(initiator), init_bytes))
    }

    pub fn accept_session(
        &mut self,
        init_bytes: &[u8],
    ) -> Result<(EcliptixResponder, Vec<u8>), ProtocolError> {
        let local_bundle_bytes = self.pre_key_bundle()?;
        let local_bundle = PreKeyBundle::decode(local_bundle_bytes.as_slice()).map_err(|e| {
            ProtocolError::decode(format!("Failed to decode local PreKeyBundle: {e}"))
        })?;

        let responder = HandshakeResponder::process(
            &mut self.identity,
            &local_bundle,
            init_bytes,
            self.max_messages,
        )?;
        let ack_bytes = responder.encoded_ack().to_vec();

        Ok((EcliptixResponder(responder), ack_bytes))
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

    pub fn create_group(&self, credential: Vec<u8>) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create(&self.identity, credential)?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn create_shielded_group(
        &self,
        credential: Vec<u8>,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy(
            &self.identity,
            credential,
            GroupSecurityPolicy::shield(),
        )?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn create_group_with_policy(
        &self,
        credential: Vec<u8>,
        policy: GroupSecurityPolicy,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let session = GroupSession::create_with_policy(&self.identity, credential, policy)?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn join_group(
        &self,
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
    ) -> Result<EcliptixGroupSession, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        let session = GroupSession::from_welcome(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            &self.identity.get_identity_ed25519_public(),
            &self.identity.get_identity_x25519_public(),
            ed25519_secret,
        )?;
        Ok(EcliptixGroupSession(session))
    }

    pub fn join_group_external(
        &self,
        public_state_bytes: &[u8],
        authorization_bytes: &[u8],
        credential: Vec<u8>,
    ) -> Result<(EcliptixGroupSession, Vec<u8>), ProtocolError> {
        let (session, commit_bytes) = GroupSession::from_external_join(
            public_state_bytes,
            authorization_bytes,
            &self.identity,
            credential,
        )?;
        Ok((EcliptixGroupSession(session), commit_bytes))
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

pub struct EcliptixVoipSession(VoipSession);

impl EcliptixVoipSession {
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

    pub fn from_sealed_state(
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
    ) -> Result<Self, ProtocolError> {
        Ok(Self(VoipSession::from_sealed_state(
            data,
            state_key,
            min_external_counter,
        )?))
    }

    pub fn sealed_state_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        VoipSession::sealed_state_external_counter(data)
    }
}

pub struct EcliptixCallInitiator {
    pub init_output: voip::call_key_exchange::CallInitOutput,
    pub call_id: Vec<u8>,
    pub shield_mode: bool,
    pub ratchet_interval_frames: u32,
    pub pq_rekey_interval_secs: u32,
}

impl EcliptixCallInitiator {
    pub fn complete(
        self,
        identity_kyber_secret: &SecureMemoryHandle,
        peer_eph_x25519_public: &[u8],
        peer_kyber_ct: &[u8],
        peer_ed25519_public: &[u8],
        peer_signature: &[u8],
        peer_key_confirm_mac: &[u8],
    ) -> Result<EcliptixVoipSession, ProtocolError> {
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
        let session = VoipSession::from_key_material(
            self.call_id,
            CallRole::Caller,
            key_material,
            self.ratchet_interval_frames,
            self.pq_rekey_interval_secs,
            self.shield_mode,
        )?;
        Ok(EcliptixVoipSession(session))
    }

    pub fn complete_from_accept(
        self,
        identity_kyber_secret: &SecureMemoryHandle,
        call_accept_bytes: &[u8],
    ) -> Result<EcliptixVoipSession, ProtocolError> {
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

impl EcliptixProtocol {
    pub fn initiate_call(
        &self,
        peer_kyber_public: &[u8],
        shield_mode: bool,
        ratchet_interval_frames: u32,
        pq_rekey_interval_secs: u32,
    ) -> Result<(EcliptixCallInitiator, Vec<u8>), ProtocolError> {
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
            media_type: 1, // audio
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode,
        };

        let mut buf = Vec::new();
        proto_init
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallInit encode: {e}")))?;

        let initiator = EcliptixCallInitiator {
            init_output,
            call_id,
            shield_mode,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
        };

        Ok((initiator, buf))
    }

    pub fn accept_call(
        &self,
        call_init_bytes: &[u8],
        peer_kyber_public: &[u8],
    ) -> Result<(EcliptixVoipSession, Vec<u8>), ProtocolError> {
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
        };

        let mut buf = Vec::new();
        proto_accept
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallAccept encode: {e}")))?;

        let session = VoipSession::from_key_material(
            call_init.call_id,
            CallRole::Callee,
            accept_output.key_material,
            call_init.ratchet_interval_frames,
            call_init.pq_rekey_interval_secs,
            call_init.shield_mode,
        )?;

        Ok((EcliptixVoipSession(session), buf))
    }

    pub fn complete_call(
        &self,
        initiator: EcliptixCallInitiator,
        call_accept_bytes: &[u8],
    ) -> Result<EcliptixVoipSession, ProtocolError> {
        let kyber_secret = self.identity.clone_kyber_secret_key()?;
        initiator.complete_from_accept(&kyber_secret, call_accept_bytes)
    }

    pub fn initiate_call_rekey(
        &self,
        session: &EcliptixVoipSession,
        peer_kyber_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let ed25519_secret = self.identity.get_identity_ed25519_private_key_copy()?;
        session.initiate_rekey(&ed25519_secret, peer_kyber_public)
    }

    pub fn process_call_rekey(
        &self,
        session: &EcliptixVoipSession,
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
        session: &EcliptixVoipSession,
        ack_bytes: &[u8],
        peer_ed25519_public: &[u8],
    ) -> Result<(), ProtocolError> {
        if ack_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_rekey("CallRekeyAck too large"));
        }
        let kyber_secret = self.identity.clone_kyber_secret_key()?;
        session.process_rekey_ack(ack_bytes, peer_ed25519_public, &kyber_secret)
    }

    pub fn import_call_state(
        &self,
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
    ) -> Result<(EcliptixVoipSession, u64), ProtocolError> {
        let session =
            EcliptixVoipSession::from_sealed_state(data, state_key, min_external_counter)?;
        let external_counter = EcliptixVoipSession::sealed_state_external_counter(data)?;
        Ok((session, external_counter))
    }
}

pub struct EcliptixGroupSession(GroupSession);

impl EcliptixGroupSession {
    pub fn add_member(
        &self,
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
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

    pub fn process_commit(&self, commit_bytes: &[u8]) -> Result<(), ProtocolError> {
        self.0.process_commit(commit_bytes)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.0.encrypt(plaintext)
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

    pub fn deserialize(
        data: &[u8],
        key: &[u8],
        ed25519_secret: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
    ) -> Result<(Self, u64), ProtocolError> {
        let external_counter = GroupSession::sealed_state_external_counter(data)?;
        let session =
            GroupSession::from_sealed_state(data, key, ed25519_secret, min_external_counter)?;
        Ok((Self(session), external_counter))
    }

    pub fn sealed_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        GroupSession::sealed_state_external_counter(data)
    }

    pub fn is_shielded(&self) -> Result<bool, ProtocolError> {
        self.0.is_shielded()
    }

    pub fn security_policy(&self) -> Result<GroupSecurityPolicy, ProtocolError> {
        self.0.security_policy()
    }
}
