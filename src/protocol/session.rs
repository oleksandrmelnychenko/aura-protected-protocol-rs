// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::mem::size_of;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{
    AesGcm, CryptoInterop, HkdfSha256, KyberInterop, MessagePadding, SecureMemoryHandle,
};
use crate::interfaces::{IProtocolEventHandler, IStateKeyProvider};
use crate::proto::{
    CachedMessageKey, CachedMetadataKey, ChainState, DhKeyPair, EnvelopeMetadata, KyberKeyPair,
    NonceState as NonceStateProto, ProtocolState, SealedState, SecureEnvelope,
};
use crate::protocol::nonce::{NonceGenerator, NonceState as NonceStateLocal};
use crate::security::DhValidator;
use hmac::{Hmac, Mac};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    pub metadata: EnvelopeMetadata,
}

pub struct HandshakeState {
    pub state: ProtocolState,
    pub kyber_shared_secret: Zeroizing<Vec<u8>>,
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        wipe_protocol_state_keys(&mut self.state);
    }
}

#[derive(Clone)]
pub struct PeerIdentity {
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

impl Drop for PeerIdentity {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.ed25519_public);
        CryptoInterop::secure_wipe(&mut self.x25519_public);
    }
}

#[derive(Clone)]
pub struct LocalIdentity {
    pub ed25519_public: Vec<u8>,
    pub x25519_public: Vec<u8>,
}

impl Drop for LocalIdentity {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.ed25519_public);
        CryptoInterop::secure_wipe(&mut self.x25519_public);
    }
}

fn derive_key_bytes(
    ikm: &[u8],
    out_len: usize,
    salt: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut z = HkdfSha256::derive_key_bytes(ikm, out_len, salt, info)?;
    Ok(std::mem::take(&mut *z))
}

fn compute_sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn compute_state_hmac(root_key: &[u8], serialized_state: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let hmac_key = derive_key_bytes(root_key, HMAC_BYTES, &[], STATE_HMAC_INFO)?;
    let mut mac = HmacSha256::new_from_slice(&hmac_key)
        .map_err(|_| ProtocolError::handshake("HMAC-SHA256 init failed"))?;
    mac.update(serialized_state);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_identity_binding_hash(
    local_ed25519: &[u8],
    local_x25519: &[u8],
    peer_ed25519: &[u8],
    peer_x25519: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if local_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
        || peer_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 identity key sizes for binding",
        ));
    }
    if local_x25519.len() != X25519_PUBLIC_KEY_BYTES || peer_x25519.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid X25519 identity key sizes for binding",
        ));
    }
    let mut ed_keys = [local_ed25519.to_vec(), peer_ed25519.to_vec()];
    if ed_keys[0] > ed_keys[1] {
        ed_keys.swap(0, 1);
    }
    let mut x_keys = [local_x25519.to_vec(), peer_x25519.to_vec()];
    if x_keys[0] > x_keys[1] {
        x_keys.swap(0, 1);
    }
    let mut input = Vec::with_capacity(
        IDENTITY_BINDING_INFO.len()
            + ed_keys[0].len()
            + ed_keys[1].len()
            + x_keys[0].len()
            + x_keys[1].len(),
    );
    input.extend_from_slice(IDENTITY_BINDING_INFO);
    input.extend_from_slice(&ed_keys[0]);
    input.extend_from_slice(&ed_keys[1]);
    input.extend_from_slice(&x_keys[0]);
    input.extend_from_slice(&x_keys[1]);

    Ok(compute_sha256(&input))
}

fn derive_message_and_chain_key(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let message_key = derive_key_bytes(chain_key, MESSAGE_KEY_BYTES, &[], MESSAGE_INFO)?;
    let next_chain_key = derive_key_bytes(chain_key, CHAIN_KEY_BYTES, &[], CHAIN_INFO)?;
    Ok((message_key, next_chain_key))
}

fn compute_dh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if private_key.len() != X25519_PRIVATE_KEY_BYTES || public_key.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid X25519 key sizes for DH",
        ));
    }
    let sk_bytes: [u8; X25519_PRIVATE_KEY_BYTES] = private_key
        .try_into()
        .map_err(|_| ProtocolError::handshake("Invalid X25519 private key"))?;
    let pk_bytes: [u8; X25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| ProtocolError::handshake("Invalid X25519 public key"))?;
    let secret = StaticSecret::from(sk_bytes);
    let public = X25519PublicKey::from(pk_bytes);
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.to_bytes();
    if is_all_zero(&shared_bytes) {
        return Err(ProtocolError::handshake(
            "X25519 DH produced all-zero output (RFC 7748 §6.1)",
        ));
    }
    Ok(shared_bytes.to_vec())
}

fn validate_dh_public_key(public_key: &[u8]) -> Result<(), ProtocolError> {
    DhValidator::validate_x25519_public_key(public_key)
}

const AAD_EPOCH_OFFSET: usize = SESSION_ID_BYTES + IDENTITY_BINDING_HASH_BYTES;
const METADATA_AAD_BYTES: usize = AAD_EPOCH_OFFSET + size_of::<u64>() + size_of::<u32>();
const PAYLOAD_AAD_BYTES: usize = METADATA_AAD_BYTES + size_of::<u64>();

fn build_metadata_aad(
    state: &ProtocolState,
    ratchet_epoch: u64,
) -> Result<[u8; METADATA_AAD_BYTES], ProtocolError> {
    if state.session_id.len() != SESSION_ID_BYTES {
        return Err(ProtocolError::invalid_input("Invalid session id size"));
    }
    if state.identity_binding_hash.len() != IDENTITY_BINDING_HASH_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid identity binding hash size",
        ));
    }
    let mut ad = [0u8; METADATA_AAD_BYTES];
    ad[..SESSION_ID_BYTES].copy_from_slice(&state.session_id);
    ad[SESSION_ID_BYTES..SESSION_ID_BYTES + IDENTITY_BINDING_HASH_BYTES]
        .copy_from_slice(&state.identity_binding_hash);
    ad[AAD_EPOCH_OFFSET..AAD_EPOCH_OFFSET + size_of::<u64>()]
        .copy_from_slice(&ratchet_epoch.to_le_bytes());
    ad[AAD_EPOCH_OFFSET + size_of::<u64>()..].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    Ok(ad)
}

fn build_payload_aad(
    state: &ProtocolState,
    ratchet_epoch: u64,
    message_index: u64,
) -> Result<[u8; PAYLOAD_AAD_BYTES], ProtocolError> {
    if state.session_id.len() != SESSION_ID_BYTES {
        return Err(ProtocolError::invalid_input("Invalid session id size"));
    }
    if state.identity_binding_hash.len() != IDENTITY_BINDING_HASH_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid identity binding hash size",
        ));
    }
    let mut ad = [0u8; PAYLOAD_AAD_BYTES];
    ad[..SESSION_ID_BYTES].copy_from_slice(&state.session_id);
    ad[SESSION_ID_BYTES..SESSION_ID_BYTES + IDENTITY_BINDING_HASH_BYTES]
        .copy_from_slice(&state.identity_binding_hash);
    let mut off = AAD_EPOCH_OFFSET;
    ad[off..off + size_of::<u64>()].copy_from_slice(&ratchet_epoch.to_le_bytes());
    off += size_of::<u64>();
    ad[off..off + size_of::<u64>()].copy_from_slice(&message_index.to_le_bytes());
    off += size_of::<u64>();
    ad[off..off + size_of::<u32>()].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    Ok(ad)
}

fn extract_nonce_index(nonce: &[u8]) -> Result<u32, ProtocolError> {
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(ProtocolError::invalid_input("Invalid nonce size"));
    }
    let offset = NONCE_PREFIX_BYTES + NONCE_COUNTER_BYTES;
    let index = u16::from_le_bytes([nonce[offset], nonce[offset + 1]]);
    Ok(u32::from(index))
}

fn load_nonce_generator(state: &ProtocolState) -> Result<NonceGenerator, ProtocolError> {
    let ng = state
        .nonce_generator
        .as_ref()
        .ok_or_else(|| ProtocolError::invalid_input("Missing nonce generator state"))?;
    if ng.prefix.len() != NONCE_PREFIX_BYTES {
        return Err(ProtocolError::invalid_input("Invalid nonce prefix size"));
    }
    let mut prefix = [0u8; NONCE_PREFIX_BYTES];
    prefix.copy_from_slice(&ng.prefix);
    let ns = NonceStateLocal::new(prefix, ng.counter)?;
    let limit = if state.max_nonce_counter == 0 {
        MAX_NONCE_COUNTER
    } else {
        state.max_nonce_counter
    };
    NonceGenerator::from_state_with_limit(ns, limit)
}

fn store_nonce_state(state: &mut ProtocolState, ns: NonceStateLocal) {
    state.nonce_generator = Some(NonceStateProto {
        prefix: ns.prefix().to_vec(),
        counter: ns.counter(),
    });
}

fn reset_nonce_generator(state: &mut ProtocolState) -> Result<(), ProtocolError> {
    let limit = if state.max_nonce_counter == 0 {
        MAX_NONCE_COUNTER
    } else {
        state.max_nonce_counter
    };
    let ng = NonceGenerator::create_with_limit(limit)?;
    store_nonce_state(state, ng.export_state());
    Ok(())
}

fn timestamp_now() -> Result<Timestamp, ProtocolError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ProtocolError::invalid_state("System clock is before UNIX epoch"))?;
    #[allow(clippy::cast_possible_wrap)]
    let seconds = now.as_secs() as i64;
    Ok(Timestamp { seconds, nanos: 0 })
}

fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

fn wipe_protocol_state_keys(state: &mut ProtocolState) {
    CryptoInterop::secure_wipe(&mut state.root_key);
    CryptoInterop::secure_wipe(&mut state.metadata_key);
    CryptoInterop::secure_wipe(&mut state.send_metadata_key);
    if let Some(dh) = state.dh_local.as_mut() {
        CryptoInterop::secure_wipe(&mut dh.private_key);
    }
    if let Some(kyber) = state.kyber_local.as_mut() {
        CryptoInterop::secure_wipe(&mut kyber.secret_key);
    }
    if let Some(chain) = state.send_chain.as_mut() {
        CryptoInterop::secure_wipe(&mut chain.chain_key);
        for cached in &mut chain.skipped_message_keys {
            CryptoInterop::secure_wipe(&mut cached.message_key);
        }
    }
    if let Some(chain) = state.recv_chain.as_mut() {
        CryptoInterop::secure_wipe(&mut chain.chain_key);
        for cached in &mut chain.skipped_message_keys {
            CryptoInterop::secure_wipe(&mut cached.message_key);
        }
    }
}

fn wipe_export_copy(copy: &mut ProtocolState) {
    wipe_protocol_state_keys(copy);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_protocol_state(
    is_initiator: bool,
    root_key: &[u8],
    session_id: &[u8],
    metadata_key: &[u8],
    dh_local_private: &[u8],
    dh_local_public: &[u8],
    dh_remote_public: &[u8],
    initial_self_public: &[u8],
    initial_peer_public: &[u8],
    kyber_secret: &[u8],
    kyber_public: &[u8],
    peer_kyber_public: &[u8],
    max_messages_per_chain: u32,
    max_nonce_counter: u64,
    nonce_generator: NonceStateLocal,
    local_identity_ed25519: &[u8],
    local_identity_x25519: &[u8],
    peer_identity_ed25519: &[u8],
    peer_identity_x25519: &[u8],
) -> Result<ProtocolState, ProtocolError> {
    if root_key.len() != ROOT_KEY_BYTES
        || session_id.len() != SESSION_ID_BYTES
        || metadata_key.len() != METADATA_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid root/session/metadata key sizes",
        ));
    }
    if dh_local_private.len() != X25519_PRIVATE_KEY_BYTES
        || dh_local_public.len() != X25519_PUBLIC_KEY_BYTES
        || dh_remote_public.len() != X25519_PUBLIC_KEY_BYTES
        || initial_self_public.len() != X25519_PUBLIC_KEY_BYTES
        || initial_peer_public.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input("Invalid DH key sizes"));
    }
    if kyber_secret.len() != KYBER_SECRET_KEY_BYTES
        || kyber_public.len() != KYBER_PUBLIC_KEY_BYTES
        || peer_kyber_public.len() != KYBER_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input("Invalid Kyber key sizes"));
    }
    if local_identity_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
        || local_identity_x25519.len() != X25519_PUBLIC_KEY_BYTES
        || peer_identity_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
        || peer_identity_x25519.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input("Invalid identity key sizes"));
    }

    validate_dh_public_key(local_identity_x25519)
        .map_err(|_| ProtocolError::invalid_input("Local X25519 identity key validation failed"))?;
    validate_dh_public_key(peer_identity_x25519)
        .map_err(|_| ProtocolError::invalid_input("Peer X25519 identity key validation failed"))?;

    if is_all_zero(local_identity_ed25519) {
        return Err(ProtocolError::invalid_input(
            "Local Ed25519 identity key is all zeros",
        ));
    }
    if is_all_zero(peer_identity_ed25519) {
        return Err(ProtocolError::invalid_input(
            "Peer Ed25519 identity key is all zeros",
        ));
    }

    if max_messages_per_chain == 0 || max_messages_per_chain as usize > MAX_MESSAGES_PER_CHAIN {
        return Err(ProtocolError::invalid_input(
            "Invalid max messages per chain",
        ));
    }
    if max_nonce_counter == 0 || max_nonce_counter > MAX_NONCE_COUNTER {
        return Err(ProtocolError::invalid_input(
            "Invalid max nonce counter (must be 1..=65535)",
        ));
    }

    let identity_binding = compute_identity_binding_hash(
        local_identity_ed25519,
        local_identity_x25519,
        peer_identity_ed25519,
        peer_identity_x25519,
    )?;

    Ok(ProtocolState {
        version: PROTOCOL_VERSION,
        is_initiator,
        created_at: Some(timestamp_now()?),
        session_id: session_id.to_vec(),
        root_key: root_key.to_vec(),
        metadata_key: metadata_key.to_vec(),
        send_metadata_key: metadata_key.to_vec(),
        state_counter: 0,
        send_ratchet_epoch: 0,
        recv_ratchet_epoch: 0,
        max_messages_per_chain,
        max_nonce_counter,
        dh_local: Some(DhKeyPair {
            private_key: dh_local_private.to_vec(),
            public_key: dh_local_public.to_vec(),
        }),
        dh_remote_public: dh_remote_public.to_vec(),
        dh_local_initial_public: initial_self_public.to_vec(),
        dh_remote_initial_public: initial_peer_public.to_vec(),
        kyber_local: Some(KyberKeyPair {
            secret_key: kyber_secret.to_vec(),
            public_key: kyber_public.to_vec(),
        }),
        kyber_remote_public: peer_kyber_public.to_vec(),
        nonce_generator: Some(NonceStateProto {
            prefix: nonce_generator.prefix().to_vec(),
            counter: nonce_generator.counter(),
        }),
        send_chain: Some(ChainState {
            message_index: 0,
            chain_key: vec![],
            skipped_message_keys: vec![],
        }),
        recv_chain: Some(ChainState {
            message_index: 0,
            chain_key: vec![],
            skipped_message_keys: vec![],
        }),
        local_identity_ed25519_public: local_identity_ed25519.to_vec(),
        local_identity_x25519_public: local_identity_x25519.to_vec(),
        peer_identity_ed25519_public: peer_identity_ed25519.to_vec(),
        peer_identity_x25519_public: peer_identity_x25519.to_vec(),
        identity_binding_hash: identity_binding,
        state_hmac: vec![],
        replay_epoch: 0,
        seen_payload_nonces: vec![],
        send_ratchet_pending: false,
        skipped_keys: vec![],
        cached_metadata_keys: vec![],
    })
}

struct SessionInner {
    state: ProtocolState,
    pending_kyber_shared_secret: Vec<u8>,
    skipped_message_keys: BTreeMap<(u64, u64), Vec<u8>>,
    cached_metadata_keys: BTreeMap<u64, Vec<u8>>,
    replay_epoch: u64,
    seen_payload_nonces: HashSet<Vec<u8>>,
    is_initiator: bool,
    dh_private_handle: Option<SecureMemoryHandle>,
    kyber_secret_handle: Option<SecureMemoryHandle>,
    send_ratchet_pending: bool,
    event_handler: Option<Arc<dyn IProtocolEventHandler>>,
    messages_since_last_dh_ratchet: u64,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.state.root_key);
        CryptoInterop::secure_wipe(&mut self.state.metadata_key);
        CryptoInterop::secure_wipe(&mut self.state.send_metadata_key);
        if let Some(dh) = self.state.dh_local.as_mut() {
            CryptoInterop::secure_wipe(&mut dh.private_key);
        }
        if let Some(kyber) = self.state.kyber_local.as_mut() {
            CryptoInterop::secure_wipe(&mut kyber.secret_key);
        }
        if let Some(chain) = self.state.send_chain.as_mut() {
            CryptoInterop::secure_wipe(&mut chain.chain_key);
            for cached in &mut chain.skipped_message_keys {
                CryptoInterop::secure_wipe(&mut cached.message_key);
            }
        }
        if let Some(chain) = self.state.recv_chain.as_mut() {
            CryptoInterop::secure_wipe(&mut chain.chain_key);
            for cached in &mut chain.skipped_message_keys {
                CryptoInterop::secure_wipe(&mut cached.message_key);
            }
        }
        CryptoInterop::secure_wipe(&mut self.pending_kyber_shared_secret);
        for key in self.skipped_message_keys.values_mut() {
            CryptoInterop::secure_wipe(key);
        }
        for key in self.cached_metadata_keys.values_mut() {
            CryptoInterop::secure_wipe(key);
        }
    }
}

pub struct Session {
    inner: Mutex<SessionInner>,
}

impl Session {
    fn new(
        mut state: ProtocolState,
        pending_kyber_shared_secret: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        let replay_epoch = state.recv_ratchet_epoch;
        let is_initiator = state.is_initiator;

        let dh_private_handle = if let Some(dh) = state.dh_local.as_mut() {
            if dh.private_key.is_empty() {
                None
            } else {
                let mut handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)
                    .map_err(ProtocolError::from_crypto)?;
                handle
                    .write(&dh.private_key)
                    .map_err(ProtocolError::from_crypto)?;
                CryptoInterop::secure_wipe(&mut dh.private_key);
                dh.private_key = vec![0u8; X25519_PRIVATE_KEY_BYTES];
                Some(handle)
            }
        } else {
            None
        };

        let kyber_secret_handle = if let Some(kyber) = state.kyber_local.as_mut() {
            if kyber.secret_key.is_empty() {
                None
            } else {
                let mut handle = SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES)
                    .map_err(ProtocolError::from_crypto)?;
                handle
                    .write(&kyber.secret_key)
                    .map_err(ProtocolError::from_crypto)?;
                CryptoInterop::secure_wipe(&mut kyber.secret_key);
                kyber.secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES];
                Some(handle)
            }
        } else {
            None
        };

        Ok(Self {
            inner: Mutex::new(SessionInner {
                state,
                pending_kyber_shared_secret,
                skipped_message_keys: BTreeMap::new(),
                cached_metadata_keys: BTreeMap::new(),
                replay_epoch,
                seen_payload_nonces: HashSet::new(),
                is_initiator,
                dh_private_handle,
                kyber_secret_handle,
                send_ratchet_pending: false,
                event_handler: None,
                messages_since_last_dh_ratchet: 0,
            }),
        })
    }

    pub fn from_handshake_state(hs: HandshakeState) -> Result<Self, ProtocolError> {
        let mut hs = std::mem::ManuallyDrop::new(hs);
        let mut state = std::mem::take(&mut hs.state);
        let mut kyber_zeroizing = std::mem::take(&mut hs.kyber_shared_secret);
        if state.version != PROTOCOL_VERSION {
            wipe_protocol_state_keys(&mut state);
            return Err(ProtocolError::invalid_input(
                "Invalid protocol version in handshake state",
            ));
        }
        let kyber_shared_secret = std::mem::take(&mut *kyber_zeroizing);
        let session = Self::new(state, kyber_shared_secret)?;
        {
            let mut inner = session
                .inner
                .lock()
                .map_err(|_| ProtocolError::invalid_state("Session lock poisoned"))?;
            Self::initialize_from_handshake_inner(&mut inner)?;
        }
        Ok(session)
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IProtocolEventHandler>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.event_handler = Some(handler);
        }
    }

    pub fn nonce_remaining(&self) -> Result<u64, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("Session lock poisoned"))?;
        let ng = load_nonce_generator(&inner.state)?;
        let counter = ng.export_state().counter();
        let max = if inner.state.max_nonce_counter == 0 {
            MAX_NONCE_COUNTER
        } else {
            inner.state.max_nonce_counter
        };
        Ok(max.saturating_sub(counter))
    }

    fn from_state_internal(state: ProtocolState) -> Result<Self, ProtocolError> {
        if state.version != PROTOCOL_VERSION {
            return Err(ProtocolError::invalid_input(
                "Invalid protocol version in state",
            ));
        }
        let mut state = state;
        if state.send_metadata_key.is_empty() {
            #[allow(clippy::assigning_clones)]
            {
                state.send_metadata_key = state.metadata_key.clone();
            }
        }
        if state.session_id.len() != SESSION_ID_BYTES
            || state.root_key.len() != ROOT_KEY_BYTES
            || state.metadata_key.len() != METADATA_KEY_BYTES
            || state.send_metadata_key.len() != METADATA_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid session key material sizes",
            ));
        }

        if state.state_hmac.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input(
                "State HMAC missing or invalid size — possible tampering",
            ));
        }
        if state.state_counter == 0 {
            return Err(ProtocolError::invalid_input(
                "State counter must be non-zero for imported state",
            ));
        }
        let saved_hmac = state.state_hmac.clone();
        state.state_hmac.clear();
        let mut tmp = Vec::new();
        state.encode(&mut tmp).map_err(|e| {
            ProtocolError::encode(format!("Failed to re-serialize state for HMAC: {e}"))
        })?;
        let expected = compute_state_hmac(&state.root_key, &tmp)?;
        let eq = CryptoInterop::constant_time_equals(&saved_hmac, &expected)
            .map_err(ProtocolError::from_crypto)?;
        if !eq {
            return Err(ProtocolError::invalid_input(
                "State HMAC verification failed — possible rollback or tampering",
            ));
        }

        let dh_local = state
            .dh_local
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Missing dh_local in state"))?;
        if dh_local.private_key.len() != X25519_PRIVATE_KEY_BYTES
            || dh_local.public_key.len() != X25519_PUBLIC_KEY_BYTES
            || state.dh_remote_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid DH key sizes in state",
            ));
        }
        if state.dh_local_initial_public.len() != X25519_PUBLIC_KEY_BYTES
            || state.dh_remote_initial_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid initial DH public key sizes in state",
            ));
        }

        let kyber_local = state
            .kyber_local
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Missing kyber_local in state"))?;
        if kyber_local.secret_key.len() != KYBER_SECRET_KEY_BYTES
            || kyber_local.public_key.len() != KYBER_PUBLIC_KEY_BYTES
            || state.kyber_remote_public.len() != KYBER_PUBLIC_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid Kyber key sizes in state",
            ));
        }

        let send_chain = state
            .send_chain
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Missing send_chain in state"))?;
        let recv_chain = state
            .recv_chain
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Missing recv_chain in state"))?;
        if send_chain.chain_key.len() != CHAIN_KEY_BYTES
            || recv_chain.chain_key.len() != CHAIN_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid chain key sizes in state",
            ));
        }

        let nonce_gen = state
            .nonce_generator
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Missing nonce_generator in state"))?;
        if nonce_gen.prefix.len() != NONCE_PREFIX_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid nonce prefix size in state",
            ));
        }

        #[allow(clippy::cast_possible_truncation)]
        let max = state.max_messages_per_chain as usize;
        if max == 0 || max > MAX_MESSAGES_PER_CHAIN {
            return Err(ProtocolError::invalid_input(
                "Invalid max messages per chain in state",
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        let (send_idx, recv_idx) = (
            send_chain.message_index as usize,
            recv_chain.message_index as usize,
        );
        if send_idx > max || recv_idx > max {
            return Err(ProtocolError::invalid_input(
                "Chain index exceeds max messages per chain",
            ));
        }
        let nonce_limit = if state.max_nonce_counter == 0 {
            MAX_NONCE_COUNTER
        } else {
            state.max_nonce_counter.min(MAX_NONCE_COUNTER)
        };
        if nonce_gen.counter > nonce_limit {
            return Err(ProtocolError::invalid_state(
                "Nonce counter exceeds maximum",
            ));
        }

        if is_all_zero(&dh_local.private_key) {
            return Err(ProtocolError::invalid_input("DH private key is all zeros"));
        }
        if is_all_zero(&kyber_local.secret_key) {
            return Err(ProtocolError::invalid_input(
                "Kyber secret key is all zeros",
            ));
        }

        validate_dh_public_key(&dh_local.public_key)?;
        validate_dh_public_key(&state.dh_remote_public)?;
        validate_dh_public_key(&state.dh_local_initial_public)?;
        validate_dh_public_key(&state.dh_remote_initial_public)?;

        KyberInterop::validate_public_key(&kyber_local.public_key)
            .map_err(ProtocolError::from_crypto)?;
        KyberInterop::validate_public_key(&state.kyber_remote_public)
            .map_err(ProtocolError::from_crypto)?;

        if state.local_identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || state.local_identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
            || state.peer_identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || state.peer_identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid identity key sizes in state",
            ));
        }
        if state.identity_binding_hash.len() != IDENTITY_BINDING_HASH_BYTES {
            return Err(ProtocolError::invalid_input(
                "Missing or invalid identity binding hash",
            ));
        }

        let computed_binding = compute_identity_binding_hash(
            &state.local_identity_ed25519_public,
            &state.local_identity_x25519_public,
            &state.peer_identity_ed25519_public,
            &state.peer_identity_x25519_public,
        )?;
        let eq =
            CryptoInterop::constant_time_equals(&computed_binding, &state.identity_binding_hash)
                .map_err(ProtocolError::from_crypto)?;
        if !eq {
            return Err(ProtocolError::invalid_input(
                "Identity binding hash verification failed",
            ));
        }

        if !send_chain.skipped_message_keys.is_empty() {
            return Err(ProtocolError::invalid_input(
                "Send chain must not include skipped message keys",
            ));
        }

        if state.skipped_keys.len() > MAX_SKIPPED_MESSAGE_KEYS {
            return Err(ProtocolError::invalid_input(
                "Too many skipped message keys in state",
            ));
        }
        let mut skipped = BTreeMap::new();
        let mut seen_tuples = HashSet::new();
        for cached in &state.skipped_keys {
            if cached.message_key.len() != MESSAGE_KEY_BYTES {
                return Err(ProtocolError::invalid_input(
                    "Invalid skipped message key size in state",
                ));
            }
            if cached.message_index > MAX_MESSAGE_INDEX {
                return Err(ProtocolError::invalid_input(
                    "Cached message key index exceeds maximum",
                ));
            }
            if cached.epoch > state.recv_ratchet_epoch {
                return Err(ProtocolError::invalid_input(
                    "Cached message key epoch exceeds current recv epoch",
                ));
            }
            if !seen_tuples.insert((cached.epoch, cached.message_index)) {
                return Err(ProtocolError::invalid_input(
                    "Duplicate skipped message key",
                ));
            }
            skipped.insert(
                (cached.epoch, cached.message_index),
                cached.message_key.clone(),
            );
        }

        if skipped.is_empty() && !recv_chain.skipped_message_keys.is_empty() {
            if recv_chain.skipped_message_keys.len() > MAX_SKIPPED_MESSAGE_KEYS {
                return Err(ProtocolError::invalid_input(
                    "Too many skipped message keys in state",
                ));
            }
            let epoch = state.recv_ratchet_epoch;
            for cached in &recv_chain.skipped_message_keys {
                if cached.message_key.len() != MESSAGE_KEY_BYTES {
                    return Err(ProtocolError::invalid_input(
                        "Invalid skipped message key size in state",
                    ));
                }
                if cached.message_index >= recv_chain.message_index {
                    return Err(ProtocolError::invalid_input(
                        "Cached message key index out of range",
                    ));
                }
                skipped.insert((epoch, cached.message_index), cached.message_key.clone());
            }
        }

        if state.cached_metadata_keys.len() > MAX_CACHED_METADATA_KEYS {
            return Err(ProtocolError::invalid_input(
                "Too many cached metadata keys in state",
            ));
        }
        let mut cached_mk = BTreeMap::new();
        {
            let mut seen_epochs = HashSet::new();
            for entry in &state.cached_metadata_keys {
                if entry.metadata_key.len() != METADATA_KEY_BYTES {
                    return Err(ProtocolError::invalid_input(
                        "Invalid cached metadata key size in state",
                    ));
                }
                if entry.epoch > state.recv_ratchet_epoch {
                    return Err(ProtocolError::invalid_input(
                        "Cached metadata key epoch exceeds current recv epoch",
                    ));
                }
                if !seen_epochs.insert(entry.epoch) {
                    return Err(ProtocolError::invalid_input(
                        "Duplicate cached metadata key epoch",
                    ));
                }
                cached_mk.insert(entry.epoch, entry.metadata_key.clone());
            }
        }

        let replay_epoch = state.replay_epoch;
        let mut seen_payload_nonces: HashSet<Vec<u8>> =
            state.seen_payload_nonces.iter().cloned().collect();
        if seen_payload_nonces.len() > MAX_SEEN_NONCES {
            Self::prune_seen_nonces(&mut seen_payload_nonces);
        }

        let mut sanitized = state;
        sanitized.state_hmac.clear();
        sanitized.seen_payload_nonces.clear();
        sanitized.skipped_keys.clear();
        sanitized.cached_metadata_keys.clear();
        if let Some(sc) = sanitized.send_chain.as_mut() {
            sc.skipped_message_keys.clear();
        }
        if let Some(rc) = sanitized.recv_chain.as_mut() {
            rc.skipped_message_keys.clear();
        }

        let dh_private_handle = if let Some(dh) = sanitized.dh_local.as_mut() {
            if dh.private_key.is_empty() {
                None
            } else {
                let mut handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)
                    .map_err(ProtocolError::from_crypto)?;
                handle
                    .write(&dh.private_key)
                    .map_err(ProtocolError::from_crypto)?;
                CryptoInterop::secure_wipe(&mut dh.private_key);
                dh.private_key = vec![0u8; X25519_PRIVATE_KEY_BYTES];
                Some(handle)
            }
        } else {
            None
        };

        let kyber_secret_handle = if let Some(kyber) = sanitized.kyber_local.as_mut() {
            if kyber.secret_key.is_empty() {
                None
            } else {
                let mut handle = SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES)
                    .map_err(ProtocolError::from_crypto)?;
                handle
                    .write(&kyber.secret_key)
                    .map_err(ProtocolError::from_crypto)?;
                CryptoInterop::secure_wipe(&mut kyber.secret_key);
                kyber.secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES];
                Some(handle)
            }
        } else {
            None
        };

        let is_initiator = sanitized.is_initiator;
        let send_ratchet_pending = sanitized.send_ratchet_pending;
        Ok(Self {
            inner: Mutex::new(SessionInner {
                state: sanitized,
                pending_kyber_shared_secret: vec![],
                skipped_message_keys: skipped,
                cached_metadata_keys: cached_mk,
                replay_epoch,
                seen_payload_nonces,
                is_initiator,
                dh_private_handle,
                kyber_secret_handle,
                send_ratchet_pending,
                event_handler: None,
                messages_since_last_dh_ratchet: 0,
            }),
        })
    }

    fn initialize_from_handshake_inner(inner: &mut SessionInner) -> Result<(), ProtocolError> {
        let wipe_pending = |inner: &mut SessionInner| {
            if !inner.pending_kyber_shared_secret.is_empty() {
                CryptoInterop::secure_wipe(&mut inner.pending_kyber_shared_secret);
                inner.pending_kyber_shared_secret.clear();
            }
        };

        if inner.pending_kyber_shared_secret.len() != KYBER_SHARED_SECRET_BYTES {
            wipe_pending(inner);
            return Err(ProtocolError::invalid_state(
                "Missing Kyber shared secret for handshake init",
            ));
        }
        if inner.state.root_key.len() != ROOT_KEY_BYTES {
            wipe_pending(inner);
            return Err(ProtocolError::invalid_input("Invalid root key size"));
        }
        let dh_priv_len = inner
            .state
            .dh_local
            .as_ref()
            .map_or(0, |d| d.private_key.len());
        if dh_priv_len != X25519_PRIVATE_KEY_BYTES
            || inner.state.dh_remote_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            wipe_pending(inner);
            return Err(ProtocolError::invalid_input(
                "Invalid DH keys for handshake init",
            ));
        }

        validate_dh_public_key(&inner.state.dh_remote_public).inspect_err(|_e| {
            wipe_pending(inner);
        })?;

        let mut dh_private = inner
            .dh_private_handle
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_state("DH private key handle missing"))?
            .read_bytes(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut dh_init = compute_dh(&dh_private, &inner.state.dh_remote_public)?;
        CryptoInterop::secure_wipe(&mut dh_private);

        let mut hybrid_ikm =
            Vec::with_capacity(dh_init.len() + inner.pending_kyber_shared_secret.len());
        hybrid_ikm.extend_from_slice(&dh_init);
        hybrid_ikm.extend_from_slice(&inner.pending_kyber_shared_secret);
        CryptoInterop::secure_wipe(&mut dh_init);

        let salt = inner.state.root_key.clone();
        let hybrid_out =
            derive_key_bytes(&hybrid_ikm, ROOT_KEY_BYTES * 2, &salt, HYBRID_RATCHET_INFO);
        CryptoInterop::secure_wipe(&mut hybrid_ikm);
        let mut hybrid_out = hybrid_out.inspect_err(|_e| {
            wipe_pending(inner);
        })?;

        if hybrid_out.len() != ROOT_KEY_BYTES * 2 {
            CryptoInterop::secure_wipe(&mut hybrid_out);
            wipe_pending(inner);
            return Err(ProtocolError::invalid_state(
                "Hybrid ratchet output size mismatch",
            ));
        }

        let new_root = hybrid_out[..ROOT_KEY_BYTES].to_vec();
        CryptoInterop::secure_wipe(&mut hybrid_out);

        let chain_init = derive_key_bytes(&new_root, CHAIN_KEY_BYTES * 2, &[], CHAIN_INIT_INFO)
            .inspect_err(|_e| {
                wipe_pending(inner);
            })?;
        if chain_init.len() != CHAIN_KEY_BYTES * 2 {
            wipe_pending(inner);
            return Err(ProtocolError::invalid_state(
                "Chain init output size mismatch",
            ));
        }

        let mut send_chain = chain_init[..CHAIN_KEY_BYTES].to_vec();
        let mut recv_chain = chain_init[CHAIN_KEY_BYTES..].to_vec();
        if !inner.is_initiator {
            std::mem::swap(&mut send_chain, &mut recv_chain);
        }

        inner.state.root_key = new_root;
        inner.state.send_chain = Some(ChainState {
            chain_key: send_chain.clone(),
            message_index: 0,
            skipped_message_keys: vec![],
        });
        inner.state.recv_chain = Some(ChainState {
            chain_key: recv_chain.clone(),
            message_index: 0,
            skipped_message_keys: vec![],
        });
        inner.state.send_ratchet_epoch = 0;
        inner.state.recv_ratchet_epoch = 0;

        CryptoInterop::secure_wipe(&mut send_chain);
        CryptoInterop::secure_wipe(&mut recv_chain);
        wipe_pending(inner);
        inner.skipped_message_keys.clear();
        Ok(())
    }

    fn next_send_message_key(inner: &mut SessionInner) -> Result<(u64, Vec<u8>), ProtocolError> {
        let chain = inner
            .state
            .send_chain
            .as_mut()
            .ok_or_else(|| ProtocolError::invalid_state("Send chain not initialized"))?;
        if chain.chain_key.len() != CHAIN_KEY_BYTES {
            return Err(ProtocolError::invalid_state("Sending chain key missing"));
        }
        let message_index = chain.message_index;
        if message_index > MAX_MESSAGE_INDEX {
            return Err(ProtocolError::invalid_state(
                "Message index exceeds maximum",
            ));
        }

        let chain_key = Zeroizing::new(chain.chain_key.clone());
        let (message_key, mut next_chain_key) = derive_message_and_chain_key(&chain_key)?;
        CryptoInterop::secure_wipe(&mut chain.chain_key);
        std::mem::swap(&mut chain.chain_key, &mut next_chain_key);
        chain.message_index = message_index + 1;
        CryptoInterop::secure_wipe(&mut next_chain_key);

        Ok((message_index, message_key))
    }

    fn skip_old_chain_keys(
        inner: &mut SessionInner,
        previous_chain_length: u64,
    ) -> Result<(), ProtocolError> {
        let recv_chain = inner
            .state
            .recv_chain
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_state("Recv chain not initialized"))?;

        if recv_chain.chain_key.len() != CHAIN_KEY_BYTES {
            return Err(ProtocolError::invalid_state("Receiving chain key missing"));
        }

        let current_index = recv_chain.message_index;
        let epoch = inner.state.recv_ratchet_epoch;

        if current_index >= previous_chain_length {
            return Ok(());
        }

        #[allow(clippy::cast_possible_truncation)]
        let count_to_skip = (previous_chain_length - current_index) as usize;
        if inner.skipped_message_keys.len() + count_to_skip > MAX_SKIPPED_MESSAGE_KEYS {
            return Err(ProtocolError::invalid_state("Message key cache overflow"));
        }

        let mut chain_key = Zeroizing::new(recv_chain.chain_key.clone());
        for idx in current_index..previous_chain_length {
            let (message_key, next_chain_key) = derive_message_and_chain_key(&chain_key)?;
            *chain_key = next_chain_key;
            inner.skipped_message_keys.insert((epoch, idx), message_key);
        }

        if let Some(rc) = inner.state.recv_chain.as_mut() {
            CryptoInterop::secure_wipe(&mut rc.chain_key);
            rc.chain_key = std::mem::take(&mut *chain_key);
            rc.message_index = previous_chain_length;
        }

        Ok(())
    }

    fn try_skipped_key(
        inner: &mut SessionInner,
        epoch: u64,
        message_index: u64,
    ) -> Option<Vec<u8>> {
        inner.skipped_message_keys.remove(&(epoch, message_index))
    }

    fn enforce_cache_limit(inner: &mut SessionInner) {
        while inner.skipped_message_keys.len() > MAX_SKIPPED_MESSAGE_KEYS {
            if let Some((_, mut key)) = inner.skipped_message_keys.pop_first() {
                CryptoInterop::secure_wipe(&mut key);
            }
        }
    }

    fn prune_seen_nonces(set: &mut HashSet<Vec<u8>>) {
        let mut entries: Vec<Vec<u8>> = set.drain().collect();
        entries.sort_by_key(|n| {
            if n.len() >= 12 {
                u32::from_le_bytes([n[8], n[9], n[10], n[11]])
            } else {
                0u32
            }
        });
        let keep_from = entries.len().saturating_sub(MAX_SEEN_NONCES / 2);
        for entry in entries.drain(keep_from..) {
            set.insert(entry);
        }
    }

    fn enforce_metadata_cache_limit(inner: &mut SessionInner) {
        while inner.cached_metadata_keys.len() > MAX_CACHED_METADATA_KEYS {
            if let Some((_, mut key)) = inner.cached_metadata_keys.pop_first() {
                CryptoInterop::secure_wipe(&mut key);
            }
        }
    }

    fn get_recv_message_key(
        inner: &mut SessionInner,
        message_index: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let epoch = inner.state.recv_ratchet_epoch;
        let current_index = {
            let chain = inner
                .state
                .recv_chain
                .as_ref()
                .ok_or_else(|| ProtocolError::invalid_state("Recv chain not initialized"))?;
            if chain.chain_key.len() != CHAIN_KEY_BYTES {
                return Err(ProtocolError::invalid_state("Receiving chain key missing"));
            }
            chain.message_index
        };

        if message_index > MAX_MESSAGE_INDEX {
            return Err(ProtocolError::invalid_input(
                "Message index exceeds maximum",
            ));
        }

        if message_index < current_index {
            if let Some(key) = inner.skipped_message_keys.remove(&(epoch, message_index)) {
                return Ok(key);
            }
            return Err(ProtocolError::replay_attack(
                "Replay attack detected: message index already processed",
            ));
        }

        let recv_chain = inner
            .state
            .recv_chain
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_state("Recv chain not initialized"))?;
        let mut chain_key = Zeroizing::new(recv_chain.chain_key.clone());
        let mut index = current_index;
        while index <= message_index {
            let (message_key, next_chain_key) = derive_message_and_chain_key(&chain_key)?;
            *chain_key = next_chain_key;

            if index < message_index {
                if inner.skipped_message_keys.len() >= MAX_SKIPPED_MESSAGE_KEYS {
                    CryptoInterop::secure_wipe(&mut { message_key });
                    return Err(ProtocolError::invalid_state("Message key cache overflow"));
                }
                inner
                    .skipped_message_keys
                    .insert((epoch, index), message_key);
            } else {
                let rc =
                    inner.state.recv_chain.as_mut().ok_or_else(|| {
                        ProtocolError::invalid_state("Recv chain not initialized")
                    })?;
                CryptoInterop::secure_wipe(&mut rc.chain_key);
                rc.chain_key = std::mem::take(&mut *chain_key);
                rc.message_index = message_index + 1;
                return Ok(message_key);
            }
            index += 1;
        }
        Err(ProtocolError::invalid_state("Failed to derive message key"))
    }

    fn maybe_rotate_send_ratchet(
        inner: &mut SessionInner,
        envelope: &mut SecureEnvelope,
    ) -> Result<(), ProtocolError> {
        let chain_idx = inner
            .state
            .send_chain
            .as_ref()
            .map_or(0, |c| c.message_index);
        let max = u64::from(inner.state.max_messages_per_chain);
        if max == 0 || max > MAX_MESSAGES_PER_CHAIN as u64 {
            return Err(ProtocolError::invalid_state(
                "Invalid max messages per chain",
            ));
        }

        let should_ratchet = inner.send_ratchet_pending || chain_idx >= max;
        if !should_ratchet {
            return Ok(());
        }

        if inner.state.dh_remote_public.len() != X25519_PUBLIC_KEY_BYTES
            || inner.state.root_key.len() != ROOT_KEY_BYTES
        {
            return Err(ProtocolError::invalid_state(
                "Cannot rotate ratchet: missing key material",
            ));
        }
        if inner.state.kyber_remote_public.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_state(
                "Peer Kyber public key missing",
            ));
        }

        let (new_private_handle, new_public) = CryptoInterop::generate_x25519_keypair("ratchet")?;
        let mut new_private = new_private_handle
            .read_bytes(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;

        validate_dh_public_key(&inner.state.dh_remote_public)?;

        let mut dh_secret = compute_dh(&new_private, &inner.state.dh_remote_public)?;

        let (kyber_ct, kyber_ss_handle) =
            KyberInterop::encapsulate(&inner.state.kyber_remote_public).map_err(|e| {
                CryptoInterop::secure_wipe(&mut new_private);
                CryptoInterop::secure_wipe(&mut dh_secret);
                ProtocolError::from_crypto(e)
            })?;
        let mut kyber_ss = kyber_ss_handle
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(|e| {
                CryptoInterop::secure_wipe(&mut new_private);
                CryptoInterop::secure_wipe(&mut dh_secret);
                ProtocolError::from_crypto(e)
            })?;

        let (new_kyber_sk_handle, new_kyber_pk) =
            KyberInterop::generate_keypair().map_err(|e| {
                CryptoInterop::secure_wipe(&mut new_private);
                CryptoInterop::secure_wipe(&mut dh_secret);
                CryptoInterop::secure_wipe(&mut kyber_ss);
                ProtocolError::from_crypto(e)
            })?;

        let mut hybrid_ikm = Vec::with_capacity(dh_secret.len() + kyber_ss.len());
        hybrid_ikm.extend_from_slice(&dh_secret);
        hybrid_ikm.extend_from_slice(&kyber_ss);
        CryptoInterop::secure_wipe(&mut dh_secret);
        CryptoInterop::secure_wipe(&mut kyber_ss);

        let mut augmented_info = Vec::with_capacity(HYBRID_RATCHET_INFO.len() + new_kyber_pk.len());
        augmented_info.extend_from_slice(HYBRID_RATCHET_INFO);
        augmented_info.extend_from_slice(&new_kyber_pk);

        let salt = inner.state.root_key.clone();
        let ratchet_out =
            derive_key_bytes(&hybrid_ikm, RATCHET_OUTPUT_BYTES, &salt, &augmented_info);
        CryptoInterop::secure_wipe(&mut hybrid_ikm);
        let mut ratchet_out = ratchet_out.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut new_private);
        })?;

        if ratchet_out.len() != RATCHET_OUTPUT_BYTES {
            CryptoInterop::secure_wipe(&mut ratchet_out);
            CryptoInterop::secure_wipe(&mut new_private);
            return Err(ProtocolError::invalid_state("Ratchet output size mismatch"));
        }

        let new_root = ratchet_out[..ROOT_KEY_BYTES].to_vec();
        let new_chain = ratchet_out[ROOT_KEY_BYTES..ROOT_KEY_BYTES + CHAIN_KEY_BYTES].to_vec();
        let new_metadata = ratchet_out[ROOT_KEY_BYTES + CHAIN_KEY_BYTES..].to_vec();
        CryptoInterop::secure_wipe(&mut ratchet_out);

        let prev_chain_len = inner
            .state
            .send_chain
            .as_ref()
            .map_or(0, |c| c.message_index);
        envelope.previous_chain_length = Some(prev_chain_len);

        inner.state.root_key.clone_from(&new_root);
        inner.state.send_metadata_key.clone_from(&new_metadata);
        inner.state.send_chain = Some(ChainState {
            chain_key: new_chain.clone(),
            message_index: 0,
            skipped_message_keys: vec![],
        });
        inner.state.send_ratchet_epoch = inner
            .state
            .send_ratchet_epoch
            .checked_add(1)
            .ok_or_else(|| ProtocolError::invalid_state("Send ratchet epoch overflow"))?;

        let mut dh_handle =
            SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES).map_err(|e| {
                CryptoInterop::secure_wipe(&mut new_private);
                ProtocolError::from_crypto(e)
            })?;
        dh_handle.write(&new_private).map_err(|e| {
            CryptoInterop::secure_wipe(&mut new_private);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut new_private);
        inner.dh_private_handle = Some(dh_handle);

        if let Some(dl) = inner.state.dh_local.as_mut() {
            dl.private_key = vec![0u8; X25519_PRIVATE_KEY_BYTES];
            dl.public_key.clone_from(&new_public);
        } else {
            inner.state.dh_local = Some(DhKeyPair {
                private_key: vec![0u8; X25519_PRIVATE_KEY_BYTES],
                public_key: new_public.clone(),
            });
        }

        inner.kyber_secret_handle = Some(new_kyber_sk_handle);
        if let Some(kyber) = inner.state.kyber_local.as_mut() {
            kyber.secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES];
            kyber.public_key.clone_from(&new_kyber_pk);
        }

        envelope.dh_public_key = Some(new_public);
        envelope.kyber_ciphertext = Some(kyber_ct);
        envelope.new_kyber_public = Some(new_kyber_pk);

        inner.send_ratchet_pending = false;
        inner.state.send_ratchet_pending = false;
        inner.messages_since_last_dh_ratchet = 0;
        reset_nonce_generator(&mut inner.state)?;

        CryptoInterop::secure_wipe(&mut { new_root });
        CryptoInterop::secure_wipe(&mut { new_chain });
        CryptoInterop::secure_wipe(&mut { new_metadata });
        Ok(())
    }

    fn apply_recv_ratchet(
        inner: &mut SessionInner,
        envelope: &SecureEnvelope,
    ) -> Result<(), ProtocolError> {
        let dh_public = envelope
            .dh_public_key
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Ratchet header missing"))?;
        let kyber_ct = envelope
            .kyber_ciphertext
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_input("Ratchet header missing"))?;
        let new_kyber_pk = envelope.new_kyber_public.as_ref().ok_or_else(|| {
            ProtocolError::invalid_input("Ratchet message missing new Kyber public key")
        })?;

        if dh_public.len() != X25519_PUBLIC_KEY_BYTES || kyber_ct.len() != KYBER_CIPHERTEXT_BYTES {
            return Err(ProtocolError::invalid_input("Invalid ratchet header sizes"));
        }
        if new_kyber_pk.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid new Kyber public key size",
            ));
        }

        validate_dh_public_key(dh_public)?;
        KyberInterop::validate_ciphertext(kyber_ct).map_err(ProtocolError::from_crypto)?;
        KyberInterop::validate_public_key(new_kyber_pk).map_err(ProtocolError::from_crypto)?;

        if inner.state.root_key.len() != ROOT_KEY_BYTES {
            return Err(ProtocolError::invalid_state("Missing ratchet key material"));
        }

        if let Some(pcl) = envelope.previous_chain_length {
            Self::skip_old_chain_keys(inner, pcl)?;
        }

        let dh_handle = inner
            .dh_private_handle
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_state("DH private key handle missing"))?;
        let mut dh_private = dh_handle
            .read_bytes(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut dh_secret = compute_dh(&dh_private, dh_public)?;
        CryptoInterop::secure_wipe(&mut dh_private);

        let sk_handle = inner
            .kyber_secret_handle
            .as_ref()
            .ok_or_else(|| ProtocolError::invalid_state("Kyber secret key handle missing"))?;

        let ss_handle = KyberInterop::decapsulate(kyber_ct, sk_handle).map_err(|e| {
            CryptoInterop::secure_wipe(&mut dh_secret);
            ProtocolError::from_crypto(e)
        })?;
        let mut kyber_ss = ss_handle
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(|e| {
                CryptoInterop::secure_wipe(&mut dh_secret);
                ProtocolError::from_crypto(e)
            })?;

        let mut hybrid_ikm = Vec::with_capacity(dh_secret.len() + kyber_ss.len());
        hybrid_ikm.extend_from_slice(&dh_secret);
        hybrid_ikm.extend_from_slice(&kyber_ss);
        CryptoInterop::secure_wipe(&mut dh_secret);
        CryptoInterop::secure_wipe(&mut kyber_ss);

        let mut augmented_info = Vec::with_capacity(HYBRID_RATCHET_INFO.len() + new_kyber_pk.len());
        augmented_info.extend_from_slice(HYBRID_RATCHET_INFO);
        augmented_info.extend_from_slice(new_kyber_pk);

        let salt = inner.state.root_key.clone();
        let ratchet_out =
            derive_key_bytes(&hybrid_ikm, RATCHET_OUTPUT_BYTES, &salt, &augmented_info);
        CryptoInterop::secure_wipe(&mut hybrid_ikm);
        let mut ratchet_out = ratchet_out?;

        if ratchet_out.len() != RATCHET_OUTPUT_BYTES {
            CryptoInterop::secure_wipe(&mut ratchet_out);
            return Err(ProtocolError::invalid_state("Ratchet output size mismatch"));
        }

        let new_root = ratchet_out[..ROOT_KEY_BYTES].to_vec();
        let new_chain = ratchet_out[ROOT_KEY_BYTES..ROOT_KEY_BYTES + CHAIN_KEY_BYTES].to_vec();
        let new_metadata = ratchet_out[ROOT_KEY_BYTES + CHAIN_KEY_BYTES..].to_vec();
        CryptoInterop::secure_wipe(&mut ratchet_out);

        inner.cached_metadata_keys.insert(
            inner.state.recv_ratchet_epoch,
            inner.state.metadata_key.clone(),
        );
        Self::enforce_metadata_cache_limit(inner);

        inner.state.root_key.clone_from(&new_root);
        inner.state.metadata_key.clone_from(&new_metadata);
        inner.state.recv_chain = Some(ChainState {
            chain_key: new_chain.clone(),
            message_index: 0,
            skipped_message_keys: vec![],
        });
        inner.state.recv_ratchet_epoch = inner
            .state
            .recv_ratchet_epoch
            .checked_add(1)
            .ok_or_else(|| ProtocolError::invalid_state("Recv ratchet epoch overflow"))?;
        inner.state.dh_remote_public.clone_from(dh_public);
        inner.state.kyber_remote_public.clone_from(new_kyber_pk);
        inner.replay_epoch = inner.state.recv_ratchet_epoch;

        Self::enforce_cache_limit(inner);

        inner.send_ratchet_pending = true;
        inner.state.send_ratchet_pending = true;

        CryptoInterop::secure_wipe(&mut { new_root });
        CryptoInterop::secure_wipe(&mut { new_chain });
        CryptoInterop::secure_wipe(&mut { new_metadata });
        Ok(())
    }

    pub fn encrypt(
        &self,
        payload: &[u8],
        envelope_type: i32,
        envelope_id: u32,
        correlation_id: Option<&str>,
    ) -> Result<SecureEnvelope, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("Session lock poisoned"))?;

        if inner.state.version == 0 {
            return Err(ProtocolError::invalid_state("Session has been destroyed"));
        }
        if inner.state.send_metadata_key.len() != METADATA_KEY_BYTES {
            return Err(ProtocolError::invalid_state(
                "Send metadata key not initialized",
            ));
        }

        let mut envelope = SecureEnvelope {
            version: PROTOCOL_VERSION,
            ..Default::default()
        };

        Self::maybe_rotate_send_ratchet(&mut inner, &mut envelope)?;

        let ratchet_epoch = inner.state.send_ratchet_epoch;
        envelope.ratchet_epoch = ratchet_epoch;

        let (message_index, mut message_key) = Self::next_send_message_key(&mut inner)?;

        let mut nonce_gen = load_nonce_generator(&inner.state)?;
        let payload_nonce = nonce_gen.next(message_index).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut message_key);
        })?;
        let nonce_export = nonce_gen.export_state();
        let max_cap = if inner.state.max_nonce_counter == 0 {
            MAX_NONCE_COUNTER
        } else {
            inner.state.max_nonce_counter
        };
        let remaining = max_cap.saturating_sub(nonce_export.counter());
        store_nonce_state(&mut inner.state, nonce_export);

        let threshold = max_cap / (100 / NONCE_EXHAUSTION_WARNING_PERCENT);
        if remaining <= threshold {
            if let Some(handler) = &inner.event_handler {
                handler.on_nonce_exhaustion_warning(remaining, max_cap);
            }
        }

        inner.messages_since_last_dh_ratchet += 1;
        if inner.messages_since_last_dh_ratchet >= RATCHET_STALLING_WARNING_THRESHOLD {
            if let Some(handler) = &inner.event_handler {
                handler.on_ratchet_stalling_warning(inner.messages_since_last_dh_ratchet);
            }
        }

        let metadata = EnvelopeMetadata {
            message_index,
            payload_nonce: payload_nonce.to_vec(),
            envelope_type,
            envelope_id,
            correlation_id: correlation_id.map(std::string::ToString::to_string),
        };

        let metadata_bytes = {
            let mut buf = Vec::new();
            metadata.encode(&mut buf).map_err(|e| {
                CryptoInterop::secure_wipe(&mut message_key);
                ProtocolError::encode(format!("Failed to serialize metadata: {e}"))
            })?;
            buf
        };

        let header_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        if header_nonce.len() != AES_GCM_NONCE_BYTES {
            CryptoInterop::secure_wipe(&mut message_key);
            return Err(ProtocolError::generic("Failed to generate header nonce"));
        }

        let metadata_aad = build_metadata_aad(&inner.state, ratchet_epoch).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut message_key);
        })?;

        let encrypted_metadata = AesGcm::encrypt(
            &inner.state.send_metadata_key,
            &header_nonce,
            &metadata_bytes,
            &metadata_aad,
        )
        .inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut message_key);
        })?;

        let payload_aad = build_payload_aad(&inner.state, ratchet_epoch, message_index)
            .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut message_key);
            })?;

        let padded_payload = MessagePadding::pad(payload);
        let encrypted_payload =
            AesGcm::encrypt(&message_key, &payload_nonce, &padded_payload, &payload_aad);
        CryptoInterop::secure_wipe(&mut message_key);
        let encrypted_payload = encrypted_payload?;

        envelope.encrypted_metadata = encrypted_metadata;
        envelope.encrypted_payload = encrypted_payload;
        envelope.header_nonce = header_nonce;
        envelope.sent_at = Some(timestamp_now()?);

        Ok(envelope)
    }

    pub fn decrypt(&self, envelope: &SecureEnvelope) -> Result<DecryptResult, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("Session lock poisoned"))?;

        if inner.state.version == 0 {
            return Err(ProtocolError::invalid_state("Session has been destroyed"));
        }
        if envelope.version != PROTOCOL_VERSION {
            return Err(ProtocolError::invalid_input("Invalid envelope version"));
        }
        if envelope.header_nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid header nonce size"));
        }
        if inner.state.metadata_key.len() != METADATA_KEY_BYTES {
            return Err(ProtocolError::invalid_state("Metadata key not initialized"));
        }

        let max = u64::from(inner.state.max_messages_per_chain);
        if max == 0 || max > MAX_MESSAGES_PER_CHAIN as u64 {
            return Err(ProtocolError::invalid_state(
                "Invalid max messages per chain",
            ));
        }

        let envelope_epoch = envelope.ratchet_epoch;
        let has_dh = envelope.dh_public_key.is_some();
        let has_kyber_ct = envelope.kyber_ciphertext.is_some();
        let has_new_kyber_pk = envelope.new_kyber_public.is_some();

        let is_old_epoch;
        type RatchetSnapshot = (
            ProtocolState,
            BTreeMap<u64, Vec<u8>>,
            Vec<u8>,
            Vec<u8>,
            BTreeMap<(u64, u64), Vec<u8>>,
            u64,
            bool,
        );
        let mut ratchet_snapshot: Option<RatchetSnapshot> = None;
        if has_dh || has_kyber_ct || has_new_kyber_pk {
            if !has_dh || !has_kyber_ct || !has_new_kyber_pk {
                return Err(ProtocolError::invalid_input("Incomplete ratchet header: dh_public_key, kyber_ciphertext, and new_kyber_public must all be present"));
            }
            if envelope_epoch != inner.state.recv_ratchet_epoch + 1 {
                return Err(ProtocolError::invalid_state("Unexpected ratchet epoch"));
            }
            let kyber_sk_backup = inner
                .kyber_secret_handle
                .as_ref()
                .map(|h| h.read_bytes(KYBER_SECRET_KEY_BYTES))
                .transpose()
                .map_err(ProtocolError::from_crypto)?
                .unwrap_or_default();
            let dh_sk_backup = inner
                .dh_private_handle
                .as_ref()
                .map(|h| h.read_bytes(X25519_PRIVATE_KEY_BYTES))
                .transpose()
                .map_err(ProtocolError::from_crypto)?
                .unwrap_or_default();
            ratchet_snapshot = Some((
                inner.state.clone(),
                inner.cached_metadata_keys.clone(),
                kyber_sk_backup,
                dh_sk_backup,
                inner.skipped_message_keys.clone(),
                inner.replay_epoch,
                inner.send_ratchet_pending,
            ));
            Self::apply_recv_ratchet(&mut inner, envelope)?;
            is_old_epoch = false;
        } else if envelope_epoch == inner.state.recv_ratchet_epoch {
            is_old_epoch = false;
        } else if envelope_epoch < inner.state.recv_ratchet_epoch {
            is_old_epoch = true;
        } else {
            return Err(ProtocolError::invalid_state(
                "Future ratchet epoch without ratchet headers",
            ));
        }

        let metadata_key_ref: &[u8] = if is_old_epoch {
            match inner.cached_metadata_keys.get(&envelope_epoch) {
                Some(k) => k.as_slice(),
                None => return Err(ProtocolError::invalid_state("Metadata decryption failed")),
            }
        } else {
            &inner.state.metadata_key
        };

        let rollback_ratchet = |inner: &mut SessionInner, snapshot: Option<RatchetSnapshot>| {
            if let Some((
                state,
                cached_mk,
                mut kyber_sk,
                mut dh_sk,
                skipped,
                replay_ep,
                ratchet_pending,
            )) = snapshot
            {
                inner.state = state;
                inner.cached_metadata_keys = cached_mk;
                inner.skipped_message_keys = skipped;
                inner.replay_epoch = replay_ep;
                inner.send_ratchet_pending = ratchet_pending;
                if !kyber_sk.is_empty() {
                    match SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES) {
                        Ok(mut handle) => {
                            let _ = handle.write(&kyber_sk);
                            inner.kyber_secret_handle = Some(handle);
                        }
                        Err(_) => {
                            inner.kyber_secret_handle = None;
                        }
                    }
                }
                if !dh_sk.is_empty() {
                    match SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES) {
                        Ok(mut handle) => {
                            let _ = handle.write(&dh_sk);
                            inner.dh_private_handle = Some(handle);
                        }
                        Err(_) => {
                            inner.dh_private_handle = None;
                        }
                    }
                }
                CryptoInterop::secure_wipe(&mut kyber_sk);
                CryptoInterop::secure_wipe(&mut dh_sk);
            }
        };

        let metadata_aad = build_metadata_aad(&inner.state, envelope_epoch)?;
        let metadata_result = AesGcm::decrypt(
            metadata_key_ref,
            &envelope.header_nonce,
            &envelope.encrypted_metadata,
            &metadata_aad,
        );
        let metadata_bytes = match metadata_result {
            Ok(bytes) => bytes,
            Err(e) => {
                rollback_ratchet(&mut inner, ratchet_snapshot);
                return Err(e);
            }
        };

        let metadata = EnvelopeMetadata::decode(metadata_bytes.as_slice())
            .map_err(|e| ProtocolError::decode(format!("Failed to parse metadata: {e}")))?;

        if metadata.payload_nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid payload nonce size"));
        }
        if metadata.message_index > MAX_MESSAGE_INDEX {
            return Err(ProtocolError::invalid_input(
                "Message index exceeds maximum",
            ));
        }
        if metadata.message_index >= max {
            return Err(ProtocolError::invalid_input(
                "Message index exceeds per-chain limit",
            ));
        }

        let nonce_index = extract_nonce_index(&metadata.payload_nonce)?;
        if u64::from(nonce_index) != metadata.message_index {
            return Err(ProtocolError::invalid_input("Nonce index mismatch"));
        }

        let nonce_key = metadata.payload_nonce.clone();
        if inner.seen_payload_nonces.contains(&nonce_key) {
            return Err(ProtocolError::replay_attack(
                "Replay attack detected: payload nonce reused",
            ));
        }

        let recv_chain_pre = if is_old_epoch {
            None
        } else {
            inner
                .state
                .recv_chain
                .as_ref()
                .map(|rc| (rc.chain_key.clone(), rc.message_index))
        };

        let mut message_key = if is_old_epoch {
            Self::try_skipped_key(&mut inner, envelope_epoch, metadata.message_index).ok_or_else(
                || {
                    ProtocolError::replay_attack(
                        "Old-epoch message key not found (already consumed or never cached)",
                    )
                },
            )?
        } else {
            Self::get_recv_message_key(&mut inner, metadata.message_index)?
        };

        let decrypt_result =
            build_payload_aad(&inner.state, envelope_epoch, metadata.message_index).and_then(
                |payload_aad| {
                    AesGcm::decrypt(
                        &message_key,
                        &metadata.payload_nonce,
                        &envelope.encrypted_payload,
                        &payload_aad,
                    )
                },
            );

        let padded_plaintext = match decrypt_result {
            Ok(pt) => {
                CryptoInterop::secure_wipe(&mut message_key);
                if let Some((mut saved_key, _)) = recv_chain_pre {
                    CryptoInterop::secure_wipe(&mut saved_key);
                }
                pt
            }
            Err(e) => {
                if ratchet_snapshot.is_some() {
                    CryptoInterop::secure_wipe(&mut message_key);
                    rollback_ratchet(&mut inner, ratchet_snapshot);
                } else if is_old_epoch {
                    inner
                        .skipped_message_keys
                        .insert((envelope_epoch, metadata.message_index), message_key);
                } else if let Some((saved_key, saved_index)) = recv_chain_pre {
                    let epoch = inner.state.recv_ratchet_epoch;
                    if metadata.message_index < saved_index {
                        inner
                            .skipped_message_keys
                            .insert((epoch, metadata.message_index), message_key);
                    } else {
                        CryptoInterop::secure_wipe(&mut message_key);
                        for idx in saved_index..metadata.message_index {
                            if let Some(mut key) = inner.skipped_message_keys.remove(&(epoch, idx))
                            {
                                CryptoInterop::secure_wipe(&mut key);
                            }
                        }
                    }
                    if let Some(rc) = inner.state.recv_chain.as_mut() {
                        CryptoInterop::secure_wipe(&mut rc.chain_key);
                        rc.chain_key = saved_key;
                        rc.message_index = saved_index;
                    } else {
                        let mut sk = saved_key;
                        CryptoInterop::secure_wipe(&mut sk);
                    }
                } else {
                    CryptoInterop::secure_wipe(&mut message_key);
                }
                return Err(e);
            }
        };
        let plaintext = MessagePadding::unpad(&padded_plaintext)?;

        inner.seen_payload_nonces.insert(nonce_key);

        if inner.seen_payload_nonces.len() > MAX_SEEN_NONCES {
            Self::prune_seen_nonces(&mut inner.seen_payload_nonces);
        }

        if !inner.send_ratchet_pending {
            inner.send_ratchet_pending = true;
            inner.state.send_ratchet_pending = true;
        }

        if let Some((mut state, _, mut kyber_sk, mut dh_sk, mut skipped, _, _)) = ratchet_snapshot {
            CryptoInterop::secure_wipe(&mut kyber_sk);
            CryptoInterop::secure_wipe(&mut dh_sk);
            wipe_protocol_state_keys(&mut state);
            for key in skipped.values_mut() {
                CryptoInterop::secure_wipe(key);
            }
        }

        Ok(DecryptResult {
            plaintext,
            metadata,
        })
    }

    pub fn export_sealed_state(
        &self,
        key_provider: &dyn IStateKeyProvider,
        external_counter: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if external_counter == 0 {
            return Err(ProtocolError::invalid_input(
                "External sealed-state counter must be > 0",
            ));
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("Session lock poisoned"))?;
        if inner.state.version == 0 {
            return Err(ProtocolError::invalid_state("Session has been destroyed"));
        }
        if inner.state.state_counter == u64::MAX {
            return Err(ProtocolError::invalid_state("State counter overflow"));
        }
        let next_gen = inner.state.state_counter + 1;
        let mut copy = inner.state.clone();
        if let Some(sc) = copy.send_chain.as_mut() {
            sc.skipped_message_keys.clear();
        }
        if let Some(rc) = copy.recv_chain.as_mut() {
            rc.skipped_message_keys.clear();
        }
        copy.state_counter = next_gen;
        copy.state_hmac.clear();

        if let (Some(dh), Some(handle)) = (copy.dh_local.as_mut(), inner.dh_private_handle.as_ref())
        {
            dh.private_key = handle
                .read_bytes(X25519_PRIVATE_KEY_BYTES)
                .map_err(ProtocolError::from_crypto)?;
        }
        if let (Some(kyber), Some(handle)) = (
            copy.kyber_local.as_mut(),
            inner.kyber_secret_handle.as_ref(),
        ) {
            kyber.secret_key = handle
                .read_bytes(KYBER_SECRET_KEY_BYTES)
                .map_err(ProtocolError::from_crypto)?;
        }

        copy.replay_epoch = inner.replay_epoch;
        copy.seen_payload_nonces = inner.seen_payload_nonces.iter().cloned().collect();

        copy.skipped_keys = inner
            .skipped_message_keys
            .iter()
            .map(|(&(epoch, msg_idx), key)| CachedMessageKey {
                epoch,
                message_index: msg_idx,
                message_key: key.clone(),
            })
            .collect();

        copy.cached_metadata_keys = inner
            .cached_metadata_keys
            .iter()
            .map(|(&epoch, key)| CachedMetadataKey {
                epoch,
                metadata_key: key.clone(),
            })
            .collect();

        inner.state.state_counter = next_gen;
        drop(inner);

        let mut plaintext_state = {
            copy.state_hmac.clear();
            let mut tmp = Vec::new();
            let enc1 = copy.encode(&mut tmp);
            if enc1.is_err() {
                wipe_export_copy(&mut copy);
            }
            enc1.map_err(|e| ProtocolError::encode(format!("Failed to serialize state: {e}")))?;

            let hmac_result = compute_state_hmac(&copy.root_key, &tmp);
            if hmac_result.is_err() {
                wipe_export_copy(&mut copy);
            }
            copy.state_hmac = hmac_result?;

            let mut buf = Vec::new();
            let enc2 = copy.encode(&mut buf);
            wipe_export_copy(&mut copy);
            enc2.map_err(|e| ProtocolError::encode(format!("Failed to serialize state: {e}")))?;
            buf
        };

        let kek_handle = key_provider.get_state_encryption_key()?;
        let mut kek_bytes = kek_handle
            .read_bytes(AES_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;

        let mut dek = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
        let dek_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        let state_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);

        const SEALED_STATE_VERSION: u8 = 1;
        let mut dek_aad = Vec::with_capacity(9);
        dek_aad.push(SEALED_STATE_VERSION);
        dek_aad.extend_from_slice(&external_counter.to_le_bytes());
        let encrypt_dek = AesGcm::encrypt(&kek_bytes, &dek_nonce, &dek, &dek_aad);
        CryptoInterop::secure_wipe(&mut kek_bytes);
        let encrypt_dek = encrypt_dek.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut dek);
            CryptoInterop::secure_wipe(&mut plaintext_state);
        })?;

        let mut state_aad = Vec::with_capacity(1 + dek_nonce.len() + encrypt_dek.len());
        state_aad.push(SEALED_STATE_VERSION);
        state_aad.extend_from_slice(&dek_nonce);
        state_aad.extend_from_slice(&encrypt_dek);

        let encrypt_state = AesGcm::encrypt(&dek, &state_nonce, &plaintext_state, &state_aad);
        CryptoInterop::secure_wipe(&mut dek);
        CryptoInterop::secure_wipe(&mut plaintext_state);
        let encrypt_state = encrypt_state?;

        let sealed = SealedState {
            version: u32::from(SEALED_STATE_VERSION),
            dek_nonce,
            state_nonce,
            encrypted_dek: encrypt_dek,
            encrypted_state: encrypt_state,
            external_counter,
        };

        let mut output = Vec::new();
        sealed
            .encode(&mut output)
            .map_err(|e| ProtocolError::encode(format!("Failed to serialize sealed state: {e}")))?;
        Ok(output)
    }

    pub fn from_sealed_state(
        sealed_data: &[u8],
        key_provider: &dyn IStateKeyProvider,
        min_external_counter: u64,
    ) -> Result<Self, ProtocolError> {
        if sealed_data.len() > MAX_PROTOBUF_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Sealed state too large"));
        }
        let sealed = SealedState::decode(sealed_data)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse sealed state: {e}")))?;

        const SEALED_STATE_VERSION: u8 = 1;
        if sealed.version != u32::from(SEALED_STATE_VERSION) {
            return Err(ProtocolError::invalid_input(
                "Unsupported sealed state version",
            ));
        }
        if sealed.dek_nonce.len() != AES_GCM_NONCE_BYTES
            || sealed.state_nonce.len() != AES_GCM_NONCE_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid nonce size in sealed state",
            ));
        }
        if sealed.external_counter == 0 {
            return Err(ProtocolError::invalid_input(
                "Sealed state external counter must be > 0",
            ));
        }
        if sealed.external_counter <= min_external_counter {
            return Err(ProtocolError::invalid_state(
                "Sealed session state rollback detected by external counter",
            ));
        }

        let kek_handle = key_provider.get_state_encryption_key()?;
        let mut kek_bytes = kek_handle
            .read_bytes(AES_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut dek_aad = Vec::with_capacity(9);
        dek_aad.push(SEALED_STATE_VERSION);
        dek_aad.extend_from_slice(&sealed.external_counter.to_le_bytes());
        let decrypt_dek = AesGcm::decrypt(
            &kek_bytes,
            &sealed.dek_nonce,
            &sealed.encrypted_dek,
            &dek_aad,
        );
        let mut dek = decrypt_dek.map_err(|_| {
            CryptoInterop::secure_wipe(&mut kek_bytes);
            ProtocolError::generic("Decryption failed - invalid key or tampered data")
        })?;

        let mut state_aad =
            Vec::with_capacity(1 + sealed.dek_nonce.len() + sealed.encrypted_dek.len());
        state_aad.push(SEALED_STATE_VERSION);
        state_aad.extend_from_slice(&sealed.dek_nonce);
        state_aad.extend_from_slice(&sealed.encrypted_dek);

        let decrypt_state = AesGcm::decrypt(
            &dek,
            &sealed.state_nonce,
            &sealed.encrypted_state,
            &state_aad,
        );
        CryptoInterop::secure_wipe(&mut dek);
        let mut plaintext_state = decrypt_state.map_err(|_| {
            CryptoInterop::secure_wipe(&mut kek_bytes);
            ProtocolError::generic("Decryption failed - invalid key or tampered data")
        })?;

        let state_proto = ProtocolState::decode(plaintext_state.as_slice()).map_err(|e| {
            CryptoInterop::secure_wipe(&mut plaintext_state);
            CryptoInterop::secure_wipe(&mut kek_bytes);
            ProtocolError::decode(format!("Failed to parse protocol state: {e}"))
        })?;
        CryptoInterop::secure_wipe(&mut plaintext_state);

        let session = Self::from_state_internal(state_proto);
        if session.is_err() {
            CryptoInterop::secure_wipe(&mut kek_bytes);
        }
        let session = session?;
        CryptoInterop::secure_wipe(&mut kek_bytes);
        Ok(session)
    }

    pub fn sealed_state_external_counter(sealed_data: &[u8]) -> Result<u64, ProtocolError> {
        if sealed_data.len() > MAX_PROTOBUF_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Sealed state too large"));
        }
        let sealed = SealedState::decode(sealed_data)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse sealed state: {e}")))?;
        Ok(sealed.external_counter)
    }

    pub const fn version(&self) -> u32 {
        PROTOCOL_VERSION
    }

    pub fn is_initiator(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_initiator
    }

    pub fn get_session_id(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
            .session_id
            .clone()
    }

    pub fn get_peer_identity(&self) -> PeerIdentity {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PeerIdentity {
            ed25519_public: inner.state.peer_identity_ed25519_public.clone(),
            x25519_public: inner.state.peer_identity_x25519_public.clone(),
        }
    }

    pub fn get_local_identity(&self) -> LocalIdentity {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        LocalIdentity {
            ed25519_public: inner.state.local_identity_ed25519_public.clone(),
            x25519_public: inner.state.local_identity_x25519_public.clone(),
        }
    }

    pub fn get_identity_binding_hash(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
            .identity_binding_hash
            .clone()
    }

    pub fn destroy(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        CryptoInterop::secure_wipe(&mut inner.state.root_key);
        CryptoInterop::secure_wipe(&mut inner.state.metadata_key);
        CryptoInterop::secure_wipe(&mut inner.state.send_metadata_key);

        if let Some(chain) = inner.state.send_chain.as_mut() {
            CryptoInterop::secure_wipe(&mut chain.chain_key);
            for cached in &mut chain.skipped_message_keys {
                CryptoInterop::secure_wipe(&mut cached.message_key);
            }
        }
        if let Some(chain) = inner.state.recv_chain.as_mut() {
            CryptoInterop::secure_wipe(&mut chain.chain_key);
            for cached in &mut chain.skipped_message_keys {
                CryptoInterop::secure_wipe(&mut cached.message_key);
            }
        }

        inner.dh_private_handle.take();
        if let Some(dh) = inner.state.dh_local.as_mut() {
            CryptoInterop::secure_wipe(&mut dh.private_key);
        }

        inner.kyber_secret_handle.take();
        if let Some(kyber) = inner.state.kyber_local.as_mut() {
            CryptoInterop::secure_wipe(&mut kyber.secret_key);
        }

        for key in inner.skipped_message_keys.values_mut() {
            CryptoInterop::secure_wipe(key);
        }
        inner.skipped_message_keys.clear();

        for key in inner.cached_metadata_keys.values_mut() {
            CryptoInterop::secure_wipe(key);
        }
        inner.cached_metadata_keys.clear();

        CryptoInterop::secure_wipe(&mut inner.pending_kyber_shared_secret);

        inner.seen_payload_nonces.clear();

        CryptoInterop::secure_wipe(&mut inner.state.identity_binding_hash);
        CryptoInterop::secure_wipe(&mut inner.state.session_id);
        CryptoInterop::secure_wipe(&mut inner.state.state_hmac);

        inner.state.version = 0;
    }

    pub fn is_destroyed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
            .version
            == 0
    }
}
