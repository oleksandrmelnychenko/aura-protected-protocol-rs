pub mod call_key_exchange;
pub mod frame;
pub mod key_ratchet;
pub mod media_crypto;
pub mod replay_window;

use std::sync::{Arc, Mutex};

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle};
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;

use call_key_exchange::CallKeyMaterial;
use frame::{build_frame_aad, FrameHeader};
use key_ratchet::MediaKeyRatchet;
use media_crypto::MediaCrypto;
use replay_window::ReplayWindow;

pub use call_key_exchange::{
    callee_accept_with_context, caller_finish_with_context, caller_init_with_context,
    rekey_complete, rekey_initiate, CallAcceptOutput, CallInitAuthContext, CallInitOutput,
    CallKeyMaterial as VoipKeyMaterial,
};

type HmacSha256 = Hmac<Sha256>;

pub trait IVoipEventHandler: Send + Sync {
    fn on_call_established(&self, call_id: &[u8], role: CallRole);
    fn on_rekey_completed(&self, call_id: &[u8], new_generation: u32);
    fn on_frame_auth_failed(&self, call_id: &[u8], frame_counter: u64);
    fn on_replay_detected(&self, call_id: &[u8], frame_counter: u64);
    fn on_ratchet_exhaustion_warning(&self, call_id: &[u8], remaining: u32, max: u32);
    fn on_call_ended(&self, call_id: &[u8]);
    fn on_frame_dropped_late(&self, call_id: &[u8], frame_counter: u64) {
        let _ = (call_id, frame_counter);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallControlType {
    Mute,
    Unmute,
    Hold,
    Unhold,
    Dtmf(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallRole {
    Caller,
    Callee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Init,
    Ringing,
    Active,
    Ended,
}

pub struct EncryptedFrame {
    pub call_id: Vec<u8>,
    pub ssrc: u32,
    pub frame_counter: u64,
    pub ratchet_generation: u32,
    pub encrypted_payload: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_header: Vec<u8>,
}

pub struct DecryptedFrame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
    pub frame_counter: u64,
    pub ratchet_generation: u32,
}

pub struct VoipSession {
    inner: Mutex<VoipSessionInner>,
}

struct VoipSessionInner {
    call_id: Vec<u8>,
    role: CallRole,
    state: CallState,
    ssrc: u32,

    send_ratchet: MediaKeyRatchet,
    recv_ratchet: MediaKeyRatchet,
    header_key_send: SecureMemoryHandle,
    header_key_recv: SecureMemoryHandle,
    root_secret: SecureMemoryHandle,

    send_frame_counter: u64,
    replay_window: ReplayWindow,
    ratchet_generation: u32,

    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
    shield_mode: bool,

    frames_since_ratchet: u32,
    event_handler: Option<Arc<dyn IVoipEventHandler>>,
    pending_rekey: Option<call_key_exchange::CallInitOutput>,
}

impl VoipSession {
    pub fn from_key_material(
        call_id: Vec<u8>,
        role: CallRole,
        key_material: CallKeyMaterial,
        ratchet_interval_frames: u32,
        pq_rekey_interval_secs: u32,
        shield_mode: bool,
    ) -> Result<Self, ProtocolError> {
        if call_id.len() != CALL_ID_BYTES {
            return Err(ProtocolError::voip_call("invalid call_id size"));
        }

        let ssrc_bytes = CryptoInterop::get_random_bytes(SSRC_BYTES);
        let ssrc = u32::from_be_bytes(
            ssrc_bytes[..4]
                .try_into()
                .map_err(|_| ProtocolError::voip_call("SSRC generation failed"))?,
        );

        let ratchet_interval = if ratchet_interval_frames == 0 {
            DEFAULT_RATCHET_INTERVAL_FRAMES
        } else {
            ratchet_interval_frames
        };

        let pq_rekey = if pq_rekey_interval_secs == 0 {
            DEFAULT_PQ_REKEY_INTERVAL_SECS
        } else {
            pq_rekey_interval_secs
        };

        let send_ratchet =
            MediaKeyRatchet::new(key_material.media_key_send, key_material.nonce_prefix_send);
        let recv_ratchet =
            MediaKeyRatchet::new(key_material.media_key_recv, key_material.nonce_prefix_recv);

        let inner = VoipSessionInner {
            call_id,
            role,
            state: CallState::Active,
            ssrc,
            send_ratchet,
            recv_ratchet,
            header_key_send: key_material.header_key_send,
            header_key_recv: key_material.header_key_recv,
            root_secret: key_material.root_secret,
            send_frame_counter: 0,
            replay_window: ReplayWindow::new(),
            ratchet_generation: 0,
            ratchet_interval_frames: ratchet_interval,
            pq_rekey_interval_secs: pq_rekey,
            shield_mode,
            frames_since_ratchet: 0,
            event_handler: None,
            pending_rekey: None,
        };

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IVoipEventHandler>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if inner.state == CallState::Active {
            handler.on_call_established(&inner.call_id, inner.role);
        }

        inner.event_handler = Some(handler);
    }

    pub fn encrypt_frame(
        &self,
        header: &FrameHeader,
        payload: &[u8],
    ) -> Result<EncryptedFrame, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_call("call is not active"));
        }
        if header.ssrc != inner.ssrc {
            return Err(ProtocolError::voip_media(
                "frame header ssrc does not match active call ssrc",
            ));
        }
        if inner.send_frame_counter > MAX_FRAME_COUNTER {
            return Err(ProtocolError::voip_media("send frame counter exhausted"));
        }

        if inner.frames_since_ratchet >= inner.ratchet_interval_frames {
            inner.send_ratchet.advance_generation()?;
            inner.frames_since_ratchet = 0;
        }

        let frame_counter = inner.send_frame_counter;
        let ratcheted_key = inner.send_ratchet.frame_key(frame_counter)?;
        let ratchet_gen = ratcheted_key.generation;

        let aad = build_frame_aad(&inner.call_id, inner.ssrc, frame_counter, ratchet_gen);

        let nonce_prefix = *inner.send_ratchet.nonce_prefix();
        let encrypted_payload = MediaCrypto::encrypt_frame(
            &ratcheted_key.media_key,
            &nonce_prefix,
            frame_counter,
            payload,
            &aad,
        )?;

        let header_bytes = header.serialize();
        let header_key_bytes = inner
            .header_key_send
            .read_bytes(VOIP_HEADER_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let encrypted_header = MediaCrypto::encrypt_header(
            &header_key_bytes,
            &nonce_prefix,
            frame_counter,
            &header_bytes,
        )?;

        let nonce = MediaCrypto::build_nonce(&nonce_prefix, frame_counter);

        inner.send_frame_counter += 1;
        inner.frames_since_ratchet += 1;

        if inner.send_ratchet.generation() > MAX_RATCHET_GENERATION - 100 {
            if let Some(handler) = &inner.event_handler {
                let remaining = MAX_RATCHET_GENERATION - inner.send_ratchet.generation();
                handler.on_ratchet_exhaustion_warning(
                    &inner.call_id,
                    remaining,
                    MAX_RATCHET_GENERATION,
                );
            }
        }

        Ok(EncryptedFrame {
            call_id: inner.call_id.clone(),
            ssrc: inner.ssrc,
            frame_counter,
            ratchet_generation: ratchet_gen,
            encrypted_payload,
            nonce: nonce.to_vec(),
            encrypted_header,
        })
    }

    pub fn decrypt_frame(
        &self,
        encrypted: &EncryptedFrame,
    ) -> Result<DecryptedFrame, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_call("call is not active"));
        }

        if encrypted.call_id != inner.call_id {
            return Err(ProtocolError::voip_call("call_id mismatch"));
        }

        if !inner.replay_window.check(encrypted.frame_counter) {
            if let Some(handler) = &inner.event_handler {
                handler.on_replay_detected(&inner.call_id, encrypted.frame_counter);
            }
            return Err(ProtocolError::replay_attack(format!(
                "VoIP frame replay or too old: counter={}, window_high={}",
                encrypted.frame_counter,
                inner.replay_window.high_water_mark()
            )));
        }

        let target_gen = encrypted.ratchet_generation;
        let (ratcheted_key, snapshot) = inner
            .recv_ratchet
            .speculative_frame_key(target_gen, encrypted.frame_counter)?;

        let nonce_prefix = *inner.recv_ratchet.nonce_prefix();

        let aad = build_frame_aad(
            &inner.call_id,
            encrypted.ssrc,
            encrypted.frame_counter,
            encrypted.ratchet_generation,
        );

        let payload = match MediaCrypto::decrypt_frame(
            &ratcheted_key.media_key,
            &nonce_prefix,
            encrypted.frame_counter,
            &encrypted.encrypted_payload,
            &aad,
        ) {
            Ok(p) => p,
            Err(e) => {
                if let Some(handler) = &inner.event_handler {
                    handler.on_frame_auth_failed(&inner.call_id, encrypted.frame_counter);
                }
                return Err(e);
            }
        };

        let header_key_bytes = inner
            .header_key_recv
            .read_bytes(VOIP_HEADER_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let header_bytes = MediaCrypto::decrypt_header(
            &header_key_bytes,
            &nonce_prefix,
            encrypted.frame_counter,
            &encrypted.encrypted_header,
        )?;

        let header = FrameHeader::deserialize(&header_bytes)?;
        if header.ssrc != encrypted.ssrc {
            return Err(ProtocolError::voip_media(
                "frame header ssrc mismatch with encrypted envelope ssrc",
            ));
        }

        inner.recv_ratchet.commit_snapshot(snapshot)?;
        inner.replay_window.mark(encrypted.frame_counter);

        Ok(DecryptedFrame {
            header,
            payload,
            frame_counter: encrypted.frame_counter,
            ratchet_generation: encrypted.ratchet_generation,
        })
    }

    pub fn encrypt_call_control(
        &self,
        control: CallControlType,
    ) -> Result<EncryptedFrame, ProtocolError> {
        let control_byte = match control {
            CallControlType::Mute => 0x01,
            CallControlType::Unmute => 0x02,
            CallControlType::Hold => 0x03,
            CallControlType::Unhold => 0x04,
            CallControlType::Dtmf(digit) => 0x10 | (digit & 0x0F),
        };
        let payload = [0xCC, control_byte];
        let header = FrameHeader {
            payload_type: 200,
            ssrc: self.ssrc(),
            timestamp: 0,
            sequence_number: 0,
        };
        self.encrypt_frame(&header, &payload)
    }

    pub fn decode_call_control(decrypted: &DecryptedFrame) -> Option<CallControlType> {
        if decrypted.header.payload_type != 200 {
            return None;
        }
        if decrypted.payload.len() < 2 || decrypted.payload[0] != 0xCC {
            return None;
        }
        let b = decrypted.payload[1];
        match b {
            0x01 => Some(CallControlType::Mute),
            0x02 => Some(CallControlType::Unmute),
            0x03 => Some(CallControlType::Hold),
            0x04 => Some(CallControlType::Unhold),
            v if v & 0xF0 == 0x10 => Some(CallControlType::Dtmf(v & 0x0F)),
            _ => None,
        }
    }

    pub fn generate_call_end_hmac(
        &self,
        device_id: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root_bytes = inner
            .root_secret
            .read_bytes(ROOT_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;

        let hmac_key = HkdfSha256::derive_key_bytes(
            &root_bytes,
            HMAC_BYTES,
            &inner.call_id,
            VOIP_CALL_END_HMAC_INFO,
        )?;

        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| ProtocolError::voip_call("CallEnd HMAC init failed"))?;
        mac.update(&inner.call_id);
        mac.update(device_id);
        mac.update(&timestamp.to_le_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify_call_end_hmac(
        &self,
        device_id: &[u8],
        timestamp: u64,
        hmac_value: &[u8],
    ) -> Result<bool, ProtocolError> {
        let expected = self.generate_call_end_hmac(device_id, timestamp)?;
        CryptoInterop::constant_time_equals(&expected, hmac_value)
            .map_err(ProtocolError::from_crypto)
    }

    pub fn build_call_end(
        &self,
        device_id: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let call_id = self.call_id();
        let hmac_value = self.generate_call_end_hmac(device_id, timestamp)?;
        let call_end = crate::proto::CallEnd {
            call_id,
            device_id: device_id.to_vec(),
            timestamp,
            hmac: hmac_value,
        };

        let mut buf = Vec::new();
        call_end
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallEnd encode: {e}")))?;
        Ok(buf)
    }

    pub fn process_call_end(&self, call_end_bytes: &[u8]) -> Result<(), ProtocolError> {
        let call_end = crate::proto::CallEnd::decode(call_end_bytes)
            .map_err(|e| ProtocolError::decode(format!("CallEnd decode: {e}")))?;

        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if call_end.call_id != inner.call_id {
            return Err(ProtocolError::voip_call("call end call_id mismatch"));
        }
        drop(inner);

        let is_valid =
            self.verify_call_end_hmac(&call_end.device_id, call_end.timestamp, &call_end.hmac)?;
        if !is_valid {
            return Err(ProtocolError::voip_call(
                "call end HMAC verification failed",
            ));
        }

        self.end_call()
    }

    pub fn export_sealed_state(
        &self,
        state_key: &[u8],
        external_counter: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.state == CallState::Ended {
            return Err(ProtocolError::voip_call("cannot export ended call state"));
        }

        let send_snapshot = inner.send_ratchet.snapshot()?;
        let recv_snapshot = inner.recv_ratchet.snapshot()?;
        let replay_bitmap_words = inner.replay_window.bitmap_words();
        let mut replay_bitmap =
            Vec::with_capacity(replay_bitmap_words.len() * std::mem::size_of::<u64>());
        for word in replay_bitmap_words {
            replay_bitmap.extend_from_slice(&word.to_le_bytes());
        }

        let state = crate::proto::VoipSessionState {
            call_id: inner.call_id.clone(),
            role: match inner.role {
                CallRole::Caller => 1,
                CallRole::Callee => 2,
            },
            ssrc: inner.ssrc,
            send_frame_counter: inner.send_frame_counter,
            replay_high_water: inner.replay_window.high_water_mark(),
            ratchet_generation: inner.ratchet_generation,
            ratchet_interval_frames: inner.ratchet_interval_frames,
            pq_rekey_interval_secs: inner.pq_rekey_interval_secs,
            shield_mode: inner.shield_mode,
            frames_since_ratchet: inner.frames_since_ratchet,
            root_secret: inner
                .root_secret
                .read_bytes(ROOT_KEY_BYTES)
                .map_err(ProtocolError::from_crypto)?,
            external_counter,
            send_ratchet_chain_key: send_snapshot.chain_bytes,
            recv_ratchet_chain_key: recv_snapshot.chain_bytes,
            send_ratchet_generation: send_snapshot.generation,
            recv_ratchet_generation: recv_snapshot.generation,
            replay_bitmap,
        };

        let mut state_bytes = Vec::new();
        state
            .encode(&mut state_bytes)
            .map_err(|e| ProtocolError::encode(format!("VoipSessionState encode: {e}")))?;

        let nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        let ct = crate::crypto::AesGcm::encrypt(state_key, &nonce, &state_bytes, &[])?;

        let hmac_key = HkdfSha256::derive_key_bytes(
            state_key,
            HMAC_BYTES,
            &external_counter.to_le_bytes(),
            b"Ecliptix-VoIP-StateHMAC",
        )?;
        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| ProtocolError::voip_call("state HMAC init failed"))?;
        mac.update(&ct);
        mac.update(&nonce);
        let hmac_tag = mac.finalize().into_bytes();

        let mut out = Vec::with_capacity(8 + AES_GCM_NONCE_BYTES + HMAC_BYTES + ct.len());
        out.extend_from_slice(&external_counter.to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&hmac_tag);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn from_sealed_state(
        data: &[u8],
        state_key: &[u8],
        min_external_counter: u64,
    ) -> Result<Self, ProtocolError> {
        let header_size = 8 + AES_GCM_NONCE_BYTES + HMAC_BYTES;
        if data.len() < header_size + AES_GCM_TAG_BYTES {
            return Err(ProtocolError::voip_call("sealed state too short"));
        }
        if data.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            return Err(ProtocolError::voip_call("sealed state too large"));
        }

        let stored_counter = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| ProtocolError::voip_call("counter parse failed"))?,
        );
        if stored_counter <= min_external_counter {
            return Err(ProtocolError::voip_call("sealed state rollback detected"));
        }

        let nonce = &data[8..8 + AES_GCM_NONCE_BYTES];
        let stored_hmac = &data[8 + AES_GCM_NONCE_BYTES..header_size];
        let ct = &data[header_size..];

        let hmac_key = HkdfSha256::derive_key_bytes(
            state_key,
            HMAC_BYTES,
            &stored_counter.to_le_bytes(),
            b"Ecliptix-VoIP-StateHMAC",
        )?;
        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| ProtocolError::voip_call("state HMAC init failed"))?;
        mac.update(ct);
        mac.update(nonce);
        let computed_hmac = mac.finalize().into_bytes();
        if !CryptoInterop::constant_time_equals(stored_hmac, &computed_hmac).unwrap_or(false) {
            return Err(ProtocolError::voip_call("sealed state HMAC mismatch"));
        }

        let state_bytes = crate::crypto::AesGcm::decrypt(state_key, nonce, ct, &[])?;
        let state = crate::proto::VoipSessionState::decode(state_bytes.as_slice())
            .map_err(|e| ProtocolError::decode(format!("VoipSessionState decode: {e}")))?;
        if state.external_counter != stored_counter {
            return Err(ProtocolError::voip_call(
                "sealed state external counter mismatch",
            ));
        }

        if state.call_id.len() != CALL_ID_BYTES {
            return Err(ProtocolError::voip_call("invalid call_id in sealed state"));
        }

        let role = match state.role {
            1 => CallRole::Caller,
            2 => CallRole::Callee,
            _ => return Err(ProtocolError::voip_call("invalid role in sealed state")),
        };

        if state.root_secret.len() != ROOT_KEY_BYTES {
            return Err(ProtocolError::voip_call(
                "invalid root secret size in sealed state",
            ));
        }

        let mut root_handle =
            SecureMemoryHandle::allocate(ROOT_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
        root_handle
            .write(&state.root_secret)
            .map_err(ProtocolError::from_crypto)?;

        let is_caller = matches!(role, CallRole::Caller);
        let key_material = call_key_exchange::derive_call_keys_from_root(
            &state.root_secret,
            &state.call_id,
            is_caller,
            state.shield_mode,
        )?;

        let send_ratchet = if state.send_ratchet_chain_key.is_empty() {
            if state.send_frame_counter != 0 || state.frames_since_ratchet != 0 {
                return Err(ProtocolError::voip_call(
                    "sealed state missing send ratchet state",
                ));
            }
            MediaKeyRatchet::new(key_material.media_key_send, key_material.nonce_prefix_send)
        } else {
            MediaKeyRatchet::from_state(
                &state.send_ratchet_chain_key,
                state.send_ratchet_generation,
                key_material.nonce_prefix_send,
            )?
        };

        let recv_ratchet = if state.recv_ratchet_chain_key.is_empty() {
            if state.replay_high_water != 0 {
                return Err(ProtocolError::voip_call(
                    "sealed state missing recv ratchet state",
                ));
            }
            MediaKeyRatchet::new(key_material.media_key_recv, key_material.nonce_prefix_recv)
        } else {
            MediaKeyRatchet::from_state(
                &state.recv_ratchet_chain_key,
                state.recv_ratchet_generation,
                key_material.nonce_prefix_recv,
            )?
        };

        let replay_window = if state.replay_bitmap.is_empty() {
            if state.replay_high_water > 0 {
                return Err(ProtocolError::voip_call(
                    "sealed state replay bitmap missing for non-zero replay window",
                ));
            }
            ReplayWindow::new()
        } else {
            let mut replay_words = ReplayWindow::new().bitmap_words();
            let expected_len = replay_words.len() * std::mem::size_of::<u64>();
            if state.replay_bitmap.len() != expected_len {
                return Err(ProtocolError::voip_call(
                    "invalid replay bitmap size in sealed state",
                ));
            }
            for (idx, chunk) in state.replay_bitmap.chunks_exact(8).enumerate() {
                replay_words[idx] = u64::from_le_bytes(
                    chunk
                        .try_into()
                        .map_err(|_| ProtocolError::voip_call("replay bitmap parse failed"))?,
                );
            }
            ReplayWindow::from_parts(state.replay_high_water, replay_words)
        };

        let ratchet_interval_frames = if state.ratchet_interval_frames == 0 {
            DEFAULT_RATCHET_INTERVAL_FRAMES
        } else {
            state.ratchet_interval_frames
        };
        let pq_rekey_interval_secs = if state.pq_rekey_interval_secs == 0 {
            DEFAULT_PQ_REKEY_INTERVAL_SECS
        } else {
            state.pq_rekey_interval_secs
        };

        let inner = VoipSessionInner {
            call_id: state.call_id,
            role,
            state: CallState::Active,
            ssrc: state.ssrc,
            send_ratchet,
            recv_ratchet,
            header_key_send: key_material.header_key_send,
            header_key_recv: key_material.header_key_recv,
            root_secret: root_handle,
            send_frame_counter: state.send_frame_counter,
            replay_window,
            ratchet_generation: state.ratchet_generation,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode: state.shield_mode,
            frames_since_ratchet: state.frames_since_ratchet,
            event_handler: None,
            pending_rekey: None,
        };

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn sealed_state_external_counter(data: &[u8]) -> Result<u64, ProtocolError> {
        if data.len() < 8 {
            return Err(ProtocolError::voip_call(
                "sealed state too short for counter",
            ));
        }
        Ok(u64::from_le_bytes(data[..8].try_into().map_err(|_| {
            ProtocolError::voip_call("counter parse failed")
        })?))
    }

    pub fn call_id(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .call_id
            .clone()
    }

    pub fn ssrc(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ssrc
    }

    pub fn role(&self) -> CallRole {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .role
    }

    pub fn state(&self) -> CallState {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
    }

    pub fn send_frame_counter(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send_frame_counter
    }

    pub fn recv_frame_counter(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replay_window
            .high_water_mark()
    }

    pub fn ratchet_generation(&self) -> u32 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ratchet_generation
    }

    pub fn is_shield_mode(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shield_mode
    }

    pub fn needs_pq_rekey(&self, elapsed_secs: u64) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        elapsed_secs >= u64::from(inner.pq_rekey_interval_secs)
    }

    pub fn apply_rekey(&self, new_keys: CallKeyMaterial) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_call("cannot rekey: call not active"));
        }

        inner
            .send_ratchet
            .reset(new_keys.media_key_send, new_keys.nonce_prefix_send);
        inner
            .recv_ratchet
            .reset(new_keys.media_key_recv, new_keys.nonce_prefix_recv);
        inner.header_key_send = new_keys.header_key_send;
        inner.header_key_recv = new_keys.header_key_recv;
        inner.root_secret = new_keys.root_secret;
        inner.ratchet_generation += 1;
        inner.frames_since_ratchet = 0;

        if let Some(handler) = &inner.event_handler {
            handler.on_rekey_completed(&inner.call_id, inner.ratchet_generation);
        }

        Ok(())
    }

    pub fn initiate_rekey(
        &self,
        identity_ed25519_secret: &[u8],
        peer_kyber_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_rekey("cannot rekey: call not active"));
        }
        if inner.pending_rekey.is_some() {
            return Err(ProtocolError::voip_rekey("rekey already pending"));
        }

        let (init_output, new_gen) = call_key_exchange::rekey_initiate(
            identity_ed25519_secret,
            peer_kyber_public,
            &inner.call_id,
            &inner.root_secret,
            inner.ratchet_generation,
        )?;

        let proto = crate::proto::CallRekey {
            call_id: inner.call_id.clone(),
            rekey_generation: new_gen,
            ephemeral_x25519_public: init_output.ephemeral_x25519_public.clone(),
            kyber_ciphertext: init_output.kyber_ciphertext.clone(),
            signature: init_output.signature.clone(),
            key_confirmation_mac: init_output.key_confirmation_mac.clone(),
        };
        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallRekey encode: {e}")))?;
        inner.pending_rekey = Some(init_output);
        Ok(buf)
    }

    pub fn process_rekey(
        &self,
        rekey_bytes: &[u8],
        peer_ed25519_public: &[u8],
        identity_kyber_secret: &SecureMemoryHandle,
        peer_kyber_public: &[u8],
        identity_ed25519_secret: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_rekey(
                "cannot process rekey: call not active",
            ));
        }
        if rekey_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_rekey("rekey message too large"));
        }

        let rekey = crate::proto::CallRekey::decode(rekey_bytes)
            .map_err(|e| ProtocolError::decode(format!("CallRekey decode: {e}")))?;

        if rekey.call_id != inner.call_id {
            return Err(ProtocolError::voip_rekey("rekey call_id mismatch"));
        }

        let expected_generation = inner
            .ratchet_generation
            .checked_add(1)
            .ok_or_else(|| ProtocolError::voip_rekey("rekey generation overflow"))?;
        if rekey.rekey_generation != expected_generation {
            return Err(ProtocolError::voip_rekey("unexpected rekey generation"));
        }

        call_key_exchange::verify_rekey_signature(
            peer_ed25519_public,
            &rekey.call_id,
            rekey.rekey_generation,
            &rekey.ephemeral_x25519_public,
            &rekey.kyber_ciphertext,
            &rekey.signature,
        )?;

        let callee_kyber_ss = crate::crypto::KyberInterop::decapsulate(
            &rekey.kyber_ciphertext,
            identity_kyber_secret,
        )
        .map_err(ProtocolError::from_crypto)?;

        let callee_kyber_bytes = callee_kyber_ss
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let expected_mac = call_key_exchange::compute_rekey_mac(
            &callee_kyber_bytes,
            VOIP_KEY_CONFIRM_CALLER_INFO,
            &rekey.call_id,
            rekey.rekey_generation,
        )?;
        if !CryptoInterop::constant_time_equals(&rekey.key_confirmation_mac, &expected_mac)
            .unwrap_or(false)
        {
            return Err(ProtocolError::voip_rekey("rekey MAC verification failed"));
        }

        let eph_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let eph_public = x25519_dalek::PublicKey::from(&eph_secret);
        let eph_public_bytes = eph_public.to_bytes().to_vec();

        let peer_eph: [u8; X25519_PUBLIC_KEY_BYTES] = rekey
            .ephemeral_x25519_public
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::voip_rekey("invalid rekey ephemeral key"))?;
        let classical_ss = eph_secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer_eph))
            .to_bytes();

        let (resp_kyber_ct, resp_kyber_ss) =
            crate::crypto::KyberInterop::encapsulate(peer_kyber_public)
                .map_err(ProtocolError::from_crypto)?;

        let resp_kyber_bytes = resp_kyber_ss
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut combined_pq = Vec::with_capacity(KYBER_SHARED_SECRET_BYTES * 2);
        combined_pq.extend_from_slice(&callee_kyber_bytes);
        combined_pq.extend_from_slice(&resp_kyber_bytes);

        let new_keys = call_key_exchange::rekey_complete(
            &inner.root_secret,
            &classical_ss,
            &combined_pq,
            &inner.call_id,
            false,
            inner.shield_mode,
        )?;

        let ack_signature = call_key_exchange::sign_rekey_material(
            identity_ed25519_secret,
            &inner.call_id,
            rekey.rekey_generation,
            &eph_public_bytes,
            &resp_kyber_ct,
        )?;

        let new_root_bytes = new_keys
            .root_secret
            .read_bytes(ROOT_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let ack_mac = call_key_exchange::compute_rekey_mac(
            &new_root_bytes,
            VOIP_KEY_CONFIRM_CALLEE_INFO,
            &inner.call_id,
            rekey.rekey_generation,
        )?;

        let proto = crate::proto::CallRekeyAck {
            call_id: inner.call_id.clone(),
            rekey_generation: rekey.rekey_generation,
            ephemeral_x25519_public: eph_public_bytes,
            kyber_ciphertext: resp_kyber_ct,
            signature: ack_signature,
            key_confirmation_mac: ack_mac,
        };

        let mut buf = Vec::new();
        proto
            .encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CallRekeyAck encode: {e}")))?;

        inner
            .send_ratchet
            .reset(new_keys.media_key_send, new_keys.nonce_prefix_send);
        inner
            .recv_ratchet
            .reset(new_keys.media_key_recv, new_keys.nonce_prefix_recv);
        inner.header_key_send = new_keys.header_key_send;
        inner.header_key_recv = new_keys.header_key_recv;
        inner.root_secret = new_keys.root_secret;
        inner.ratchet_generation = rekey.rekey_generation;
        inner.frames_since_ratchet = 0;

        if let Some(handler) = &inner.event_handler {
            handler.on_rekey_completed(&inner.call_id, inner.ratchet_generation);
        }
        Ok(buf)
    }

    pub fn process_rekey_ack(
        &self,
        ack_bytes: &[u8],
        peer_ed25519_public: &[u8],
        identity_kyber_secret: &SecureMemoryHandle,
    ) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.state != CallState::Active {
            return Err(ProtocolError::voip_rekey(
                "cannot process rekey ack: call not active",
            ));
        }
        if ack_bytes.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            return Err(ProtocolError::voip_rekey("rekey ack message too large"));
        }

        let ack = crate::proto::CallRekeyAck::decode(ack_bytes)
            .map_err(|e| ProtocolError::decode(format!("CallRekeyAck decode: {e}")))?;

        if ack.call_id != inner.call_id {
            return Err(ProtocolError::voip_rekey("rekey ack call_id mismatch"));
        }

        let expected_generation = inner
            .ratchet_generation
            .checked_add(1)
            .ok_or_else(|| ProtocolError::voip_rekey("rekey generation overflow"))?;
        if ack.rekey_generation != expected_generation {
            return Err(ProtocolError::voip_rekey("unexpected rekey ack generation"));
        }

        call_key_exchange::verify_rekey_signature(
            peer_ed25519_public,
            &ack.call_id,
            ack.rekey_generation,
            &ack.ephemeral_x25519_public,
            &ack.kyber_ciphertext,
            &ack.signature,
        )?;

        let pending = inner
            .pending_rekey
            .as_ref()
            .ok_or_else(|| ProtocolError::voip_rekey("no pending rekey"))?;

        let eph_priv = pending
            .ephemeral_x25519_private
            .read_bytes(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let eph_priv_arr: [u8; X25519_PRIVATE_KEY_BYTES] = eph_priv
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::voip_rekey("invalid rekey private key"))?;
        let peer_eph: [u8; X25519_PUBLIC_KEY_BYTES] = ack
            .ephemeral_x25519_public
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::voip_rekey("invalid rekey ack ephemeral key"))?;

        let secret = x25519_dalek::StaticSecret::from(eph_priv_arr);
        let classical_ss = secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer_eph))
            .to_bytes();

        let resp_kyber_ss =
            crate::crypto::KyberInterop::decapsulate(&ack.kyber_ciphertext, identity_kyber_secret)
                .map_err(ProtocolError::from_crypto)?;

        let init_kyber_bytes = pending
            .kyber_shared_secret
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let resp_kyber_bytes = resp_kyber_ss
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut combined_pq = Vec::with_capacity(KYBER_SHARED_SECRET_BYTES * 2);
        combined_pq.extend_from_slice(&init_kyber_bytes);
        combined_pq.extend_from_slice(&resp_kyber_bytes);

        let new_keys = call_key_exchange::rekey_complete(
            &inner.root_secret,
            &classical_ss,
            &combined_pq,
            &inner.call_id,
            true,
            inner.shield_mode,
        )?;

        let new_root_bytes = new_keys
            .root_secret
            .read_bytes(ROOT_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let expected_ack_mac = call_key_exchange::compute_rekey_mac(
            &new_root_bytes,
            VOIP_KEY_CONFIRM_CALLEE_INFO,
            &inner.call_id,
            ack.rekey_generation,
        )?;
        if !CryptoInterop::constant_time_equals(&ack.key_confirmation_mac, &expected_ack_mac)
            .unwrap_or(false)
        {
            return Err(ProtocolError::voip_rekey(
                "rekey ack MAC verification failed",
            ));
        }

        inner
            .send_ratchet
            .reset(new_keys.media_key_send, new_keys.nonce_prefix_send);
        inner
            .recv_ratchet
            .reset(new_keys.media_key_recv, new_keys.nonce_prefix_recv);
        inner.header_key_send = new_keys.header_key_send;
        inner.header_key_recv = new_keys.header_key_recv;
        inner.root_secret = new_keys.root_secret;
        inner.ratchet_generation = ack.rekey_generation;
        inner.frames_since_ratchet = 0;
        inner.pending_rekey = None;

        if let Some(handler) = &inner.event_handler {
            handler.on_rekey_completed(&inner.call_id, inner.ratchet_generation);
        }

        Ok(())
    }

    pub fn root_secret_handle(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bytes = inner
            .root_secret
            .read_bytes(ROOT_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut h =
            SecureMemoryHandle::allocate(ROOT_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
        h.write(&bytes).map_err(ProtocolError::from_crypto)?;
        Ok(h)
    }

    pub fn end_call(&self) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.state = CallState::Ended;
        if let Some(handler) = &inner.event_handler {
            handler.on_call_ended(&inner.call_id);
        }
        Ok(())
    }
}
