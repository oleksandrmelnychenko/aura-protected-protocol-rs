// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub mod attachment;
pub mod channel;
pub mod group;
pub mod handshake;
pub mod nonce;
pub mod session;
pub mod voip;

pub use attachment::{EncryptedChunk, StreamingDecryptor, StreamingEncryptor};
pub use channel::{
    decrypt_message as channel_decrypt_message, encrypt_message as channel_encrypt_message,
    generate_channel_key, unwrap_key_blob as unwrap_channel_key_blob,
    wrap_key_for_device as wrap_channel_key_for_device, ChannelDecryptedMessage,
    ChannelEncryptedFields, ChannelKeyMaterial, CHANNEL_ED25519_SECRET_BYTES, CHANNEL_ID_BYTES,
    CHANNEL_KEY_BLOB_BYTES, CHANNEL_KEY_ID_BYTES,
};
pub use group::{
    ContentType, FrankingData, GroupDecryptResult, GroupSecurityPolicy, GroupSecurityTier,
    GroupSession, MessagePolicy, SealedPayload,
};
pub use handshake::{HandshakeInitReplayGuard, HandshakeInitiator, HandshakeResponder};
pub use nonce::{NonceGenerator, NonceState};
pub use session::{
    DecryptResult, HandshakeState, LocalIdentity, PeerIdentity, Session, SessionMetadata,
};
pub use voip::{
    CallControlType, CallRole, CallState, CallStatistics, IVoipEventHandler, VoipSession,
};
