// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("crypto library not found")]
    LibraryNotFound,

    #[error("crypto initialisation failed")]
    InitializationFailed,

    #[error("secure memory region too small: capacity {capacity} bytes, operation requires {required} bytes")]
    BufferTooSmall { capacity: usize, required: usize },

    #[error("buffer exceeds maximum permitted size ({max} bytes, got {actual} bytes)")]
    BufferTooLarge { max: usize, actual: usize },

    #[error("failed to pin memory pages into RAM (mlock syscall failed)")]
    MemoryPinningFailed,

    #[error("secure memory allocation of {size} bytes failed")]
    AllocationFailed { size: usize },

    #[error("write into secure memory region failed")]
    WriteOperationFailed,

    #[error("read from secure memory region failed")]
    ReadOperationFailed,

    #[error(
        "constant-time comparison requires equal-length inputs (left = {left} bytes, right = {right} bytes)"
    )]
    ComparisonFailed { left: usize, right: usize },

    #[error("unsupported or invalid crypto operation: {operation}")]
    InvalidOperation { operation: &'static str },

    #[error("Kyber-768 KEM '{operation}' failed: {detail}")]
    KyberFailed {
        operation: &'static str,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    #[error("key derivation failed: {0}")]
    DeriveKey(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("local bundle preparation failed: {0}")]
    PrepareLocal(String),

    #[error("peer public key error: {0}")]
    PeerPubKey(String),

    #[error("handshake failed: {0}")]
    Handshake(String),

    #[error("protobuf decode failed: {0}")]
    Decode(String),

    #[error("protobuf encode failed: {0}")]
    Encode(String),

    #[error("output buffer too small: {0}")]
    BufferTooSmall(String),

    #[error("session object has been disposed")]
    ObjectDisposed,

    #[error("replay attack detected: {0}")]
    ReplayAttack(String),

    #[error("invalid session state: {0}")]
    InvalidState(String),

    #[error("unexpected null pointer received by FFI")]
    NullPointer,

    #[error("generic error: {0}")]
    Generic(String),

    #[error("group protocol error: {0}")]
    GroupProtocol(String),

    #[error("group membership error: {0}")]
    GroupMembership(String),

    #[error("tree integrity error: {0}")]
    TreeIntegrity(String),

    #[error("welcome processing failed: {0}")]
    WelcomeError(String),

    #[error("message expired: {0}")]
    MessageExpired(String),

    #[error("franking verification failed: {0}")]
    FrankingFailed(String),

    #[error("VoIP call error: {0}")]
    VoipCall(String),

    #[error("VoIP media error: {0}")]
    VoipMedia(String),

    #[error("VoIP rekey error: {0}")]
    VoipRekey(String),

    #[error("secure-memory error: {0}")]
    Crypto(#[from] CryptoError),
}

impl ProtocolError {
    #[inline]
    pub const fn from_crypto(e: CryptoError) -> Self {
        ProtocolError::Crypto(e)
    }

    #[inline]
    pub fn generic(msg: impl Into<String>) -> Self {
        ProtocolError::Generic(msg.into())
    }

    #[inline]
    pub fn key_generation(msg: impl Into<String>) -> Self {
        ProtocolError::KeyGeneration(msg.into())
    }

    #[inline]
    pub fn derive_key(msg: impl Into<String>) -> Self {
        ProtocolError::DeriveKey(msg.into())
    }

    #[inline]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        ProtocolError::InvalidInput(msg.into())
    }

    #[inline]
    pub fn prepare_local(msg: impl Into<String>) -> Self {
        ProtocolError::PrepareLocal(msg.into())
    }

    #[inline]
    pub fn handshake(msg: impl Into<String>) -> Self {
        ProtocolError::Handshake(msg.into())
    }

    #[inline]
    pub fn decode(msg: impl Into<String>) -> Self {
        ProtocolError::Decode(msg.into())
    }

    #[inline]
    pub fn encode(msg: impl Into<String>) -> Self {
        ProtocolError::Encode(msg.into())
    }

    #[inline]
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        ProtocolError::InvalidState(msg.into())
    }

    #[inline]
    pub fn replay_attack(msg: impl Into<String>) -> Self {
        ProtocolError::ReplayAttack(msg.into())
    }

    #[inline]
    pub fn peer_pub_key(msg: impl Into<String>) -> Self {
        ProtocolError::PeerPubKey(msg.into())
    }

    #[inline]
    pub fn buffer_too_small(msg: impl Into<String>) -> Self {
        ProtocolError::BufferTooSmall(msg.into())
    }

    #[inline]
    pub fn group_protocol(msg: impl Into<String>) -> Self {
        ProtocolError::GroupProtocol(msg.into())
    }

    #[inline]
    pub fn group_membership(msg: impl Into<String>) -> Self {
        ProtocolError::GroupMembership(msg.into())
    }

    #[inline]
    pub fn tree_integrity(msg: impl Into<String>) -> Self {
        ProtocolError::TreeIntegrity(msg.into())
    }

    #[inline]
    pub fn welcome_error(msg: impl Into<String>) -> Self {
        ProtocolError::WelcomeError(msg.into())
    }

    #[inline]
    pub fn message_expired(msg: impl Into<String>) -> Self {
        ProtocolError::MessageExpired(msg.into())
    }

    #[inline]
    pub fn franking_failed(msg: impl Into<String>) -> Self {
        ProtocolError::FrankingFailed(msg.into())
    }

    #[inline]
    pub fn voip_call(msg: impl Into<String>) -> Self {
        ProtocolError::VoipCall(msg.into())
    }

    #[inline]
    pub fn voip_media(msg: impl Into<String>) -> Self {
        ProtocolError::VoipMedia(msg.into())
    }

    #[inline]
    pub fn voip_rekey(msg: impl Into<String>) -> Self {
        ProtocolError::VoipRekey(msg.into())
    }
}
