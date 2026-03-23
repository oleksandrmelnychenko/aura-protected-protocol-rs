// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, SecureMemoryHandle};

pub trait IStateKeyProvider: Send + Sync {
    fn get_state_encryption_key(&self) -> Result<SecureMemoryHandle, ProtocolError>;
}

pub trait IProtocolEventHandler: Send + Sync {
    fn on_handshake_completed(&self, session_id: &[u8]);
    fn on_ratchet_rotated(&self, epoch: u64);
    fn on_error(&self, error: &ProtocolError);
    fn on_nonce_exhaustion_warning(&self, remaining: u64, max_capacity: u64);

    fn on_ratchet_stalling_warning(&self, messages_since_ratchet: u64) {
        let _ = messages_since_ratchet;
    }
}

pub trait IGroupEventHandler: Send + Sync {
    fn on_member_added(&self, leaf_index: u32, identity_ed25519: &[u8]);
    fn on_member_removed(&self, leaf_index: u32);
    fn on_epoch_advanced(&self, new_epoch: u64, member_count: u32);
    fn on_sender_key_exhaustion_warning(&self, remaining: u32, max_capacity: u32);
    /// Fired when a ReInit proposal is applied in a Commit.
    /// The group should be considered deprecated; migrate to a new group
    /// identified by `new_group_id` using the protocol version `new_version`.
    fn on_reinit_proposed(&self, new_group_id: &[u8], new_version: u32) {
        let _ = (new_group_id, new_version);
    }
}

pub trait IIdentityEventHandler: Send + Sync {
    /// Fired after an OTK is consumed and the remaining pool has dropped below
    /// the exhaustion-warning threshold.  The caller should upload fresh OTKs
    /// via `replenish_one_time_pre_keys` to avoid running out.
    fn on_otk_exhaustion_warning(&self, remaining: u32, max_capacity: u32);
}

pub struct StaticStateKeyProvider {
    key: Vec<u8>,
}

impl StaticStateKeyProvider {
    pub fn new(key: Vec<u8>) -> Result<Self, ProtocolError> {
        if key.len() != 32 {
            return Err(ProtocolError::invalid_input("State key must be 32 bytes"));
        }
        Ok(Self { key })
    }
}

impl Drop for StaticStateKeyProvider {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.key);
    }
}

impl IStateKeyProvider for StaticStateKeyProvider {
    fn get_state_encryption_key(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let mut handle = SecureMemoryHandle::allocate(32).map_err(ProtocolError::from_crypto)?;
        handle
            .write(&self.key)
            .map_err(ProtocolError::from_crypto)?;
        Ok(handle)
    }
}
