// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::models::keys::OneTimePreKeyPublic;

#[derive(Clone)]
pub struct LocalPublicKeyBundle {
    identity_ed25519_public: Vec<u8>,
    identity_x25519_public: Vec<u8>,
    identity_x25519_signature: Vec<u8>,
    signed_pre_key_id: u32,
    signed_pre_key_public: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    one_time_pre_keys: Vec<OneTimePreKeyPublic>,
    ephemeral_x25519_public: Option<Vec<u8>>,
    kyber_public: Option<Vec<u8>>,
    kyber_ciphertext: Option<Vec<u8>>,
    used_one_time_pre_key_id: Option<u32>,
}

impl LocalPublicKeyBundle {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        identity_ed25519_public: Vec<u8>,
        identity_x25519_public: Vec<u8>,
        identity_x25519_signature: Vec<u8>,
        signed_pre_key_id: u32,
        signed_pre_key_public: Vec<u8>,
        signed_pre_key_signature: Vec<u8>,
        one_time_pre_keys: Vec<OneTimePreKeyPublic>,
        ephemeral_x25519_public: Option<Vec<u8>>,
        kyber_public: Option<Vec<u8>>,
        kyber_ciphertext: Option<Vec<u8>>,
        used_one_time_pre_key_id: Option<u32>,
    ) -> Self {
        Self {
            identity_ed25519_public,
            identity_x25519_public,
            identity_x25519_signature,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            one_time_pre_keys,
            ephemeral_x25519_public,
            kyber_public,
            kyber_ciphertext,
            used_one_time_pre_key_id,
        }
    }

    pub fn identity_ed25519_public(&self) -> &[u8] {
        &self.identity_ed25519_public
    }

    pub fn identity_x25519_public(&self) -> &[u8] {
        &self.identity_x25519_public
    }

    pub fn identity_x25519_public_vec(&self) -> Vec<u8> {
        self.identity_x25519_public.clone()
    }

    pub fn identity_x25519_signature(&self) -> &[u8] {
        &self.identity_x25519_signature
    }

    pub const fn signed_pre_key_id(&self) -> u32 {
        self.signed_pre_key_id
    }

    pub fn signed_pre_key_public(&self) -> &[u8] {
        &self.signed_pre_key_public
    }

    pub fn signed_pre_key_public_vec(&self) -> Vec<u8> {
        self.signed_pre_key_public.clone()
    }

    pub fn signed_pre_key_signature(&self) -> &[u8] {
        &self.signed_pre_key_signature
    }

    pub fn one_time_pre_keys(&self) -> &[OneTimePreKeyPublic] {
        &self.one_time_pre_keys
    }

    pub const fn one_time_pre_key_count(&self) -> usize {
        self.one_time_pre_keys.len()
    }

    pub const fn has_one_time_pre_keys(&self) -> bool {
        !self.one_time_pre_keys.is_empty()
    }

    pub fn ephemeral_x25519_public(&self) -> Option<&[u8]> {
        self.ephemeral_x25519_public.as_deref()
    }

    pub const fn has_ephemeral_x25519_public(&self) -> bool {
        self.ephemeral_x25519_public.is_some()
    }

    pub fn kyber_public(&self) -> Option<&[u8]> {
        self.kyber_public.as_deref()
    }

    pub const fn has_kyber_public(&self) -> bool {
        self.kyber_public.is_some()
    }

    pub fn kyber_ciphertext(&self) -> Option<&[u8]> {
        self.kyber_ciphertext.as_deref()
    }

    pub const fn has_kyber_ciphertext(&self) -> bool {
        matches!(&self.kyber_ciphertext, Some(ct) if !ct.is_empty())
    }

    pub const fn used_one_time_pre_key_id(&self) -> Option<u32> {
        self.used_one_time_pre_key_id
    }

    pub const fn has_used_one_time_pre_key_id(&self) -> bool {
        self.used_one_time_pre_key_id.is_some()
    }

    pub const fn set_used_one_time_pre_key_id(&mut self, id: u32) {
        self.used_one_time_pre_key_id = Some(id);
    }
}
