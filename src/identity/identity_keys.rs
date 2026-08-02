// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{
    AesGcm, CryptoInterop, HkdfSha256, KyberInterop, MasterKeyDerivation, SecureMemoryHandle,
};
use crate::interfaces::IIdentityEventHandler;
use crate::models::bundles::LocalPublicKeyBundle;
use crate::models::key_materials::{Ed25519KeyPair, SignedPreKeyPair, X25519KeyPair};
use crate::models::keys::{OneTimePreKey, OneTimePreKeyPublic};
use crate::models::IdentityKeyBundle;
use crate::proto::IdentityReplayState;
use crate::security::DhValidator;
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct HybridHandshakeArtifacts {
    pub kyber_ciphertext: Vec<u8>,
    pub kyber_shared_secret: Vec<u8>,
}

impl Drop for HybridHandshakeArtifacts {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.kyber_shared_secret);
        CryptoInterop::secure_wipe(&mut self.kyber_ciphertext);
    }
}

struct IdentityKeysInner {
    identity_ed25519_secret_key: SecureMemoryHandle,
    identity_ed25519_public: Vec<u8>,
    identity_x25519_secret_key: SecureMemoryHandle,
    identity_x25519_public: Vec<u8>,
    identity_x25519_signature: Vec<u8>,
    signed_pre_key_id: u32,
    signed_pre_key_secret_key: SecureMemoryHandle,
    signed_pre_key_public: Vec<u8>,
    signed_pre_key_signature: Vec<u8>,
    one_time_pre_keys: Vec<OneTimePreKey>,
    one_time_pre_key_capacity: u32,
    kyber_secret_key: SecureMemoryHandle,
    kyber_public: Vec<u8>,
    pending_kyber_handshake: Option<HybridHandshakeArtifacts>,
    ephemeral_secret_key: Option<SecureMemoryHandle>,
    ephemeral_x25519_public: Option<Vec<u8>>,
    selected_one_time_pre_key_id: Option<u32>,
    inflight_handshake_init_hashes: HashSet<Vec<u8>>,
    recent_handshake_init_hashes: HashSet<Vec<u8>>,
    recent_handshake_init_order: VecDeque<Vec<u8>>,
    event_handler: Option<Arc<dyn IIdentityEventHandler>>,
}

pub struct IdentityKeys {
    inner: RwLock<IdentityKeysInner>,
}

impl IdentityKeys {
    fn new(material: IdentityKeyBundle, identity_x25519_signature: Vec<u8>) -> Self {
        let spk_id = material.signed_pre_key.id();
        let (spk_sk, spk_pk, spk_sig) = material.signed_pre_key.take();
        let (ed_sk, ed_pk) = material.ed25519.take();
        let (x_sk, x_pk) = material.identity_x25519.take();
        let one_time_pre_key_capacity =
            u32::try_from(material.one_time_pre_keys.len()).unwrap_or(u32::MAX);
        Self {
            inner: RwLock::new(IdentityKeysInner {
                identity_ed25519_secret_key: ed_sk,
                identity_ed25519_public: ed_pk,
                identity_x25519_secret_key: x_sk,
                identity_x25519_public: x_pk,
                identity_x25519_signature,
                signed_pre_key_id: spk_id,
                signed_pre_key_secret_key: spk_sk,
                signed_pre_key_public: spk_pk,
                signed_pre_key_signature: spk_sig,
                one_time_pre_keys: material.one_time_pre_keys,
                one_time_pre_key_capacity,
                kyber_secret_key: material.kyber_secret_key,
                kyber_public: material.kyber_public,
                pending_kyber_handshake: None,
                ephemeral_secret_key: None,
                ephemeral_x25519_public: None,
                selected_one_time_pre_key_id: None,
                inflight_handshake_init_hashes: HashSet::new(),
                recent_handshake_init_hashes: HashSet::new(),
                recent_handshake_init_order: VecDeque::new(),
                event_handler: None,
            }),
        }
    }

    pub fn create(one_time_key_count: u32) -> Result<Self, ProtocolError> {
        let ed_pair = Self::generate_ed25519_keys()?;
        let x_pair = Self::generate_x25519_identity_keys()?;
        let identity_x25519_signature =
            Self::sign_identity_x25519_binding(ed_pair.private_key_handle(), x_pair.public_key())?;

        let random_bytes = CryptoInterop::get_random_bytes(SPK_ID_BYTES);
        let spk_id = u32::from_le_bytes([
            random_bytes[0],
            random_bytes[1],
            random_bytes[2],
            random_bytes[3],
        ]);

        let spk_pair = Self::generate_x25519_signed_pre_key()?;
        let spk_public = spk_pair.public_key().to_vec();
        let spk_signature = Self::sign_signed_pre_key(ed_pair.private_key_handle(), &spk_public)?;

        let opks = Self::generate_one_time_pre_keys_excluding(
            one_time_key_count,
            &std::collections::HashSet::new(),
        )?;

        let (kyber_sk, kyber_pk) =
            KyberInterop::generate_keypair().map_err(ProtocolError::from_crypto)?;

        let (spk_sk, spk_pk) = spk_pair.take();
        let spk_material = SignedPreKeyPair::new(spk_id, spk_sk, spk_pk, spk_signature)?;

        let material =
            IdentityKeyBundle::new(ed_pair, x_pair, spk_material, opks, kyber_sk, kyber_pk);
        Ok(Self::new(material, identity_x25519_signature))
    }

    pub fn create_from_master_key(
        master_key: &[u8],
        membership_id: &str,
        one_time_key_count: u32,
    ) -> Result<Self, ProtocolError> {
        let mut ed_seed = MasterKeyDerivation::derive_ed25519_seed(master_key, membership_id)?;
        let ed_seed_array: [u8; X25519_PRIVATE_KEY_BYTES] = ed_seed[..X25519_PRIVATE_KEY_BYTES]
            .try_into()
            .map_err(|_| ProtocolError::key_generation("Ed25519 seed has wrong length"))?;
        let signing_key = SigningKey::from_bytes(&ed_seed_array);
        CryptoInterop::secure_wipe(&mut ed_seed);
        let ed_public = signing_key.verifying_key().to_bytes().to_vec();
        let mut ed_secret = signing_key.to_keypair_bytes().to_vec();
        let mut ed_handle =
            SecureMemoryHandle::allocate(ED25519_SECRET_KEY_BYTES).map_err(|e| {
                CryptoInterop::secure_wipe(&mut ed_secret);
                ProtocolError::from_crypto(e)
            })?;
        ed_handle.write(&ed_secret).map_err(|e| {
            CryptoInterop::secure_wipe(&mut ed_secret);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut ed_secret);
        let ed_material = Ed25519KeyPair::new(ed_handle, ed_public)?;

        let mut x_seed = MasterKeyDerivation::derive_x25519_seed(master_key, membership_id)?;
        x_seed[0] &= X25519_CLAMP_BYTE0;
        x_seed[31] &= X25519_CLAMP_BYTE31_LOW;
        x_seed[31] |= X25519_CLAMP_BYTE31_HIGH;
        let x_seed_array: [u8; X25519_PRIVATE_KEY_BYTES] = x_seed[..X25519_PRIVATE_KEY_BYTES]
            .try_into()
            .map_err(|_| ProtocolError::key_generation("X25519 seed has wrong length"))?;
        let x_secret = StaticSecret::from(x_seed_array);
        let x_public = X25519PublicKey::from(&x_secret).as_bytes().to_vec();
        let mut x_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES).map_err(|e| {
            CryptoInterop::secure_wipe(&mut x_seed);
            ProtocolError::from_crypto(e)
        })?;
        x_handle.write(&x_seed).map_err(|e| {
            CryptoInterop::secure_wipe(&mut x_seed);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut x_seed);
        let x_material = X25519KeyPair::new(x_handle, x_public)?;
        let identity_x25519_signature = Self::sign_identity_x25519_binding(
            ed_material.private_key_handle(),
            x_material.public_key(),
        )?;

        let mut spk_seed =
            MasterKeyDerivation::derive_signed_pre_key_seed(master_key, membership_id)?;
        let spk_id_bytes = HkdfSha256::derive_key_bytes(&spk_seed, SPK_ID_BYTES, b"", SPK_ID_INFO)?;
        let spk_id = u32::from_le_bytes([
            spk_id_bytes[0],
            spk_id_bytes[1],
            spk_id_bytes[2],
            spk_id_bytes[3],
        ]);
        let mut spk_secret = spk_seed[..X25519_PRIVATE_KEY_BYTES].to_vec();
        CryptoInterop::secure_wipe(&mut spk_seed);
        spk_secret[0] &= X25519_CLAMP_BYTE0;
        spk_secret[31] &= X25519_CLAMP_BYTE31_LOW;
        spk_secret[31] |= X25519_CLAMP_BYTE31_HIGH;
        let spk_secret_array: [u8; X25519_PRIVATE_KEY_BYTES] = spk_secret
            [..X25519_PRIVATE_KEY_BYTES]
            .try_into()
            .map_err(|_| ProtocolError::key_generation("SPK secret has wrong length"))?;
        let spk_x_secret = StaticSecret::from(spk_secret_array);
        let spk_public = X25519PublicKey::from(&spk_x_secret).as_bytes().to_vec();
        let mut spk_handle =
            SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES).map_err(|e| {
                CryptoInterop::secure_wipe(&mut spk_secret);
                ProtocolError::from_crypto(e)
            })?;
        spk_handle.write(&spk_secret).map_err(|e| {
            CryptoInterop::secure_wipe(&mut spk_secret);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut spk_secret);

        let spk_signature =
            Self::sign_signed_pre_key(ed_material.private_key_handle(), &spk_public)?;
        let spk_material = SignedPreKeyPair::new(spk_id, spk_handle, spk_public, spk_signature)?;

        let opks = Self::generate_one_time_pre_keys_from_master_key(
            master_key,
            membership_id,
            one_time_key_count,
        )?;

        let mut kyber_seed = MasterKeyDerivation::derive_kyber_seed(master_key, membership_id)?;
        let (kyber_sk, kyber_pk) =
            KyberInterop::generate_keypair_from_seed(&kyber_seed).map_err(|e| {
                CryptoInterop::secure_wipe(&mut kyber_seed);
                ProtocolError::from_crypto(e)
            })?;
        CryptoInterop::secure_wipe(&mut kyber_seed);

        let material = IdentityKeyBundle::new(
            ed_material,
            x_material,
            spk_material,
            opks,
            kyber_sk,
            kyber_pk,
        );
        Ok(Self::new(material, identity_x25519_signature))
    }

    pub fn get_identity_x25519_public(&self) -> Vec<u8> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identity_x25519_public
            .clone()
    }

    pub fn get_identity_ed25519_public(&self) -> Vec<u8> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .identity_ed25519_public
            .clone()
    }

    pub fn get_kyber_public(&self) -> Vec<u8> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .kyber_public
            .clone()
    }

    pub fn get_identity_x25519_private_key_copy(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .identity_x25519_secret_key
            .read_zeroizing(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)
    }

    pub fn clone_kyber_secret_key(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes = inner
            .kyber_secret_key
            .read_bytes(KYBER_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut handle = SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let write_result = handle.write(&bytes);
        CryptoInterop::secure_wipe(&mut bytes);
        write_result.map_err(ProtocolError::from_crypto)?;
        Ok(handle)
    }

    pub fn get_ephemeral_x25519_public(&self) -> Option<Vec<u8>> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ephemeral_x25519_public
            .clone()
    }

    pub fn get_signed_pre_key_public(&self) -> Vec<u8> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .signed_pre_key_public
            .clone()
    }

    pub fn get_ephemeral_x25519_private_key_copy(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let handle = inner
            .ephemeral_secret_key
            .as_ref()
            .ok_or_else(|| ProtocolError::generic("Ephemeral key has not been generated"))?;
        handle
            .read_zeroizing(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)
    }

    pub fn get_identity_ed25519_private_key_copy(
        &self,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .identity_ed25519_secret_key
            .read_zeroizing(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)
    }

    pub fn get_signed_pre_key_private_copy(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .signed_pre_key_secret_key
            .read_zeroizing(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)
    }

    pub fn get_selected_one_time_pre_key_id(&self) -> Option<u32> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .selected_one_time_pre_key_id
    }

    pub fn set_selected_one_time_pre_key_id(&self, id: u32) -> Result<(), ProtocolError> {
        self.inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?
            .selected_one_time_pre_key_id = Some(id);
        Ok(())
    }

    pub fn clear_selected_one_time_pre_key_id(&self) -> Result<(), ProtocolError> {
        self.inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?
            .selected_one_time_pre_key_id = None;
        Ok(())
    }

    pub fn create_public_bundle(&self) -> Result<LocalPublicKeyBundle, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let opk_records: Vec<OneTimePreKeyPublic> = inner
            .one_time_pre_keys
            .iter()
            .map(|opk| OneTimePreKeyPublic::new(opk.id(), opk.public_key_vec(), None))
            .collect();
        Ok(LocalPublicKeyBundle::new(
            inner.identity_ed25519_public.clone(),
            inner.identity_x25519_public.clone(),
            inner.identity_x25519_signature.clone(),
            inner.signed_pre_key_id,
            inner.signed_pre_key_public.clone(),
            inner.signed_pre_key_signature.clone(),
            opk_records,
            inner.ephemeral_x25519_public.clone(),
            Some(inner.kyber_public.clone()),
            None,
            None,
        ))
    }

    pub fn generate_ephemeral_key_pair(&self) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        if inner.ephemeral_secret_key.is_some() && inner.ephemeral_x25519_public.is_some() {
            return Ok(());
        }
        inner.ephemeral_secret_key = None;
        if let Some(ref mut pk) = inner.ephemeral_x25519_public {
            CryptoInterop::secure_wipe(pk);
        }
        inner.ephemeral_x25519_public = None;

        let (handle, public_key) = CryptoInterop::generate_x25519_keypair("ephemeral")?;
        inner.ephemeral_secret_key = Some(handle);
        inner.ephemeral_x25519_public = Some(public_key);
        Ok(())
    }

    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    pub fn set_ephemeral_key_pair_from_seed(&self, seed: &[u8]) -> Result<(), ProtocolError> {
        if seed.len() != X25519_PRIVATE_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid seed size for deterministic ephemeral key",
            ));
        }

        let mut private_key = seed.to_vec();
        private_key[0] &= X25519_CLAMP_BYTE0;
        private_key[31] &= X25519_CLAMP_BYTE31_LOW;
        private_key[31] |= X25519_CLAMP_BYTE31_HIGH;
        let private_array: [u8; X25519_PRIVATE_KEY_BYTES] = private_key[..X25519_PRIVATE_KEY_BYTES]
            .try_into()
            .map_err(|_| {
                ProtocolError::key_generation("Deterministic ephemeral seed has wrong length")
            })?;
        let public_key = X25519PublicKey::from(&StaticSecret::from(private_array))
            .as_bytes()
            .to_vec();
        let mut handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES).map_err(|e| {
            CryptoInterop::secure_wipe(&mut private_key);
            ProtocolError::from_crypto(e)
        })?;
        handle.write(&private_key).map_err(|e| {
            CryptoInterop::secure_wipe(&mut private_key);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut private_key);

        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        inner.ephemeral_secret_key = Some(handle);
        if let Some(ref mut pk) = inner.ephemeral_x25519_public {
            CryptoInterop::secure_wipe(pk);
        }
        inner.ephemeral_x25519_public = Some(public_key);
        Ok(())
    }

    pub fn clear_ephemeral_key_pair(&self) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        Self::clear_ephemeral_key_pair_locked(&mut inner);
        Ok(())
    }

    fn clear_ephemeral_key_pair_locked(inner: &mut IdentityKeysInner) {
        inner.ephemeral_secret_key = None;
        if let Some(ref mut pk) = inner.ephemeral_x25519_public {
            CryptoInterop::secure_wipe(pk);
        }
        inner.ephemeral_x25519_public = None;
    }

    pub fn verify_remote_spk_signature(
        remote_identity_ed25519: &[u8],
        remote_spk_public: &[u8],
        remote_spk_signature: &[u8],
    ) -> Result<bool, ProtocolError> {
        if remote_identity_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
            || remote_spk_public.len() != X25519_PUBLIC_KEY_BYTES
            || remote_spk_signature.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid key or signature length for SPK verification",
            ));
        }
        Ed25519KeyPair::verify(
            remote_identity_ed25519,
            remote_spk_public,
            remote_spk_signature,
        )?;
        Ok(true)
    }

    pub fn verify_remote_identity_x25519_signature(
        remote_identity_ed25519: &[u8],
        remote_identity_x25519_public: &[u8],
        remote_identity_x25519_signature: &[u8],
    ) -> Result<bool, ProtocolError> {
        if remote_identity_ed25519.len() != ED25519_PUBLIC_KEY_BYTES
            || remote_identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
            || remote_identity_x25519_signature.len() != ED25519_SIGNATURE_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid key or signature length for identity X25519 binding verification",
            ));
        }
        Ed25519KeyPair::verify(
            remote_identity_ed25519,
            remote_identity_x25519_public,
            remote_identity_x25519_signature,
        )?;
        Ok(true)
    }

    pub fn find_one_time_pre_key_by_id(&self, id: u32) -> Option<Vec<u8>> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .one_time_pre_keys
            .iter()
            .find(|opk| opk.id() == id)
            .map(super::super::models::keys::one_time_pre_key::OneTimePreKey::public_key_vec)
    }

    pub fn get_one_time_pre_key_private_by_id(
        &self,
        id: u32,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let opk = inner
            .one_time_pre_keys
            .iter()
            .find(|opk| opk.id() == id)
            .ok_or_else(|| ProtocolError::handshake("Requested OPK not found"))?;
        opk.private_key_handle()
            .read_zeroizing(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)
    }

    /// Generate `count` fresh OTKs, add them to the local pool, and return
    /// their (id, public_key) pairs so the caller can upload them to the key
    /// server.  IDs are collision-free against the keys already in the pool, not
    /// merely within the new batch.
    pub fn replenish_one_time_pre_keys(
        &self,
        count: u32,
    ) -> Result<Vec<(u32, Vec<u8>)>, ProtocolError> {
        // Generate under the write lock so two concurrent replenishes cannot
        // each read the same pool and then both extend it with the same IDs.
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        let reserved: std::collections::HashSet<u32> = inner
            .one_time_pre_keys
            .iter()
            .map(OneTimePreKey::id)
            .collect();
        let new_opks = Self::generate_one_time_pre_keys_excluding(count, &reserved)?;
        let pairs: Vec<(u32, Vec<u8>)> = new_opks
            .iter()
            .map(|opk| (opk.id(), opk.public_key_vec()))
            .collect();
        inner.one_time_pre_keys.extend(new_opks);
        inner.one_time_pre_key_capacity = inner.one_time_pre_key_capacity.saturating_add(count);
        Ok(pairs)
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IIdentityEventHandler>) {
        if let Ok(mut inner) = self.inner.write() {
            inner.event_handler = Some(handler);
        }
    }

    pub fn consume_one_time_pre_key_by_id(&self, id: u32) -> Result<(), ProtocolError> {
        let (warning_handler, remaining, max_capacity) = {
            let mut inner = self
                .inner
                .write()
                .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
            let pos = inner
                .one_time_pre_keys
                .iter()
                .position(|opk| opk.id() == id)
                .ok_or_else(|| ProtocolError::invalid_input("OPK with requested ID not found"))?;
            inner.one_time_pre_keys.remove(pos);

            let remaining = u32::try_from(inner.one_time_pre_keys.len()).unwrap_or(u32::MAX);
            let max_capacity = inner.one_time_pre_key_capacity;
            let threshold = max_capacity
                .saturating_mul(OTK_EXHAUSTION_WARNING_PERCENT)
                .div_ceil(100);
            let warning_handler = if remaining <= threshold {
                inner.event_handler.clone()
            } else {
                None
            };
            (warning_handler, remaining, max_capacity)
        };

        if let Some(handler) = warning_handler {
            handler.on_otk_exhaustion_warning(remaining, max_capacity);
        }
        Ok(())
    }

    /// Seal this identity's anti-replay state so it survives a process restart.
    ///
    /// Sessions, groups and VoIP all have sealed state; identity did not.  That
    /// mattered because `reserve_handshake_init_fingerprint` is backed by
    /// in-memory sets and, for a seed-derived identity, every one-time prekey is
    /// a pure function of the master seed — so after a restart a recorded
    /// `HandshakeInit` replayed into a byte-identical session and the attacker
    /// could replay the whole recorded message stream as fresh traffic.
    ///
    /// `external_counter` is the caller's monotonic persistence counter, checked
    /// on restore to reject a rolled-back blob.
    pub fn export_sealed_replay_state(
        &self,
        seal_key: &[u8],
        external_counter: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if seal_key.len() != AES_KEY_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "Seal key must be {AES_KEY_BYTES} bytes"
            )));
        }
        let inner = self
            .inner
            .read()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys read lock poisoned"))?;

        let state = IdentityReplayState {
            state_version: u32::from(IDENTITY_REPLAY_STATE_VERSION),
            identity_ed25519_public: inner.identity_ed25519_public.clone(),
            remaining_one_time_pre_key_ids: inner
                .one_time_pre_keys
                .iter()
                .map(OneTimePreKey::id)
                .collect(),
            recent_handshake_init_fingerprints: inner
                .recent_handshake_init_order
                .iter()
                .cloned()
                .collect(),
            external_counter,
        };
        drop(inner);

        let mut plaintext = Zeroizing::new(Vec::with_capacity(state.encoded_len()));
        state
            .encode(&mut *plaintext)
            .map_err(|e| ProtocolError::encode(format!("IdentityReplayState encode: {e}")))?;

        let aad = Self::identity_replay_state_aad(external_counter);
        let nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        let ciphertext = AesGcm::encrypt(seal_key, &nonce, &plaintext, &aad)?;

        let mut out = Vec::with_capacity(1 + 8 + nonce.len() + ciphertext.len());
        out.push(IDENTITY_REPLAY_STATE_VERSION);
        out.extend_from_slice(&external_counter.to_le_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Restore sealed anti-replay state, returning the blob's external counter.
    ///
    /// Drops any one-time prekey the blob says was already consumed — this is
    /// what stops a seed-derived identity from resurrecting them — and rebuilds
    /// the recently-seen `HandshakeInit` fingerprints.  Rejects a blob whose
    /// counter is below `min_external_counter`, whose seal key is wrong, or that
    /// belongs to a different identity.
    pub fn restore_sealed_replay_state(
        &self,
        sealed: &[u8],
        seal_key: &[u8],
        min_external_counter: u64,
    ) -> Result<u64, ProtocolError> {
        if seal_key.len() != AES_KEY_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "Seal key must be {AES_KEY_BYTES} bytes"
            )));
        }
        const HEADER: usize = 1 + 8 + AES_GCM_NONCE_BYTES;
        if sealed.len() <= HEADER {
            return Err(ProtocolError::invalid_input(
                "Sealed identity replay state is truncated",
            ));
        }
        if sealed[0] != IDENTITY_REPLAY_STATE_VERSION {
            return Err(ProtocolError::invalid_input(
                "Unsupported sealed identity replay state version",
            ));
        }
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&sealed[1..9]);
        let external_counter = u64::from_le_bytes(counter_bytes);
        if external_counter < min_external_counter {
            return Err(ProtocolError::invalid_state(
                "Sealed identity replay state is older than the expected counter",
            ));
        }

        let nonce = &sealed[9..HEADER];
        let aad = Self::identity_replay_state_aad(external_counter);
        let plaintext = Zeroizing::new(AesGcm::decrypt(seal_key, nonce, &sealed[HEADER..], &aad)?);
        let state = IdentityReplayState::decode(plaintext.as_slice())
            .map_err(|e| ProtocolError::decode(format!("IdentityReplayState decode: {e}")))?;

        if state.state_version != u32::from(IDENTITY_REPLAY_STATE_VERSION) {
            return Err(ProtocolError::invalid_input(
                "Unsupported sealed identity replay state version",
            ));
        }
        if state.recent_handshake_init_fingerprints.len() > MAX_SEEN_HANDSHAKE_INITS {
            return Err(ProtocolError::invalid_input(
                "Sealed identity replay state has too many fingerprints",
            ));
        }
        if state
            .recent_handshake_init_fingerprints
            .iter()
            .any(|fp| fp.len() != HMAC_BYTES)
        {
            return Err(ProtocolError::invalid_input(
                "Sealed identity replay state has a malformed fingerprint",
            ));
        }

        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;

        if state.identity_ed25519_public != inner.identity_ed25519_public {
            return Err(ProtocolError::invalid_input(
                "Sealed identity replay state belongs to a different identity",
            ));
        }

        let remaining: HashSet<u32> = state
            .remaining_one_time_pre_key_ids
            .iter()
            .copied()
            .collect();
        inner
            .one_time_pre_keys
            .retain(|opk| remaining.contains(&opk.id()));

        inner.recent_handshake_init_hashes.clear();
        inner.recent_handshake_init_order.clear();
        for fingerprint in state.recent_handshake_init_fingerprints {
            inner
                .recent_handshake_init_hashes
                .insert(fingerprint.clone());
            inner.recent_handshake_init_order.push_back(fingerprint);
        }

        Ok(external_counter)
    }

    /// External counter of a sealed replay-state blob, without decrypting it.
    ///
    /// Lets a host pick the newest of several persisted blobs before committing
    /// to one.  The counter is authenticated by the AEAD on restore, so a
    /// tampered value here only misleads the selection, never the restore.
    pub fn sealed_replay_state_external_counter(sealed: &[u8]) -> Result<u64, ProtocolError> {
        if sealed.len() < 9 || sealed[0] != IDENTITY_REPLAY_STATE_VERSION {
            return Err(ProtocolError::invalid_input(
                "Sealed identity replay state is malformed",
            ));
        }
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&sealed[1..9]);
        Ok(u64::from_le_bytes(counter_bytes))
    }

    fn identity_replay_state_aad(external_counter: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(IDENTITY_REPLAY_STATE_AAD.len() + 1 + 8);
        aad.extend_from_slice(IDENTITY_REPLAY_STATE_AAD);
        aad.push(IDENTITY_REPLAY_STATE_VERSION);
        aad.extend_from_slice(&external_counter.to_le_bytes());
        aad
    }

    pub fn reserve_handshake_init_fingerprint(
        &self,
        fingerprint: &[u8],
    ) -> Result<bool, ProtocolError> {
        if fingerprint.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid HandshakeInit fingerprint size",
            ));
        }
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;

        if inner.recent_handshake_init_hashes.contains(fingerprint)
            || inner.inflight_handshake_init_hashes.contains(fingerprint)
        {
            return Ok(false);
        }
        if inner.inflight_handshake_init_hashes.len() >= MAX_INFLIGHT_HANDSHAKE_INITS {
            return Err(ProtocolError::invalid_state(
                "Too many inflight HandshakeInit reservations",
            ));
        }

        inner
            .inflight_handshake_init_hashes
            .insert(fingerprint.to_vec());

        Ok(true)
    }

    pub fn remember_handshake_init_fingerprint(
        &self,
        fingerprint: &[u8],
    ) -> Result<(), ProtocolError> {
        if fingerprint.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid HandshakeInit fingerprint size",
            ));
        }
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;

        inner.inflight_handshake_init_hashes.remove(fingerprint);

        if inner.recent_handshake_init_hashes.contains(fingerprint) {
            return Ok(());
        }

        let fingerprint = fingerprint.to_vec();
        inner
            .recent_handshake_init_hashes
            .insert(fingerprint.clone());
        inner.recent_handshake_init_order.push_back(fingerprint);

        while inner.recent_handshake_init_order.len() > MAX_SEEN_HANDSHAKE_INITS {
            let Some(oldest) = inner.recent_handshake_init_order.pop_front() else {
                break;
            };
            inner.recent_handshake_init_hashes.remove(&oldest);
        }

        Ok(())
    }

    pub fn release_handshake_init_fingerprint(&self, fingerprint: &[u8]) {
        if fingerprint.len() != HMAC_BYTES {
            return;
        }
        if let Ok(mut inner) = self.inner.write() {
            inner.inflight_handshake_init_hashes.remove(fingerprint);
        }
    }

    pub fn forget_handshake_init_fingerprint(
        &self,
        fingerprint: &[u8],
    ) -> Result<(), ProtocolError> {
        if fingerprint.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid HandshakeInit fingerprint size",
            ));
        }
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;

        inner.inflight_handshake_init_hashes.remove(fingerprint);
        inner.recent_handshake_init_hashes.remove(fingerprint);
        inner
            .recent_handshake_init_order
            .retain(|entry| entry.as_slice() != fingerprint);

        Ok(())
    }

    pub fn store_pending_kyber_handshake(
        &self,
        kyber_ciphertext: Vec<u8>,
        kyber_shared_secret: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        inner.pending_kyber_handshake = Some(HybridHandshakeArtifacts {
            kyber_ciphertext,
            kyber_shared_secret,
        });
        Ok(())
    }

    pub fn consume_pending_kyber_handshake(
        &self,
    ) -> Result<HybridHandshakeArtifacts, ProtocolError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        inner
            .pending_kyber_handshake
            .take()
            .ok_or_else(|| ProtocolError::invalid_input("No pending Kyber handshake data"))
    }

    pub fn get_pending_kyber_ciphertext(&self) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .pending_kyber_handshake
            .as_ref()
            .map(|a| a.kyber_ciphertext.clone())
            .ok_or_else(|| ProtocolError::invalid_input("No pending Kyber handshake data"))
    }

    pub fn decapsulate_kyber_ciphertext(
        &self,
        ciphertext: &[u8],
    ) -> Result<HybridHandshakeArtifacts, ProtocolError> {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        KyberInterop::validate_ciphertext(ciphertext).map_err(ProtocolError::from_crypto)?;
        let ss_handle = KyberInterop::decapsulate(ciphertext, &inner.kyber_secret_key)
            .map_err(ProtocolError::from_crypto)?;
        let ss_bytes = ss_handle
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        Ok(HybridHandshakeArtifacts {
            kyber_ciphertext: ciphertext.to_vec(),
            kyber_shared_secret: ss_bytes,
        })
    }

    pub fn x3dh_derive_shared_secret(
        &self,
        remote_bundle: &LocalPublicKeyBundle,
        info: &[u8],
        is_initiator: bool,
    ) -> Result<SecureMemoryHandle, ProtocolError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        Self::validate_hkdf_info(info)?;
        Self::validate_remote_bundle(remote_bundle)?;
        Self::ensure_local_keys_valid(&inner)?;

        if !remote_bundle.has_kyber_public() {
            return Err(ProtocolError::invalid_input(
                "Remote Kyber public key required for hybrid X3DH",
            ));
        }

        let mut dh_results = vec![0u8; X25519_SHARED_SECRET_BYTES * X3DH_DH_COUNT];
        let dh_offset;
        let used_one_time_pre_key_id;

        if is_initiator {
            let eph_secret = inner
                .ephemeral_secret_key
                .as_ref()
                .ok_or_else(|| ProtocolError::prepare_local("Local ephemeral key missing"))?
                .read_bytes(X25519_PRIVATE_KEY_BYTES)
                .map_err(ProtocolError::from_crypto)?;
            let id_secret = inner
                .identity_x25519_secret_key
                .read_bytes(X25519_PRIVATE_KEY_BYTES)
                .map_err(|e| {
                    let mut v = eph_secret.clone();
                    CryptoInterop::secure_wipe(&mut v);
                    ProtocolError::from_crypto(e)
                })?;

            let opk_to_use = remote_bundle
                .used_one_time_pre_key_id()
                .or(inner.selected_one_time_pre_key_id);
            if let Some(id) = opk_to_use {
                inner.selected_one_time_pre_key_id = Some(id);
            } else {
                inner.selected_one_time_pre_key_id = None;
            }
            used_one_time_pre_key_id = opk_to_use;

            let result = Self::perform_x3dh_dh_as_initiator(
                &eph_secret,
                &id_secret,
                remote_bundle,
                opk_to_use,
                &mut dh_results,
            );
            let mut es = eph_secret;
            CryptoInterop::secure_wipe(&mut es);
            let mut ids = id_secret;
            CryptoInterop::secure_wipe(&mut ids);
            dh_offset = result?;
        } else {
            used_one_time_pre_key_id = inner
                .selected_one_time_pre_key_id
                .or_else(|| remote_bundle.used_one_time_pre_key_id());

            let result = Self::perform_x3dh_dh_as_responder(
                &inner,
                remote_bundle,
                used_one_time_pre_key_id,
                &mut dh_results,
            );
            dh_offset = result?;
        }

        let mut ikm = vec![0u8; X25519_SHARED_SECRET_BYTES + dh_offset];
        ikm[..X25519_SHARED_SECRET_BYTES].fill(X3DH_FILL_BYTE);
        ikm[X25519_SHARED_SECRET_BYTES..X25519_SHARED_SECRET_BYTES + dh_offset]
            .copy_from_slice(&dh_results[..dh_offset]);
        CryptoInterop::secure_wipe(&mut dh_results);

        let mut classical_shared = {
            let mut z = HkdfSha256::derive_key_bytes(&ikm, X25519_SHARED_SECRET_BYTES, &[], info)
                .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut ikm);
            })?;
            std::mem::take(&mut *z)
        };
        CryptoInterop::secure_wipe(&mut ikm);

        let (kyber_ciphertext, mut kyber_ss_bytes, used_stored);
        let has_peer_ct = remote_bundle.has_kyber_ciphertext();
        let use_pending = inner.pending_kyber_handshake.is_some() && (is_initiator || !has_peer_ct);

        if use_pending {
            let artifacts = inner
                .pending_kyber_handshake
                .as_ref()
                .ok_or_else(|| ProtocolError::invalid_state("Pending Kyber handshake missing"))?;
            kyber_ciphertext = artifacts.kyber_ciphertext.clone();
            kyber_ss_bytes = artifacts.kyber_shared_secret.clone();
            used_stored = true;
        } else if has_peer_ct {
            let peer_ct = remote_bundle.kyber_ciphertext().ok_or_else(|| {
                ProtocolError::invalid_input("Remote bundle missing Kyber ciphertext")
            })?;
            KyberInterop::validate_ciphertext(peer_ct).map_err(ProtocolError::from_crypto)?;
            let ss_handle = KyberInterop::decapsulate(peer_ct, &inner.kyber_secret_key)
                .map_err(ProtocolError::from_crypto)?;
            let ss_b = ss_handle
                .read_bytes(KYBER_SHARED_SECRET_BYTES)
                .map_err(ProtocolError::from_crypto)?;
            kyber_ciphertext = peer_ct.to_vec();
            kyber_ss_bytes = ss_b;
            used_stored = false;
        } else {
            let remote_kyber_pk = remote_bundle.kyber_public().ok_or_else(|| {
                ProtocolError::invalid_input("Remote bundle missing Kyber public key")
            })?;
            let (ct, ss_handle) = KyberInterop::encapsulate(remote_kyber_pk).map_err(|e| {
                CryptoInterop::secure_wipe(&mut classical_shared);
                ProtocolError::from_crypto(e)
            })?;
            let ss_b = ss_handle
                .read_bytes(KYBER_SHARED_SECRET_BYTES)
                .map_err(|e| {
                    CryptoInterop::secure_wipe(&mut classical_shared);
                    ProtocolError::from_crypto(e)
                })?;
            kyber_ciphertext = ct;
            kyber_ss_bytes = ss_b;
            used_stored = false;
        }

        let hybrid_bytes = KyberInterop::combine_hybrid_secrets(
            &classical_shared,
            &kyber_ss_bytes,
            X25519_SHARED_SECRET_BYTES,
            X3DH_INFO,
        )
        .inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut classical_shared);
            let mut ks = kyber_ss_bytes.clone();
            CryptoInterop::secure_wipe(&mut ks);
        })?;
        CryptoInterop::secure_wipe(&mut classical_shared);

        if !used_stored {
            inner.pending_kyber_handshake = Some(HybridHandshakeArtifacts {
                kyber_ciphertext,
                kyber_shared_secret: kyber_ss_bytes.clone(),
            });
        }
        CryptoInterop::secure_wipe(&mut kyber_ss_bytes);

        if is_initiator {
            Self::clear_ephemeral_key_pair_locked(&mut inner);
        }

        if !is_initiator {
            if let Some(opk_id) = used_one_time_pre_key_id {
                let pos = inner
                    .one_time_pre_keys
                    .iter()
                    .position(|o| o.id() == opk_id);
                if let Some(idx) = pos {
                    inner.one_time_pre_keys.remove(idx);
                }
            }
        }
        inner.selected_one_time_pre_key_id = None;

        let mut result_handle = SecureMemoryHandle::allocate(X25519_SHARED_SECRET_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        result_handle
            .write(&hybrid_bytes)
            .map_err(ProtocolError::from_crypto)?;
        Ok(result_handle)
    }

    fn generate_ed25519_keys() -> Result<Ed25519KeyPair, ProtocolError> {
        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        let mut secret_key = signing_key.to_keypair_bytes().to_vec();
        let mut handle = SecureMemoryHandle::allocate(ED25519_SECRET_KEY_BYTES).map_err(|e| {
            CryptoInterop::secure_wipe(&mut secret_key);
            ProtocolError::from_crypto(e)
        })?;
        handle.write(&secret_key).map_err(|e| {
            CryptoInterop::secure_wipe(&mut secret_key);
            ProtocolError::from_crypto(e)
        })?;
        CryptoInterop::secure_wipe(&mut secret_key);
        Ed25519KeyPair::new(handle, public_key)
    }

    fn generate_x25519_identity_keys() -> Result<X25519KeyPair, ProtocolError> {
        let (handle, pk) = CryptoInterop::generate_x25519_keypair("identity")?;
        X25519KeyPair::new(handle, pk)
    }

    fn generate_x25519_signed_pre_key() -> Result<X25519KeyPair, ProtocolError> {
        let (handle, pk) = CryptoInterop::generate_x25519_keypair("spk")?;
        X25519KeyPair::new(handle, pk)
    }

    fn sign_with_ed25519(
        ed_secret_key_handle: &SecureMemoryHandle,
        message: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut sk_bytes = ed_secret_key_handle
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::generic("Ed25519 secret key has wrong length"))?;
        let signing_key = SigningKey::from_keypair_bytes(&sk_array)
            .map_err(|_| ProtocolError::generic("Failed to parse Ed25519 keypair bytes"))?;
        CryptoInterop::secure_wipe(&mut sk_bytes);
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn sign_signed_pre_key(
        ed_secret_key_handle: &SecureMemoryHandle,
        spk_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        Self::sign_with_ed25519(ed_secret_key_handle, spk_public)
    }

    fn sign_identity_x25519_binding(
        ed_secret_key_handle: &SecureMemoryHandle,
        identity_x25519_public: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        Self::sign_with_ed25519(ed_secret_key_handle, identity_x25519_public)
    }

    /// Generate `count` one-time prekeys whose IDs avoid `reserved_ids`.
    ///
    /// The counter used to restart at 2 on every call with a batch-local
    /// collision set, so `create(5)` followed by `replenish(14)` published IDs
    /// 2..6 twice under *different* public keys.  Lookup is first-match-wins, so
    /// an initiator that fetched the replenished public key for a duplicated ID
    /// would derive against the original private key and the handshake would
    /// fail — or, once the original was consumed, silently reuse a one-time key
    /// and lose the forward secrecy it exists to provide.
    ///
    /// IDs are now drawn from the same space as the deterministic sibling and
    /// checked against the live pool, with exhaustion treated as a hard error
    /// exactly as `generate_one_time_pre_keys_from_master_key` does.
    fn generate_one_time_pre_keys_excluding(
        count: u32,
        reserved_ids: &std::collections::HashSet<u32>,
    ) -> Result<Vec<OneTimePreKey>, ProtocolError> {
        const OPK_ID_RETRY_LIMIT: usize = 64;

        if count == 0 {
            return Ok(vec![]);
        }
        let mut opks = Vec::with_capacity(count as usize);
        let mut used_ids = reserved_ids.clone();
        for i in 0..count {
            let mut id = None;
            for _ in 0..OPK_ID_RETRY_LIMIT {
                let rb = CryptoInterop::get_random_bytes(4);
                let raw = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]);
                let candidate = (raw % OPK_ID_MODULUS).wrapping_add(OPK_ID_OFFSET);
                if used_ids.insert(candidate) {
                    id = Some(candidate);
                    break;
                }
            }
            let id = id.ok_or_else(|| {
                ProtocolError::key_generation(format!(
                    "Could not find an unused one-time prekey ID at index {i} after {OPK_ID_RETRY_LIMIT} attempts"
                ))
            })?;
            opks.push(OneTimePreKey::generate(id)?);
        }
        Ok(opks)
    }

    fn generate_one_time_pre_keys_from_master_key(
        master_key: &[u8],
        membership_id: &str,
        count: u32,
    ) -> Result<Vec<OneTimePreKey>, ProtocolError> {
        if count == 0 {
            return Ok(vec![]);
        }
        let mut opks = Vec::with_capacity(count as usize);
        let mut used_ids = std::collections::HashSet::with_capacity(count as usize);
        for i in 0..count {
            let mut id_seed =
                MasterKeyDerivation::derive_one_time_pre_key_seed(master_key, membership_id, i)?;
            let id = {
                let raw = u32::from_le_bytes([id_seed[0], id_seed[1], id_seed[2], id_seed[3]]);
                (raw % OPK_ID_MODULUS).wrapping_add(OPK_ID_OFFSET)
            };
            CryptoInterop::secure_wipe(&mut id_seed);

            if !used_ids.insert(id) {
                return Err(ProtocolError::key_generation(format!(
                    "Deterministic OPK ID collision at index {i} (id={id})"
                )));
            }

            let mut opk_seed = MasterKeyDerivation::derive_one_time_pre_key_seed(
                master_key,
                membership_id,
                count + i,
            )?;
            let opk = OneTimePreKey::create_from_seed(id, &opk_seed);
            CryptoInterop::secure_wipe(&mut opk_seed);
            opks.push(opk?);
        }
        Ok(opks)
    }

    fn validate_hkdf_info(info: &[u8]) -> Result<(), ProtocolError> {
        if info.is_empty() {
            return Err(ProtocolError::derive_key("HKDF info cannot be empty"));
        }
        Ok(())
    }

    fn validate_remote_bundle(bundle: &LocalPublicKeyBundle) -> Result<(), ProtocolError> {
        if bundle.identity_ed25519_public().len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::peer_pub_key(
                "Invalid remote Ed25519 identity key",
            ));
        }
        if bundle.identity_x25519_public().len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::peer_pub_key(
                "Invalid remote identity X25519 key",
            ));
        }
        if bundle.signed_pre_key_public().len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::peer_pub_key(
                "Invalid remote signed pre-key public key",
            ));
        }
        DhValidator::validate_x25519_public_key(bundle.identity_x25519_public()).map_err(|e| {
            ProtocolError::peer_pub_key(format!("Invalid remote identity X25519 key: {e}"))
        })?;
        DhValidator::validate_x25519_public_key(bundle.signed_pre_key_public()).map_err(|e| {
            ProtocolError::peer_pub_key(format!("Invalid remote signed pre-key X25519 key: {e}"))
        })?;
        if let Some(ephemeral) = bundle.ephemeral_x25519_public() {
            DhValidator::validate_x25519_public_key(ephemeral).map_err(|e| {
                ProtocolError::peer_pub_key(format!("Invalid remote ephemeral X25519 key: {e}"))
            })?;
        }
        for opk in bundle.one_time_pre_keys() {
            DhValidator::validate_x25519_public_key(opk.public_key()).map_err(|e| {
                ProtocolError::peer_pub_key(format!("Invalid remote one-time X25519 key: {e}"))
            })?;
            if let Some(kyber_public) = opk.kyber_public() {
                KyberInterop::validate_public_key(kyber_public)
                    .map_err(ProtocolError::from_crypto)?;
            }
        }
        Self::verify_remote_identity_x25519_signature(
            bundle.identity_ed25519_public(),
            bundle.identity_x25519_public(),
            bundle.identity_x25519_signature(),
        )?;
        Self::verify_remote_spk_signature(
            bundle.identity_ed25519_public(),
            bundle.signed_pre_key_public(),
            bundle.signed_pre_key_signature(),
        )?;
        match bundle.kyber_public() {
            Some(kp) if kp.len() == KYBER_PUBLIC_KEY_BYTES => {
                KyberInterop::validate_public_key(kp).map_err(ProtocolError::from_crypto)?;
            }
            _ => {
                return Err(ProtocolError::peer_pub_key(
                    "Invalid remote Kyber-768 public key",
                ))
            }
        }
        Ok(())
    }

    fn ensure_local_keys_valid(inner: &IdentityKeysInner) -> Result<(), ProtocolError> {
        if inner.ephemeral_secret_key.is_none() {
            return Err(ProtocolError::prepare_local(
                "Local ephemeral key missing or invalid",
            ));
        }
        Ok(())
    }

    fn x25519_dh(
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<[u8; X25519_SHARED_SECRET_BYTES], ProtocolError> {
        let sk: [u8; X25519_PRIVATE_KEY_BYTES] = private_key
            .try_into()
            .map_err(|_| ProtocolError::generic("Invalid X25519 private key size"))?;
        let pk: [u8; X25519_PUBLIC_KEY_BYTES] = public_key
            .try_into()
            .map_err(|_| ProtocolError::generic("Invalid X25519 public key size"))?;
        DhValidator::validate_x25519_public_key(public_key)?;
        let secret = StaticSecret::from(sk);
        let public = X25519PublicKey::from(pk);
        let shared = secret.diffie_hellman(&public).to_bytes();
        if shared.iter().fold(0u8, |acc, &b| acc | b) == 0 {
            return Err(ProtocolError::invalid_input(
                "X25519 DH produced all-zero shared secret",
            ));
        }
        Ok(shared)
    }

    fn perform_x3dh_dh_as_initiator(
        ephemeral_secret: &[u8],
        identity_secret: &[u8],
        remote_bundle: &LocalPublicKeyBundle,
        one_time_pre_key_id: Option<u32>,
        dh_results: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        let mut offset = 0usize;

        let dh1 = Self::x25519_dh(identity_secret, remote_bundle.signed_pre_key_public())?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh1);
        offset += X25519_SHARED_SECRET_BYTES;

        let dh2 = Self::x25519_dh(ephemeral_secret, remote_bundle.identity_x25519_public())?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh2);
        offset += X25519_SHARED_SECRET_BYTES;

        let dh3 = Self::x25519_dh(ephemeral_secret, remote_bundle.signed_pre_key_public())?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh3);
        offset += X25519_SHARED_SECRET_BYTES;

        if let Some(opk_id) = one_time_pre_key_id {
            if remote_bundle.has_one_time_pre_keys() {
                let target_opk = remote_bundle
                    .one_time_pre_keys()
                    .iter()
                    .find(|opk| opk.id() == opk_id);
                match target_opk {
                    Some(opk) if opk.public_key().len() == X25519_PUBLIC_KEY_BYTES => {
                        let dh4 = Self::x25519_dh(ephemeral_secret, opk.public_key())?;
                        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES]
                            .copy_from_slice(&dh4);
                        offset += X25519_SHARED_SECRET_BYTES;
                    }
                    _ => {
                        return Err(ProtocolError::invalid_input(
                            "Requested OPK ID not found in peer bundle",
                        ));
                    }
                }
            }
        }
        Ok(offset)
    }

    fn perform_x3dh_dh_as_responder(
        inner: &IdentityKeysInner,
        remote_bundle: &LocalPublicKeyBundle,
        used_one_time_pre_key_id: Option<u32>,
        dh_results: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        if !remote_bundle.has_ephemeral_x25519_public() {
            return Err(ProtocolError::invalid_input(
                "Remote bundle must have ephemeral key for responder X3DH",
            ));
        }
        let peer_ephemeral = remote_bundle.ephemeral_x25519_public().ok_or_else(|| {
            ProtocolError::invalid_input("Remote bundle missing ephemeral X25519 key")
        })?;
        let peer_identity = remote_bundle.identity_x25519_public();

        let mut spk_secret = inner
            .signed_pre_key_secret_key
            .read_bytes(X25519_PRIVATE_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let id_secret_result = inner
            .identity_x25519_secret_key
            .read_bytes(X25519_PRIVATE_KEY_BYTES);
        let mut identity_secret = match id_secret_result {
            Ok(s) => s,
            Err(e) => {
                CryptoInterop::secure_wipe(&mut spk_secret);
                return Err(ProtocolError::from_crypto(e));
            }
        };

        let mut offset = 0usize;

        let dh1 = Self::x25519_dh(&spk_secret, peer_identity).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_secret);
            CryptoInterop::secure_wipe(&mut identity_secret);
        })?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh1);
        offset += X25519_SHARED_SECRET_BYTES;

        let dh2 = Self::x25519_dh(&identity_secret, peer_ephemeral).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_secret);
            CryptoInterop::secure_wipe(&mut identity_secret);
        })?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh2);
        offset += X25519_SHARED_SECRET_BYTES;

        let dh3 = Self::x25519_dh(&spk_secret, peer_ephemeral).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_secret);
            CryptoInterop::secure_wipe(&mut identity_secret);
        })?;
        dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh3);
        offset += X25519_SHARED_SECRET_BYTES;

        if let Some(opk_id) = used_one_time_pre_key_id {
            let opk = inner.one_time_pre_keys.iter().find(|o| o.id() == opk_id);
            if let Some(opk) = opk {
                let mut opk_secret = opk
                    .private_key_handle()
                    .read_bytes(X25519_PRIVATE_KEY_BYTES)
                    .map_err(|e| {
                        CryptoInterop::secure_wipe(&mut spk_secret);
                        CryptoInterop::secure_wipe(&mut identity_secret);
                        ProtocolError::from_crypto(e)
                    })?;
                let dh4 = Self::x25519_dh(&opk_secret, peer_ephemeral).inspect_err(|_e| {
                    CryptoInterop::secure_wipe(&mut opk_secret);
                    CryptoInterop::secure_wipe(&mut spk_secret);
                    CryptoInterop::secure_wipe(&mut identity_secret);
                })?;
                CryptoInterop::secure_wipe(&mut opk_secret);
                dh_results[offset..offset + X25519_SHARED_SECRET_BYTES].copy_from_slice(&dh4);
                offset += X25519_SHARED_SECRET_BYTES;
            } else {
                CryptoInterop::secure_wipe(&mut spk_secret);
                CryptoInterop::secure_wipe(&mut identity_secret);
                return Err(ProtocolError::invalid_input(
                    "OPK with requested ID not found",
                ));
            }
        }

        CryptoInterop::secure_wipe(&mut spk_secret);
        CryptoInterop::secure_wipe(&mut identity_secret);
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_dh_rejects_small_order_public_key() {
        CryptoInterop::initialize().expect("crypto init");

        let private_key = [0x42u8; X25519_PRIVATE_KEY_BYTES];
        let small_order_public = [0u8; X25519_PUBLIC_KEY_BYTES];

        assert!(IdentityKeys::x25519_dh(&private_key, &small_order_public).is_err());
    }

    #[test]
    fn remote_bundle_validation_rejects_malformed_kyber_public_key() {
        CryptoInterop::initialize().expect("crypto init");

        let identity = IdentityKeys::create(1).unwrap();
        let bundle = identity.create_public_bundle().unwrap();
        let malformed = LocalPublicKeyBundle::new(
            bundle.identity_ed25519_public().to_vec(),
            bundle.identity_x25519_public().to_vec(),
            bundle.identity_x25519_signature().to_vec(),
            bundle.signed_pre_key_id(),
            bundle.signed_pre_key_public().to_vec(),
            bundle.signed_pre_key_signature().to_vec(),
            bundle.one_time_pre_keys().to_vec(),
            bundle.ephemeral_x25519_public().map(Vec::from),
            Some(vec![0u8; KYBER_PUBLIC_KEY_BYTES]),
            None,
            None,
        );

        assert!(IdentityKeys::validate_remote_bundle(&malformed).is_err());
    }
}
