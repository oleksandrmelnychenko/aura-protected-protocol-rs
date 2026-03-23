// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{
    CryptoInterop, HkdfSha256, KyberInterop, MasterKeyDerivation, SecureMemoryHandle,
};
use crate::interfaces::IIdentityEventHandler;
use crate::models::bundles::LocalPublicKeyBundle;
use crate::models::key_materials::{Ed25519KeyPair, SignedPreKeyPair, X25519KeyPair};
use crate::models::keys::{OneTimePreKey, OneTimePreKeyPublic};
use crate::models::IdentityKeyBundle;
use ed25519_dalek::{Signer, SigningKey};
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
    kyber_secret_key: SecureMemoryHandle,
    kyber_public: Vec<u8>,
    pending_kyber_handshake: Option<HybridHandshakeArtifacts>,
    ephemeral_secret_key: Option<SecureMemoryHandle>,
    ephemeral_x25519_public: Option<Vec<u8>>,
    selected_one_time_pre_key_id: Option<u32>,
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
                kyber_secret_key: material.kyber_secret_key,
                kyber_public: material.kyber_public,
                pending_kyber_handshake: None,
                ephemeral_secret_key: None,
                ephemeral_x25519_public: None,
                selected_one_time_pre_key_id: None,
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

        let opks = Self::generate_one_time_pre_keys(one_time_key_count)?;

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
    /// server.  IDs are random and collision-free within the new batch.
    pub fn replenish_one_time_pre_keys(
        &self,
        count: u32,
    ) -> Result<Vec<(u32, Vec<u8>)>, ProtocolError> {
        let new_opks = Self::generate_one_time_pre_keys(count)?;
        let pairs: Vec<(u32, Vec<u8>)> = new_opks
            .iter()
            .map(|opk| (opk.id(), opk.public_key_vec()))
            .collect();
        let mut inner = self
            .inner
            .write()
            .map_err(|_| ProtocolError::invalid_state("IdentityKeys write lock poisoned"))?;
        inner.one_time_pre_keys.extend(new_opks);
        Ok(pairs)
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IIdentityEventHandler>) {
        if let Ok(mut inner) = self.inner.write() {
            inner.event_handler = Some(handler);
        }
    }

    pub fn consume_one_time_pre_key_by_id(&self, id: u32) -> Result<(), ProtocolError> {
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
        let max_capacity = DEFAULT_ONE_TIME_KEY_COUNT;
        let threshold = max_capacity * OTK_EXHAUSTION_WARNING_PERCENT / 100;
        if remaining <= threshold {
            if let Some(ref handler) = inner.event_handler {
                handler.on_otk_exhaustion_warning(remaining, max_capacity);
            }
        }
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

    fn generate_one_time_pre_keys(count: u32) -> Result<Vec<OneTimePreKey>, ProtocolError> {
        if count == 0 {
            return Ok(vec![]);
        }
        let mut opks = Vec::with_capacity(count as usize);
        let mut used_ids = std::collections::HashSet::new();
        let mut id_counter: u32 = 2;
        for _ in 0..count {
            let mut id = id_counter;
            id_counter = id_counter.wrapping_add(1);
            while used_ids.contains(&id) {
                let rb = CryptoInterop::get_random_bytes(4);
                id = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]);
            }
            used_ids.insert(id);
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
            Some(kp) if kp.len() == KYBER_PUBLIC_KEY_BYTES => {}
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
        let secret = StaticSecret::from(sk);
        let public = X25519PublicKey::from(pk);
        Ok(secret.diffie_hellman(&public).to_bytes())
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
