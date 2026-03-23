// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, KyberInterop, SecureMemoryHandle};
use sha2::Digest;

pub struct EpochKeys {
    pub epoch_secret: Vec<u8>,
    pub metadata_key: Vec<u8>,
    pub welcome_key: Vec<u8>,
    pub confirmation_key: Vec<u8>,
    pub init_secret: Vec<u8>,
}

impl Drop for EpochKeys {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.epoch_secret);
        CryptoInterop::secure_wipe(&mut self.metadata_key);
        CryptoInterop::secure_wipe(&mut self.welcome_key);
        CryptoInterop::secure_wipe(&mut self.confirmation_key);
        CryptoInterop::secure_wipe(&mut self.init_secret);
    }
}

pub struct GroupKeySchedule;

impl GroupKeySchedule {
    fn derive_sub_key(
        epoch_secret: &[u8],
        info: &[u8],
        len: usize,
        enhanced: bool,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtocolError> {
        if enhanced {
            let mut pass1_info = Vec::with_capacity(info.len() + GROUP_ENHANCED_KDF_PASS1.len());
            pass1_info.extend_from_slice(info);
            pass1_info.extend_from_slice(GROUP_ENHANCED_KDF_PASS1);
            let intermediate = HkdfSha256::expand(epoch_secret, &pass1_info, len)?;
            let mut pass2_info = Vec::with_capacity(info.len() + GROUP_ENHANCED_KDF_PASS2.len());
            pass2_info.extend_from_slice(info);
            pass2_info.extend_from_slice(GROUP_ENHANCED_KDF_PASS2);
            HkdfSha256::expand(&intermediate, &pass2_info, len)
        } else {
            HkdfSha256::expand(epoch_secret, info, len)
        }
    }

    pub fn derive_sub_keys_from_epoch_secret(
        epoch_secret: &[u8],
    ) -> Result<EpochKeys, ProtocolError> {
        Self::derive_sub_keys_from_epoch_secret_ex(epoch_secret, false)
    }

    pub fn derive_sub_keys_from_epoch_secret_ex(
        epoch_secret: &[u8],
        enhanced: bool,
    ) -> Result<EpochKeys, ProtocolError> {
        let mut metadata_key = Self::derive_sub_key(
            epoch_secret,
            GROUP_METADATA_KEY_INFO,
            METADATA_KEY_BYTES,
            enhanced,
        )?;
        let mut welcome_key = Self::derive_sub_key(
            epoch_secret,
            GROUP_WELCOME_KEY_INFO,
            WELCOME_KEY_BYTES,
            enhanced,
        )?;
        let mut confirmation_key = Self::derive_sub_key(
            epoch_secret,
            GROUP_CONFIRM_KEY_INFO,
            CONFIRMATION_KEY_BYTES,
            enhanced,
        )?;
        let mut init_secret = Self::derive_sub_key(
            epoch_secret,
            GROUP_INIT_SECRET_INFO,
            INIT_SECRET_BYTES,
            enhanced,
        )?;

        Ok(EpochKeys {
            epoch_secret: epoch_secret.to_vec(),
            metadata_key: std::mem::take(&mut *metadata_key),
            welcome_key: std::mem::take(&mut *welcome_key),
            confirmation_key: std::mem::take(&mut *confirmation_key),
            init_secret: std::mem::take(&mut *init_secret),
        })
    }

    pub fn derive_epoch_keys(
        prev_init_secret: &[u8],
        commit_secret: &[u8],
        group_context_hash: &[u8],
        enhanced: bool,
    ) -> Result<EpochKeys, ProtocolError> {
        let joiner_secret = HkdfSha256::extract(prev_init_secret, commit_secret);

        let mut epoch_info =
            Vec::with_capacity(GROUP_EPOCH_SECRET_INFO.len() + group_context_hash.len());
        epoch_info.extend_from_slice(GROUP_EPOCH_SECRET_INFO);
        epoch_info.extend_from_slice(group_context_hash);
        let epoch_secret = HkdfSha256::expand(&joiner_secret, &epoch_info, EPOCH_SECRET_BYTES)?;

        Self::derive_sub_keys_from_epoch_secret_ex(&epoch_secret, enhanced)
    }

    pub fn derive_joiner_secret(
        prev_init_secret: &[u8],
        commit_secret: &[u8],
    ) -> zeroize::Zeroizing<Vec<u8>> {
        HkdfSha256::extract(prev_init_secret, commit_secret)
    }

    pub fn derive_sender_key_base(
        epoch_secret: &[u8],
        leaf_index: u32,
        group_context_hash: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut info = Vec::with_capacity(
            GROUP_SENDER_KEY_INFO.len() + std::mem::size_of::<u32>() + group_context_hash.len(),
        );
        info.extend_from_slice(GROUP_SENDER_KEY_INFO);
        info.extend_from_slice(&leaf_index.to_le_bytes());
        info.extend_from_slice(group_context_hash);
        let mut z = HkdfSha256::expand(epoch_secret, &info, SENDER_KEY_BASE_BYTES)?;
        Ok(std::mem::take(&mut *z))
    }

    pub fn compute_group_context_hash(
        group_id: &[u8],
        epoch: u64,
        tree_hash: &[u8],
        policy_bytes: &[u8],
    ) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(
            group_id.len() + std::mem::size_of::<u64>() + tree_hash.len() + policy_bytes.len(),
        );
        ctx.extend_from_slice(group_id);
        ctx.extend_from_slice(&epoch.to_le_bytes());
        ctx.extend_from_slice(tree_hash);
        ctx.extend_from_slice(policy_bytes);

        sha2::Sha256::digest(&ctx).to_vec()
    }

    pub fn derive_external_keypairs(
        init_secret: &[u8],
    ) -> Result<(SecureMemoryHandle, Vec<u8>, SecureMemoryHandle, Vec<u8>), ProtocolError> {
        let mut x25519_seed = {
            let mut z = HkdfSha256::expand(
                init_secret,
                GROUP_EXTERNAL_PUB_X25519_INFO,
                X25519_PRIVATE_KEY_BYTES,
            )?;
            std::mem::take(&mut *z)
        };

        x25519_seed[0] &= X25519_CLAMP_BYTE0;
        x25519_seed[31] &= X25519_CLAMP_BYTE31_LOW;
        x25519_seed[31] |= X25519_CLAMP_BYTE31_HIGH;

        let seed_array: [u8; X25519_PRIVATE_KEY_BYTES] = x25519_seed
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::group_protocol("External X25519 seed has wrong length"))?;
        let x25519_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed_array))
                .as_bytes()
                .to_vec();
        let mut x25519_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)?;
        x25519_handle.write(&x25519_seed)?;
        CryptoInterop::secure_wipe(&mut x25519_seed);

        let mut kyber_seed = {
            let mut z = HkdfSha256::expand(
                init_secret,
                GROUP_EXTERNAL_PUB_KYBER_INFO,
                KYBER_SEED_KEY_BYTES,
            )?;
            std::mem::take(&mut *z)
        };
        let (kyber_secret, kyber_public) = KyberInterop::generate_keypair_from_seed(&kyber_seed)?;
        CryptoInterop::secure_wipe(&mut kyber_seed);

        Ok((x25519_handle, x25519_public, kyber_secret, kyber_public))
    }

    pub fn inject_psk(
        epoch_secret: &[u8],
        psk: &[u8],
        psk_nonce: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let psk_input = HkdfSha256::extract(psk_nonce, psk);

        let extracted = HkdfSha256::extract(epoch_secret, &psk_input);
        let mut intermediate =
            HkdfSha256::expand(&extracted, GROUP_PSK_EXTRACT_INFO, EPOCH_SECRET_BYTES)?;
        let mut z = HkdfSha256::expand(&intermediate, GROUP_PSK_SECRET_INFO, EPOCH_SECRET_BYTES)?;
        CryptoInterop::secure_wipe(&mut intermediate);
        Ok(std::mem::take(&mut z))
    }

    pub fn compute_confirmation_mac(
        confirmation_key: &[u8],
        group_context_hash: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(confirmation_key)
            .map_err(|e| ProtocolError::group_protocol(format!("HMAC init failed: {e}")))?;
        mac.update(group_context_hash);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}
