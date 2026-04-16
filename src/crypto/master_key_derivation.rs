// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use zeroize::Zeroizing;

use crate::core::constants::{
    KYBER_SEED_KEY_BYTES, MIN_MASTER_KEY_BYTES, MKD_ED25519_INFO, MKD_KYBER_SEED_1_INFO,
    MKD_KYBER_SEED_2_INFO, MKD_OPK_PREFIX, MKD_SIGNED_PRE_KEY_INFO, MKD_X25519_INFO,
    X25519_PRIVATE_KEY_BYTES,
};
use crate::core::errors::ProtocolError;
use crate::crypto::HkdfSha256;

const MKD_LABEL: &[u8] = b"aura-mkd";
const MAX_OUTPUT_BYTES: usize = 64;

pub struct MasterKeyDerivation;

impl MasterKeyDerivation {
    pub fn derive(
        master_key: &[u8],
        context_string: &[u8],
        membership_id: &[u8],
        out_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if master_key.len() < MIN_MASTER_KEY_BYTES {
            return Err(ProtocolError::derive_key(
                "Master key must be at least 32 bytes",
            ));
        }
        if out_len == 0 || out_len > MAX_OUTPUT_BYTES {
            return Err(ProtocolError::derive_key(format!(
                "Invalid output length: {out_len}"
            )));
        }
        if context_string.len() > u16::MAX as usize {
            return Err(ProtocolError::invalid_input(
                "Context string too long (max 65535 bytes)",
            ));
        }
        if membership_id.len() > u16::MAX as usize {
            return Err(ProtocolError::invalid_input(
                "Membership ID too long (max 65535 bytes)",
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        let ctx_len = context_string.len() as u16;
        #[allow(clippy::cast_possible_truncation)]
        let mid_len = membership_id.len() as u16;
        let mut info = Vec::with_capacity(4 + context_string.len() + membership_id.len());
        info.extend_from_slice(&ctx_len.to_le_bytes());
        info.extend_from_slice(context_string);
        info.extend_from_slice(&mid_len.to_le_bytes());
        info.extend_from_slice(membership_id);

        let extracted = HkdfSha256::extract(MKD_LABEL, master_key);
        HkdfSha256::expand(&extracted, &info, out_len)
    }

    pub fn derive_ed25519_seed(
        master_key: &[u8],
        membership_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        Self::derive(
            master_key,
            MKD_ED25519_INFO,
            membership_id.as_bytes(),
            X25519_PRIVATE_KEY_BYTES,
        )
    }

    pub fn derive_x25519_seed(
        master_key: &[u8],
        membership_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        Self::derive(
            master_key,
            MKD_X25519_INFO,
            membership_id.as_bytes(),
            X25519_PRIVATE_KEY_BYTES,
        )
    }

    pub fn derive_signed_pre_key_seed(
        master_key: &[u8],
        membership_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        Self::derive(
            master_key,
            MKD_SIGNED_PRE_KEY_INFO,
            membership_id.as_bytes(),
            X25519_PRIVATE_KEY_BYTES,
        )
    }

    pub fn derive_one_time_pre_key_seed(
        master_key: &[u8],
        membership_id: &str,
        index: u32,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let label = format!("{MKD_OPK_PREFIX}{index}");
        Self::derive(
            master_key,
            label.as_bytes(),
            membership_id.as_bytes(),
            X25519_PRIVATE_KEY_BYTES,
        )
    }

    pub fn derive_kyber_seed(
        master_key: &[u8],
        membership_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        if master_key.len() < MIN_MASTER_KEY_BYTES {
            return Err(ProtocolError::derive_key(
                "Master key must be at least 32 bytes for Kyber seed derivation",
            ));
        }
        let membership = membership_id.as_bytes();
        let mut seed = Self::derive(
            master_key,
            MKD_KYBER_SEED_1_INFO,
            membership,
            KYBER_SEED_KEY_BYTES,
        )?;
        let seed2 = Self::derive(
            master_key,
            MKD_KYBER_SEED_2_INFO,
            membership,
            KYBER_SEED_KEY_BYTES,
        )?;
        seed.extend_from_slice(&seed2);
        Ok(seed)
    }
}
