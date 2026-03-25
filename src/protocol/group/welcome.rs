// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use prost::Message;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{AesGcm, CryptoInterop, HkdfSha256, SecureMemoryHandle};
use crate::proto::{GroupInfo, GroupWelcome};

use super::key_schedule::{EpochKeys, GroupKeySchedule};
use super::sender_key::SenderKeyStore;
use super::tree::RatchetTree;
use super::tree_kem::TreeKem;
use super::GroupSecurityPolicy;

pub struct WelcomeResult {
    pub tree: RatchetTree,
    pub my_leaf_idx: u32,
    pub epoch: u64,
    pub group_id: Vec<u8>,
    pub epoch_keys: EpochKeys,
    pub group_context_hash: Vec<u8>,
    pub sender_store: SenderKeyStore,
    pub security_policy_bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn create_welcome(
    tree: &RatchetTree,
    new_member_leaf_idx: u32,
    _epoch_keys: &EpochKeys,
    joiner_secret: &[u8],
    group_id: &[u8],
    epoch: u64,
    confirmation_mac: &[u8],
    group_context_hash: &[u8],
    security_policy_bytes: &[u8],
) -> Result<GroupWelcome, ProtocolError> {
    let tree_hash = tree.tree_hash()?;

    let mut welcome_epoch_info =
        Vec::with_capacity(GROUP_EPOCH_SECRET_INFO.len() + tree_hash.len());
    welcome_epoch_info.extend_from_slice(GROUP_EPOCH_SECRET_INFO);
    welcome_epoch_info.extend_from_slice(&tree_hash);
    let temp_epoch_secret =
        HkdfSha256::expand(joiner_secret, &welcome_epoch_info, EPOCH_SECRET_BYTES)?;
    let welcome_key = HkdfSha256::expand(
        &temp_epoch_secret,
        GROUP_WELCOME_KEY_INFO,
        WELCOME_KEY_BYTES,
    )?;

    let mut group_info = GroupInfo {
        group_id: group_id.to_vec(),
        epoch,
        tree_nodes: tree.export_for_welcome(new_member_leaf_idx)?,
        group_context_hash: group_context_hash.to_vec(),
        confirmation_mac: confirmation_mac.to_vec(),
        security_policy: security_policy_bytes.to_vec(),
    };

    let mut group_info_bytes = Vec::new();
    let encode_result = group_info
        .encode(&mut group_info_bytes)
        .map_err(|e| ProtocolError::encode(format!("GroupInfo encode: {e}")));
    for tn in &mut group_info.tree_nodes {
        CryptoInterop::secure_wipe(&mut tn.x25519_private);
        CryptoInterop::secure_wipe(&mut tn.kyber_secret);
    }
    encode_result?;

    let welcome_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
    let mut welcome_aad = Vec::with_capacity(group_id.len() + 8);
    welcome_aad.extend_from_slice(group_id);
    welcome_aad.extend_from_slice(&epoch.to_le_bytes());

    let encrypted_group_info = AesGcm::encrypt(
        &welcome_key,
        &welcome_nonce,
        &group_info_bytes,
        &welcome_aad,
    );
    CryptoInterop::secure_wipe(&mut group_info_bytes);
    let encrypted_group_info = encrypted_group_info?;

    let (target_x25519, target_kyber) = tree
        .get_node_public_keys(super::tree::checked_leaf_to_node(new_member_leaf_idx)?)
        .ok_or_else(|| ProtocolError::welcome_error("New member leaf is blank"))?;

    let encrypted_joiner = TreeKem::encrypt_path_secret(
        joiner_secret,
        target_x25519,
        target_kyber,
        new_member_leaf_idx,
    )?;

    Ok(GroupWelcome {
        version: GROUP_PROTOCOL_VERSION,
        group_id: group_id.to_vec(),
        epoch,
        encrypted_group_info,
        welcome_nonce,
        encrypted_joiner_secret: Some(encrypted_joiner),
        tree_hash,
        target_leaf_index: new_member_leaf_idx,
    })
}

pub fn process_welcome(
    welcome: &GroupWelcome,
    my_x25519_private: SecureMemoryHandle,
    my_kyber_secret: SecureMemoryHandle,
    my_identity_ed25519: &[u8],
    my_identity_x25519: &[u8],
) -> Result<WelcomeResult, ProtocolError> {
    if welcome.version != GROUP_PROTOCOL_VERSION {
        return Err(ProtocolError::welcome_error(format!(
            "Unsupported Welcome version: {}",
            welcome.version
        )));
    }

    let encrypted_joiner = welcome
        .encrypted_joiner_secret
        .as_ref()
        .ok_or_else(|| ProtocolError::welcome_error("Missing encrypted joiner secret"))?;

    let my_leaf_idx = welcome.target_leaf_index;

    let mut joiner_secret = TreeKem::decrypt_path_secret(
        encrypted_joiner,
        &my_x25519_private,
        &my_kyber_secret,
        my_leaf_idx,
    )
    .map_err(|e| {
        ProtocolError::welcome_error(format!(
            "Failed to decrypt joiner secret at target leaf {my_leaf_idx}: {e}"
        ))
    })?;

    let mut welcome_epoch_info =
        Vec::with_capacity(GROUP_EPOCH_SECRET_INFO.len() + welcome.tree_hash.len());
    welcome_epoch_info.extend_from_slice(GROUP_EPOCH_SECRET_INFO);
    welcome_epoch_info.extend_from_slice(&welcome.tree_hash);
    let temp_epoch_secret =
        HkdfSha256::expand(&joiner_secret, &welcome_epoch_info, EPOCH_SECRET_BYTES)?;
    let welcome_key = HkdfSha256::expand(
        &temp_epoch_secret,
        GROUP_WELCOME_KEY_INFO,
        WELCOME_KEY_BYTES,
    )?;

    let mut welcome_aad = Vec::with_capacity(welcome.group_id.len() + 8);
    welcome_aad.extend_from_slice(&welcome.group_id);
    welcome_aad.extend_from_slice(&welcome.epoch.to_le_bytes());

    let mut group_info_bytes = AesGcm::decrypt(
        &welcome_key,
        &welcome.welcome_nonce,
        &welcome.encrypted_group_info,
        &welcome_aad,
    )?;

    if group_info_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::welcome_error(
            "Decrypted GroupInfo too large",
        ));
    }
    let mut group_info = GroupInfo::decode(group_info_bytes.as_slice())
        .map_err(|e| ProtocolError::decode(format!("GroupInfo decode: {e}")))?;
    CryptoInterop::secure_wipe(&mut group_info_bytes);
    if group_info.group_id != welcome.group_id {
        return Err(ProtocolError::welcome_error(
            "Welcome group_id mismatch between envelope and group_info",
        ));
    }

    let mut tree = RatchetTree::from_proto(&group_info.tree_nodes, my_leaf_idx)?;
    for tn in &mut group_info.tree_nodes {
        CryptoInterop::secure_wipe(&mut tn.x25519_private);
        CryptoInterop::secure_wipe(&mut tn.kyber_secret);
    }

    if let Some(leaf_data) = tree.get_leaf_data(my_leaf_idx) {
        if leaf_data.identity_ed25519_public != my_identity_ed25519
            || leaf_data.identity_x25519_public != my_identity_x25519
        {
            return Err(ProtocolError::welcome_error(
                "Identity mismatch: Welcome leaf does not match joiner identity keys",
            ));
        }
    } else {
        return Err(ProtocolError::welcome_error(
            "My leaf is blank after Welcome reconstruction",
        ));
    }

    let my_node = super::tree::checked_leaf_to_node(my_leaf_idx)?;
    tree.set_node_private_keys(my_node, my_x25519_private, my_kyber_secret)?;

    let computed_tree_hash = tree.tree_hash()?;
    let hash_ok = CryptoInterop::constant_time_equals(&computed_tree_hash, &welcome.tree_hash)?;
    if !hash_ok {
        return Err(ProtocolError::welcome_error("Tree hash mismatch"));
    }

    let group_context_hash = GroupKeySchedule::compute_group_context_hash(
        &welcome.group_id,
        welcome.epoch,
        &computed_tree_hash,
        &group_info.security_policy,
    );

    let policy = GroupSecurityPolicy::from_proto_bytes(&group_info.security_policy)?;
    policy.validate()?;

    let mut epoch_info_full =
        Vec::with_capacity(GROUP_EPOCH_SECRET_INFO.len() + group_context_hash.len());
    epoch_info_full.extend_from_slice(GROUP_EPOCH_SECRET_INFO);
    epoch_info_full.extend_from_slice(&group_context_hash);
    let mut epoch_secret =
        HkdfSha256::expand(&joiner_secret, &epoch_info_full, EPOCH_SECRET_BYTES)?;

    let epoch_keys = GroupKeySchedule::derive_sub_keys_from_epoch_secret_ex(
        &epoch_secret,
        policy.enhanced_key_schedule,
    )?;
    CryptoInterop::secure_wipe(&mut epoch_secret);

    let expected_mac = GroupKeySchedule::compute_confirmation_mac(
        &epoch_keys.confirmation_key,
        &group_context_hash,
    )?;
    let mac_ok = CryptoInterop::constant_time_equals(&expected_mac, &group_info.confirmation_mac)?;
    if !mac_ok {
        return Err(ProtocolError::welcome_error(
            "Confirmation MAC verification failed",
        ));
    }

    let leaf_indices = tree.populated_leaf_indices();
    let sender_store = SenderKeyStore::new_epoch_with_policy(
        &epoch_keys.epoch_secret,
        &leaf_indices,
        &group_context_hash,
        policy.enhanced_key_schedule,
        policy.effective_max_messages_per_epoch(),
        policy.effective_max_skipped_per_sender(),
    )?;

    CryptoInterop::secure_wipe(&mut joiner_secret);

    Ok(WelcomeResult {
        tree,
        my_leaf_idx,
        epoch: welcome.epoch,
        group_id: welcome.group_id.clone(),
        epoch_keys,
        group_context_hash,
        sender_store,
        security_policy_bytes: group_info.security_policy,
    })
}
