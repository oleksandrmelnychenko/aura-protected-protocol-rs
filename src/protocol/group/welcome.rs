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

const WELCOME_PROVENANCE_SIGNATURE_INFO: &[u8] = b"Aura-Group-WelcomeProvenance-v1";

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

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn welcome_signature_input(welcome: &GroupWelcome) -> Result<Vec<u8>, ProtocolError> {
    let mut encrypted_joiner_bytes = Vec::new();
    if let Some(encrypted_joiner) = &welcome.encrypted_joiner_secret {
        encrypted_joiner
            .encode(&mut encrypted_joiner_bytes)
            .map_err(|e| ProtocolError::encode(format!("Welcome joiner secret encode: {e}")))?;
    }

    let mut input = Vec::new();
    input.extend_from_slice(WELCOME_PROVENANCE_SIGNATURE_INFO);
    input.extend_from_slice(&welcome.version.to_le_bytes());
    input.extend_from_slice(&welcome.epoch.to_le_bytes());
    input.extend_from_slice(&welcome.target_leaf_index.to_le_bytes());
    input.extend_from_slice(&welcome.committer_leaf_index.to_le_bytes());
    append_len_prefixed(&mut input, &welcome.group_id);
    append_len_prefixed(&mut input, &welcome.encrypted_group_info);
    append_len_prefixed(&mut input, &welcome.welcome_nonce);
    append_len_prefixed(&mut input, &encrypted_joiner_bytes);
    append_len_prefixed(&mut input, &welcome.tree_hash);
    Ok(input)
}

fn ed25519_sign_welcome(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if secret_key.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 secret key size",
        ));
    }
    let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = secret_key
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 secret key size"))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_array)
        .map_err(|_| ProtocolError::key_generation("Invalid Ed25519 keypair bytes"))?;
    use ed25519_dalek::Signer;
    Ok(signing_key.sign(message).to_bytes().to_vec())
}

fn ed25519_verify_welcome(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), ProtocolError> {
    if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::welcome_error(
            "Welcome committer Ed25519 public key has invalid size",
        ));
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::welcome_error(
            "Welcome committer signature has invalid size",
        ));
    }
    let pk_array: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key.try_into().map_err(|_| {
        ProtocolError::welcome_error("Welcome committer Ed25519 public key has invalid size")
    })?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| ProtocolError::welcome_error("Invalid Welcome committer Ed25519 key"))?;
    let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature.try_into().map_err(|_| {
        ProtocolError::welcome_error("Welcome committer signature has invalid size")
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    vk.verify_strict(message, &sig).map_err(|_| {
        ProtocolError::welcome_error("Welcome committer signature verification failed")
    })
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
    committer_leaf_index: u32,
    committer_ed25519_secret: &[u8],
) -> Result<GroupWelcome, ProtocolError> {
    if committer_leaf_index == new_member_leaf_idx {
        return Err(ProtocolError::welcome_error(
            "Welcome committer cannot be the new member",
        ));
    }
    if tree.get_leaf_data(committer_leaf_index).is_none() {
        return Err(ProtocolError::welcome_error(
            "Welcome committer leaf is not present in tree",
        ));
    }

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

    let mut welcome = GroupWelcome {
        version: GROUP_PROTOCOL_VERSION,
        group_id: group_id.to_vec(),
        epoch,
        encrypted_group_info,
        welcome_nonce,
        encrypted_joiner_secret: Some(encrypted_joiner),
        tree_hash,
        target_leaf_index: new_member_leaf_idx,
        committer_leaf_index,
        committer_signature: Vec::new(),
    };
    let signature_input = welcome_signature_input(&welcome)?;
    welcome.committer_signature = ed25519_sign_welcome(committer_ed25519_secret, &signature_input)?;

    Ok(welcome)
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

    if welcome.committer_leaf_index == my_leaf_idx {
        return Err(ProtocolError::welcome_error(
            "Welcome committer cannot be the target member",
        ));
    }
    let committer = tree
        .get_leaf_data(welcome.committer_leaf_index)
        .ok_or_else(|| ProtocolError::welcome_error("Welcome committer leaf is not present"))?;
    let signature_input = welcome_signature_input(welcome)?;
    ed25519_verify_welcome(
        &committer.identity_ed25519_public,
        &welcome.committer_signature,
        &signature_input,
    )?;

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
