// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use prost::Message;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, KyberInterop};
use crate::proto::{GroupCommit, GroupExternalJoinAuthorization, GroupKeyPackage, GroupProposal};
use crate::security::DhValidator;

use super::key_package;
use super::key_schedule::{EpochKeys, GroupKeySchedule};
use super::membership;
use super::sender_key::SenderKeyStore;
use super::tree::RatchetTree;
use super::tree_kem::TreeKem;
use super::{GroupSecurityPolicy, PskResolver};

pub struct CommitOutput {
    pub commit: GroupCommit,
    pub epoch_keys: EpochKeys,
    pub new_sender_store: SenderKeyStore,
    pub added_leaf_indices: Vec<u32>,
    pub group_context_hash: Vec<u8>,
    pub joiner_secret: Vec<u8>,
}

pub struct ProcessedCommit {
    pub epoch_keys: EpochKeys,
    pub new_sender_store: SenderKeyStore,
    pub added_leaf_indices: Vec<u32>,
    pub group_context_hash: Vec<u8>,
}

#[inline]
fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

#[allow(clippy::too_many_arguments)]
pub fn create_commit(
    tree: &mut RatchetTree,
    proposals: Vec<GroupProposal>,
    my_leaf_idx: u32,
    prev_init_secret: &[u8],
    group_id: &[u8],
    epoch: u64,
    ed25519_secret: &[u8],
    psk_resolver: Option<&dyn PskResolver>,
    policy: &GroupSecurityPolicy,
) -> Result<CommitOutput, ProtocolError> {
    membership::validate_proposals(tree, &proposals, my_leaf_idx)?;

    let added_leaf_indices = membership::apply_proposals(tree, &proposals)?;

    let (mut update_path, mut commit_secret, new_private_keys) =
        TreeKem::create_update_path(tree, my_leaf_idx)?;

    let my_leaf = tree.get_leaf_data(my_leaf_idx).ok_or_else(|| {
        ProtocolError::group_protocol(format!(
            "Committer leaf {my_leaf_idx} is blank before update path signing",
        ))
    })?;
    update_path.leaf_signature = key_package::sign_existing_key_package(
        ed25519_secret,
        &my_leaf.identity_ed25519_public,
        &my_leaf.identity_x25519_public,
        &update_path.leaf_x25519_public,
        &update_path.leaf_kyber_public,
        &my_leaf.credential,
    )?;

    let leaf_node = super::tree::checked_leaf_to_node(my_leaf_idx)?;
    tree.set_node_public_keys(
        leaf_node,
        update_path.leaf_x25519_public.clone(),
        update_path.leaf_kyber_public.clone(),
    )?;
    tree.set_leaf_signature(my_leaf_idx, update_path.leaf_signature.clone())?;

    let direct_path = super::tree::direct_path(my_leaf_idx, tree.leaf_count())?;
    for (i, &node_idx) in direct_path.iter().enumerate() {
        if i < update_path.nodes.len() {
            tree.set_node_public_keys(
                node_idx,
                update_path.nodes[i].x25519_public.clone(),
                update_path.nodes[i].kyber_public.clone(),
            )?;
        }
    }

    for (i, &node_idx) in direct_path.iter().enumerate() {
        if i < update_path.nodes.len() && !update_path.nodes[i].parent_hash.is_empty() {
            tree.set_node_parent_hash(node_idx, update_path.nodes[i].parent_hash.clone())?;
        }
    }

    for (node_idx, x25519_priv, kyber_sec) in new_private_keys {
        tree.set_node_private_keys(node_idx, x25519_priv, kyber_sec)?;
    }

    let tree_hash = tree.tree_hash()?;
    let new_epoch = epoch
        .checked_add(1)
        .ok_or_else(|| ProtocolError::group_protocol("Epoch counter overflow"))?;
    let policy_bytes = policy.policy_bytes();
    let group_context_hash = GroupKeySchedule::compute_group_context_hash(
        group_id,
        new_epoch,
        &tree_hash,
        &policy_bytes,
    );

    let mut joiner_zeroizing =
        GroupKeySchedule::derive_joiner_secret(prev_init_secret, &commit_secret);
    let joiner_secret = std::mem::take(&mut *joiner_zeroizing);

    let mut epoch_keys = GroupKeySchedule::derive_epoch_keys(
        prev_init_secret,
        &commit_secret,
        &group_context_hash,
        policy.enhanced_key_schedule,
    )?;
    epoch_keys = apply_psk_proposals(epoch_keys, &proposals, psk_resolver)?;
    CryptoInterop::secure_wipe(&mut commit_secret);

    let confirmation_mac = GroupKeySchedule::compute_confirmation_mac(
        &epoch_keys.confirmation_key,
        &group_context_hash,
    )?;

    let leaf_indices = tree.populated_leaf_indices();
    let new_sender_store = SenderKeyStore::new_epoch_with_policy(
        &epoch_keys.epoch_secret,
        &leaf_indices,
        &group_context_hash,
        policy.enhanced_key_schedule,
        policy.effective_max_messages_per_epoch(),
        policy.effective_max_skipped_per_sender(),
    )?;

    let mut commit = GroupCommit {
        committer_leaf_index: my_leaf_idx,
        proposals,
        update_path: Some(update_path),
        confirmation_mac,
        epoch: new_epoch,
        group_id: group_id.to_vec(),
        committer_signature: vec![],
    };

    let mut commit_bytes_for_sig = Vec::new();
    commit
        .encode(&mut commit_bytes_for_sig)
        .map_err(|e| ProtocolError::encode(format!("Commit encode for signing: {e}")))?;
    commit.committer_signature = ed25519_sign_commit(ed25519_secret, &commit_bytes_for_sig)?;

    Ok(CommitOutput {
        commit,
        epoch_keys,
        new_sender_store,
        added_leaf_indices,
        group_context_hash,
        joiner_secret,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn process_commit(
    tree: &mut RatchetTree,
    commit: &GroupCommit,
    my_leaf_idx: u32,
    prev_init_secret: &[u8],
    group_id: &[u8],
    current_epoch: u64,
    psk_resolver: Option<&dyn PskResolver>,
    policy: &GroupSecurityPolicy,
) -> Result<ProcessedCommit, ProtocolError> {
    let expected_epoch = current_epoch
        .checked_add(1)
        .ok_or_else(|| ProtocolError::group_protocol("Epoch counter overflow"))?;
    if commit.epoch != expected_epoch {
        return Err(ProtocolError::group_protocol(format!(
            "Commit epoch mismatch: expected {}, got {}",
            expected_epoch, commit.epoch
        )));
    }

    let is_external_join = commit.proposals.iter().any(|p| {
        matches!(
            p.proposal,
            Some(crate::proto::group_proposal::Proposal::ExternalInit(_))
        )
    });

    if is_external_join {
        if policy.block_external_join {
            return Err(ProtocolError::group_protocol(
                "External join blocked by group security policy",
            ));
        }
        validate_external_join_structure(&commit.proposals)?;
        validate_external_join_authorization(tree, group_id, current_epoch, &commit.proposals)?;
    }

    if !is_external_join && commit.committer_leaf_index >= tree.leaf_count() {
        return Err(ProtocolError::group_protocol(format!(
            "Committer leaf index {} out of range (tree has {} leaves)",
            commit.committer_leaf_index,
            tree.leaf_count()
        )));
    }

    let committer_ed25519 = if is_external_join {
        commit
            .proposals
            .iter()
            .find_map(|p| {
                if let Some(crate::proto::group_proposal::Proposal::Add(ref add)) = p.proposal {
                    add.key_package
                        .as_ref()
                        .map(|kp| kp.identity_ed25519_public.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                ProtocolError::group_protocol(
                    "External join commit missing Add proposal with KeyPackage",
                )
            })?
    } else {
        let committer_leaf = tree
            .get_leaf_data(commit.committer_leaf_index)
            .ok_or_else(|| {
                ProtocolError::group_protocol(format!(
                    "Committer leaf {} is blank — cannot verify signature",
                    commit.committer_leaf_index
                ))
            })?;
        committer_leaf.identity_ed25519_public.clone()
    };

    let mut commit_for_verify = commit.clone();
    commit_for_verify.committer_signature = vec![];
    let mut commit_bytes_for_verify = Vec::new();
    commit_for_verify
        .encode(&mut commit_bytes_for_verify)
        .map_err(|e| ProtocolError::encode(format!("Commit encode for verify: {e}")))?;
    ed25519_verify_commit(
        &committer_ed25519,
        &commit.committer_signature,
        &commit_bytes_for_verify,
    )?;

    let effective_init_secret =
        find_and_process_external_init(&commit.proposals, prev_init_secret)?;
    let init_secret_for_epoch = effective_init_secret.as_deref().unwrap_or(prev_init_secret);

    membership::validate_proposals(tree, &commit.proposals, commit.committer_leaf_index)?;

    let added_leaf_indices = membership::apply_proposals(tree, &commit.proposals)?;

    if is_external_join && !added_leaf_indices.contains(&commit.committer_leaf_index) {
        return Err(ProtocolError::group_protocol(format!(
            "External join committer_leaf_index {} does not match the added leaf",
            commit.committer_leaf_index
        )));
    }

    if commit.committer_leaf_index >= tree.leaf_count() {
        return Err(ProtocolError::group_protocol(format!(
            "Committer leaf index {} out of range after proposal application (tree has {})",
            commit.committer_leaf_index,
            tree.leaf_count()
        )));
    }
    if tree.get_leaf_data(commit.committer_leaf_index).is_none() {
        return Err(ProtocolError::group_protocol(format!(
            "Committer leaf {} is blank after proposal application",
            commit.committer_leaf_index
        )));
    }

    let update_path = commit
        .update_path
        .as_ref()
        .ok_or_else(|| ProtocolError::group_protocol("Commit missing update_path"))?;

    let committer_leaf_data = tree
        .get_leaf_data(commit.committer_leaf_index)
        .ok_or_else(|| ProtocolError::group_protocol("Committer leaf metadata missing"))?;
    validate_leaf_update_signature(committer_leaf_data, update_path)?;

    let mut commit_secret =
        TreeKem::process_update_path(tree, update_path, commit.committer_leaf_index, my_leaf_idx)?;
    tree.set_leaf_signature(
        commit.committer_leaf_index,
        update_path.leaf_signature.clone(),
    )?;

    let tree_hash = tree.tree_hash()?;
    let policy_bytes = policy.policy_bytes();
    let group_context_hash = GroupKeySchedule::compute_group_context_hash(
        group_id,
        commit.epoch,
        &tree_hash,
        &policy_bytes,
    );

    let mut epoch_keys = GroupKeySchedule::derive_epoch_keys(
        init_secret_for_epoch,
        &commit_secret,
        &group_context_hash,
        policy.enhanced_key_schedule,
    )?;
    epoch_keys = apply_psk_proposals(epoch_keys, &commit.proposals, psk_resolver)?;
    CryptoInterop::secure_wipe(&mut commit_secret);

    let expected_mac = GroupKeySchedule::compute_confirmation_mac(
        &epoch_keys.confirmation_key,
        &group_context_hash,
    )?;
    let mac_ok = CryptoInterop::constant_time_equals(&expected_mac, &commit.confirmation_mac)?;
    if !mac_ok {
        return Err(ProtocolError::group_protocol(
            "Confirmation MAC verification failed",
        ));
    }

    let leaf_indices = tree.populated_leaf_indices();
    let new_sender_store = SenderKeyStore::new_epoch_with_policy(
        &epoch_keys.epoch_secret,
        &leaf_indices,
        &group_context_hash,
        policy.enhanced_key_schedule,
        policy.effective_max_messages_per_epoch(),
        policy.effective_max_skipped_per_sender(),
    )?;

    Ok(ProcessedCommit {
        epoch_keys,
        new_sender_store,
        added_leaf_indices,
        group_context_hash,
    })
}

fn apply_psk_proposals(
    mut epoch_keys: EpochKeys,
    proposals: &[GroupProposal],
    psk_resolver: Option<&dyn PskResolver>,
) -> Result<EpochKeys, ProtocolError> {
    let mut has_psk = false;
    for proposal in proposals {
        if let Some(crate::proto::group_proposal::Proposal::Psk(ref psk)) = proposal.proposal {
            let resolver = psk_resolver.ok_or_else(|| {
                ProtocolError::group_protocol("PSK proposal present but no PSK resolver configured")
            })?;
            let psk_value = resolver.resolve(&psk.psk_id).ok_or_else(|| {
                ProtocolError::group_protocol(format!("No PSK found for id {:?}", psk.psk_id))
            })?;
            epoch_keys.epoch_secret =
                GroupKeySchedule::inject_psk(&epoch_keys.epoch_secret, &psk_value, &psk.psk_nonce)?;
            has_psk = true;
        }
    }

    if has_psk {
        epoch_keys = GroupKeySchedule::derive_sub_keys_from_epoch_secret(&epoch_keys.epoch_secret)?;
    }

    Ok(epoch_keys)
}

fn find_and_process_external_init(
    proposals: &[GroupProposal],
    prev_init_secret: &[u8],
) -> Result<Option<Vec<u8>>, ProtocolError> {
    CryptoInterop::ensure_initialized();
    let ext_init = proposals.iter().find_map(|p| {
        if let Some(crate::proto::group_proposal::Proposal::ExternalInit(ref ei)) = p.proposal {
            Some(ei)
        } else {
            None
        }
    });

    let Some(ext) = ext_init else {
        return Ok(None);
    };

    if ext.ephemeral_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::group_protocol(format!(
            "ExternalInit ephemeral_x25519_public must be {} bytes, got {}",
            X25519_PUBLIC_KEY_BYTES,
            ext.ephemeral_x25519_public.len()
        )));
    }
    DhValidator::validate_x25519_public_key(&ext.ephemeral_x25519_public).map_err(|e| {
        ProtocolError::group_protocol(format!("ExternalInit ephemeral X25519 key rejected: {e}"))
    })?;
    if ext.kyber_ciphertext.len() != KYBER_CIPHERTEXT_BYTES {
        return Err(ProtocolError::group_protocol(format!(
            "ExternalInit kyber_ciphertext must be {} bytes, got {}",
            KYBER_CIPHERTEXT_BYTES,
            ext.kyber_ciphertext.len()
        )));
    }

    let (ext_x25519_priv, _ext_x25519_pub, ext_kyber_sec, _ext_kyber_pub) =
        GroupKeySchedule::derive_external_keypairs(prev_init_secret)?;

    let mut priv_bytes = ext_x25519_priv.read_bytes(X25519_PRIVATE_KEY_BYTES)?;
    let mut sk: [u8; X25519_PRIVATE_KEY_BYTES] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::group_protocol("Invalid X25519 private key size"))?;
    let pk: [u8; X25519_PUBLIC_KEY_BYTES] = ext
        .ephemeral_x25519_public
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolError::group_protocol("Invalid X25519 public key size"))?;
    let mut dh_shared = x25519_dalek::StaticSecret::from(sk)
        .diffie_hellman(&x25519_dalek::PublicKey::from(pk))
        .to_bytes()
        .to_vec();
    CryptoInterop::secure_wipe(&mut priv_bytes);
    CryptoInterop::secure_wipe(&mut sk);
    if is_all_zero(&dh_shared) {
        CryptoInterop::secure_wipe(&mut dh_shared);
        return Err(ProtocolError::group_protocol(
            "ExternalInit X25519 DH produced all-zero output (RFC 7748 section 6.1)",
        ));
    }

    let kyber_ss_handle = KyberInterop::decapsulate(&ext.kyber_ciphertext, &ext_kyber_sec)?;
    let mut kyber_ss = kyber_ss_handle.read_bytes(KYBER_SHARED_SECRET_BYTES)?;

    let kem_output = HkdfSha256::extract(&dh_shared, &kyber_ss);
    CryptoInterop::secure_wipe(&mut dh_shared);
    CryptoInterop::secure_wipe(&mut kyber_ss);

    let mut init_secret_proxy = HkdfSha256::expand(
        &kem_output,
        GROUP_EXTERNAL_INIT_SECRET_INFO,
        INIT_SECRET_BYTES,
    )?;

    Ok(Some(std::mem::take(&mut *init_secret_proxy)))
}

fn ed25519_sign_commit(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if secret_key.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 secret key size for commit signing",
        ));
    }
    let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = secret_key
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 secret key size"))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_array)
        .map_err(|_| ProtocolError::key_generation("Invalid Ed25519 keypair bytes"))?;
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}

fn validate_external_join_structure(proposals: &[GroupProposal]) -> Result<(), ProtocolError> {
    let mut ext_init_count = 0u32;
    let mut add_count = 0u32;

    for p in proposals {
        match &p.proposal {
            Some(crate::proto::group_proposal::Proposal::ExternalInit(_)) => {
                ext_init_count += 1;
            }
            Some(crate::proto::group_proposal::Proposal::Add(_)) => {
                add_count += 1;
            }
            Some(crate::proto::group_proposal::Proposal::Remove(_)) => {
                return Err(ProtocolError::group_protocol(
                    "External join commit must not contain Remove proposals",
                ));
            }
            Some(crate::proto::group_proposal::Proposal::Update(_)) => {
                return Err(ProtocolError::group_protocol(
                    "External join commit must not contain Update proposals",
                ));
            }
            _ => {}
        }
    }

    if ext_init_count != 1 {
        return Err(ProtocolError::group_protocol(format!(
            "External join commit must contain exactly 1 ExternalInit, got {ext_init_count}"
        )));
    }
    if add_count != 1 {
        return Err(ProtocolError::group_protocol(format!(
            "External join commit must contain exactly 1 Add proposal, got {add_count}"
        )));
    }

    Ok(())
}

fn validate_external_join_authorization(
    tree: &RatchetTree,
    group_id: &[u8],
    current_epoch: u64,
    proposals: &[GroupProposal],
) -> Result<(), ProtocolError> {
    let external_init = proposals
        .iter()
        .find_map(|proposal| match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::ExternalInit(ext)) => Some(ext),
            _ => None,
        });
    let add_key_package = proposals
        .iter()
        .find_map(|proposal| match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::Add(add)) => add.key_package.as_ref(),
            _ => None,
        });
    let external_init = external_init.ok_or_else(|| {
        ProtocolError::group_protocol("External join commit missing ExternalInit proposal")
    })?;
    let add_key_package = add_key_package.ok_or_else(|| {
        ProtocolError::group_protocol("External join commit missing Add proposal with KeyPackage")
    })?;
    if external_init.authorization.is_empty() {
        return Err(ProtocolError::group_protocol(
            "External join authorization is required",
        ));
    }

    let auth = GroupExternalJoinAuthorization::decode(external_init.authorization.as_slice())
        .map_err(|e| ProtocolError::decode(format!("External join auth decode: {e}")))?;
    if auth.group_id != group_id {
        return Err(ProtocolError::group_protocol(
            "External join authorization group_id mismatch",
        ));
    }
    if auth.epoch != current_epoch {
        return Err(ProtocolError::group_protocol(format!(
            "External join authorization epoch mismatch: expected {current_epoch}, got {}",
            auth.epoch
        )));
    }
    if auth.joiner_identity_ed25519_public != add_key_package.identity_ed25519_public
        || auth.joiner_identity_x25519_public != add_key_package.identity_x25519_public
        || auth.joiner_credential != add_key_package.credential
    {
        return Err(ProtocolError::group_protocol(
            "External join authorization does not match Add proposal identity",
        ));
    }
    let authorizer_leaf = tree
        .get_leaf_data(auth.authorizer_leaf_index)
        .ok_or_else(|| ProtocolError::group_protocol("External join authorizer leaf is blank"))?;
    let mut auth_for_verify = auth.clone();
    auth_for_verify.authorizer_signature.clear();
    let mut auth_bytes = Vec::new();
    auth_for_verify
        .encode(&mut auth_bytes)
        .map_err(|e| ProtocolError::encode(format!("External join auth encode: {e}")))?;
    ed25519_verify_message(
        &authorizer_leaf.identity_ed25519_public,
        &auth.authorizer_signature,
        &auth_bytes,
        "External join authorization signature verification failed",
    )
}

fn validate_leaf_update_signature(
    committer_leaf: &super::tree::LeafData,
    update_path: &crate::proto::GroupUpdatePath,
) -> Result<(), ProtocolError> {
    let key_package = GroupKeyPackage {
        version: GROUP_PROTOCOL_VERSION,
        identity_ed25519_public: committer_leaf.identity_ed25519_public.clone(),
        identity_x25519_public: committer_leaf.identity_x25519_public.clone(),
        leaf_x25519_public: update_path.leaf_x25519_public.clone(),
        leaf_kyber_public: update_path.leaf_kyber_public.clone(),
        signature: update_path.leaf_signature.clone(),
        credential: committer_leaf.credential.clone(),
        created_at: None,
    };
    key_package::validate_key_package(&key_package)
}

fn ed25519_verify_commit(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), ProtocolError> {
    ed25519_verify_message(
        public_key,
        signature,
        message,
        "Committer Ed25519 signature verification failed",
    )
}

fn ed25519_verify_message(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &str,
) -> Result<(), ProtocolError> {
    if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid committer Ed25519 public key size",
        ));
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid committer signature size",
        ));
    }
    let pk_array: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 public key size"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| ProtocolError::group_protocol("Invalid committer Ed25519 public key"))?;
    let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 signature size"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    use ed25519_dalek::Verifier;
    vk.verify(message, &sig)
        .map_err(|_| ProtocolError::group_protocol(context))
}
