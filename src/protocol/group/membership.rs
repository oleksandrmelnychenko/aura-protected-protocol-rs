// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::collections::HashSet;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::proto::{GroupAddProposal, GroupProposal, GroupRemoveProposal};

use super::key_package::validate_key_package;
use super::tree::{LeafData, RatchetTree};

pub fn validate_proposals(
    tree: &RatchetTree,
    proposals: &[GroupProposal],
    committer_leaf_idx: u32,
) -> Result<(), ProtocolError> {
    if proposals.len() > MAX_PROPOSALS_PER_COMMIT {
        return Err(ProtocolError::group_membership(format!(
            "Too many proposals: {} (max {})",
            proposals.len(),
            MAX_PROPOSALS_PER_COMMIT
        )));
    }

    let mut removed_leaves = HashSet::new();
    let mut added_identity_keys: HashSet<Vec<u8>> = HashSet::new();

    for proposal in proposals {
        match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::Add(add)) => {
                let kp = add.key_package.as_ref().ok_or_else(|| {
                    ProtocolError::group_membership("Add proposal missing key package")
                })?;
                validate_key_package(kp)?;
                for existing_leaf_idx in tree.populated_leaf_indices() {
                    if let Some(ld) = tree.get_leaf_data(existing_leaf_idx) {
                        if ld.identity_ed25519_public == kp.identity_ed25519_public {
                            return Err(ProtocolError::group_membership(
                                "Add proposal: identity key already exists in group tree",
                            ));
                        }
                    }
                }
                if !added_identity_keys.insert(kp.identity_ed25519_public.clone()) {
                    return Err(ProtocolError::group_membership(
                        "Duplicate Add proposal: same identity key added twice",
                    ));
                }
            }
            Some(crate::proto::group_proposal::Proposal::Remove(remove)) => {
                let leaf_idx = remove.removed_leaf_index;
                if !removed_leaves.insert(leaf_idx) {
                    return Err(ProtocolError::group_membership(format!(
                        "Duplicate Remove proposal for leaf {leaf_idx}"
                    )));
                }
                if leaf_idx >= tree.leaf_count() {
                    return Err(ProtocolError::group_membership(format!(
                        "Remove: leaf index {leaf_idx} out of range"
                    )));
                }
                if tree.get_leaf_data(leaf_idx).is_none() {
                    return Err(ProtocolError::group_membership(format!(
                        "Remove: leaf {leaf_idx} is already blank"
                    )));
                }
                if leaf_idx == committer_leaf_idx {
                    return Err(ProtocolError::group_membership(
                        "Cannot remove the committer",
                    ));
                }
            }
            Some(crate::proto::group_proposal::Proposal::Update(_)) => {}
            Some(crate::proto::group_proposal::Proposal::ExternalInit(ext)) => {
                if ext.ephemeral_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
                    return Err(ProtocolError::group_membership(format!(
                        "ExternalInit: invalid ephemeral X25519 key length: {}",
                        ext.ephemeral_x25519_public.len()
                    )));
                }
                if ext.kyber_ciphertext.len() != KYBER_CIPHERTEXT_BYTES {
                    return Err(ProtocolError::group_membership(format!(
                        "ExternalInit: invalid Kyber ciphertext length: {}",
                        ext.kyber_ciphertext.len()
                    )));
                }
            }
            Some(crate::proto::group_proposal::Proposal::Psk(psk)) => {
                if psk.psk_id.is_empty() {
                    return Err(ProtocolError::group_membership(
                        "PSK proposal: empty psk_id",
                    ));
                }
                if psk.psk_nonce.len() != PSK_BYTES {
                    return Err(ProtocolError::group_membership(format!(
                        "PSK proposal: psk_nonce must be {} bytes, got {}",
                        PSK_BYTES,
                        psk.psk_nonce.len()
                    )));
                }
            }
            Some(crate::proto::group_proposal::Proposal::ReInit(reinit)) => {
                if reinit.new_group_id.len() != GROUP_ID_BYTES {
                    return Err(ProtocolError::group_membership(format!(
                        "ReInit: new_group_id must be {} bytes, got {}",
                        GROUP_ID_BYTES,
                        reinit.new_group_id.len()
                    )));
                }
            }
            None => {
                return Err(ProtocolError::group_membership("Empty proposal"));
            }
        }
    }

    Ok(())
}

pub fn apply_add(tree: &mut RatchetTree, add: &GroupAddProposal) -> Result<u32, ProtocolError> {
    let kp = add
        .key_package
        .as_ref()
        .ok_or_else(|| ProtocolError::group_membership("Add proposal missing key package"))?;

    let leaf_data = LeafData {
        credential: kp.credential.clone(),
        identity_ed25519_public: kp.identity_ed25519_public.clone(),
        identity_x25519_public: kp.identity_x25519_public.clone(),
        signature: kp.signature.clone(),
    };

    tree.add_leaf(
        kp.leaf_x25519_public.clone(),
        kp.leaf_kyber_public.clone(),
        leaf_data,
    )
}

pub fn apply_remove(
    tree: &mut RatchetTree,
    remove: &GroupRemoveProposal,
) -> Result<(), ProtocolError> {
    tree.blank_leaf(remove.removed_leaf_index)
}

pub fn apply_proposals(
    tree: &mut RatchetTree,
    proposals: &[GroupProposal],
) -> Result<Vec<u32>, ProtocolError> {
    let mut added = Vec::new();

    for proposal in proposals {
        if let Some(crate::proto::group_proposal::Proposal::Remove(remove)) = &proposal.proposal {
            apply_remove(tree, remove)?;
        }
    }

    for proposal in proposals {
        if let Some(crate::proto::group_proposal::Proposal::Update(_)) = &proposal.proposal {}
    }

    for proposal in proposals {
        if let Some(crate::proto::group_proposal::Proposal::Add(add)) = &proposal.proposal {
            let leaf_idx = apply_add(tree, add)?;
            added.push(leaf_idx);
        }
    }

    Ok(added)
}
