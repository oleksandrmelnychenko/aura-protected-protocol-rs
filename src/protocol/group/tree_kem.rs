// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{AesGcm, CryptoInterop, HkdfSha256, KyberInterop, SecureMemoryHandle};
use crate::proto::{GroupHybridCiphertext, GroupUpdatePath, GroupUpdatePathNode};
use crate::security::DhValidator;

use super::tree::{self, RatchetTree};

pub struct TreeKem;

#[inline]
fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

impl TreeKem {
    #[allow(clippy::type_complexity, clippy::cast_possible_truncation)]
    pub fn create_update_path(
        tree_ref: &RatchetTree,
        my_leaf_idx: u32,
    ) -> Result<
        (
            GroupUpdatePath,
            Vec<u8>,
            Vec<(u32, SecureMemoryHandle, SecureMemoryHandle)>,
        ),
        ProtocolError,
    > {
        let n = tree_ref.leaf_count();
        if n <= 1 {
            let commit_secret = CryptoInterop::get_random_bytes(COMMIT_SECRET_BYTES);
            let (x25519_priv, x25519_pub) =
                CryptoInterop::generate_x25519_keypair("group-leaf-update")?;
            let (kyber_sec, kyber_pub) = KyberInterop::generate_keypair()?;

            let update_path = GroupUpdatePath {
                leaf_x25519_public: x25519_pub,
                leaf_kyber_public: kyber_pub,
                nodes: vec![],
                leaf_signature: vec![],
            };
            return Ok((
                update_path,
                commit_secret,
                vec![(
                    tree::checked_leaf_to_node(my_leaf_idx)?,
                    x25519_priv,
                    kyber_sec,
                )],
            ));
        }

        let (leaf_x25519_priv, leaf_x25519_pub) =
            CryptoInterop::generate_x25519_keypair("group-leaf-update")?;
        let (leaf_kyber_sec, leaf_kyber_pub) = KyberInterop::generate_keypair()?;

        let direct_path = tree::direct_path(my_leaf_idx, n)?;
        let co_path = tree::copath(my_leaf_idx, n)?;

        let mut path_secrets: Vec<Vec<u8>> = Vec::with_capacity(direct_path.len());
        path_secrets.push(CryptoInterop::get_random_bytes(PATH_SECRET_BYTES));

        for i in 1..direct_path.len() {
            let next = Self::derive_next_path_secret(&path_secrets[i - 1], i as u32)?;
            path_secrets.push(next);
        }

        let mut update_nodes = Vec::with_capacity(direct_path.len());
        let mut new_private_keys = Vec::with_capacity(direct_path.len() + 1);
        new_private_keys.push((
            tree::checked_leaf_to_node(my_leaf_idx)?,
            leaf_x25519_priv,
            leaf_kyber_sec,
        ));

        let mut path_pub_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(direct_path.len());

        for (i, &node_idx) in direct_path.iter().enumerate() {
            let (x25519_priv, x25519_pub, kyber_sec, kyber_pub) =
                Self::derive_node_keypairs(&path_secrets[i])?;

            let copath_node = co_path[i];
            let resolution = tree_ref.resolution(copath_node)?;
            let mut encrypted_secrets = Vec::with_capacity(resolution.len());

            for &res_node in &resolution {
                let (target_x25519, target_kyber) =
                    tree_ref.get_node_public_keys(res_node).ok_or_else(|| {
                        ProtocolError::tree_integrity(format!(
                            "Resolution node {res_node} is blank"
                        ))
                    })?;

                let ct = Self::encrypt_path_secret(
                    &path_secrets[i],
                    target_x25519,
                    target_kyber,
                    node_idx,
                )?;
                encrypted_secrets.push(ct);
            }

            path_pub_keys.push((x25519_pub.clone(), kyber_pub.clone()));
            update_nodes.push(GroupUpdatePathNode {
                x25519_public: x25519_pub,
                kyber_public: kyber_pub,
                encrypted_path_secrets: encrypted_secrets,
                parent_hash: vec![0u8; SHA256_HASH_BYTES],
            });

            new_private_keys.push((node_idx, x25519_priv, kyber_sec));
        }

        if !direct_path.is_empty() {
            let last = direct_path.len() - 1;
            update_nodes[last].parent_hash = vec![0u8; SHA256_HASH_BYTES];

            for i in (0..last).rev() {
                let child_node_idx = direct_path[i];
                let parent_idx = i + 1;
                let sib_idx = tree::sibling(child_node_idx, n)?;

                update_nodes[i].parent_hash = tree_ref.compute_parent_hash_value(
                    &path_pub_keys[parent_idx].0,
                    &path_pub_keys[parent_idx].1,
                    &update_nodes[parent_idx].parent_hash,
                    sib_idx,
                )?;
            }
        }

        let commit_secret = path_secrets
            .last()
            .ok_or_else(|| ProtocolError::invalid_state("Empty path secrets"))?
            .clone();

        for ps in &mut path_secrets {
            CryptoInterop::secure_wipe(ps);
        }

        let final_update_path = GroupUpdatePath {
            leaf_x25519_public: leaf_x25519_pub,
            leaf_kyber_public: leaf_kyber_pub,
            nodes: update_nodes,
            leaf_signature: vec![],
        };

        Ok((final_update_path, commit_secret, new_private_keys))
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn process_update_path(
        tree: &mut RatchetTree,
        update_path: &GroupUpdatePath,
        committer_leaf_idx: u32,
        my_leaf_idx: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        let n = tree.leaf_count();
        if n <= 1 {
            return Err(ProtocolError::tree_integrity(
                "Cannot process UpdatePath in single-member group",
            ));
        }
        if committer_leaf_idx >= n {
            return Err(ProtocolError::tree_integrity(format!(
                "Committer leaf index {committer_leaf_idx} out of range for tree with {n} leaves"
            )));
        }
        if my_leaf_idx >= n {
            return Err(ProtocolError::tree_integrity(format!(
                "My leaf index {my_leaf_idx} out of range for tree with {n} leaves"
            )));
        }

        DhValidator::validate_x25519_public_key(&update_path.leaf_x25519_public)?;
        KyberInterop::validate_public_key(&update_path.leaf_kyber_public)
            .map_err(ProtocolError::from_crypto)?;
        for (i, node) in update_path.nodes.iter().enumerate() {
            DhValidator::validate_x25519_public_key(&node.x25519_public).map_err(|e| {
                ProtocolError::tree_integrity(format!(
                    "UpdatePath node {i} X25519 key invalid: {e}"
                ))
            })?;
            KyberInterop::validate_public_key(&node.kyber_public).map_err(|e| {
                ProtocolError::tree_integrity(format!("UpdatePath node {i} Kyber key invalid: {e}"))
            })?;
        }

        let committer_direct_path = tree::direct_path(committer_leaf_idx, n)?;
        let committer_copath = tree::copath(committer_leaf_idx, n)?;
        let my_node = tree::checked_leaf_to_node(my_leaf_idx)?;

        if update_path.nodes.len() != committer_direct_path.len() {
            return Err(ProtocolError::tree_integrity(format!(
                "UpdatePath node count mismatch: expected {}, got {}",
                committer_direct_path.len(),
                update_path.nodes.len()
            )));
        }
        for (i, node) in update_path.nodes.iter().enumerate() {
            if node.parent_hash.len() != SHA256_HASH_BYTES {
                return Err(ProtocolError::tree_integrity(format!(
                    "Invalid parent_hash length at node level {i}: expected {}, got {}",
                    SHA256_HASH_BYTES,
                    node.parent_hash.len()
                )));
            }
            if i + 1 != update_path.nodes.len() && is_all_zero(&node.parent_hash) {
                return Err(ProtocolError::tree_integrity(format!(
                    "parent_hash is all-zero at non-root node level {i}"
                )));
            }
        }

        let my_direct_path = tree::direct_path(my_leaf_idx, n)?;
        let mut my_ancestor_level = None;
        for (i, &dp_node) in committer_direct_path.iter().enumerate() {
            if dp_node == my_node || my_direct_path.contains(&dp_node) {
                let copath_node = committer_copath[i];
                let resolution = tree.resolution(copath_node)?;
                if resolution.contains(&my_node)
                    || resolution
                        .iter()
                        .any(|&r| r == my_node || my_direct_path.contains(&r))
                {
                    my_ancestor_level = Some(i);
                    break;
                }
            }
        }

        if my_ancestor_level.is_none() {
            for (i, &copath_node) in committer_copath.iter().enumerate() {
                let resolution = tree.resolution(copath_node)?;
                for &res_node in &resolution {
                    if res_node == my_node {
                        my_ancestor_level = Some(i);
                        break;
                    }
                    if my_direct_path.contains(&res_node) {
                        my_ancestor_level = Some(i);
                        break;
                    }
                }
                if my_ancestor_level.is_some() {
                    break;
                }
            }
        }

        let ancestor_level = my_ancestor_level.ok_or_else(|| {
            ProtocolError::tree_integrity("Could not find common ancestor with committer")
        })?;

        if ancestor_level >= update_path.nodes.len() {
            return Err(ProtocolError::tree_integrity(
                "UpdatePath too short for common ancestor",
            ));
        }

        let copath_node = committer_copath[ancestor_level];
        let resolution = tree.resolution(copath_node)?;

        let mut my_res_idx = None;
        for (idx, &res_node) in resolution.iter().enumerate() {
            if res_node == my_node || my_direct_path.contains(&res_node) {
                my_res_idx = Some(idx);
                break;
            }
        }
        let res_idx = my_res_idx
            .ok_or_else(|| ProtocolError::tree_integrity("Not found in co-path resolution"))?;

        let path_node = &update_path.nodes[ancestor_level];
        if res_idx >= path_node.encrypted_path_secrets.len() {
            return Err(ProtocolError::tree_integrity(
                "Missing encrypted path secret for my resolution index",
            ));
        }

        let decrypt_node = resolution[res_idx];
        let node_keys = tree
            .get_node_keys(decrypt_node)
            .ok_or_else(|| ProtocolError::tree_integrity("Decrypt node is blank"))?;
        let x25519_priv = node_keys
            .x25519_private
            .as_ref()
            .ok_or_else(|| ProtocolError::tree_integrity("No X25519 private key for decryption"))?;
        let kyber_sec = node_keys
            .kyber_secret
            .as_ref()
            .ok_or_else(|| ProtocolError::tree_integrity("No Kyber secret key for decryption"))?;

        let ancestor_node_idx = committer_direct_path[ancestor_level];
        let path_secret = Self::decrypt_path_secret(
            &path_node.encrypted_path_secrets[res_idx],
            x25519_priv,
            kyber_sec,
            ancestor_node_idx,
        )?;

        let my_direct_path_set: std::collections::HashSet<u32> =
            my_direct_path.iter().copied().collect();

        let (anc_x25519_priv, _anc_x25519_pub, anc_kyber_sec, _anc_kyber_pub) =
            Self::derive_node_keypairs(&path_secret)?;

        tree.set_node_public_keys(
            ancestor_node_idx,
            path_node.x25519_public.clone(),
            path_node.kyber_public.clone(),
        )?;

        if my_direct_path_set.contains(&ancestor_node_idx) {
            tree.set_node_private_keys(ancestor_node_idx, anc_x25519_priv, anc_kyber_sec)?;
        }

        let mut current_secret = path_secret;
        #[allow(clippy::needless_range_loop)]
        for i in (ancestor_level + 1)..committer_direct_path.len() {
            let next_secret = Self::derive_next_path_secret(&current_secret, i as u32)?;
            CryptoInterop::secure_wipe(&mut current_secret);
            current_secret = next_secret;

            let node_idx = committer_direct_path[i];
            let expected_node = &update_path.nodes[i];

            let (derived_x25519_priv, derived_x25519_pub, derived_kyber_sec, derived_kyber_pub) =
                Self::derive_node_keypairs(&current_secret)?;

            if derived_x25519_pub != expected_node.x25519_public {
                return Err(ProtocolError::tree_integrity(format!(
                    "X25519 public key mismatch at path level {i}"
                )));
            }
            if derived_kyber_pub != expected_node.kyber_public {
                return Err(ProtocolError::tree_integrity(format!(
                    "Kyber public key mismatch at path level {i}"
                )));
            }

            tree.set_node_public_keys(
                node_idx,
                expected_node.x25519_public.clone(),
                expected_node.kyber_public.clone(),
            )?;

            if my_direct_path_set.contains(&node_idx) {
                tree.set_node_private_keys(node_idx, derived_x25519_priv, derived_kyber_sec)?;
            }
        }

        for (i, &node_idx) in committer_direct_path
            .iter()
            .enumerate()
            .take(ancestor_level)
        {
            if i < update_path.nodes.len() {
                tree.set_node_public_keys(
                    node_idx,
                    update_path.nodes[i].x25519_public.clone(),
                    update_path.nodes[i].kyber_public.clone(),
                )?;
            }
        }

        let committer_node = tree::checked_leaf_to_node(committer_leaf_idx)?;
        tree.set_node_public_keys(
            committer_node,
            update_path.leaf_x25519_public.clone(),
            update_path.leaf_kyber_public.clone(),
        )?;

        for (i, &node_idx) in committer_direct_path.iter().enumerate() {
            tree.set_node_parent_hash(node_idx, update_path.nodes[i].parent_hash.clone())?;
        }
        tree.verify_parent_hash_chain(committer_leaf_idx)?;

        let commit_secret = current_secret;
        Ok(commit_secret)
    }

    pub fn encrypt_path_secret(
        path_secret: &[u8],
        target_x25519_public: &[u8],
        target_kyber_public: &[u8],
        node_index: u32,
    ) -> Result<GroupHybridCiphertext, ProtocolError> {
        let (eph_private, eph_public) = CryptoInterop::generate_x25519_keypair("group-kem")?;

        let mut eph_priv_bytes = eph_private.read_bytes(X25519_PRIVATE_KEY_BYTES)?;
        let mut sk: [u8; X25519_PRIVATE_KEY_BYTES] = eph_priv_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::group_protocol("Invalid X25519 private key size"))?;
        let pk: [u8; X25519_PUBLIC_KEY_BYTES] = target_x25519_public
            .try_into()
            .map_err(|_| ProtocolError::group_protocol("Invalid X25519 public key size"))?;
        let mut dh_shared = x25519_dalek::StaticSecret::from(sk)
            .diffie_hellman(&x25519_dalek::PublicKey::from(pk))
            .to_bytes()
            .to_vec();
        CryptoInterop::secure_wipe(&mut eph_priv_bytes);
        CryptoInterop::secure_wipe(&mut sk);
        if is_all_zero(&dh_shared) {
            CryptoInterop::secure_wipe(&mut dh_shared);
            return Err(ProtocolError::group_protocol(
                "X25519 DH produced all-zero output in encrypt_path_secret (RFC 7748 section 6.1)",
            ));
        }

        let (kyber_ct, kyber_ss_handle) = KyberInterop::encapsulate(target_kyber_public)?;
        let mut kyber_ss = kyber_ss_handle.read_bytes(KYBER_SHARED_SECRET_BYTES)?;

        let mut salt = Vec::with_capacity(GROUP_HYBRID_SALT_PREFIX.len() + dh_shared.len());
        salt.extend_from_slice(GROUP_HYBRID_SALT_PREFIX);
        salt.extend_from_slice(&dh_shared);
        let mut hybrid_key = {
            let mut z = HkdfSha256::derive_key_bytes(
                &kyber_ss,
                AES_KEY_BYTES,
                &salt,
                GROUP_HYBRID_PATH_INFO,
            )?;
            std::mem::take(&mut *z)
        };

        CryptoInterop::secure_wipe(&mut dh_shared);
        CryptoInterop::secure_wipe(&mut kyber_ss);

        let nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        let aad = node_index.to_le_bytes();
        let encrypted = AesGcm::encrypt(&hybrid_key, &nonce, path_secret, &aad)?;

        CryptoInterop::secure_wipe(&mut hybrid_key);

        Ok(GroupHybridCiphertext {
            ephemeral_x25519_public: eph_public,
            kyber_ciphertext: kyber_ct,
            encrypted_secret: encrypted,
            nonce,
        })
    }

    pub fn decrypt_path_secret(
        ciphertext: &GroupHybridCiphertext,
        x25519_private: &SecureMemoryHandle,
        kyber_secret: &SecureMemoryHandle,
        node_index: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        DhValidator::validate_x25519_public_key(&ciphertext.ephemeral_x25519_public).map_err(
            |e| {
                ProtocolError::group_protocol(format!(
                    "decrypt_path_secret: invalid ephemeral X25519 key: {e}"
                ))
            },
        )?;
        KyberInterop::validate_ciphertext(&ciphertext.kyber_ciphertext).map_err(|e| {
            ProtocolError::group_protocol(format!(
                "decrypt_path_secret: invalid Kyber ciphertext: {e}"
            ))
        })?;

        let mut priv_bytes = x25519_private.read_bytes(X25519_PRIVATE_KEY_BYTES)?;
        let mut sk: [u8; X25519_PRIVATE_KEY_BYTES] = priv_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::group_protocol("Invalid X25519 private key size"))?;
        let pk: [u8; X25519_PUBLIC_KEY_BYTES] = ciphertext
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
                "X25519 DH produced all-zero output in decrypt_path_secret (RFC 7748 section 6.1)",
            ));
        }

        let kyber_ss_handle =
            KyberInterop::decapsulate(&ciphertext.kyber_ciphertext, kyber_secret)?;
        let mut kyber_ss = kyber_ss_handle.read_bytes(KYBER_SHARED_SECRET_BYTES)?;

        let mut salt = Vec::with_capacity(GROUP_HYBRID_SALT_PREFIX.len() + dh_shared.len());
        salt.extend_from_slice(GROUP_HYBRID_SALT_PREFIX);
        salt.extend_from_slice(&dh_shared);
        let mut hybrid_key = {
            let mut z = HkdfSha256::derive_key_bytes(
                &kyber_ss,
                AES_KEY_BYTES,
                &salt,
                GROUP_HYBRID_PATH_INFO,
            )?;
            std::mem::take(&mut *z)
        };

        CryptoInterop::secure_wipe(&mut dh_shared);
        CryptoInterop::secure_wipe(&mut kyber_ss);

        let aad = node_index.to_le_bytes();
        let path_secret = AesGcm::decrypt(
            &hybrid_key,
            &ciphertext.nonce,
            &ciphertext.encrypted_secret,
            &aad,
        )?;

        CryptoInterop::secure_wipe(&mut hybrid_key);

        Ok(path_secret)
    }

    pub fn derive_node_keypairs(
        path_secret: &[u8],
    ) -> Result<(SecureMemoryHandle, Vec<u8>, SecureMemoryHandle, Vec<u8>), ProtocolError> {
        let mut x25519_info = Vec::with_capacity(GROUP_NODE_KEY_INFO.len() + 7);
        x25519_info.extend_from_slice(GROUP_NODE_KEY_INFO);
        x25519_info.extend_from_slice(b"x25519");
        let mut x25519_seed = {
            let mut z = HkdfSha256::expand(path_secret, &x25519_info, X25519_PRIVATE_KEY_BYTES)?;
            std::mem::take(&mut *z)
        };

        x25519_seed[0] &= X25519_CLAMP_BYTE0;
        x25519_seed[31] &= X25519_CLAMP_BYTE31_LOW;
        x25519_seed[31] |= X25519_CLAMP_BYTE31_HIGH;

        let seed_array: [u8; X25519_PRIVATE_KEY_BYTES] = x25519_seed
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::tree_integrity("X25519 seed has wrong length"))?;
        let x25519_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(seed_array))
                .as_bytes()
                .to_vec();

        let mut x25519_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)?;
        x25519_handle.write(&x25519_seed)?;
        CryptoInterop::secure_wipe(&mut x25519_seed);

        let mut kyber_info = Vec::with_capacity(GROUP_NODE_KEY_INFO.len() + 5);
        kyber_info.extend_from_slice(GROUP_NODE_KEY_INFO);
        kyber_info.extend_from_slice(b"kyber");
        let mut kyber_seed = {
            let mut z = HkdfSha256::expand(path_secret, &kyber_info, KYBER_SEED_KEY_BYTES)?;
            std::mem::take(&mut *z)
        };

        let (kyber_secret, kyber_public) = KyberInterop::generate_keypair_from_seed(&kyber_seed)?;
        CryptoInterop::secure_wipe(&mut kyber_seed);

        Ok((x25519_handle, x25519_public, kyber_secret, kyber_public))
    }

    fn derive_next_path_secret(current: &[u8], level: u32) -> Result<Vec<u8>, ProtocolError> {
        let mut info = Vec::with_capacity(GROUP_PATH_SECRET_INFO.len() + 4);
        info.extend_from_slice(GROUP_PATH_SECRET_INFO);
        info.extend_from_slice(&level.to_le_bytes());
        let mut z = HkdfSha256::expand(current, &info, PATH_SECRET_BYTES)?;
        Ok(std::mem::take(&mut *z))
    }
}
