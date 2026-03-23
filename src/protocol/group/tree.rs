// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, SecureMemoryHandle};
use crate::proto::{GroupKeyPackage, GroupTreeNode};
use sha2::Digest;

pub struct HybridNodeKeys {
    pub x25519_public: Vec<u8>,
    pub kyber_public: Vec<u8>,
    pub x25519_private: Option<SecureMemoryHandle>,
    pub kyber_secret: Option<SecureMemoryHandle>,
}

impl HybridNodeKeys {
    fn try_clone(&self) -> Result<Self, ProtocolError> {
        let x25519_private = match &self.x25519_private {
            Some(handle) => Some(handle.try_clone().map_err(ProtocolError::from_crypto)?),
            None => None,
        };
        let kyber_secret = match &self.kyber_secret {
            Some(handle) => Some(handle.try_clone().map_err(ProtocolError::from_crypto)?),
            None => None,
        };
        Ok(Self {
            x25519_public: self.x25519_public.clone(),
            kyber_public: self.kyber_public.clone(),
            x25519_private,
            kyber_secret,
        })
    }
}

impl Drop for HybridNodeKeys {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.x25519_public);
        CryptoInterop::secure_wipe(&mut self.kyber_public);
    }
}

pub enum TreeNodeContent {
    Blank,
    Populated {
        keys: HybridNodeKeys,
        parent_hash: Vec<u8>,
    },
}

impl TreeNodeContent {
    fn try_clone(&self) -> Result<Self, ProtocolError> {
        match self {
            Self::Blank => Ok(Self::Blank),
            Self::Populated { keys, parent_hash } => Ok(Self::Populated {
                keys: keys.try_clone()?,
                parent_hash: parent_hash.clone(),
            }),
        }
    }
}

#[derive(Clone)]
pub struct LeafData {
    pub credential: Vec<u8>,
    pub identity_ed25519_public: Vec<u8>,
    pub identity_x25519_public: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct RatchetTree {
    nodes: Vec<TreeNodeContent>,
    leaves: Vec<Option<LeafData>>,
    leaf_count: u32,
}

impl RatchetTree {
    pub fn try_clone(&self) -> Result<Self, ProtocolError> {
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            nodes.push(node.try_clone()?);
        }
        Ok(Self {
            nodes,
            leaves: self.leaves.clone(),
            leaf_count: self.leaf_count,
        })
    }
}

#[inline]
pub const fn level(x: u32) -> u32 {
    (!x).trailing_zeros()
}

#[inline]
pub const fn is_leaf(x: u32) -> bool {
    x & 1 == 0
}

#[inline]
pub const fn node_count(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        2 * n - 1
    }
}

pub fn root(n: u32) -> Result<u32, ProtocolError> {
    if n == 0 {
        return Err(ProtocolError::tree_integrity(
            "root: leaf count must be > 0",
        ));
    }
    let w = node_count(n);
    Ok((1u32 << log2(w)?) - 1)
}

pub fn left(x: u32) -> Result<u32, ProtocolError> {
    if is_leaf(x) {
        return Err(ProtocolError::tree_integrity(
            "left: leaves have no children",
        ));
    }
    let k = level(x);
    if k == 0 {
        return Err(ProtocolError::tree_integrity(
            "left: level must be > 0 for non-leaf",
        ));
    }
    Ok(x ^ (1 << (k - 1)))
}

pub fn right(x: u32, n: u32) -> Result<u32, ProtocolError> {
    if is_leaf(x) {
        return Err(ProtocolError::tree_integrity(
            "right: leaves have no children",
        ));
    }
    let k = level(x);
    if k == 0 {
        return Err(ProtocolError::tree_integrity(
            "right: level must be > 0 for non-leaf",
        ));
    }
    let mut r = x ^ (3 << (k - 1));
    while r >= node_count(n) {
        r = left(r)?;
    }
    Ok(r)
}

#[allow(clippy::many_single_char_names)]
pub fn parent(x: u32, n: u32) -> Result<u32, ProtocolError> {
    let r = root(n)?;
    if x == r {
        return Err(ProtocolError::tree_integrity("parent: root has no parent"));
    }
    let k = level(x);
    if k >= 31 {
        return Err(ProtocolError::tree_integrity(
            "parent: node level exceeds tree depth",
        ));
    }
    let b = (x >> (k + 1)) & 1;
    let p = (x | (1 << k)) ^ (b << (k + 1));
    if p > r || p >= node_count(n) {
        return parent_walk(x, n);
    }
    Ok(p)
}

fn parent_walk(x: u32, n: u32) -> Result<u32, ProtocolError> {
    let r = root(n)?;
    let nc = node_count(n);
    fn find_parent(
        node: u32,
        target: u32,
        n: u32,
        nc: u32,
        depth: usize,
    ) -> Result<Option<u32>, ProtocolError> {
        if depth > MAX_TREE_DEPTH {
            return Err(ProtocolError::tree_integrity(
                "parent_walk: exceeded MAX_TREE_DEPTH",
            ));
        }
        if is_leaf(node) || node >= nc {
            return Ok(None);
        }
        let l = left(node)?;
        let r = right(node, n)?;
        if l == target || r == target {
            return Ok(Some(node));
        }
        let left_result = find_parent(l, target, n, nc, depth + 1)?;
        if left_result.is_some() {
            Ok(left_result)
        } else {
            find_parent(r, target, n, nc, depth + 1)
        }
    }
    Ok(find_parent(r, x, n, nc, 0)?.unwrap_or(r))
}

pub fn sibling(x: u32, n: u32) -> Result<u32, ProtocolError> {
    let p = parent(x, n)?;
    let l = left(p)?;
    if l == x {
        right(p, n)
    } else {
        Ok(l)
    }
}

#[inline]
pub const fn leaf_to_node(leaf_idx: u32) -> u32 {
    leaf_idx
        .checked_mul(2)
        .expect("leaf_to_node: leaf index overflow")
}

#[inline]
pub fn checked_leaf_to_node(leaf_idx: u32) -> Result<u32, ProtocolError> {
    leaf_idx
        .checked_mul(2)
        .ok_or_else(|| ProtocolError::tree_integrity("checked_leaf_to_node: leaf index overflow"))
}

#[inline]
pub const fn node_to_leaf(node_idx: u32) -> Option<u32> {
    if is_leaf(node_idx) {
        Some(node_idx / 2)
    } else {
        None
    }
}

pub fn direct_path(leaf_idx: u32, n: u32) -> Result<Vec<u32>, ProtocolError> {
    let mut path = Vec::new();
    let r = root(n)?;
    let mut x = checked_leaf_to_node(leaf_idx)?;
    while x != r {
        x = parent(x, n)?;
        path.push(x);
    }
    Ok(path)
}

pub fn copath(leaf_idx: u32, n: u32) -> Result<Vec<u32>, ProtocolError> {
    let mut cp = Vec::new();
    let r = root(n)?;
    let mut x = checked_leaf_to_node(leaf_idx)?;
    while x != r {
        cp.push(sibling(x, n)?);
        x = parent(x, n)?;
    }
    Ok(cp)
}

fn log2(x: u32) -> Result<u32, ProtocolError> {
    if x == 0 {
        return Err(ProtocolError::tree_integrity("log2(0) is undefined"));
    }
    Ok(x.ilog2())
}

#[inline]
fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

impl RatchetTree {
    #[allow(clippy::too_many_arguments)]
    pub fn new_single(
        x25519_public: Vec<u8>,
        kyber_public: Vec<u8>,
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
        identity_ed25519: Vec<u8>,
        identity_x25519: Vec<u8>,
        credential: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid X25519 public key size",
            ));
        }
        if kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid Kyber public key size",
            ));
        }

        let keys = HybridNodeKeys {
            x25519_public,
            kyber_public,
            x25519_private: Some(x25519_private),
            kyber_secret: Some(kyber_secret),
        };
        let leaf = TreeNodeContent::Populated {
            keys,
            parent_hash: vec![0u8; SHA256_HASH_BYTES],
        };
        let leaf_data = LeafData {
            credential,
            identity_ed25519_public: identity_ed25519,
            identity_x25519_public: identity_x25519,
            signature,
        };

        Ok(Self {
            nodes: vec![leaf],
            leaves: vec![Some(leaf_data)],
            leaf_count: 1,
        })
    }

    pub const fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn member_count(&self) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let count = self.leaves.iter().filter(|l| l.is_some()).count() as u32;
        count
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_leaf_data(&self, leaf_idx: u32) -> Option<&LeafData> {
        self.leaves.get(leaf_idx as usize).and_then(|l| l.as_ref())
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn populated_leaf_indices(&self) -> Vec<u32> {
        self.leaves
            .iter()
            .enumerate()
            .filter_map(|(i, l)| if l.is_some() { Some(i as u32) } else { None })
            .collect()
    }

    pub fn get_node_public_keys(&self, node_idx: u32) -> Option<(&[u8], &[u8])> {
        self.nodes.get(node_idx as usize).and_then(|n| match n {
            TreeNodeContent::Populated { keys, .. } => {
                Some((keys.x25519_public.as_slice(), keys.kyber_public.as_slice()))
            }
            TreeNodeContent::Blank => None,
        })
    }

    pub fn get_node_keys(&self, node_idx: u32) -> Option<&HybridNodeKeys> {
        self.nodes.get(node_idx as usize).and_then(|n| match n {
            TreeNodeContent::Populated { keys, .. } => Some(keys),
            TreeNodeContent::Blank => None,
        })
    }

    pub fn is_blank(&self, node_idx: u32) -> bool {
        match self.nodes.get(node_idx as usize) {
            Some(TreeNodeContent::Blank) | None => true,
            Some(TreeNodeContent::Populated { .. }) => false,
        }
    }

    pub fn resolution(&self, node_idx: u32) -> Result<Vec<u32>, ProtocolError> {
        self.resolution_inner(node_idx, 0)
    }

    fn resolution_inner(&self, node_idx: u32, depth: usize) -> Result<Vec<u32>, ProtocolError> {
        if depth > MAX_TREE_DEPTH {
            return Err(ProtocolError::tree_integrity(
                "resolution: exceeded MAX_TREE_DEPTH",
            ));
        }
        if (node_idx as usize) >= self.nodes.len() {
            return Ok(vec![]);
        }
        match &self.nodes[node_idx as usize] {
            TreeNodeContent::Populated { .. } => Ok(vec![node_idx]),
            TreeNodeContent::Blank => {
                if is_leaf(node_idx) {
                    return Ok(vec![]);
                }
                let l = left(node_idx)?;
                let r = right(node_idx, self.leaf_count)?;
                let mut res = self.resolution_inner(l, depth + 1)?;
                res.extend(self.resolution_inner(r, depth + 1)?);
                Ok(res)
            }
        }
    }

    pub fn next_leaf_index(&self) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        self.leaves
            .iter()
            .position(std::option::Option::is_none)
            .map_or(self.leaf_count, |idx| idx as u32)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn add_leaf(
        &mut self,
        x25519_public: Vec<u8>,
        kyber_public: Vec<u8>,
        leaf_data: LeafData,
    ) -> Result<u32, ProtocolError> {
        if self.member_count() as usize >= MAX_GROUP_MEMBERS {
            return Err(ProtocolError::group_membership(
                "Group member limit reached",
            ));
        }

        let blank_slot = self.leaves.iter().position(std::option::Option::is_none);

        let leaf_idx = if let Some(idx) = blank_slot {
            let node_idx = checked_leaf_to_node(idx as u32)?;
            self.nodes[node_idx as usize] = TreeNodeContent::Populated {
                keys: HybridNodeKeys {
                    x25519_public,
                    kyber_public,
                    x25519_private: None,
                    kyber_secret: None,
                },
                parent_hash: vec![0u8; SHA256_HASH_BYTES],
            };
            self.leaves[idx] = Some(leaf_data);
            idx as u32
        } else {
            let new_leaf_idx = self.leaf_count;
            let new_leaf_count = self.leaf_count + 1;
            let new_node_count = node_count(new_leaf_count) as usize;

            while self.nodes.len() < new_node_count {
                self.nodes.push(TreeNodeContent::Blank);
            }

            let node_idx = checked_leaf_to_node(new_leaf_idx)?;
            self.nodes[node_idx as usize] = TreeNodeContent::Populated {
                keys: HybridNodeKeys {
                    x25519_public,
                    kyber_public,
                    x25519_private: None,
                    kyber_secret: None,
                },
                parent_hash: vec![0u8; SHA256_HASH_BYTES],
            };
            self.leaves.push(Some(leaf_data));
            self.leaf_count = new_leaf_count;
            new_leaf_idx
        };

        Ok(leaf_idx)
    }

    pub fn blank_leaf(&mut self, leaf_idx: u32) -> Result<(), ProtocolError> {
        if leaf_idx >= self.leaf_count {
            return Err(ProtocolError::group_membership("Leaf index out of range"));
        }
        if self.leaves[leaf_idx as usize].is_none() {
            return Err(ProtocolError::group_membership("Leaf already blank"));
        }

        let node_idx = checked_leaf_to_node(leaf_idx)?;
        self.nodes[node_idx as usize] = TreeNodeContent::Blank;
        self.leaves[leaf_idx as usize] = None;

        if self.leaf_count > 1 {
            let path = direct_path(leaf_idx, self.leaf_count)?;
            for &p in &path {
                if (p as usize) < self.nodes.len() {
                    self.nodes[p as usize] = TreeNodeContent::Blank;
                }
            }
        }

        Ok(())
    }

    pub fn set_node_public_keys(
        &mut self,
        node_idx: u32,
        x25519_public: Vec<u8>,
        kyber_public: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        if (node_idx as usize) >= self.nodes.len() {
            return Err(ProtocolError::tree_integrity("Node index out of range"));
        }
        match &mut self.nodes[node_idx as usize] {
            TreeNodeContent::Populated { keys, .. } => {
                keys.x25519_public = x25519_public;
                keys.kyber_public = kyber_public;
            }
            node @ TreeNodeContent::Blank => {
                *node = TreeNodeContent::Populated {
                    keys: HybridNodeKeys {
                        x25519_public,
                        kyber_public,
                        x25519_private: None,
                        kyber_secret: None,
                    },
                    parent_hash: vec![0u8; SHA256_HASH_BYTES],
                };
            }
        }
        Ok(())
    }

    pub fn set_node_private_keys(
        &mut self,
        node_idx: u32,
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
    ) -> Result<(), ProtocolError> {
        match self.nodes.get_mut(node_idx as usize) {
            Some(TreeNodeContent::Populated { keys, .. }) => {
                keys.x25519_private = Some(x25519_private);
                keys.kyber_secret = Some(kyber_secret);
                Ok(())
            }
            _ => Err(ProtocolError::tree_integrity(
                "Cannot set private keys on blank node",
            )),
        }
    }

    pub fn set_leaf_signature(
        &mut self,
        leaf_idx: u32,
        signature: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        let Some(leaf) = self
            .leaves
            .get_mut(leaf_idx as usize)
            .and_then(|l| l.as_mut())
        else {
            return Err(ProtocolError::tree_integrity(
                "Cannot set signature on blank leaf",
            ));
        };
        leaf.signature = signature;
        Ok(())
    }

    pub fn update_leaf(
        &mut self,
        leaf_idx: u32,
        x25519_public: Vec<u8>,
        kyber_public: Vec<u8>,
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
    ) -> Result<(), ProtocolError> {
        let node_idx = checked_leaf_to_node(leaf_idx)?;
        if (node_idx as usize) >= self.nodes.len() {
            return Err(ProtocolError::tree_integrity(
                "Leaf node index out of range",
            ));
        }
        self.nodes[node_idx as usize] = TreeNodeContent::Populated {
            keys: HybridNodeKeys {
                x25519_public,
                kyber_public,
                x25519_private: Some(x25519_private),
                kyber_secret: Some(kyber_secret),
            },
            parent_hash: vec![0u8; SHA256_HASH_BYTES],
        };
        Ok(())
    }

    pub fn tree_hash(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.leaf_count == 0 {
            return Ok(vec![0u8; SHA256_HASH_BYTES]);
        }
        let r = root(self.leaf_count)?;
        self.compute_node_hash(r)
    }

    fn compute_node_hash(&self, node_idx: u32) -> Result<Vec<u8>, ProtocolError> {
        self.compute_node_hash_inner(node_idx, 0)
    }

    fn compute_node_hash_inner(
        &self,
        node_idx: u32,
        depth: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if depth > MAX_TREE_DEPTH {
            return Err(ProtocolError::tree_integrity(
                "compute_node_hash: exceeded MAX_TREE_DEPTH",
            ));
        }

        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&node_idx.to_le_bytes());

        match self.nodes.get(node_idx as usize) {
            Some(TreeNodeContent::Populated { keys, .. }) => {
                hasher_input.push(1);
                hasher_input.extend_from_slice(&keys.x25519_public);
                hasher_input.extend_from_slice(&keys.kyber_public);
            }
            _ => {
                hasher_input.push(0);
            }
        }

        if !is_leaf(node_idx) && self.leaf_count > 1 {
            let l = left(node_idx)?;
            let r = right(node_idx, self.leaf_count)?;
            let left_hash = self.compute_node_hash_inner(l, depth + 1)?;
            let right_hash = self.compute_node_hash_inner(r, depth + 1)?;
            hasher_input.extend_from_slice(&left_hash);
            hasher_input.extend_from_slice(&right_hash);
        }

        let hash = sha2::Sha256::digest(&hasher_input).to_vec();
        Ok(hash)
    }

    pub fn set_node_parent_hash(
        &mut self,
        node_idx: u32,
        hash: Vec<u8>,
    ) -> Result<(), ProtocolError> {
        match self.nodes.get_mut(node_idx as usize) {
            Some(TreeNodeContent::Populated {
                parent_hash: ref mut ph,
                ..
            }) => {
                *ph = hash;
                Ok(())
            }
            _ => Err(ProtocolError::tree_integrity(
                "Cannot set parent_hash on blank node",
            )),
        }
    }

    pub fn get_node_parent_hash(&self, node_idx: u32) -> Option<&[u8]> {
        match self.nodes.get(node_idx as usize) {
            Some(TreeNodeContent::Populated { parent_hash, .. }) => Some(parent_hash.as_slice()),
            _ => None,
        }
    }

    pub fn subtree_hash(&self, node_idx: u32) -> Result<Vec<u8>, ProtocolError> {
        self.compute_node_hash(node_idx)
    }

    pub fn compute_parent_hash_value(
        &self,
        parent_x25519: &[u8],
        parent_kyber: &[u8],
        parent_parent_hash: &[u8],
        sibling_idx: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        let sibling_hash = self.subtree_hash(sibling_idx)?;

        let mut input = Vec::with_capacity(
            GROUP_PARENT_HASH_LABEL.len()
                + parent_x25519.len()
                + parent_kyber.len()
                + parent_parent_hash.len()
                + sibling_hash.len(),
        );
        input.extend_from_slice(GROUP_PARENT_HASH_LABEL);
        input.extend_from_slice(parent_x25519);
        input.extend_from_slice(parent_kyber);
        input.extend_from_slice(parent_parent_hash);
        input.extend_from_slice(&sibling_hash);

        let hash = sha2::Sha256::digest(&input).to_vec();
        Ok(hash)
    }

    pub fn verify_parent_hash_chain(&self, leaf_idx: u32) -> Result<(), ProtocolError> {
        if self.leaf_count <= 1 {
            return Ok(());
        }

        let dp = direct_path(leaf_idx, self.leaf_count)?;
        if dp.is_empty() {
            return Ok(());
        }

        let root_idx = root(self.leaf_count)?;

        let mut expected_parent_hash = vec![0u8; SHA256_HASH_BYTES];

        for i in (0..dp.len()).rev() {
            let node_idx = dp[i];
            let stored = self.get_node_parent_hash(node_idx).ok_or_else(|| {
                ProtocolError::tree_integrity(format!("Missing parent_hash at node {node_idx}"))
            })?;
            if stored.len() != SHA256_HASH_BYTES {
                return Err(ProtocolError::tree_integrity(format!(
                    "Invalid parent_hash length at node {node_idx}: expected {}, got {}",
                    SHA256_HASH_BYTES,
                    stored.len()
                )));
            }

            let is_zero = is_all_zero(stored);
            if node_idx == root_idx {
                if !is_zero {
                    return Err(ProtocolError::tree_integrity(
                        "parent_hash at root node must be all-zero",
                    ));
                }
            } else if is_zero {
                return Err(ProtocolError::tree_integrity(format!(
                    "parent_hash is all-zero at non-root node {node_idx}"
                )));
            }

            let hash_ok = CryptoInterop::constant_time_equals(stored, &expected_parent_hash)?;
            if !hash_ok {
                return Err(ProtocolError::tree_integrity(format!(
                    "parent_hash mismatch at node {node_idx}"
                )));
            }

            if i > 0 {
                let child_node_idx = dp[i - 1];
                let sib_idx = sibling(child_node_idx, self.leaf_count)?;
                let keys = self.get_node_public_keys(node_idx).ok_or_else(|| {
                    ProtocolError::tree_integrity(format!(
                        "Missing public keys at node {node_idx} for parent_hash verification"
                    ))
                })?;
                expected_parent_hash =
                    self.compute_parent_hash_value(keys.0, keys.1, stored, sib_idx)?;
            }
        }

        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn export_public(&self) -> Vec<GroupTreeNode> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, node)| match node {
                TreeNodeContent::Blank => GroupTreeNode {
                    node_index: i as u32,
                    x25519_public: vec![],
                    kyber_public: vec![],
                    x25519_private: vec![],
                    kyber_secret: vec![],
                    parent_hash: vec![],
                    key_package: self.leaf_key_package(i as u32),
                },
                TreeNodeContent::Populated { keys, parent_hash } => GroupTreeNode {
                    node_index: i as u32,
                    x25519_public: keys.x25519_public.clone(),
                    kyber_public: keys.kyber_public.clone(),
                    x25519_private: vec![],
                    kyber_secret: vec![],
                    parent_hash: parent_hash.clone(),
                    key_package: self.leaf_key_package(i as u32),
                },
            })
            .collect()
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn export_for_welcome(
        &self,
        new_member_leaf_idx: u32,
    ) -> Result<Vec<GroupTreeNode>, ProtocolError> {
        let dp: std::collections::HashSet<u32> = direct_path(new_member_leaf_idx, self.leaf_count)?
            .into_iter()
            .collect();

        Ok(self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let idx = i as u32;
                match node {
                    TreeNodeContent::Blank => GroupTreeNode {
                        node_index: idx,
                        x25519_public: vec![],
                        kyber_public: vec![],
                        x25519_private: vec![],
                        kyber_secret: vec![],
                        parent_hash: vec![],
                        key_package: self.leaf_key_package(idx),
                    },
                    TreeNodeContent::Populated { keys, parent_hash } => {
                        let include_priv = !is_leaf(idx) && dp.contains(&idx);
                        let x25519_priv = if include_priv {
                            keys.x25519_private
                                .as_ref()
                                .and_then(|h| h.read_bytes(X25519_PRIVATE_KEY_BYTES).ok())
                                .unwrap_or_default()
                        } else {
                            vec![]
                        };
                        let kyber_sk = if include_priv {
                            keys.kyber_secret
                                .as_ref()
                                .and_then(|h| h.read_bytes(KYBER_SECRET_KEY_BYTES).ok())
                                .unwrap_or_default()
                        } else {
                            vec![]
                        };
                        GroupTreeNode {
                            node_index: idx,
                            x25519_public: keys.x25519_public.clone(),
                            kyber_public: keys.kyber_public.clone(),
                            x25519_private: x25519_priv,
                            kyber_secret: kyber_sk,
                            parent_hash: parent_hash.clone(),
                            key_package: self.leaf_key_package(idx),
                        }
                    }
                }
            })
            .collect())
    }

    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn export_with_private_keys(&self) -> Vec<GroupTreeNode> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, node)| match node {
                TreeNodeContent::Blank => GroupTreeNode {
                    node_index: i as u32,
                    x25519_public: vec![],
                    kyber_public: vec![],
                    x25519_private: vec![],
                    kyber_secret: vec![],
                    parent_hash: vec![],
                    key_package: self.leaf_key_package(i as u32),
                },
                TreeNodeContent::Populated { keys, parent_hash } => {
                    let x25519_priv = keys
                        .x25519_private
                        .as_ref()
                        .and_then(|h| h.read_bytes(X25519_PRIVATE_KEY_BYTES).ok())
                        .unwrap_or_default();
                    let kyber_sk = keys
                        .kyber_secret
                        .as_ref()
                        .and_then(|h| h.read_bytes(KYBER_SECRET_KEY_BYTES).ok())
                        .unwrap_or_default();
                    GroupTreeNode {
                        node_index: i as u32,
                        x25519_public: keys.x25519_public.clone(),
                        kyber_public: keys.kyber_public.clone(),
                        x25519_private: x25519_priv,
                        kyber_secret: kyber_sk,
                        parent_hash: parent_hash.clone(),
                        key_package: self.leaf_key_package(i as u32),
                    }
                }
            })
            .collect()
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn from_proto(
        proto_nodes: &[GroupTreeNode],
        _my_leaf_idx: u32,
    ) -> Result<Self, ProtocolError> {
        if proto_nodes.is_empty() {
            return Err(ProtocolError::tree_integrity("Empty tree"));
        }

        let nc = proto_nodes.len();
        if nc % 2 == 0 {
            return Err(ProtocolError::tree_integrity(format!(
                "Node count must be odd (2n-1), got {nc}"
            )));
        }
        if nc > MAX_TREE_NODES {
            return Err(ProtocolError::tree_integrity(format!(
                "Tree node count {nc} exceeds MAX_TREE_NODES ({MAX_TREE_NODES})"
            )));
        }
        let lc = nc.div_ceil(2) as u32;

        let mut nodes = Vec::with_capacity(nc);
        let mut leaves: Vec<Option<LeafData>> = Vec::with_capacity(lc as usize);

        for pn in proto_nodes {
            if pn.x25519_public.is_empty() {
                nodes.push(TreeNodeContent::Blank);
            } else {
                if pn.x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
                    return Err(ProtocolError::tree_integrity(format!(
                        "Invalid X25519 public key size in tree node {}: expected {}, got {}",
                        pn.node_index,
                        X25519_PUBLIC_KEY_BYTES,
                        pn.x25519_public.len()
                    )));
                }
                if !pn.kyber_public.is_empty() && pn.kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
                    return Err(ProtocolError::tree_integrity(format!(
                        "Invalid Kyber public key size in tree node {}: expected {}, got {}",
                        pn.node_index,
                        KYBER_PUBLIC_KEY_BYTES,
                        pn.kyber_public.len()
                    )));
                }
                if !pn.x25519_private.is_empty()
                    && pn.x25519_private.len() != X25519_PRIVATE_KEY_BYTES
                {
                    return Err(ProtocolError::tree_integrity(format!(
                        "Invalid X25519 private key size in tree node {}",
                        pn.node_index
                    )));
                }
                if !pn.kyber_secret.is_empty() && pn.kyber_secret.len() != KYBER_SECRET_KEY_BYTES {
                    return Err(ProtocolError::tree_integrity(format!(
                        "Invalid Kyber secret key size in tree node {}",
                        pn.node_index
                    )));
                }

                let mut keys = HybridNodeKeys {
                    x25519_public: pn.x25519_public.clone(),
                    kyber_public: pn.kyber_public.clone(),
                    x25519_private: None,
                    kyber_secret: None,
                };
                if !pn.x25519_private.is_empty() {
                    let mut handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)?;
                    handle.write(&pn.x25519_private)?;
                    keys.x25519_private = Some(handle);
                }
                if !pn.kyber_secret.is_empty() {
                    let mut handle = SecureMemoryHandle::allocate(KYBER_SECRET_KEY_BYTES)?;
                    handle.write(&pn.kyber_secret)?;
                    keys.kyber_secret = Some(handle);
                }
                nodes.push(TreeNodeContent::Populated {
                    keys,
                    parent_hash: pn.parent_hash.clone(),
                });
            }
        }

        for i in 0..lc {
            let node_idx = checked_leaf_to_node(i)? as usize;
            if node_idx < proto_nodes.len() {
                if let Some(ref kp) = proto_nodes[node_idx].key_package {
                    super::key_package::validate_key_package(kp)?;
                    match &nodes[node_idx] {
                        TreeNodeContent::Populated { keys, .. } => {
                            if keys.x25519_public != kp.leaf_x25519_public
                                || keys.kyber_public != kp.leaf_kyber_public
                            {
                                return Err(ProtocolError::tree_integrity(
                                    "Leaf key package does not match leaf node public keys",
                                ));
                            }
                        }
                        TreeNodeContent::Blank => {
                            return Err(ProtocolError::tree_integrity(
                                "Blank leaf cannot carry a key package",
                            ));
                        }
                    }
                    leaves.push(Some(LeafData {
                        credential: kp.credential.clone(),
                        identity_ed25519_public: kp.identity_ed25519_public.clone(),
                        identity_x25519_public: kp.identity_x25519_public.clone(),
                        signature: kp.signature.clone(),
                    }));
                } else {
                    leaves.push(None);
                }
            } else {
                leaves.push(None);
            }
        }

        Ok(Self {
            nodes,
            leaves,
            leaf_count: lc,
        })
    }

    pub fn from_public_proto(proto_nodes: &[GroupTreeNode]) -> Result<Self, ProtocolError> {
        Self::from_proto(proto_nodes, u32::MAX)
    }

    fn leaf_key_package(&self, node_idx: u32) -> Option<GroupKeyPackage> {
        if !is_leaf(node_idx) {
            return None;
        }
        let leaf_idx = node_idx / 2;
        let ld = self.leaves.get(leaf_idx as usize)?.as_ref()?;
        let (x25519_pub, kyber_pub) = self.get_node_public_keys(node_idx)?;
        Some(GroupKeyPackage {
            version: GROUP_PROTOCOL_VERSION,
            identity_ed25519_public: ld.identity_ed25519_public.clone(),
            identity_x25519_public: ld.identity_x25519_public.clone(),
            leaf_x25519_public: x25519_pub.to_vec(),
            leaf_kyber_public: kyber_pub.to_vec(),
            signature: ld.signature.clone(),
            credential: ld.credential.clone(),
            created_at: None,
        })
    }
}
