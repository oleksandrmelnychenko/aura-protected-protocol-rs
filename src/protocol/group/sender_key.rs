// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{Blake2bHash, CryptoInterop, HkdfSha256};

pub struct SenderKeyChain {
    leaf_index: u32,
    chain_key: Vec<u8>,
    generation: u32,
    enhanced: bool,
    max_generation: u32,
    max_skipped_per_sender: usize,
}

impl Drop for SenderKeyChain {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.chain_key);
    }
}

impl SenderKeyChain {
    pub fn new(leaf_index: u32, sender_key_base: Vec<u8>) -> Result<Self, ProtocolError> {
        Self::new_with_policy(
            leaf_index,
            sender_key_base,
            false,
            MAX_SENDER_KEY_GENERATION,
            MAX_SKIPPED_SENDER_KEYS_PER_SENDER,
        )
    }

    pub fn new_with_policy(
        leaf_index: u32,
        sender_key_base: Vec<u8>,
        enhanced: bool,
        max_generation: u32,
        max_skipped_per_sender: usize,
    ) -> Result<Self, ProtocolError> {
        if sender_key_base.len() != SENDER_KEY_BASE_BYTES {
            return Err(ProtocolError::invalid_input("Invalid sender key base size"));
        }
        Ok(Self {
            leaf_index,
            chain_key: sender_key_base,
            generation: 0,
            enhanced,
            max_generation,
            max_skipped_per_sender,
        })
    }

    pub fn from_state(
        leaf_index: u32,
        chain_key: Vec<u8>,
        generation: u32,
    ) -> Result<Self, ProtocolError> {
        Self::from_state_with_policy(
            leaf_index,
            chain_key,
            generation,
            false,
            MAX_SENDER_KEY_GENERATION,
            MAX_SKIPPED_SENDER_KEYS_PER_SENDER,
        )
    }

    pub fn from_state_with_policy(
        leaf_index: u32,
        chain_key: Vec<u8>,
        generation: u32,
        enhanced: bool,
        max_generation: u32,
        max_skipped_per_sender: usize,
    ) -> Result<Self, ProtocolError> {
        if chain_key.len() != CHAIN_KEY_BYTES {
            return Err(ProtocolError::invalid_input("Invalid chain key size"));
        }
        Ok(Self {
            leaf_index,
            chain_key,
            generation,
            enhanced,
            max_generation,
            max_skipped_per_sender,
        })
    }

    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub fn chain_key(&self) -> &[u8] {
        &self.chain_key
    }

    pub fn next_message_key(&mut self) -> Result<(u32, Vec<u8>), ProtocolError> {
        if self.generation >= self.max_generation {
            return Err(ProtocolError::group_protocol(
                "Sender key chain exhausted — trigger epoch update",
            ));
        }

        let gen = self.generation;
        let message_key = {
            let mut z = HkdfSha256::expand(&self.chain_key, GROUP_MSG_INFO, MESSAGE_KEY_BYTES)?;
            std::mem::take(&mut *z)
        };
        let mut next_chain = {
            let mut z = HkdfSha256::expand(&self.chain_key, GROUP_CHAIN_INFO, CHAIN_KEY_BYTES)?;
            std::mem::take(&mut *z)
        };

        if self.enhanced {
            let blaked = Blake2bHash::keyed_hash(GROUP_BLAKE2B_CHAIN_PERSONALIZATION, &next_chain)?;
            CryptoInterop::secure_wipe(&mut next_chain);
            next_chain = blaked;
        }

        CryptoInterop::secure_wipe(&mut self.chain_key);
        std::mem::swap(&mut self.chain_key, &mut next_chain);
        CryptoInterop::secure_wipe(&mut next_chain);

        self.generation = gen + 1;
        Ok((gen, message_key))
    }

    #[allow(clippy::type_complexity)]
    pub fn advance_to(
        &mut self,
        target_generation: u32,
    ) -> Result<(Vec<u8>, Vec<(u32, Vec<u8>)>), ProtocolError> {
        if target_generation < self.generation {
            return Err(ProtocolError::replay_attack(format!(
                "Sender key generation {} already consumed (current: {})",
                target_generation, self.generation
            )));
        }
        if target_generation >= self.max_generation {
            return Err(ProtocolError::group_protocol(
                "Target generation exceeds maximum",
            ));
        }
        let skip_count = (target_generation - self.generation) as usize;
        if skip_count > self.max_skipped_per_sender {
            return Err(ProtocolError::group_protocol(format!(
                "Too many skipped generations: {skip_count} (max {})",
                self.max_skipped_per_sender
            )));
        }

        let mut skipped = Vec::with_capacity(skip_count);
        while self.generation < target_generation {
            let (gen, key) = self.next_message_key()?;
            skipped.push((gen, key));
        }
        let (_, message_key) = self.next_message_key()?;
        Ok((message_key, skipped))
    }
}

pub struct SenderKeyStore {
    chains: Vec<(u32, SenderKeyChain)>,
    skipped_keys: BTreeMap<(u32, u32), Vec<u8>>,
    max_skipped_per_sender: usize,
    max_skipped_total: usize,
}

impl Drop for SenderKeyStore {
    fn drop(&mut self) {
        for key in self.skipped_keys.values_mut() {
            CryptoInterop::secure_wipe(key);
        }
    }
}

impl SenderKeyStore {
    pub fn new_epoch(
        epoch_secret: &[u8],
        leaf_indices: &[u32],
        group_context_hash: &[u8],
    ) -> Result<Self, ProtocolError> {
        Self::new_epoch_with_policy(
            epoch_secret,
            leaf_indices,
            group_context_hash,
            false,
            MAX_SENDER_KEY_GENERATION,
            MAX_SKIPPED_SENDER_KEYS_PER_SENDER,
        )
    }

    pub fn new_epoch_with_policy(
        epoch_secret: &[u8],
        leaf_indices: &[u32],
        group_context_hash: &[u8],
        enhanced: bool,
        max_generation: u32,
        max_skipped_per_sender: usize,
    ) -> Result<Self, ProtocolError> {
        let mut chains = Vec::with_capacity(leaf_indices.len());
        for &leaf_idx in leaf_indices {
            let base = super::key_schedule::GroupKeySchedule::derive_sender_key_base(
                epoch_secret,
                leaf_idx,
                group_context_hash,
            )?;
            chains.push((
                leaf_idx,
                SenderKeyChain::new_with_policy(
                    leaf_idx,
                    base,
                    enhanced,
                    max_generation,
                    max_skipped_per_sender,
                )?,
            ));
        }
        Ok(Self {
            chains,
            skipped_keys: BTreeMap::new(),
            max_skipped_per_sender,
            max_skipped_total: MAX_SKIPPED_SENDER_KEYS,
        })
    }

    pub fn from_chains(
        chains: BTreeMap<u32, SenderKeyChain>,
        max_skipped_per_sender: usize,
    ) -> Self {
        let chains_vec: Vec<(u32, SenderKeyChain)> = chains.into_iter().collect();
        Self {
            chains: chains_vec,
            skipped_keys: BTreeMap::new(),
            max_skipped_per_sender,
            max_skipped_total: MAX_SKIPPED_SENDER_KEYS,
        }
    }

    pub fn get_chain(&self, leaf_index: u32) -> Option<&SenderKeyChain> {
        self.chains
            .iter()
            .find(|(idx, _)| *idx == leaf_index)
            .map(|(_, chain)| chain)
    }

    fn get_chain_mut(&mut self, leaf_index: u32) -> Option<&mut SenderKeyChain> {
        self.chains
            .iter_mut()
            .find(|(idx, _)| *idx == leaf_index)
            .map(|(_, chain)| chain)
    }

    pub fn next_own_message_key(
        &mut self,
        my_leaf_index: u32,
    ) -> Result<(u32, Vec<u8>), ProtocolError> {
        let chain = self
            .get_chain_mut(my_leaf_index)
            .ok_or_else(|| ProtocolError::group_protocol("Own sender key chain not found"))?;
        chain.next_message_key()
    }

    pub fn get_message_key(
        &mut self,
        sender_leaf_index: u32,
        generation: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        if let Some(mut key) = self.skipped_keys.remove(&(sender_leaf_index, generation)) {
            let result = key.clone();
            CryptoInterop::secure_wipe(&mut key);
            return Ok(result);
        }

        let chain = self.get_chain_mut(sender_leaf_index).ok_or_else(|| {
            ProtocolError::group_protocol(format!(
                "No sender key chain for leaf {sender_leaf_index}"
            ))
        })?;

        if generation < chain.generation() {
            return Err(ProtocolError::replay_attack(format!(
                "Generation {generation} already consumed for sender {sender_leaf_index}"
            )));
        }

        if generation == chain.generation() {
            let (_, key) = chain.next_message_key()?;
            return Ok(key);
        }

        let (message_key, skipped) = chain.advance_to(generation)?;
        for (gen, key) in skipped {
            self.skipped_keys.insert((sender_leaf_index, gen), key);
        }
        self.enforce_cache_limit();
        Ok(message_key)
    }

    fn enforce_cache_limit(&mut self) {
        let mut per_sender: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
        for &(sender, gen) in self.skipped_keys.keys() {
            per_sender.entry(sender).or_default().push((sender, gen));
        }
        for (_sender, mut keys) in per_sender {
            if keys.len() > self.max_skipped_per_sender {
                keys.sort_by_key(|&(_, gen)| gen);
                let evict_count = keys.len() - self.max_skipped_per_sender;
                for &key in &keys[..evict_count] {
                    if let Some(mut removed) = self.skipped_keys.remove(&key) {
                        CryptoInterop::secure_wipe(&mut removed);
                    }
                }
            }
        }

        while self.skipped_keys.len() > self.max_skipped_total {
            if let Some((&oldest_key, _)) = self.skipped_keys.iter().next() {
                if let Some(mut removed) = self.skipped_keys.remove(&oldest_key) {
                    CryptoInterop::secure_wipe(&mut removed);
                }
            } else {
                break;
            }
        }
    }

    pub fn export_chains(&self) -> Vec<(u32, Vec<u8>, u32)> {
        self.chains
            .iter()
            .map(|(_, chain)| {
                (
                    chain.leaf_index(),
                    chain.chain_key().to_vec(),
                    chain.generation(),
                )
            })
            .collect()
    }
}
