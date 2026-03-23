use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{HkdfSha256, SecureMemoryHandle};
use zeroize::Zeroizing;

pub struct MediaKeyRatchet {
    chain_key: SecureMemoryHandle,
    generation: u32,
    nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
}

pub struct RatchetedKey {
    pub media_key: Zeroizing<Vec<u8>>,
    pub generation: u32,
}

pub struct RatchetSnapshot {
    pub(crate) chain_bytes: Vec<u8>,
    pub(crate) generation: u32,
}

type DerivedGeneration = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

fn derive_at_generation(
    chain_bytes: &[u8],
    generation: u32,
    nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
) -> Result<DerivedGeneration, ProtocolError> {
    let gen_bytes = generation.to_le_bytes();
    let mut salt = Vec::with_capacity(VOIP_NONCE_PREFIX_BYTES + gen_bytes.len());
    salt.extend_from_slice(&nonce_prefix);
    salt.extend_from_slice(&gen_bytes);

    let output_key = HkdfSha256::derive_key_bytes(
        chain_bytes,
        VOIP_MEDIA_KEY_BYTES,
        &salt,
        VOIP_RATCHET_CHAIN_INFO,
    )?;

    let next_chain = HkdfSha256::derive_key_bytes(
        chain_bytes,
        VOIP_MEDIA_KEY_BYTES,
        &salt,
        b"Ecliptix-VoIP-NextChain",
    )?;

    Ok((output_key, next_chain))
}

fn derive_frame_key_at_generation(
    chain_bytes: &[u8],
    generation: u32,
    nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
    frame_counter: u64,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let (generation_key, _) = derive_at_generation(chain_bytes, generation, nonce_prefix)?;
    HkdfSha256::derive_key_bytes(
        &generation_key,
        VOIP_MEDIA_KEY_BYTES,
        &frame_counter.to_le_bytes(),
        VOIP_FRAME_KEY_INFO,
    )
}

impl MediaKeyRatchet {
    pub const fn new(
        initial_key: SecureMemoryHandle,
        nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
    ) -> Self {
        Self {
            chain_key: initial_key,
            generation: 0,
            nonce_prefix,
        }
    }

    pub fn from_state(
        chain_bytes: &[u8],
        generation: u32,
        nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
    ) -> Result<Self, ProtocolError> {
        if chain_bytes.len() != VOIP_MEDIA_KEY_BYTES {
            return Err(ProtocolError::voip_media("invalid ratchet chain key size"));
        }

        let mut handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        handle
            .write(chain_bytes)
            .map_err(ProtocolError::from_crypto)?;

        Ok(Self {
            chain_key: handle,
            generation,
            nonce_prefix,
        })
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn nonce_prefix(&self) -> &[u8; VOIP_NONCE_PREFIX_BYTES] {
        &self.nonce_prefix
    }

    pub fn advance(&mut self) -> Result<RatchetedKey, ProtocolError> {
        if self.generation >= MAX_RATCHET_GENERATION {
            return Err(ProtocolError::voip_media(
                "media key ratchet generation exhausted",
            ));
        }

        let chain_bytes = self
            .chain_key
            .read_bytes(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;

        let (output_key, next_chain) =
            derive_at_generation(&chain_bytes, self.generation, self.nonce_prefix)?;

        let mut new_handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        new_handle
            .write(&next_chain)
            .map_err(ProtocolError::from_crypto)?;

        self.chain_key = new_handle;
        let current_gen = self.generation;
        self.generation += 1;

        Ok(RatchetedKey {
            media_key: output_key,
            generation: current_gen,
        })
    }

    pub fn advance_generation(&mut self) -> Result<u32, ProtocolError> {
        let _ = self.advance()?;
        Ok(self.generation)
    }

    pub fn advance_to(&mut self, target_generation: u32) -> Result<RatchetedKey, ProtocolError> {
        if target_generation < self.generation {
            return Err(ProtocolError::voip_media(format!(
                "cannot ratchet backwards: current={}, target={}",
                self.generation, target_generation
            )));
        }

        let skip_count = target_generation - self.generation;
        if skip_count > MAX_SKIPPED_RATCHET_GENERATIONS {
            return Err(ProtocolError::voip_media(format!(
                "ratchet skip too large: {skip_count} exceeds max {MAX_SKIPPED_RATCHET_GENERATIONS}"
            )));
        }

        for _ in 0..skip_count {
            let _ = self.advance()?;
        }

        self.advance()
    }

    pub fn snapshot(&self) -> Result<RatchetSnapshot, ProtocolError> {
        let chain_bytes = self
            .chain_key
            .read_bytes(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        Ok(RatchetSnapshot {
            chain_bytes,
            generation: self.generation,
        })
    }

    pub fn frame_key(&self, frame_counter: u64) -> Result<RatchetedKey, ProtocolError> {
        let snapshot = self.snapshot()?;
        let media_key = derive_frame_key_at_generation(
            &snapshot.chain_bytes,
            snapshot.generation,
            self.nonce_prefix,
            frame_counter,
        )?;
        Ok(RatchetedKey {
            media_key,
            generation: snapshot.generation,
        })
    }

    pub fn speculative_sync_to(
        &self,
        target_generation: u32,
    ) -> Result<RatchetSnapshot, ProtocolError> {
        if target_generation < self.generation {
            return Err(ProtocolError::voip_media(format!(
                "cannot ratchet backwards: current={}, target={}",
                self.generation, target_generation
            )));
        }

        let skip_count = target_generation - self.generation;
        if skip_count > MAX_SKIPPED_RATCHET_GENERATIONS {
            return Err(ProtocolError::voip_media(format!(
                "ratchet skip too large: {skip_count} exceeds max {MAX_SKIPPED_RATCHET_GENERATIONS}"
            )));
        }

        let mut current_chain = self
            .chain_key
            .read_bytes(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut current_gen = self.generation;

        for _ in 0..skip_count {
            let (_, next) = derive_at_generation(&current_chain, current_gen, self.nonce_prefix)?;
            current_chain = next.to_vec();
            current_gen += 1;
        }

        Ok(RatchetSnapshot {
            chain_bytes: current_chain,
            generation: current_gen,
        })
    }

    pub fn speculative_advance_to(
        &self,
        target_generation: u32,
    ) -> Result<(RatchetedKey, RatchetSnapshot), ProtocolError> {
        if target_generation < self.generation {
            return Err(ProtocolError::voip_media(format!(
                "cannot ratchet backwards: current={}, target={}",
                self.generation, target_generation
            )));
        }

        let skip_count = target_generation - self.generation;
        if skip_count > MAX_SKIPPED_RATCHET_GENERATIONS {
            return Err(ProtocolError::voip_media(format!(
                "ratchet skip too large: {skip_count} exceeds max {MAX_SKIPPED_RATCHET_GENERATIONS}"
            )));
        }

        let mut current_chain = self
            .chain_key
            .read_bytes(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut current_gen = self.generation;

        for _ in 0..skip_count {
            let (_, next) = derive_at_generation(&current_chain, current_gen, self.nonce_prefix)?;
            current_chain = next.to_vec();
            current_gen += 1;
        }

        let (output_key, next_chain) =
            derive_at_generation(&current_chain, current_gen, self.nonce_prefix)?;

        Ok((
            RatchetedKey {
                media_key: output_key,
                generation: current_gen,
            },
            RatchetSnapshot {
                chain_bytes: next_chain.to_vec(),
                generation: current_gen + 1,
            },
        ))
    }

    pub fn speculative_frame_key(
        &self,
        target_generation: u32,
        frame_counter: u64,
    ) -> Result<(RatchetedKey, RatchetSnapshot), ProtocolError> {
        let snapshot = self.speculative_sync_to(target_generation)?;
        let media_key = derive_frame_key_at_generation(
            &snapshot.chain_bytes,
            snapshot.generation,
            self.nonce_prefix,
            frame_counter,
        )?;
        Ok((
            RatchetedKey {
                media_key,
                generation: snapshot.generation,
            },
            snapshot,
        ))
    }

    pub fn commit_snapshot(&mut self, snapshot: RatchetSnapshot) -> Result<(), ProtocolError> {
        let mut new_handle = SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        new_handle
            .write(&snapshot.chain_bytes)
            .map_err(ProtocolError::from_crypto)?;
        self.chain_key = new_handle;
        self.generation = snapshot.generation;
        Ok(())
    }

    pub fn reset(
        &mut self,
        new_key: SecureMemoryHandle,
        new_nonce_prefix: [u8; VOIP_NONCE_PREFIX_BYTES],
    ) {
        self.chain_key = new_key;
        self.generation = 0;
        self.nonce_prefix = new_nonce_prefix;
    }

    pub const fn set_generation(&mut self, gen: u32) {
        self.generation = gen;
    }
}
