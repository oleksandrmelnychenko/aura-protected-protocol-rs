use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::padding::ct_gt_mask;
use crate::crypto::AesGcm;

pub struct MediaCrypto;

impl MediaCrypto {
    pub fn build_nonce(
        nonce_prefix: &[u8; VOIP_NONCE_PREFIX_BYTES],
        frame_counter: u64,
    ) -> [u8; VOIP_MEDIA_NONCE_BYTES] {
        let mut nonce = [0u8; VOIP_MEDIA_NONCE_BYTES];
        nonce[..VOIP_NONCE_PREFIX_BYTES].copy_from_slice(nonce_prefix);
        let counter_bytes = frame_counter.to_be_bytes();
        nonce[VOIP_NONCE_PREFIX_BYTES..].copy_from_slice(&counter_bytes);
        nonce
    }

    pub fn encrypt_frame(
        media_key: &[u8],
        nonce_prefix: &[u8; VOIP_NONCE_PREFIX_BYTES],
        frame_counter: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if media_key.len() != VOIP_MEDIA_KEY_BYTES {
            return Err(ProtocolError::voip_media("invalid media key size"));
        }
        if plaintext.is_empty() {
            return Err(ProtocolError::voip_media("empty frame payload"));
        }
        if plaintext.len() > MAX_VOIP_FRAME_SIZE {
            return Err(ProtocolError::voip_media("frame payload too large"));
        }
        if frame_counter > MAX_FRAME_COUNTER {
            return Err(ProtocolError::voip_media("frame counter overflow"));
        }

        let padded = pad_frame(plaintext);
        let nonce_bytes = Self::build_nonce(nonce_prefix, frame_counter);

        AesGcm::encrypt(media_key, &nonce_bytes, &padded, aad)
            .map_err(|_| ProtocolError::voip_media("AES-256-GCM-SIV frame encryption failed"))
    }

    pub fn decrypt_frame(
        media_key: &[u8],
        nonce_prefix: &[u8; VOIP_NONCE_PREFIX_BYTES],
        frame_counter: u64,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if media_key.len() != VOIP_MEDIA_KEY_BYTES {
            return Err(ProtocolError::voip_media("invalid media key size"));
        }
        if ciphertext.len() < AES_GCM_TAG_BYTES {
            return Err(ProtocolError::voip_media("ciphertext too small"));
        }
        if frame_counter > MAX_FRAME_COUNTER {
            return Err(ProtocolError::voip_media("frame counter overflow"));
        }

        let nonce_bytes = Self::build_nonce(nonce_prefix, frame_counter);

        let padded = AesGcm::decrypt(media_key, &nonce_bytes, ciphertext, aad).map_err(|_| {
            ProtocolError::voip_media("frame authentication failed — tampered data")
        })?;

        unpad_frame(&padded)
    }

    pub fn encrypt_header(
        header_key: &[u8],
        nonce_prefix: &[u8; VOIP_NONCE_PREFIX_BYTES],
        frame_counter: u64,
        header: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if header_key.len() != VOIP_HEADER_KEY_BYTES {
            return Err(ProtocolError::voip_media("invalid header key size"));
        }

        let nonce_bytes = Self::build_nonce(nonce_prefix, frame_counter);
        let mut header_nonce = nonce_bytes;
        header_nonce[0] ^= 0xFF;

        AesGcm::encrypt(header_key, &header_nonce, header, &[])
            .map_err(|_| ProtocolError::voip_media("header encryption failed"))
    }

    pub fn decrypt_header(
        header_key: &[u8],
        nonce_prefix: &[u8; VOIP_NONCE_PREFIX_BYTES],
        frame_counter: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if header_key.len() != VOIP_HEADER_KEY_BYTES {
            return Err(ProtocolError::voip_media("invalid header key size"));
        }
        if ciphertext.len() < AES_GCM_TAG_BYTES {
            return Err(ProtocolError::voip_media("header ciphertext too small"));
        }

        let nonce_bytes = Self::build_nonce(nonce_prefix, frame_counter);
        let mut header_nonce = nonce_bytes;
        header_nonce[0] ^= 0xFF;

        AesGcm::decrypt(header_key, &header_nonce, ciphertext, &[])
            .map_err(|_| ProtocolError::voip_media("header authentication failed"))
    }
}

fn pad_frame(data: &[u8]) -> Vec<u8> {
    let padded_len = {
        let with_sentinel = data.len() + 1;
        let blocks = with_sentinel.div_ceil(VOIP_FRAME_PADDING_BLOCK);
        blocks * VOIP_FRAME_PADDING_BLOCK
    };
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(data);
    buf.push(0x01);
    buf.resize(padded_len, 0x00);
    buf
}

fn unpad_frame(padded: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if padded.is_empty() {
        return Err(ProtocolError::voip_media("invalid padding: empty"));
    }
    if padded.len() % VOIP_FRAME_PADDING_BLOCK != 0 {
        return Err(ProtocolError::voip_media("invalid padding: not aligned"));
    }

    let mut found_pos: usize = 0;
    let mut found: usize = 0;
    for (i, &byte) in padded.iter().enumerate() {
        let diff = byte ^ 0x01;
        let is_nonzero = ((u16::from(diff) | u16::from(diff).wrapping_neg()) >> 7) as usize & 1;
        let mask = is_nonzero.wrapping_sub(1);
        found_pos = (found_pos & !mask) | (i & mask);
        found |= mask & 1;
    }
    if found == 0 {
        return Err(ProtocolError::voip_media(
            "invalid padding: no sentinel found",
        ));
    }
    // Iterate the *entire* buffer so the loop trip-count is independent of
    // `found_pos`, preventing a plaintext-length-dependent timing side-channel
    // on VoIP frames (the attacker could otherwise distinguish active speech
    // from silence by measuring decrypt latency). Mirrors `MessagePadding::unpad`.
    let mut non_zero_after = 0u8;
    for (i, &byte) in padded.iter().enumerate() {
        // `after_sentinel` is 0xFF when `i > found_pos`, 0x00 otherwise.
        let after_sentinel = ct_gt_mask(i, found_pos);
        non_zero_after |= byte & after_sentinel;
    }
    if non_zero_after != 0 {
        return Err(ProtocolError::voip_media(
            "invalid padding: non-zero after sentinel",
        ));
    }
    Ok(padded[..found_pos].to_vec())
}
