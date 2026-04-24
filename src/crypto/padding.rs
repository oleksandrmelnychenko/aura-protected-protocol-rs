// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::MESSAGE_PADDING_BLOCK_SIZE;
use crate::core::errors::ProtocolError;

/// Constant-time "greater than" mask: returns `0xFF` when `a > b`, `0x00` otherwise.
/// Uses wrapping arithmetic to avoid branches entirely.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub(crate) const fn ct_gt_mask(a: usize, b: usize) -> u8 {
    // If a > b then b.wrapping_sub(a) has its MSB set (underflow).
    // Arithmetic shift right fills with the sign bit.
    let diff = b.wrapping_sub(a) as isize;
    // Right-shift by (bits - 1) produces all-ones (-1) when negative, 0 otherwise.
    (diff >> (usize::BITS - 1)) as u8
}

pub struct MessagePadding;

impl MessagePadding {
    pub fn pad(plaintext: &[u8]) -> Vec<u8> {
        let padded_len = Self::padded_length(plaintext.len());
        let mut buf = Vec::with_capacity(padded_len);
        buf.extend_from_slice(plaintext);
        buf.push(0x01);
        buf.resize(padded_len, 0x00);
        buf
    }

    pub fn unpad(padded: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if padded.is_empty() {
            return Err(ProtocolError::decode("Invalid padding: empty input"));
        }
        if padded.len() % MESSAGE_PADDING_BLOCK_SIZE != 0 {
            return Err(ProtocolError::decode("Invalid padding: not block-aligned"));
        }

        // ── Phase 1: find the *last* sentinel byte (0x01) in constant time ──
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
            return Err(ProtocolError::decode(
                "Invalid padding: no sentinel byte found",
            ));
        }

        // ── Phase 2: constant-time check that all bytes after sentinel are 0x00 ──
        // Iterate the *entire* buffer so the loop trip-count is independent of
        // `found_pos`, preventing timing side-channels.
        let mut non_zero_after_sentinel: u8 = 0;
        for (i, &byte) in padded.iter().enumerate() {
            // `after_sentinel` is 0xFF when `i > found_pos`, 0x00 otherwise.
            // Computed with branchless arithmetic to avoid data-dependent branches.
            let after_sentinel = ct_gt_mask(i, found_pos);
            non_zero_after_sentinel |= byte & after_sentinel;
        }
        if non_zero_after_sentinel != 0 {
            return Err(ProtocolError::decode(
                "Invalid padding: non-zero bytes after sentinel",
            ));
        }

        Ok(padded[..found_pos].to_vec())
    }

    const fn padded_length(plaintext_len: usize) -> usize {
        let with_sentinel = plaintext_len + 1;
        let blocks = with_sentinel.div_ceil(MESSAGE_PADDING_BLOCK_SIZE);
        blocks * MESSAGE_PADDING_BLOCK_SIZE
    }
}
