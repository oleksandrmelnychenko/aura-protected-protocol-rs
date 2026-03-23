// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::{HMAC_BYTES, MAX_SHARE_SIZE};
use crate::core::errors::ProtocolError;
use crate::crypto::CryptoInterop;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const MAGIC_BYTES: [u8; 4] = [0xEC, 0x11, 0x1C, 0x00];
const SHARE_HEADER_SIZE: usize = MAGIC_BYTES.len() + 1;
const MIN_SHARE_SIZE: usize = SHARE_HEADER_SIZE + 1;
const GF256_MODULUS: u16 = 0x11B;
const GF256_OVERFLOW: u16 = 0x100;

#[allow(clippy::cast_possible_truncation)]
static EXP_TABLE: [u8; 512] = {
    let mut table = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0usize;
    while i < 512 {
        table[i] = val as u8;
        val = (val << 1) ^ val;
        if val & GF256_OVERFLOW != 0 {
            val ^= GF256_MODULUS;
        }
        i += 1;
    }
    table
};

#[allow(clippy::cast_possible_truncation)]
static LOG_TABLE: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0u16;
    while i < 255 {
        let exp_val = EXP_TABLE[i as usize];
        table[exp_val as usize] = i as u8;
        i += 1;
    }
    table
};

#[allow(clippy::cast_possible_truncation)]
fn gf_mul(a: u8, b: u8) -> u8 {
    let log_sum = u16::from(LOG_TABLE[a as usize]) + u16::from(LOG_TABLE[b as usize]);
    let result = EXP_TABLE[log_sum as usize];
    let mask = (u16::from(a).wrapping_sub(1) >> 8) | (u16::from(b).wrapping_sub(1) >> 8);
    result & (!mask as u8)
}

#[allow(clippy::cast_possible_truncation)]
fn gf_inv(a: u8) -> u8 {
    let log_a = u16::from(LOG_TABLE[a as usize]);
    let result = EXP_TABLE[(255 - log_a) as usize];
    let mask = u16::from(a).wrapping_sub(1) >> 8;
    result & (!mask as u8)
}

fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    for &coef in coefficients.iter().rev() {
        result = gf_mul(result, x) ^ coef;
    }
    result
}

fn lagrange_interpolate(x_values: &[u8], y_values: &[u8], x: u8) -> Result<u8, ProtocolError> {
    let n = x_values.len();
    if n != y_values.len() {
        return Err(ProtocolError::generic(
            "x/y length mismatch in Lagrange interpolation",
        ));
    }
    let mut result: u8 = 0;
    for i in 0..n {
        let mut numerator: u8 = y_values[i];
        let mut denominator: u8 = 1;
        for j in 0..n {
            let is_same = u8::from((i ^ j) == 0);
            let num_factor = (x ^ x_values[j]) | is_same.wrapping_neg();
            let den_factor = (x_values[i] ^ x_values[j]) | is_same.wrapping_neg();
            let num_product = gf_mul(numerator, num_factor);
            let den_product = gf_mul(denominator, den_factor);
            let mask = is_same.wrapping_neg();
            numerator = (numerator & mask) | (num_product & !mask);
            denominator = (denominator & mask) | (den_product & !mask);
        }
        result ^= gf_mul(numerator, gf_inv(denominator));
    }
    Ok(result)
}

pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    pub fn split(
        secret: &[u8],
        threshold: u8,
        share_count: u8,
        auth_key: &[u8],
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        if threshold < 2 {
            return Err(ProtocolError::invalid_input("Threshold must be at least 2"));
        }
        if share_count < threshold {
            return Err(ProtocolError::invalid_input(
                "share_count must be >= threshold",
            ));
        }
        if secret.is_empty() || secret.len() > MAX_SHARE_SIZE {
            return Err(ProtocolError::invalid_input("Invalid secret length"));
        }
        if auth_key.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input("Auth key must be 32 bytes"));
        }

        let share_count_usize = share_count as usize;
        let share_size = SHARE_HEADER_SIZE + secret.len();
        let mut shares: Vec<Vec<u8>> = (0..share_count_usize)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let x = (i as u8) + 1;
                let mut s = Vec::with_capacity(share_size);
                s.extend_from_slice(&MAGIC_BYTES);
                s.push(x);
                s
            })
            .collect();

        for &secret_byte in secret {
            let mut coefficients = vec![secret_byte];
            let mut rand = CryptoInterop::get_random_bytes((threshold - 1) as usize);
            coefficients.extend_from_slice(&rand);
            CryptoInterop::secure_wipe(&mut rand);

            for (share_idx, share) in shares.iter_mut().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                let x = (share_idx as u8) + 1;
                let y = evaluate_polynomial(&coefficients, x);
                share.push(y);
            }
            CryptoInterop::secure_wipe(&mut coefficients);
        }

        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|_| ProtocolError::generic("HMAC key init failed"))?;
        mac.update(secret);
        let auth_tag = mac.finalize().into_bytes();
        shares.push(auth_tag.to_vec());

        Ok(shares)
    }

    pub fn reconstruct(
        shares: &[Vec<u8>],
        auth_key: &[u8],
        threshold: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if shares.len() < 2 {
            return Err(ProtocolError::invalid_input(
                "Need at least one data share plus auth tag",
            ));
        }
        if auth_key.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input("Auth key must be 32 bytes"));
        }

        let auth_tag = shares
            .last()
            .ok_or_else(|| ProtocolError::invalid_input("Empty shares list"))?;
        let data_shares = &shares[..shares.len() - 1];

        if data_shares.len() < threshold {
            return Err(ProtocolError::invalid_input("Not enough shares"));
        }

        let first_len = data_shares[0].len();
        if first_len < MIN_SHARE_SIZE {
            return Err(ProtocolError::invalid_input("Share too short"));
        }
        for share in data_shares {
            if share.len() != first_len || share[0..4] != MAGIC_BYTES {
                return Err(ProtocolError::invalid_input("Invalid share format"));
            }
        }

        let share_header_len = SHARE_HEADER_SIZE;
        let secret_len = first_len - share_header_len;
        let mut secret = vec![0u8; secret_len];
        let x_values: Vec<u8> = data_shares.iter().map(|s| s[MAGIC_BYTES.len()]).collect();

        let mut seen_x = [false; 256];
        for &x in &x_values {
            if seen_x[x as usize] {
                return Err(ProtocolError::invalid_input(
                    "Duplicate x-coordinate in shares",
                ));
            }
            seen_x[x as usize] = true;
        }

        for byte_idx in 0..secret_len {
            let y_values: Vec<u8> = data_shares
                .iter()
                .map(|s| s[share_header_len + byte_idx])
                .collect();
            secret[byte_idx] = lagrange_interpolate(&x_values, &y_values, 0)?;
        }

        let mut mac = HmacSha256::new_from_slice(auth_key)
            .map_err(|_| ProtocolError::generic("HMAC key init failed"))?;
        mac.update(&secret);
        let expected = mac.finalize().into_bytes();
        if !CryptoInterop::constant_time_equals(auth_tag, &expected).unwrap_or(false) {
            CryptoInterop::secure_wipe(&mut secret);
            return Err(ProtocolError::invalid_input("Share authentication failed"));
        }

        Ok(secret)
    }

    pub fn reconstruct_serialized(
        serialized: &[u8],
        share_length: usize,
        share_count: usize,
        auth_key: &[u8],
        threshold: usize,
    ) -> Result<Vec<u8>, ProtocolError> {
        if serialized.len() != share_length * share_count {
            return Err(ProtocolError::invalid_input(
                "Invalid serialized shares length",
            ));
        }
        let shares: Vec<Vec<u8>> = (0..share_count)
            .map(|i| serialized[i * share_length..(i + 1) * share_length].to_vec())
            .collect();
        Self::reconstruct(&shares, auth_key, threshold)
    }
}
