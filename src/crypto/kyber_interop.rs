// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::core::constants::*;
use crate::core::errors::{CryptoError, ProtocolError};
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle};

type Dk = <MlKem768 as KemCore>::DecapsulationKey;
type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Ct = ml_kem::Ciphertext<MlKem768>;

pub struct KyberInterop;

impl KyberInterop {
    pub const fn install_rng() {}

    pub fn generate_keypair() -> Result<(SecureMemoryHandle, Vec<u8>), CryptoError> {
        let (dk, ek) = MlKem768::generate(&mut OsRng);

        let pk_bytes = ek.as_bytes().as_slice().to_vec();
        let sk_bytes = dk.as_bytes();

        let (ct, ss_enc) = ek
            .encapsulate(&mut OsRng)
            .map_err(|()| CryptoError::KyberFailed {
                operation: "self-test/encapsulate",
                detail: "ML-KEM-768 encapsulation failed".to_string(),
            })?;
        let ss_dec = dk.decapsulate(&ct).map_err(|()| CryptoError::KyberFailed {
            operation: "self-test/decapsulate",
            detail: "ML-KEM-768 decapsulation failed".to_string(),
        })?;
        if !bool::from(ss_enc.as_slice().ct_eq(ss_dec.as_slice())) {
            return Err(CryptoError::KyberFailed {
                operation: "self-test",
                detail: "encapsulate/decapsulate shared secrets do not match".to_string(),
            });
        }

        let mut sk_handle = SecureMemoryHandle::allocate(sk_bytes.as_slice().len())?;
        sk_handle.write(sk_bytes.as_slice())?;
        Ok((sk_handle, pk_bytes))
    }

    pub fn generate_keypair_from_seed(
        seed: &[u8],
    ) -> Result<(SecureMemoryHandle, Vec<u8>), CryptoError> {
        if seed.len() < KYBER_SEED_KEY_BYTES {
            return Err(CryptoError::KyberFailed {
                operation: "generate_keypair_from_seed",
                detail: format!(
                    "seed too short: expected at least {} bytes, got {}",
                    KYBER_SEED_KEY_BYTES,
                    seed.len()
                ),
            });
        }
        let seed_array: [u8; KYBER_SEED_KEY_BYTES] = seed[..KYBER_SEED_KEY_BYTES]
            .try_into()
            .map_err(|_| CryptoError::KyberFailed {
                operation: "generate_keypair_from_seed",
                detail: "seed slice to array conversion failed".to_string(),
            })?;
        let mut rng = ChaCha20Rng::from_seed(seed_array);
        let (dk, ek) = MlKem768::generate(&mut rng);

        let pk_bytes = ek.as_bytes().as_slice().to_vec();
        let sk_bytes = dk.as_bytes();
        let mut sk_handle = SecureMemoryHandle::allocate(sk_bytes.as_slice().len())?;
        sk_handle.write(sk_bytes.as_slice())?;
        Ok((sk_handle, pk_bytes))
    }

    fn encapsulate_with_rng<R: CryptoRng + RngCore>(
        peer_public_key: &[u8],
        rng: &mut R,
        operation: &'static str,
    ) -> Result<(Vec<u8>, SecureMemoryHandle), CryptoError> {
        if peer_public_key.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(CryptoError::KyberFailed {
                operation,
                detail: format!(
                    "invalid public key size: expected {} bytes, got {}",
                    KYBER_PUBLIC_KEY_BYTES,
                    peer_public_key.len()
                ),
            });
        }

        let ek_encoded: &ml_kem::Encoded<Ek> =
            peer_public_key
                .try_into()
                .map_err(|_| CryptoError::KyberFailed {
                    operation,
                    detail: "failed to parse ML-KEM public key bytes".to_string(),
                })?;
        let ek = Ek::from_bytes(ek_encoded);

        let (ct, ss) = ek.encapsulate(rng).map_err(|()| CryptoError::KyberFailed {
            operation,
            detail: "ML-KEM-768 encapsulation failed".to_string(),
        })?;

        let ct_bytes = ct.as_slice().to_vec();
        let mut ss_handle = SecureMemoryHandle::allocate(KYBER_SHARED_SECRET_BYTES)?;
        ss_handle.write(ss.as_slice())?;
        Ok((ct_bytes, ss_handle))
    }

    pub fn encapsulate(
        peer_public_key: &[u8],
    ) -> Result<(Vec<u8>, SecureMemoryHandle), CryptoError> {
        Self::encapsulate_with_rng(peer_public_key, &mut OsRng, "encapsulate")
    }

    #[cfg(feature = "test-vectors")]
    #[doc(hidden)]
    pub fn encapsulate_from_seed(
        peer_public_key: &[u8],
        seed: &[u8],
    ) -> Result<(Vec<u8>, SecureMemoryHandle), CryptoError> {
        if seed.len() < KYBER_SEED_KEY_BYTES {
            return Err(CryptoError::KyberFailed {
                operation: "encapsulate_from_seed",
                detail: format!(
                    "seed too short: expected at least {} bytes, got {}",
                    KYBER_SEED_KEY_BYTES,
                    seed.len()
                ),
            });
        }
        let seed_array: [u8; KYBER_SEED_KEY_BYTES] = seed[..KYBER_SEED_KEY_BYTES]
            .try_into()
            .map_err(|_| CryptoError::KyberFailed {
                operation: "encapsulate_from_seed",
                detail: "seed slice to array conversion failed".to_string(),
            })?;
        let mut rng = ChaCha20Rng::from_seed(seed_array);
        Self::encapsulate_with_rng(peer_public_key, &mut rng, "encapsulate_from_seed")
    }

    pub fn decapsulate(
        ciphertext: &[u8],
        secret_key_handle: &SecureMemoryHandle,
    ) -> Result<SecureMemoryHandle, CryptoError> {
        if ciphertext.len() != KYBER_CIPHERTEXT_BYTES {
            return Err(CryptoError::KyberFailed {
                operation: "decapsulate",
                detail: format!(
                    "invalid ciphertext size: expected {} bytes, got {}",
                    KYBER_CIPHERTEXT_BYTES,
                    ciphertext.len()
                ),
            });
        }

        let mut sk_bytes = secret_key_handle.read_bytes(KYBER_SECRET_KEY_BYTES)?;
        let result = (|| -> Result<SecureMemoryHandle, CryptoError> {
            let dk_encoded: &ml_kem::Encoded<Dk> =
                sk_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::KyberFailed {
                        operation: "decapsulate",
                        detail: "failed to parse ML-KEM secret key bytes".to_string(),
                    })?;
            let dk = Dk::from_bytes(dk_encoded);

            let ct_arr: &Ct = ciphertext
                .try_into()
                .map_err(|_| CryptoError::KyberFailed {
                    operation: "decapsulate",
                    detail: "failed to parse ML-KEM ciphertext bytes".to_string(),
                })?;

            let ss = dk
                .decapsulate(ct_arr)
                .map_err(|()| CryptoError::KyberFailed {
                    operation: "decapsulate",
                    detail: "ML-KEM-768 decapsulation failed".to_string(),
                })?;

            let mut ss_handle = SecureMemoryHandle::allocate(KYBER_SHARED_SECRET_BYTES)?;
            ss_handle.write(ss.as_slice())?;
            Ok(ss_handle)
        })();
        CryptoInterop::secure_wipe(&mut sk_bytes);
        result
    }

    pub fn validate_public_key(key: &[u8]) -> Result<(), CryptoError> {
        if key.len() != KYBER_PUBLIC_KEY_BYTES {
            return Err(CryptoError::KyberFailed {
                operation: "validate_public_key",
                detail: format!(
                    "invalid public key size: expected {} bytes, got {}",
                    KYBER_PUBLIC_KEY_BYTES,
                    key.len()
                ),
            });
        }
        if key.iter().all(|&b| b == 0) {
            return Err(CryptoError::KyberFailed {
                operation: "validate_public_key",
                detail: "degenerate all-zero public key".to_string(),
            });
        }
        let ek_encoded: &ml_kem::Encoded<Ek> =
            key.try_into().map_err(|_| CryptoError::KyberFailed {
                operation: "validate_public_key",
                detail: "failed to parse ML-KEM public key bytes".to_string(),
            })?;
        let ek = Ek::from_bytes(ek_encoded);
        if ek.as_bytes().as_slice() != key {
            return Err(CryptoError::KyberFailed {
                operation: "validate_public_key",
                detail: "public key fails re-encoding structural check".to_string(),
            });
        }
        Ok(())
    }

    pub fn validate_ciphertext(ct: &[u8]) -> Result<(), CryptoError> {
        if ct.len() != KYBER_CIPHERTEXT_BYTES {
            return Err(CryptoError::KyberFailed {
                operation: "validate_ciphertext",
                detail: format!(
                    "invalid ciphertext size: expected {} bytes, got {}",
                    KYBER_CIPHERTEXT_BYTES,
                    ct.len()
                ),
            });
        }
        if ct.iter().all(|&b| b == 0) {
            return Err(CryptoError::KyberFailed {
                operation: "validate_ciphertext",
                detail: "degenerate all-zero ciphertext".to_string(),
            });
        }
        Ok(())
    }

    pub fn combine_hybrid_secrets(
        classical_secret: &[u8],
        kyber_secret: &[u8],
        out_len: usize,
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut salt = Vec::with_capacity(HYBRID_SALT_PREFIX.len() + classical_secret.len());
        salt.extend_from_slice(HYBRID_SALT_PREFIX);
        salt.extend_from_slice(classical_secret);
        let result = HkdfSha256::derive_key_bytes(kyber_secret, out_len, &salt, info);
        CryptoInterop::secure_wipe(&mut salt);
        result
    }
}
