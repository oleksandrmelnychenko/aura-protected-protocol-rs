// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, KeyInit, MlKem768};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::core::constants::*;
use crate::core::errors::{CryptoError, ProtocolError};
use crate::crypto::{CryptoInterop, HkdfSha256, SecureMemoryHandle};

type Dk = <MlKem768 as Kem>::DecapsulationKey;
type Ek = <MlKem768 as Kem>::EncapsulationKey;
type Ct = ml_kem::Ciphertext<MlKem768>;

struct MlKemRng<'a, R>(&'a mut R);

impl<R> rand_core_next::TryRng for MlKemRng<'_, R>
where
    R: RngCore + CryptoRng,
{
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dst);
        Ok(())
    }
}

impl<R> rand_core_next::TryCryptoRng for MlKemRng<'_, R> where R: RngCore + CryptoRng {}

pub struct KyberInterop;

impl KyberInterop {
    pub const fn install_rng() {}

    pub fn generate_keypair() -> Result<(SecureMemoryHandle, Vec<u8>), CryptoError> {
        let (dk, ek) = MlKem768::generate_keypair();

        let pk_bytes = ek.to_bytes().as_slice().to_vec();
        let sk_bytes = dk.to_bytes();

        let (ct, ss_enc) = ek.encapsulate();
        let ss_dec = dk.decapsulate(&ct);
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
        let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut MlKemRng(&mut rng));

        let pk_bytes = ek.to_bytes().as_slice().to_vec();
        let sk_bytes = dk.to_bytes();
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

        let ek_encoded: ml_kem::Key<Ek> =
            peer_public_key
                .try_into()
                .map_err(|_| CryptoError::KyberFailed {
                    operation,
                    detail: "failed to parse ML-KEM public key bytes".to_string(),
                })?;
        let ek = Ek::new(&ek_encoded).map_err(|_| CryptoError::KyberFailed {
            operation,
            detail: "failed to parse ML-KEM public key bytes".to_string(),
        })?;

        let (ct, ss) = ek.encapsulate_with_rng(&mut MlKemRng(rng));

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
            let dk_encoded: ml_kem::Key<Dk> =
                sk_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::KyberFailed {
                        operation: "decapsulate",
                        detail: "failed to parse ML-KEM secret key bytes".to_string(),
                    })?;
            let dk = Dk::new(&dk_encoded);

            let ct_arr: Ct = ciphertext
                .try_into()
                .map_err(|_| CryptoError::KyberFailed {
                    operation: "decapsulate",
                    detail: "failed to parse ML-KEM ciphertext bytes".to_string(),
                })?;

            let ss = dk.decapsulate(&ct_arr);

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
        let ek_encoded: ml_kem::Key<Ek> = key.try_into().map_err(|_| CryptoError::KyberFailed {
            operation: "validate_public_key",
            detail: "failed to parse ML-KEM public key bytes".to_string(),
        })?;
        let ek = Ek::new(&ek_encoded).map_err(|_| CryptoError::KyberFailed {
            operation: "validate_public_key",
            detail: "failed to parse ML-KEM public key bytes".to_string(),
        })?;
        if ek.to_bytes().as_slice() != key {
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
