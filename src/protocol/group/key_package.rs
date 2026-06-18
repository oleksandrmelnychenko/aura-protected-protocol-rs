// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::mem::size_of;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{AesGcm, CryptoInterop, KyberInterop, SecureMemoryHandle};
use crate::identity::IdentityKeys;
use crate::proto::GroupKeyPackage;
use crate::security::validation::DhValidator;

pub fn create_key_package(
    identity: &IdentityKeys,
    credential: Vec<u8>,
) -> Result<(GroupKeyPackage, SecureMemoryHandle, SecureMemoryHandle), ProtocolError> {
    let (x25519_private, x25519_public) = CryptoInterop::generate_x25519_keypair("group-leaf")?;
    let (kyber_secret, kyber_public) = KyberInterop::generate_keypair()?;

    if credential.len() > MAX_CREDENTIAL_SIZE {
        return Err(ProtocolError::invalid_input(format!(
            "Credential size {} exceeds maximum {MAX_CREDENTIAL_SIZE} bytes",
            credential.len()
        )));
    }

    let identity_ed25519 = identity.get_identity_ed25519_public();
    let identity_x25519 = identity.get_identity_x25519_public();
    let identity_kyber = identity.get_kyber_public();

    let sign_content = build_signed_content(
        GROUP_PROTOCOL_VERSION,
        &identity_ed25519,
        &identity_x25519,
        &identity_kyber,
        &x25519_public,
        &kyber_public,
        &credential,
    );

    let mut ed25519_secret = identity.get_identity_ed25519_private_key_copy()?;
    let signature = ed25519_sign(&ed25519_secret, &sign_content)?;
    CryptoInterop::secure_wipe(&mut ed25519_secret);

    let kp = GroupKeyPackage {
        version: GROUP_PROTOCOL_VERSION,
        identity_ed25519_public: identity_ed25519,
        identity_x25519_public: identity_x25519,
        identity_kyber_public: identity_kyber,
        leaf_x25519_public: x25519_public,
        leaf_kyber_public: kyber_public,
        signature,
        credential,
        created_at: None,
    };

    Ok((kp, x25519_private, kyber_secret))
}

/// Version + domain-separation AAD for a sealed key-package-secrets blob, so it
/// can only ever be opened back into key-package secrets (never confused with a
/// session/group sealed state) and the on-disk format can evolve.
const KEY_PACKAGE_SECRETS_SEAL_VERSION: u8 = 1;
const KEY_PACKAGE_SECRETS_SEAL_AAD: &[u8] = b"aura-group-key-package-secrets-v1";

/// Seals a key package's PRIVATE secrets (leaf x25519 private key + Kyber decap
/// secret) under a 32-byte at-rest key so the host can PERSIST them across app
/// launches and still process a Welcome that arrives in a later session.
/// Without this the secrets live only in RAM and every cross-session Welcome
/// fails. Mirrors the session/group sealed-state pattern (AES-256-GCM-SIV).
/// Output layout: `version(1) || nonce(12) || AEAD(len16(x)||x || len16(k)||k)`.
pub fn seal_key_package_secrets(
    x25519_private: &SecureMemoryHandle,
    kyber_secret: &SecureMemoryHandle,
    seal_key: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if seal_key.len() != AES_KEY_BYTES {
        return Err(ProtocolError::invalid_input(format!(
            "Seal key must be {AES_KEY_BYTES} bytes"
        )));
    }
    let x = x25519_private
        .read_zeroizing(x25519_private.size())
        .map_err(ProtocolError::from_crypto)?;
    let k = kyber_secret
        .read_zeroizing(kyber_secret.size())
        .map_err(ProtocolError::from_crypto)?;
    if x.len() > u16::MAX as usize || k.len() > u16::MAX as usize {
        return Err(ProtocolError::invalid_input(
            "Key package secret exceeds maximum length",
        ));
    }

    let mut inner = zeroize::Zeroizing::new(Vec::with_capacity(4 + x.len() + k.len()));
    inner.extend_from_slice(&(x.len() as u16).to_be_bytes());
    inner.extend_from_slice(&x);
    inner.extend_from_slice(&(k.len() as u16).to_be_bytes());
    inner.extend_from_slice(&k);

    let nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
    let ciphertext = AesGcm::encrypt(seal_key, &nonce, &inner, KEY_PACKAGE_SECRETS_SEAL_AAD)?;

    let mut out = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    out.push(KEY_PACKAGE_SECRETS_SEAL_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn read_len_prefixed(buf: &[u8], offset: usize) -> Result<(&[u8], usize), ProtocolError> {
    if offset + 2 > buf.len() {
        return Err(ProtocolError::invalid_input(
            "Malformed sealed key package secrets",
        ));
    }
    let len = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    let start = offset + 2;
    let end = start
        .checked_add(len)
        .ok_or_else(|| ProtocolError::invalid_input("Malformed sealed key package secrets"))?;
    if end > buf.len() {
        return Err(ProtocolError::invalid_input(
            "Malformed sealed key package secrets",
        ));
    }
    Ok((&buf[start..end], end))
}

/// Reverses `seal_key_package_secrets`: authenticates + decrypts the blob and
/// rebuilds the two secure-memory handles. A wrong key or tampering fails the
/// AEAD tag check and returns an error (never partial secrets).
pub fn unseal_key_package_secrets(
    sealed: &[u8],
    seal_key: &[u8],
) -> Result<(SecureMemoryHandle, SecureMemoryHandle), ProtocolError> {
    if seal_key.len() != AES_KEY_BYTES {
        return Err(ProtocolError::invalid_input(format!(
            "Seal key must be {AES_KEY_BYTES} bytes"
        )));
    }
    let header = 1 + AES_GCM_NONCE_BYTES;
    if sealed.len() < header + AES_GCM_TAG_BYTES {
        return Err(ProtocolError::invalid_input(
            "Sealed key package secrets too short",
        ));
    }
    if sealed[0] != KEY_PACKAGE_SECRETS_SEAL_VERSION {
        return Err(ProtocolError::invalid_input(
            "Unsupported sealed key package secrets version",
        ));
    }
    let nonce = &sealed[1..header];
    let ciphertext = &sealed[header..];
    let inner = zeroize::Zeroizing::new(AesGcm::decrypt(
        seal_key,
        nonce,
        ciphertext,
        KEY_PACKAGE_SECRETS_SEAL_AAD,
    )?);

    let (x, off1) = read_len_prefixed(&inner, 0)?;
    let (k, off2) = read_len_prefixed(&inner, off1)?;
    if off2 != inner.len() {
        return Err(ProtocolError::invalid_input(
            "Trailing bytes in sealed key package secrets",
        ));
    }

    let mut x_handle = SecureMemoryHandle::allocate(x.len()).map_err(ProtocolError::from_crypto)?;
    x_handle.write(x).map_err(ProtocolError::from_crypto)?;
    let mut k_handle = SecureMemoryHandle::allocate(k.len()).map_err(ProtocolError::from_crypto)?;
    k_handle.write(k).map_err(ProtocolError::from_crypto)?;
    Ok((x_handle, k_handle))
}

pub fn build_signed_content(
    version: u32,
    identity_ed25519_public: &[u8],
    identity_x25519_public: &[u8],
    identity_kyber_public: &[u8],
    leaf_x25519_public: &[u8],
    leaf_kyber_public: &[u8],
    credential: &[u8],
) -> Vec<u8> {
    let mut sign_content = Vec::with_capacity(
        size_of::<u32>()
            + ED25519_PUBLIC_KEY_BYTES
            + X25519_PUBLIC_KEY_BYTES
            + KYBER_PUBLIC_KEY_BYTES
            + X25519_PUBLIC_KEY_BYTES
            + KYBER_PUBLIC_KEY_BYTES
            + credential.len(),
    );
    sign_content.extend_from_slice(&version.to_le_bytes());
    sign_content.extend_from_slice(identity_ed25519_public);
    sign_content.extend_from_slice(identity_x25519_public);
    sign_content.extend_from_slice(identity_kyber_public);
    sign_content.extend_from_slice(leaf_x25519_public);
    sign_content.extend_from_slice(leaf_kyber_public);
    sign_content.extend_from_slice(credential);
    sign_content
}

pub fn validate_key_package(pkg: &GroupKeyPackage) -> Result<(), ProtocolError> {
    if pkg.version != GROUP_PROTOCOL_VERSION {
        return Err(ProtocolError::invalid_input(format!(
            "Unsupported KeyPackage version: {} (expected {})",
            pkg.version, GROUP_PROTOCOL_VERSION
        )));
    }

    if pkg.credential.len() > MAX_CREDENTIAL_SIZE {
        return Err(ProtocolError::invalid_input(format!(
            "Credential size {} exceeds maximum {MAX_CREDENTIAL_SIZE} bytes",
            pkg.credential.len()
        )));
    }

    if pkg.identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 public key size",
        ));
    }
    if pkg.identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid identity X25519 public key size",
        ));
    }
    if pkg.identity_kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid identity Kyber public key size",
        ));
    }
    if pkg.leaf_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid leaf X25519 public key size",
        ));
    }
    if pkg.leaf_kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid leaf Kyber public key size",
        ));
    }
    if pkg.signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::invalid_input("Invalid signature size"));
    }

    DhValidator::validate_x25519_public_key(&pkg.identity_x25519_public)?;
    KyberInterop::validate_public_key(&pkg.identity_kyber_public)?;
    DhValidator::validate_x25519_public_key(&pkg.leaf_x25519_public)?;

    KyberInterop::validate_public_key(&pkg.leaf_kyber_public)?;

    let sign_content = build_signed_content(
        pkg.version,
        &pkg.identity_ed25519_public,
        &pkg.identity_x25519_public,
        &pkg.identity_kyber_public,
        &pkg.leaf_x25519_public,
        &pkg.leaf_kyber_public,
        &pkg.credential,
    );

    ed25519_verify(&pkg.identity_ed25519_public, &pkg.signature, &sign_content)?;

    Ok(())
}

pub fn sign_existing_key_package(
    ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    identity_x25519_public: &[u8],
    identity_kyber_public: &[u8],
    leaf_x25519_public: &[u8],
    leaf_kyber_public: &[u8],
    credential: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let sign_content = build_signed_content(
        GROUP_PROTOCOL_VERSION,
        identity_ed25519_public,
        identity_x25519_public,
        identity_kyber_public,
        leaf_x25519_public,
        leaf_kyber_public,
        credential,
    );
    ed25519_sign(ed25519_secret, &sign_content)
}

fn ed25519_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if secret_key.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 secret key size",
        ));
    }
    let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = secret_key
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 secret key size"))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_array)
        .map_err(|_| ProtocolError::key_generation("Invalid Ed25519 keypair bytes"))?;
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(message);
    Ok(sig.to_bytes().to_vec())
}

fn ed25519_verify(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), ProtocolError> {
    if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 public key size",
        ));
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 signature size",
        ));
    }
    let pk_array: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 public key size"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
        .map_err(|_| ProtocolError::peer_pub_key("Invalid Ed25519 public key"))?;
    let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 signature size"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    vk.verify_strict(message, &sig)
        .map_err(|_| ProtocolError::peer_pub_key("Ed25519 signature verification failed"))
}

#[cfg(test)]
mod key_package_secret_seal_tests {
    use super::*;

    fn secret(byte: u8, len: usize) -> SecureMemoryHandle {
        let mut handle = SecureMemoryHandle::allocate(len).expect("allocate secure memory");
        handle.write(&vec![byte; len]).expect("write secret");
        handle
    }

    #[test]
    fn seal_then_unseal_recovers_both_secrets() {
        let _ = CryptoInterop::initialize();
        let seal_key = [0x11u8; AES_KEY_BYTES];
        // Distinct lengths so a swapped or mis-framed blob would be caught.
        let sealed = seal_key_package_secrets(&secret(0xAA, 32), &secret(0xBB, 64), &seal_key)
            .expect("seal");
        assert_eq!(
            sealed[0], KEY_PACKAGE_SECRETS_SEAL_VERSION,
            "sealed blob must carry the version byte"
        );

        let (rx, rk) = unseal_key_package_secrets(&sealed, &seal_key).expect("unseal");
        assert_eq!(
            rx.read_zeroizing(rx.size()).unwrap().as_slice(),
            vec![0xAAu8; 32].as_slice(),
            "x25519 private secret must round-trip exactly"
        );
        assert_eq!(
            rk.read_zeroizing(rk.size()).unwrap().as_slice(),
            vec![0xBBu8; 64].as_slice(),
            "kyber decap secret must round-trip exactly"
        );
    }

    #[test]
    fn unseal_with_wrong_key_fails() {
        let _ = CryptoInterop::initialize();
        let sealed =
            seal_key_package_secrets(&secret(0x01, 32), &secret(0x02, 64), &[0x11u8; AES_KEY_BYTES])
                .expect("seal");
        assert!(
            unseal_key_package_secrets(&sealed, &[0x22u8; AES_KEY_BYTES]).is_err(),
            "a secret sealed under one key must not open under another"
        );
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let _ = CryptoInterop::initialize();
        let seal_key = [0x11u8; AES_KEY_BYTES];
        let mut sealed = seal_key_package_secrets(&secret(0x01, 32), &secret(0x02, 64), &seal_key)
            .expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(
            unseal_key_package_secrets(&sealed, &seal_key).is_err(),
            "the AEAD tag must reject a flipped ciphertext bit"
        );
    }

    #[test]
    fn unseal_rejects_unknown_version() {
        let _ = CryptoInterop::initialize();
        let seal_key = [0x11u8; AES_KEY_BYTES];
        let mut sealed = seal_key_package_secrets(&secret(0x01, 32), &secret(0x02, 64), &seal_key)
            .expect("seal");
        sealed[0] = 0xFE;
        assert!(
            unseal_key_package_secrets(&sealed, &seal_key).is_err(),
            "an unknown version byte must be rejected"
        );
    }

    #[test]
    fn seal_rejects_non_32_byte_key() {
        let _ = CryptoInterop::initialize();
        assert!(
            seal_key_package_secrets(&secret(0x01, 32), &secret(0x02, 64), &[0u8; 16]).is_err(),
            "a seal key that is not AES_KEY_BYTES long must be rejected"
        );
    }
}
