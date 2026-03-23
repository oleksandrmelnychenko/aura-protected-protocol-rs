// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::mem::size_of;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, KyberInterop, SecureMemoryHandle};
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

    let sign_content = build_signed_content(
        GROUP_PROTOCOL_VERSION,
        &identity_ed25519,
        &identity_x25519,
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
        leaf_x25519_public: x25519_public,
        leaf_kyber_public: kyber_public,
        signature,
        credential,
        created_at: None,
    };

    Ok((kp, x25519_private, kyber_secret))
}

pub fn build_signed_content(
    version: u32,
    identity_ed25519_public: &[u8],
    identity_x25519_public: &[u8],
    leaf_x25519_public: &[u8],
    leaf_kyber_public: &[u8],
    credential: &[u8],
) -> Vec<u8> {
    let mut sign_content = Vec::with_capacity(
        size_of::<u32>()
            + ED25519_PUBLIC_KEY_BYTES
            + X25519_PUBLIC_KEY_BYTES
            + X25519_PUBLIC_KEY_BYTES
            + KYBER_PUBLIC_KEY_BYTES
            + credential.len(),
    );
    sign_content.extend_from_slice(&version.to_le_bytes());
    sign_content.extend_from_slice(identity_ed25519_public);
    sign_content.extend_from_slice(identity_x25519_public);
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
    DhValidator::validate_x25519_public_key(&pkg.leaf_x25519_public)?;

    KyberInterop::validate_public_key(&pkg.leaf_kyber_public)?;

    let sign_content = build_signed_content(
        pkg.version,
        &pkg.identity_ed25519_public,
        &pkg.identity_x25519_public,
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
    leaf_x25519_public: &[u8],
    leaf_kyber_public: &[u8],
    credential: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let sign_content = build_signed_content(
        GROUP_PROTOCOL_VERSION,
        identity_ed25519_public,
        identity_x25519_public,
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
    use ed25519_dalek::Verifier;
    vk.verify(message, &sig)
        .map_err(|_| ProtocolError::peer_pub_key("Ed25519 signature verification failed"))
}
