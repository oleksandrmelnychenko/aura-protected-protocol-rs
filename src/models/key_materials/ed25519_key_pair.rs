// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use zeroize::Zeroize;

use crate::core::constants::{
    ED25519_PUBLIC_KEY_BYTES, ED25519_SECRET_KEY_BYTES, ED25519_SIGNATURE_BYTES,
};
use crate::core::errors::{CryptoError, ProtocolError};
use crate::crypto::{CryptoInterop, SecureMemoryHandle};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub struct Ed25519KeyPair {
    private_key: SecureMemoryHandle,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("private_key", &"[REDACTED]")
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl Ed25519KeyPair {
    pub fn new(
        private_key: SecureMemoryHandle,
        public_key: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid Ed25519 public key size",
            ));
        }
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub const fn private_key_handle(&self) -> &SecureMemoryHandle {
        &self.private_key
    }

    pub fn get_private_key_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.private_key.read_bytes(ED25519_SECRET_KEY_BYTES)
    }

    pub fn take(self) -> (SecureMemoryHandle, Vec<u8>) {
        (self.private_key, self.public_key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut sk_bytes = self
            .private_key
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let mut sk_array: [u8; ED25519_SECRET_KEY_BYTES] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::generic("Ed25519 secret key has wrong length"))?;
        let signing_key = SigningKey::from_keypair_bytes(&sk_array)
            .map_err(|_| ProtocolError::generic("Ed25519 sign failed: invalid keypair bytes"))?;
        CryptoInterop::secure_wipe(&mut sk_bytes);
        sk_array.zeroize();
        let sig = signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    pub fn verify(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), ProtocolError> {
        if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid Ed25519 public key size",
            ));
        }
        if signature.len() != ED25519_SIGNATURE_BYTES {
            return Err(ProtocolError::peer_pub_key(
                "Invalid Ed25519 signature size",
            ));
        }
        let pk_array: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key
            .try_into()
            .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 public key size"))?;
        let vk = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| ProtocolError::peer_pub_key("Invalid Ed25519 public key"))?;
        let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| ProtocolError::peer_pub_key("Invalid Ed25519 signature size"))?;
        let sig = Signature::from_bytes(&sig_array);
        vk.verify_strict(message, &sig)
            .map_err(|_| ProtocolError::peer_pub_key("Ed25519 signature verification failed"))
    }
}
