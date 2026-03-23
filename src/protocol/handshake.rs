// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, KyberInterop};
use crate::identity::IdentityKeys;
use crate::models::key_materials::Ed25519KeyPair;
use crate::proto::{HandshakeAck, HandshakeInit, PreKeyBundle};
use crate::protocol::nonce::NonceGenerator;
use crate::protocol::session::{build_protocol_state, HandshakeState, Session};
use crate::security::DhValidator;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

fn derive_key_bytes(
    ikm: &[u8],
    out_len: usize,
    salt: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let mut z = HkdfSha256::derive_key_bytes(ikm, out_len, salt, info)?;
    Ok(std::mem::take(&mut *z))
}

fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if key.len() != HMAC_BYTES {
        return Err(ProtocolError::invalid_input("HMAC key must be 32 bytes"));
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ProtocolError::handshake("HMAC-SHA256 computation failed"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

fn compute_dh(
    private_key: &[u8],
    public_key: &[u8],
    context: &str,
) -> Result<Vec<u8>, ProtocolError> {
    if private_key.len() != X25519_PRIVATE_KEY_BYTES || public_key.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid X25519 key size for DH",
        ));
    }
    let sk_bytes: [u8; X25519_PRIVATE_KEY_BYTES] = private_key
        .try_into()
        .map_err(|_| ProtocolError::handshake("Invalid X25519 private key"))?;
    let pk_bytes: [u8; X25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| ProtocolError::handshake("Invalid X25519 public key"))?;
    let secret = StaticSecret::from(sk_bytes);
    let public = X25519PublicKey::from(pk_bytes);
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.to_bytes();
    if is_all_zero(&shared_bytes) {
        return Err(ProtocolError::handshake(format!(
            "X25519 DH produced all-zero output for {context} (RFC 7748 §6.1)"
        )));
    }
    Ok(shared_bytes.to_vec())
}

fn build_transcript_hash(
    bundle: &PreKeyBundle,
    init: &HandshakeInit,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bundle_bytes = Vec::new();
    bundle
        .encode(&mut bundle_bytes)
        .map_err(|e| ProtocolError::encode(format!("Failed to serialize PreKeyBundle: {e}")))?;

    let mut init_copy = init.clone();
    init_copy.key_confirmation_mac.clear();
    let mut init_bytes = Vec::new();
    init_copy
        .encode(&mut init_bytes)
        .map_err(|e| ProtocolError::encode(format!("Failed to serialize HandshakeInit: {e}")))?;

    let mut transcript = Vec::with_capacity(8 + bundle_bytes.len() + init_bytes.len());
    #[allow(clippy::cast_possible_truncation)]
    let bundle_len_u32 = bundle_bytes.len() as u32;
    transcript.extend_from_slice(&bundle_len_u32.to_le_bytes());
    transcript.extend_from_slice(&bundle_bytes);
    #[allow(clippy::cast_possible_truncation)]
    let init_len_u32 = init_bytes.len() as u32;
    transcript.extend_from_slice(&init_len_u32.to_le_bytes());
    transcript.extend_from_slice(&init_bytes);

    let mut mac = HmacSha256::new_from_slice(TRANSCRIPT_LABEL)
        .map_err(|_| ProtocolError::handshake("HMAC-SHA256 init failed"))?;
    mac.update(&transcript);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn build_metadata_context(
    self_dh_public: &[u8],
    peer_dh_public: &[u8],
    session_id: &[u8],
) -> Vec<u8> {
    let mut keys = [self_dh_public.to_vec(), peer_dh_public.to_vec()];
    if keys[0] > keys[1] {
        keys.swap(0, 1);
    }
    let mut context = Vec::with_capacity(keys[0].len() + keys[1].len() + session_id.len());
    context.extend_from_slice(&keys[0]);
    context.extend_from_slice(&keys[1]);
    context.extend_from_slice(session_id);
    context
}

fn build_init_identity_binding_message(
    initiator_identity_ed25519_public: &[u8],
    initiator_identity_x25519_public: &[u8],
    initiator_kyber_public: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        HANDSHAKE_INIT_IDENTITY_BINDING_INFO.len()
            + initiator_identity_ed25519_public.len()
            + initiator_identity_x25519_public.len()
            + initiator_kyber_public.len(),
    );
    message.extend_from_slice(HANDSHAKE_INIT_IDENTITY_BINDING_INFO);
    message.extend_from_slice(initiator_identity_ed25519_public);
    message.extend_from_slice(initiator_identity_x25519_public);
    message.extend_from_slice(initiator_kyber_public);
    message
}

fn sign_init_identity_binding(
    ed25519_secret: &[u8],
    initiator_identity_ed25519_public: &[u8],
    initiator_identity_x25519_public: &[u8],
    initiator_kyber_public: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if ed25519_secret.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 secret key size for handshake identity binding",
        ));
    }
    let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = ed25519_secret
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 secret key size"))?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_array)
        .map_err(|_| ProtocolError::key_generation("Invalid Ed25519 keypair bytes"))?;
    let message = build_init_identity_binding_message(
        initiator_identity_ed25519_public,
        initiator_identity_x25519_public,
        initiator_kyber_public,
    );
    use ed25519_dalek::Signer;
    Ok(signing_key.sign(&message).to_bytes().to_vec())
}

fn verify_init_identity_binding(init: &HandshakeInit) -> Result<(), ProtocolError> {
    let message = build_init_identity_binding_message(
        &init.initiator_identity_ed25519_public,
        &init.initiator_identity_x25519_public,
        &init.initiator_kyber_public,
    );
    Ed25519KeyPair::verify(
        &init.initiator_identity_ed25519_public,
        &message,
        &init.initiator_identity_binding_signature,
    )
}

fn validate_bundle(bundle: &PreKeyBundle) -> Result<(), ProtocolError> {
    if bundle.version != PROTOCOL_VERSION {
        return Err(ProtocolError::invalid_input("Invalid PreKeyBundle version"));
    }
    if bundle.identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
        || bundle.identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        || bundle.identity_x25519_signature.len() != ED25519_SIGNATURE_BYTES
        || bundle.signed_pre_key_public.len() != X25519_PUBLIC_KEY_BYTES
        || bundle.signed_pre_key_signature.len() != ED25519_SIGNATURE_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid PreKeyBundle key sizes",
        ));
    }
    if bundle.kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Kyber public key required for handshake",
        ));
    }

    IdentityKeys::verify_remote_identity_x25519_signature(
        &bundle.identity_ed25519_public,
        &bundle.identity_x25519_public,
        &bundle.identity_x25519_signature,
    )?;

    IdentityKeys::verify_remote_spk_signature(
        &bundle.identity_ed25519_public,
        &bundle.signed_pre_key_public,
        &bundle.signed_pre_key_signature,
    )?;

    DhValidator::validate_x25519_public_key(&bundle.identity_x25519_public)?;
    DhValidator::validate_x25519_public_key(&bundle.signed_pre_key_public)?;

    for opk in &bundle.one_time_pre_keys {
        if opk.public_key.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid OPK size in PreKeyBundle",
            ));
        }
        DhValidator::validate_x25519_public_key(&opk.public_key)?;
    }

    KyberInterop::validate_public_key(&bundle.kyber_public).map_err(ProtocolError::from_crypto)?;

    Ok(())
}

fn validate_max_messages_per_chain(max: u32) -> Result<(), ProtocolError> {
    if max == 0 {
        return Err(ProtocolError::invalid_input(
            "Max messages per chain must be greater than zero",
        ));
    }
    if max as usize > MAX_MESSAGES_PER_CHAIN {
        return Err(ProtocolError::invalid_input(
            "Max messages per chain exceeds protocol limit",
        ));
    }
    Ok(())
}

fn validate_init_message(init: &HandshakeInit) -> Result<(), ProtocolError> {
    if init.version != PROTOCOL_VERSION {
        return Err(ProtocolError::invalid_input(
            "Invalid HandshakeInit version",
        ));
    }
    if init.initiator_identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
        || init.initiator_identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        || init.initiator_ephemeral_x25519_public.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::invalid_input("Invalid initiator key sizes"));
    }
    if init.kyber_ciphertext.len() != KYBER_CIPHERTEXT_BYTES {
        return Err(ProtocolError::invalid_input(
            "Kyber ciphertext required for handshake",
        ));
    }
    if init.key_confirmation_mac.len() != HMAC_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid key confirmation MAC size",
        ));
    }
    if init.initiator_identity_binding_signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid initiator identity binding signature size",
        ));
    }
    if init.initiator_kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Initiator Kyber public key required for handshake",
        ));
    }

    DhValidator::validate_x25519_public_key(&init.initiator_identity_x25519_public)?;
    DhValidator::validate_x25519_public_key(&init.initiator_ephemeral_x25519_public)?;

    KyberInterop::validate_ciphertext(&init.kyber_ciphertext)
        .map_err(ProtocolError::from_crypto)?;
    KyberInterop::validate_public_key(&init.initiator_kyber_public)
        .map_err(ProtocolError::from_crypto)?;

    validate_max_messages_per_chain(init.max_messages_per_chain)?;
    verify_init_identity_binding(init)?;
    Ok(())
}

struct InitiatorState {
    session_state: Option<HandshakeState>,
    expected_ack_mac: Vec<u8>,
}

impl Drop for InitiatorState {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.expected_ack_mac);
    }
}

pub struct HandshakeInitiator {
    init_message: HandshakeInit,
    init_bytes: Vec<u8>,
    state: Option<InitiatorState>,
}

impl HandshakeInitiator {
    pub fn start(
        identity_keys: &mut IdentityKeys,
        peer_bundle: &PreKeyBundle,
        max_messages_per_chain: u32,
    ) -> Result<Self, ProtocolError> {
        validate_bundle(peer_bundle)?;
        validate_max_messages_per_chain(max_messages_per_chain)?;

        let local_ed25519 = identity_keys.get_identity_ed25519_public();
        if CryptoInterop::constant_time_equals(&local_ed25519, &peer_bundle.identity_ed25519_public)
            .unwrap_or(false)
        {
            return Err(ProtocolError::invalid_input(
                "Reflexion attack: peer identity key matches local identity key",
            ));
        }

        identity_keys.generate_ephemeral_key_pair()?;
        let eph_public = identity_keys
            .get_ephemeral_x25519_public()
            .ok_or_else(|| ProtocolError::prepare_local("Initiator ephemeral key not available"))?;
        if eph_public.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::prepare_local(
                "Initiator ephemeral key invalid size",
            ));
        }

        let mut eph_private = identity_keys.get_ephemeral_x25519_private_key_copy()?;
        let mut identity_private = identity_keys.get_identity_x25519_private_key_copy()?;

        let opk_count = peer_bundle.one_time_pre_keys.len();
        let (used_opk_id, opk_public) = if opk_count > 0 {
            let rand_idx = (CryptoInterop::generate_random_u32(false) as usize) % opk_count;
            let opk = &peer_bundle.one_time_pre_keys[rand_idx];
            if opk.public_key.len() != X25519_PUBLIC_KEY_BYTES {
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                return Err(ProtocolError::invalid_input("Invalid OPK public key size"));
            }
            DhValidator::validate_x25519_public_key(&opk.public_key)?;
            (Some(opk.one_time_pre_key_id), opk.public_key.clone())
        } else {
            (None, vec![])
        };

        let dh1 = compute_dh(&identity_private, &peer_bundle.signed_pre_key_public, "DH1");
        let dh2 = compute_dh(&eph_private, &peer_bundle.identity_x25519_public, "DH2");
        let dh3 = compute_dh(&eph_private, &peer_bundle.signed_pre_key_public, "DH3");

        let (mut dh1, mut dh2, mut dh3) = match (dh1, dh2, dh3) {
            (Ok(d1), Ok(d2), Ok(d3)) => (d1, d2, d3),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                return Err(e);
            }
        };

        let mut dh4 = if used_opk_id.is_some() {
            match compute_dh(&eph_private, &opk_public, "DH4") {
                Ok(v) => v,
                Err(e) => {
                    CryptoInterop::secure_wipe(&mut identity_private);
                    CryptoInterop::secure_wipe(&mut eph_private);
                    CryptoInterop::secure_wipe(&mut dh1);
                    CryptoInterop::secure_wipe(&mut dh2);
                    CryptoInterop::secure_wipe(&mut dh3);
                    return Err(e);
                }
            }
        } else {
            vec![]
        };

        let dh_total = dh1.len() + dh2.len() + dh3.len() + dh4.len();
        let mut ikm = vec![X3DH_FILL_BYTE; X25519_PUBLIC_KEY_BYTES + dh_total];
        let mut off = X25519_PUBLIC_KEY_BYTES;
        ikm[off..off + dh1.len()].copy_from_slice(&dh1);
        off += dh1.len();
        ikm[off..off + dh2.len()].copy_from_slice(&dh2);
        off += dh2.len();
        ikm[off..off + dh3.len()].copy_from_slice(&dh3);
        off += dh3.len();
        if !dh4.is_empty() {
            ikm[off..off + dh4.len()].copy_from_slice(&dh4);
        }

        let classical_shared = derive_key_bytes(&ikm, ROOT_KEY_BYTES, &[], X3DH_INFO);
        CryptoInterop::secure_wipe(&mut ikm);
        CryptoInterop::secure_wipe(&mut dh1);
        CryptoInterop::secure_wipe(&mut dh2);
        CryptoInterop::secure_wipe(&mut dh3);
        if !dh4.is_empty() {
            CryptoInterop::secure_wipe(&mut dh4);
        }

        let mut classical_shared = classical_shared.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut identity_private);
            CryptoInterop::secure_wipe(&mut eph_private);
        })?;

        let (kyber_ciphertext, kyber_ss_handle) =
            KyberInterop::encapsulate(&peer_bundle.kyber_public).map_err(|e| {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut classical_shared);
                ProtocolError::from_crypto(e)
            })?;
        let mut kyber_shared_secret = kyber_ss_handle
            .read_bytes(KYBER_SHARED_SECRET_BYTES)
            .map_err(|e| {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut classical_shared);
                ProtocolError::from_crypto(e)
            })?;

        let root_key = derive_key_bytes(
            &kyber_shared_secret,
            ROOT_KEY_BYTES,
            &classical_shared,
            HYBRID_X3DH_INFO,
        );
        CryptoInterop::secure_wipe(&mut classical_shared);

        let mut root_key = root_key.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut identity_private);
            CryptoInterop::secure_wipe(&mut eph_private);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
        })?;

        let session_id = derive_key_bytes(&root_key, SESSION_ID_BYTES, &[], SESSION_ID_INFO)
            .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            })?;

        let metadata_context =
            build_metadata_context(&eph_public, &peer_bundle.signed_pre_key_public, &session_id);
        let metadata_key = derive_key_bytes(
            &root_key,
            METADATA_KEY_BYTES,
            &metadata_context,
            METADATA_KEY_INFO,
        )
        .inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut identity_private);
            CryptoInterop::secure_wipe(&mut eph_private);
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
        })?;

        let kc_i = derive_key_bytes(&root_key, HMAC_BYTES, &[], KEY_CONFIRM_INIT_INFO);
        let kc_r = derive_key_bytes(&root_key, HMAC_BYTES, &[], KEY_CONFIRM_RESP_INFO);
        let (mut kc_i, mut kc_r) = match (kc_i, kc_r) {
            (Ok(i), Ok(r)) => (i, r),
            (Err(e), _) | (_, Err(e)) => {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                return Err(e);
            }
        };

        let ed_public = identity_keys.get_identity_ed25519_public();
        let id_public = identity_keys.get_identity_x25519_public();

        let kyber_public = identity_keys.get_kyber_public();
        if kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
            CryptoInterop::secure_wipe(&mut identity_private);
            CryptoInterop::secure_wipe(&mut eph_private);
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            CryptoInterop::secure_wipe(&mut kc_i);
            CryptoInterop::secure_wipe(&mut kc_r);
            return Err(ProtocolError::prepare_local(
                "Invalid local Kyber public key size",
            ));
        }
        let mut ed25519_secret = identity_keys.get_identity_ed25519_private_key_copy()?;
        let identity_binding_signature =
            sign_init_identity_binding(&ed25519_secret, &ed_public, &id_public, &kyber_public)
                .inspect_err(|_| {
                    CryptoInterop::secure_wipe(&mut identity_private);
                    CryptoInterop::secure_wipe(&mut eph_private);
                    CryptoInterop::secure_wipe(&mut root_key);
                    CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                    CryptoInterop::secure_wipe(&mut kc_i);
                    CryptoInterop::secure_wipe(&mut kc_r);
                })?;
        CryptoInterop::secure_wipe(&mut ed25519_secret);

        let mut init_message = HandshakeInit {
            version: PROTOCOL_VERSION,
            initiator_identity_ed25519_public: ed_public.clone(),
            initiator_identity_x25519_public: id_public.clone(),
            initiator_ephemeral_x25519_public: eph_public.clone(),
            one_time_pre_key_id: used_opk_id,
            kyber_ciphertext,
            initiator_kyber_public: kyber_public.clone(),
            max_messages_per_chain,
            key_confirmation_mac: vec![],
            initiator_identity_binding_signature: identity_binding_signature,
        };

        let transcript_hash =
            build_transcript_hash(peer_bundle, &init_message).inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                CryptoInterop::secure_wipe(&mut kc_i);
                CryptoInterop::secure_wipe(&mut kc_r);
            })?;

        let mut confirmation_mac = compute_hmac_sha256(&kc_i, &transcript_hash)?;
        CryptoInterop::secure_wipe(&mut kc_i);

        init_message
            .key_confirmation_mac
            .clone_from(&confirmation_mac);
        CryptoInterop::secure_wipe(&mut confirmation_mac);

        let mut serialized = Vec::new();
        init_message.encode(&mut serialized).map_err(|e| {
            CryptoInterop::secure_wipe(&mut identity_private);
            CryptoInterop::secure_wipe(&mut eph_private);
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            CryptoInterop::secure_wipe(&mut kc_r);
            ProtocolError::encode(format!("Failed to serialize HandshakeInit: {e}"))
        })?;

        let nonce_generator = NonceGenerator::create()?.export_state();

        let kyber_secret_handle = identity_keys.clone_kyber_secret_key()?;
        let mut kyber_secret = kyber_secret_handle
            .read_bytes(KYBER_SECRET_KEY_BYTES)
            .map_err(|e| {
                CryptoInterop::secure_wipe(&mut identity_private);
                CryptoInterop::secure_wipe(&mut eph_private);
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                CryptoInterop::secure_wipe(&mut kc_r);
                ProtocolError::from_crypto(e)
            })?;

        let proto_state = build_protocol_state(
            true,
            &root_key,
            &session_id,
            &metadata_key,
            &eph_private,
            &eph_public,
            &peer_bundle.signed_pre_key_public,
            &eph_public,
            &peer_bundle.signed_pre_key_public,
            &kyber_secret,
            &kyber_public,
            &peer_bundle.kyber_public,
            max_messages_per_chain,
            MAX_NONCE_COUNTER,
            nonce_generator,
            &ed_public,
            &id_public,
            &peer_bundle.identity_ed25519_public,
            &peer_bundle.identity_x25519_public,
        );
        CryptoInterop::secure_wipe(&mut identity_private);
        CryptoInterop::secure_wipe(&mut eph_private);
        CryptoInterop::secure_wipe(&mut kyber_secret);

        let proto_state = proto_state.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            CryptoInterop::secure_wipe(&mut kc_r);
        })?;
        CryptoInterop::secure_wipe(&mut root_key);
        CryptoInterop::secure_wipe(&mut { metadata_key });
        CryptoInterop::secure_wipe(&mut { session_id });

        let expected_ack_mac = compute_hmac_sha256(&kc_r, &transcript_hash)?;
        CryptoInterop::secure_wipe(&mut kc_r);

        identity_keys.clear_ephemeral_key_pair()?;

        Ok(Self {
            init_message,
            init_bytes: serialized,
            state: Some(InitiatorState {
                session_state: Some(HandshakeState {
                    state: proto_state,
                    kyber_shared_secret: Zeroizing::new(kyber_shared_secret),
                }),
                expected_ack_mac,
            }),
        })
    }

    pub fn encoded_message(&self) -> &[u8] {
        &self.init_bytes
    }

    pub const fn message(&self) -> &HandshakeInit {
        &self.init_message
    }

    pub fn finish(mut self, ack_bytes: &[u8]) -> Result<Session, ProtocolError> {
        let mut st = self
            .state
            .take()
            .ok_or_else(|| ProtocolError::invalid_state("Handshake initiator not initialized"))?;

        if ack_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("HandshakeAck too large"));
        }
        let ack = HandshakeAck::decode(ack_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse HandshakeAck: {e}")))?;

        if ack.version != PROTOCOL_VERSION {
            return Err(ProtocolError::invalid_input("Invalid HandshakeAck version"));
        }
        if ack.key_confirmation_mac.len() != HMAC_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid acknowledgement MAC size",
            ));
        }

        let eq =
            CryptoInterop::constant_time_equals(&st.expected_ack_mac, &ack.key_confirmation_mac)
                .map_err(ProtocolError::from_crypto)?;
        if !eq {
            return Err(ProtocolError::handshake(
                "Responder key confirmation failed",
            ));
        }

        let session_state = st
            .session_state
            .take()
            .ok_or_else(|| ProtocolError::invalid_state("InitiatorState already consumed"))?;
        CryptoInterop::secure_wipe(&mut st.expected_ack_mac);
        Session::from_handshake_state(session_state)
    }
}

struct ResponderState {
    session_state: HandshakeState,
}

pub struct HandshakeResponder {
    ack_message: HandshakeAck,
    ack_bytes: Vec<u8>,
    state: Option<ResponderState>,
}

impl HandshakeResponder {
    pub fn process(
        identity_keys: &mut IdentityKeys,
        local_bundle: &PreKeyBundle,
        init_message_bytes: &[u8],
        max_messages_per_chain: u32,
    ) -> Result<Self, ProtocolError> {
        validate_bundle(local_bundle)?;
        validate_max_messages_per_chain(max_messages_per_chain)?;

        if init_message_bytes.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Message too large"));
        }
        let init_message = HandshakeInit::decode(init_message_bytes)
            .map_err(|e| ProtocolError::decode(format!("Failed to parse HandshakeInit: {e}")))?;
        validate_init_message(&init_message)?;

        if CryptoInterop::constant_time_equals(
            &local_bundle.identity_ed25519_public,
            &init_message.initiator_identity_ed25519_public,
        )
        .unwrap_or(false)
        {
            return Err(ProtocolError::invalid_input(
                "Reflexion attack: initiator identity key matches local identity key",
            ));
        }

        if init_message.max_messages_per_chain != max_messages_per_chain {
            return Err(ProtocolError::invalid_input(
                "Handshake ratchet config mismatch",
            ));
        }

        let (used_opk_id, mut opk_private) = if let Some(opk_id) = init_message.one_time_pre_key_id
        {
            let priv_bytes = identity_keys.get_one_time_pre_key_private_by_id(opk_id)?;
            (Some(opk_id), priv_bytes)
        } else {
            (None, Zeroizing::new(vec![]))
        };

        let mut spk_private = identity_keys.get_signed_pre_key_private_copy()?;
        let mut identity_private = identity_keys.get_identity_x25519_private_key_copy()?;

        let dh1 = compute_dh(
            &spk_private,
            &init_message.initiator_identity_x25519_public,
            "DH1",
        );
        let dh2 = compute_dh(
            &identity_private,
            &init_message.initiator_ephemeral_x25519_public,
            "DH2",
        );
        let dh3 = compute_dh(
            &spk_private,
            &init_message.initiator_ephemeral_x25519_public,
            "DH3",
        );

        let (mut dh1, mut dh2, mut dh3) = match (dh1, dh2, dh3) {
            (Ok(d1), Ok(d2), Ok(d3)) => (d1, d2, d3),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                return Err(e);
            }
        };

        let mut dh4 = if used_opk_id.is_some() {
            match compute_dh(
                &opk_private,
                &init_message.initiator_ephemeral_x25519_public,
                "DH4",
            ) {
                Ok(v) => v,
                Err(e) => {
                    CryptoInterop::secure_wipe(&mut spk_private);
                    CryptoInterop::secure_wipe(&mut identity_private);
                    CryptoInterop::secure_wipe(&mut opk_private);
                    CryptoInterop::secure_wipe(&mut dh1);
                    CryptoInterop::secure_wipe(&mut dh2);
                    CryptoInterop::secure_wipe(&mut dh3);
                    return Err(e);
                }
            }
        } else {
            vec![]
        };

        let dh_total = dh1.len() + dh2.len() + dh3.len() + dh4.len();
        let mut ikm = vec![X3DH_FILL_BYTE; X25519_PUBLIC_KEY_BYTES + dh_total];
        let mut off = X25519_PUBLIC_KEY_BYTES;
        ikm[off..off + dh1.len()].copy_from_slice(&dh1);
        off += dh1.len();
        ikm[off..off + dh2.len()].copy_from_slice(&dh2);
        off += dh2.len();
        ikm[off..off + dh3.len()].copy_from_slice(&dh3);
        off += dh3.len();
        if !dh4.is_empty() {
            ikm[off..off + dh4.len()].copy_from_slice(&dh4);
        }

        let classical_shared = derive_key_bytes(&ikm, ROOT_KEY_BYTES, &[], X3DH_INFO);
        CryptoInterop::secure_wipe(&mut ikm);
        CryptoInterop::secure_wipe(&mut dh1);
        CryptoInterop::secure_wipe(&mut dh2);
        CryptoInterop::secure_wipe(&mut dh3);
        if !dh4.is_empty() {
            CryptoInterop::secure_wipe(&mut dh4);
        }

        let mut classical_shared = classical_shared.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
        })?;

        let artifacts = identity_keys
            .decapsulate_kyber_ciphertext(&init_message.kyber_ciphertext)
            .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                CryptoInterop::secure_wipe(&mut classical_shared);
            })?;
        let mut kyber_shared_secret = std::mem::take(&mut { artifacts }.kyber_shared_secret);

        let root_key = derive_key_bytes(
            &kyber_shared_secret,
            ROOT_KEY_BYTES,
            &classical_shared,
            HYBRID_X3DH_INFO,
        );
        CryptoInterop::secure_wipe(&mut classical_shared);

        let mut root_key = root_key.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
        })?;

        let session_id = derive_key_bytes(&root_key, SESSION_ID_BYTES, &[], SESSION_ID_INFO)
            .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            })?;

        let metadata_context = build_metadata_context(
            &local_bundle.signed_pre_key_public,
            &init_message.initiator_ephemeral_x25519_public,
            &session_id,
        );
        let mut metadata_key = derive_key_bytes(
            &root_key,
            METADATA_KEY_BYTES,
            &metadata_context,
            METADATA_KEY_INFO,
        )
        .inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
        })?;

        let kc_i = derive_key_bytes(&root_key, HMAC_BYTES, &[], KEY_CONFIRM_INIT_INFO);
        let kc_r = derive_key_bytes(&root_key, HMAC_BYTES, &[], KEY_CONFIRM_RESP_INFO);
        let (mut kc_i, mut kc_r) = match (kc_i, kc_r) {
            (Ok(i), Ok(r)) => (i, r),
            (Err(e), _) | (_, Err(e)) => {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                return Err(e);
            }
        };

        let transcript_hash =
            build_transcript_hash(local_bundle, &init_message).inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                CryptoInterop::secure_wipe(&mut kc_i);
                CryptoInterop::secure_wipe(&mut kc_r);
            })?;

        let expected_init_mac = compute_hmac_sha256(&kc_i, &transcript_hash)?;
        CryptoInterop::secure_wipe(&mut kc_i);

        let eq = CryptoInterop::constant_time_equals(
            &expected_init_mac,
            &init_message.key_confirmation_mac,
        )
        .map_err(ProtocolError::from_crypto)?;
        if !eq {
            // Diagnostic: include hashes for debugging MAC mismatch
            use sha2::{Digest as _, Sha256};
            fn to_hex(bytes: &[u8]) -> String {
                use std::fmt::Write as _;
                let mut out = String::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    let _ = write!(&mut out, "{byte:02x}");
                }
                out
            }
            let th_hash = {
                let mut h = Sha256::new();
                h.update(&transcript_hash);
                to_hex(&h.finalize()[..8])
            };
            let expected_hex = to_hex(&expected_init_mac[..8.min(expected_init_mac.len())]);
            let received_hex = to_hex(
                &init_message.key_confirmation_mac
                    [..8.min(init_message.key_confirmation_mac.len())],
            );
            let bundle_diag = {
                let mut bb = Vec::new();
                local_bundle.encode(&mut bb).ok();
                let mut h = Sha256::new();
                h.update(&bb);
                format!(
                    "bundle_len={} bundle_sha={}",
                    bb.len(),
                    to_hex(&h.finalize()[..8])
                )
            };
            let init_diag = {
                let mut ic = init_message;
                ic.key_confirmation_mac.clear();
                let mut ib = Vec::new();
                ic.encode(&mut ib).ok();
                let mut h = Sha256::new();
                h.update(&ib);
                format!(
                    "init_len={} init_sha={}",
                    ib.len(),
                    to_hex(&h.finalize()[..8])
                )
            };
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            CryptoInterop::secure_wipe(&mut kc_r);
            return Err(ProtocolError::handshake(
                format!("Initiator key confirmation failed: th_sha={th_hash} expected_mac={expected_hex} received_mac={received_hex} {bundle_diag} {init_diag}"),
            ));
        }

        let ack_mac = compute_hmac_sha256(&kc_r, &transcript_hash)?;
        CryptoInterop::secure_wipe(&mut kc_r);

        let ack_message = HandshakeAck {
            version: PROTOCOL_VERSION,
            key_confirmation_mac: ack_mac,
        };
        let mut ack_bytes = Vec::new();
        ack_message.encode(&mut ack_bytes).map_err(|e| {
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            ProtocolError::encode(format!("Failed to serialize HandshakeAck: {e}"))
        })?;

        let nonce_generator = NonceGenerator::create()?.export_state();

        let kyber_secret_handle = identity_keys.clone_kyber_secret_key()?;
        let mut kyber_secret = kyber_secret_handle
            .read_bytes(KYBER_SECRET_KEY_BYTES)
            .map_err(|e| {
                CryptoInterop::secure_wipe(&mut spk_private);
                CryptoInterop::secure_wipe(&mut identity_private);
                if !opk_private.is_empty() {
                    CryptoInterop::secure_wipe(&mut opk_private);
                }
                CryptoInterop::secure_wipe(&mut root_key);
                CryptoInterop::secure_wipe(&mut kyber_shared_secret);
                ProtocolError::from_crypto(e)
            })?;
        let kyber_public = identity_keys.get_kyber_public();
        if kyber_public.len() != KYBER_PUBLIC_KEY_BYTES {
            CryptoInterop::secure_wipe(&mut spk_private);
            CryptoInterop::secure_wipe(&mut identity_private);
            if !opk_private.is_empty() {
                CryptoInterop::secure_wipe(&mut opk_private);
            }
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
            CryptoInterop::secure_wipe(&mut kyber_secret);
            return Err(ProtocolError::prepare_local(
                "Invalid local Kyber public key size",
            ));
        }

        let local_spk_pub = local_bundle.signed_pre_key_public.clone();
        let local_ed_pub = local_bundle.identity_ed25519_public.clone();
        let local_x25519_pub = local_bundle.identity_x25519_public.clone();
        let init_eph_pub = init_message.initiator_ephemeral_x25519_public.clone();
        let init_kyber_pub = init_message.initiator_kyber_public.clone();
        let init_ed_pub = init_message.initiator_identity_ed25519_public.clone();
        let init_x25519_pub = init_message.initiator_identity_x25519_public;

        let proto_state = build_protocol_state(
            false,
            &root_key,
            &session_id,
            &metadata_key,
            &spk_private,
            &local_spk_pub,
            &init_eph_pub,
            &local_spk_pub,
            &init_eph_pub,
            &kyber_secret,
            &kyber_public,
            &init_kyber_pub,
            max_messages_per_chain,
            MAX_NONCE_COUNTER,
            nonce_generator,
            &local_ed_pub,
            &local_x25519_pub,
            &init_ed_pub,
            &init_x25519_pub,
        );
        CryptoInterop::secure_wipe(&mut spk_private);
        CryptoInterop::secure_wipe(&mut identity_private);
        if !opk_private.is_empty() {
            CryptoInterop::secure_wipe(&mut opk_private);
        }
        CryptoInterop::secure_wipe(&mut kyber_secret);

        let proto_state = proto_state.inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut root_key);
            CryptoInterop::secure_wipe(&mut metadata_key);
            CryptoInterop::secure_wipe(&mut kyber_shared_secret);
        })?;
        CryptoInterop::secure_wipe(&mut root_key);
        CryptoInterop::secure_wipe(&mut { metadata_key });
        CryptoInterop::secure_wipe(&mut { session_id });

        if let Some(opk_id) = used_opk_id {
            identity_keys.consume_one_time_pre_key_by_id(opk_id)?;
        }

        Ok(Self {
            ack_message,
            ack_bytes,
            state: Some(ResponderState {
                session_state: HandshakeState {
                    state: proto_state,
                    kyber_shared_secret: Zeroizing::new(kyber_shared_secret),
                },
            }),
        })
    }

    pub fn encoded_ack(&self) -> &[u8] {
        &self.ack_bytes
    }

    pub const fn ack(&self) -> &HandshakeAck {
        &self.ack_message
    }

    pub fn finish(mut self) -> Result<Session, ProtocolError> {
        let st = self
            .state
            .take()
            .ok_or_else(|| ProtocolError::invalid_state("Handshake responder not initialized"))?;
        Session::from_handshake_state(st.session_state)
    }
}
