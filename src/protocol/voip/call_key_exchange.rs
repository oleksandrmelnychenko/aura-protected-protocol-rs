use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{CryptoInterop, HkdfSha256, KyberInterop, SecureMemoryHandle};
use crate::proto::ScreenShareMetadata;
use crate::security::DhValidator;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallInitAuthContext {
    pub version: u32,
    pub media_type: i32,
    pub ratchet_interval_frames: u32,
    pub pq_rekey_interval_secs: u32,
    pub shield_mode: bool,
}

pub struct CallKeyMaterial {
    pub root_secret: SecureMemoryHandle,
    pub media_key_send: SecureMemoryHandle,
    pub media_key_recv: SecureMemoryHandle,
    pub header_key_send: SecureMemoryHandle,
    pub header_key_recv: SecureMemoryHandle,
    pub nonce_prefix_send: [u8; VOIP_NONCE_PREFIX_BYTES],
    pub nonce_prefix_recv: [u8; VOIP_NONCE_PREFIX_BYTES],
}

pub struct CallInitOutput {
    pub call_id: Vec<u8>,
    pub ephemeral_x25519_public: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    pub identity_ed25519_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub key_confirmation_mac: Vec<u8>,
    pub ephemeral_x25519_private: SecureMemoryHandle,
    pub kyber_shared_secret: SecureMemoryHandle,
    pub classical_shared_secret: Zeroizing<Vec<u8>>,
}

pub struct CallAcceptOutput {
    pub ephemeral_x25519_public: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    pub identity_ed25519_public: Vec<u8>,
    pub signature: Vec<u8>,
    pub key_confirmation_mac: Vec<u8>,
    pub key_material: CallKeyMaterial,
}

fn compute_dh(
    private_key: &[u8],
    public_key: &[u8],
    context: &str,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if private_key.len() != X25519_PRIVATE_KEY_BYTES || public_key.len() != X25519_PUBLIC_KEY_BYTES
    {
        return Err(ProtocolError::voip_call(
            "invalid X25519 key size for VoIP DH",
        ));
    }
    DhValidator::validate_x25519_public_key(public_key)?;

    let sk_bytes: [u8; X25519_PRIVATE_KEY_BYTES] = private_key
        .try_into()
        .map_err(|_| ProtocolError::voip_call("invalid X25519 private key"))?;
    let pk_bytes: [u8; X25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| ProtocolError::voip_call("invalid X25519 public key"))?;

    let secret = StaticSecret::from(sk_bytes);
    let public = X25519PublicKey::from(pk_bytes);
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.to_bytes();

    let mut acc = 0u8;
    for &b in &shared_bytes {
        acc |= b;
    }
    if acc == 0 {
        return Err(ProtocolError::voip_call(format!(
            "X25519 DH produced all-zero output for {context}"
        )));
    }
    Ok(Zeroizing::new(shared_bytes.to_vec()))
}

fn append_call_material_message(
    message: &mut Vec<u8>,
    call_id: &[u8],
    eph_x25519_public: &[u8],
    kyber_ct: &[u8],
) {
    message.extend_from_slice(call_id);
    message.extend_from_slice(eph_x25519_public);
    message.extend_from_slice(kyber_ct);
}

fn append_call_init_auth_context(message: &mut Vec<u8>, context: &CallInitAuthContext) {
    message.extend_from_slice(&context.version.to_le_bytes());
    message.extend_from_slice(&context.media_type.to_le_bytes());
    message.extend_from_slice(&context.ratchet_interval_frames.to_le_bytes());
    message.extend_from_slice(&context.pq_rekey_interval_secs.to_le_bytes());
    message.push(u8::from(context.shield_mode));
}

fn append_screen_share_signature_context(
    message: &mut Vec<u8>,
    screen_share: Option<&ScreenShareMetadata>,
) -> Result<(), ProtocolError> {
    let Some(meta) = screen_share else {
        return Ok(());
    };

    message.extend_from_slice(b"Aura-VoIP-ScreenShare-v1");
    message.extend_from_slice(&meta.width.to_le_bytes());
    message.extend_from_slice(&meta.height.to_le_bytes());
    message.extend_from_slice(&meta.frame_rate.to_le_bytes());
    match meta.codec_hint.as_deref() {
        Some(hint) => {
            message.push(1);
            let hint_len = u32::try_from(hint.len())
                .map_err(|_| ProtocolError::voip_call("screen-share codec hint too long"))?;
            message.extend_from_slice(&hint_len.to_le_bytes());
            message.extend_from_slice(hint.as_bytes());
        }
        None => message.push(0),
    }
    Ok(())
}

fn sign_call_material_with_context(
    ed25519_secret: &[u8],
    call_id: &[u8],
    eph_x25519_public: &[u8],
    kyber_ct: &[u8],
    context: &CallInitAuthContext,
    screen_share: Option<&ScreenShareMetadata>,
) -> Result<Vec<u8>, ProtocolError> {
    if ed25519_secret.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::voip_call("invalid Ed25519 secret key size"));
    }
    let key_bytes: [u8; ED25519_SECRET_KEY_BYTES] = ed25519_secret
        .try_into()
        .map_err(|_| ProtocolError::voip_call("Ed25519 key conversion failed"))?;
    let signing_key = SigningKey::from_keypair_bytes(&key_bytes)
        .map_err(|_| ProtocolError::voip_call("invalid Ed25519 keypair bytes"))?;

    let mut message =
        Vec::with_capacity(call_id.len() + eph_x25519_public.len() + kyber_ct.len() + 17);
    append_call_material_message(&mut message, call_id, eph_x25519_public, kyber_ct);
    append_call_init_auth_context(&mut message, context);
    append_screen_share_signature_context(&mut message, screen_share)?;

    let sig = signing_key.sign(&message);
    Ok(sig.to_bytes().to_vec())
}

fn verify_call_signature_with_context(
    ed25519_public: &[u8],
    call_id: &[u8],
    eph_x25519_public: &[u8],
    kyber_ct: &[u8],
    signature: &[u8],
    context: &CallInitAuthContext,
    screen_share: Option<&ScreenShareMetadata>,
) -> Result<(), ProtocolError> {
    if ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::voip_call("invalid Ed25519 public key size"));
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::voip_call("invalid signature size"));
    }

    let pk_bytes: [u8; ED25519_PUBLIC_KEY_BYTES] = ed25519_public
        .try_into()
        .map_err(|_| ProtocolError::voip_call("Ed25519 public key conversion failed"))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| ProtocolError::voip_call("invalid Ed25519 public key"))?;

    let sig_bytes: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| ProtocolError::voip_call("signature conversion failed"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let mut message =
        Vec::with_capacity(call_id.len() + eph_x25519_public.len() + kyber_ct.len() + 17);
    append_call_material_message(&mut message, call_id, eph_x25519_public, kyber_ct);
    append_call_init_auth_context(&mut message, context);
    append_screen_share_signature_context(&mut message, screen_share)?;

    verifying_key
        .verify_strict(&message, &sig)
        .map_err(|_| ProtocolError::voip_call("call signature verification failed"))
}

fn compute_key_confirm_mac_with_context(
    root_secret: &[u8],
    info: &[u8],
    call_id: &[u8],
    context: &CallInitAuthContext,
) -> Result<Vec<u8>, ProtocolError> {
    let mut mac_context = Vec::with_capacity(call_id.len() + 17);
    mac_context.extend_from_slice(call_id);
    append_call_init_auth_context(&mut mac_context, context);

    let mac_key = HkdfSha256::derive_key_bytes(root_secret, HMAC_BYTES, &mac_context, info)?;
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|_| ProtocolError::voip_call("HMAC key init failed"))?;
    mac.update(&mac_context);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn derive_call_keys_from_root(
    root_secret: &[u8],
    call_id: &[u8],
    is_caller: bool,
    shield_mode: bool,
) -> Result<CallKeyMaterial, ProtocolError> {
    derive_call_keys(root_secret, call_id, is_caller, shield_mode)
}

pub fn caller_init_with_context(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    peer_kyber_public: &[u8],
    auth_context: &CallInitAuthContext,
) -> Result<CallInitOutput, ProtocolError> {
    caller_init_with_context_and_screen_share(
        identity_ed25519_secret,
        identity_ed25519_public,
        peer_kyber_public,
        auth_context,
        None,
    )
}

pub fn caller_init_with_context_and_screen_share(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    peer_kyber_public: &[u8],
    auth_context: &CallInitAuthContext,
    screen_share: Option<&ScreenShareMetadata>,
) -> Result<CallInitOutput, ProtocolError> {
    let call_id = CryptoInterop::get_random_bytes(CALL_ID_BYTES);

    let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let eph_public_bytes = eph_public.to_bytes().to_vec();
    let eph_secret_bytes = eph_secret.to_bytes();

    let mut eph_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    eph_handle
        .write(&eph_secret_bytes)
        .map_err(ProtocolError::from_crypto)?;

    let (kyber_ct, kyber_ss) =
        KyberInterop::encapsulate(peer_kyber_public).map_err(ProtocolError::from_crypto)?;

    let signature = sign_call_material_with_context(
        identity_ed25519_secret,
        &call_id,
        &eph_public_bytes,
        &kyber_ct,
        auth_context,
        screen_share,
    )?;

    let kyber_ss_bytes = kyber_ss
        .read_bytes(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let mac = compute_key_confirm_mac_with_context(
        &kyber_ss_bytes,
        VOIP_KEY_CONFIRM_CALLER_INFO,
        &call_id,
        auth_context,
    )?;

    Ok(CallInitOutput {
        call_id,
        ephemeral_x25519_public: eph_public_bytes,
        kyber_ciphertext: kyber_ct,
        identity_ed25519_public: identity_ed25519_public.to_vec(),
        signature,
        key_confirmation_mac: mac,
        ephemeral_x25519_private: eph_handle,
        kyber_shared_secret: kyber_ss,
        classical_shared_secret: Zeroizing::new(Vec::new()),
    })
}

pub fn verify_rekey_signature(
    ed25519_public: &[u8],
    call_id: &[u8],
    rekey_generation: u32,
    eph_x25519_public: &[u8],
    kyber_ct: &[u8],
    signature: &[u8],
) -> Result<(), ProtocolError> {
    if ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::voip_rekey("invalid Ed25519 public key size"));
    }
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(ProtocolError::voip_rekey("invalid signature size"));
    }
    if eph_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::voip_rekey(
            "invalid rekey ephemeral key size",
        ));
    }
    if kyber_ct.len() != KYBER_CIPHERTEXT_BYTES {
        return Err(ProtocolError::voip_rekey("invalid rekey ciphertext size"));
    }

    let pk_bytes: [u8; ED25519_PUBLIC_KEY_BYTES] = ed25519_public
        .try_into()
        .map_err(|_| ProtocolError::voip_rekey("Ed25519 public key conversion failed"))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| ProtocolError::voip_rekey("invalid Ed25519 public key"))?;

    let sig_bytes: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| ProtocolError::voip_rekey("signature conversion failed"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let mut message =
        Vec::with_capacity(call_id.len() + eph_x25519_public.len() + kyber_ct.len() + 4);
    append_call_material_message(&mut message, call_id, eph_x25519_public, kyber_ct);
    message.extend_from_slice(&rekey_generation.to_le_bytes());

    verifying_key
        .verify_strict(&message, &sig)
        .map_err(|_| ProtocolError::voip_rekey("rekey signature verification failed"))
}

pub fn sign_rekey_material(
    ed25519_secret: &[u8],
    call_id: &[u8],
    rekey_generation: u32,
    eph_x25519_public: &[u8],
    kyber_ct: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if ed25519_secret.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::voip_rekey("invalid Ed25519 secret key size"));
    }
    let key_bytes: [u8; ED25519_SECRET_KEY_BYTES] = ed25519_secret
        .try_into()
        .map_err(|_| ProtocolError::voip_rekey("Ed25519 key conversion failed"))?;
    let signing_key = SigningKey::from_keypair_bytes(&key_bytes)
        .map_err(|_| ProtocolError::voip_rekey("invalid Ed25519 keypair bytes"))?;

    let mut message =
        Vec::with_capacity(call_id.len() + eph_x25519_public.len() + kyber_ct.len() + 4);
    append_call_material_message(&mut message, call_id, eph_x25519_public, kyber_ct);
    message.extend_from_slice(&rekey_generation.to_le_bytes());

    Ok(signing_key.sign(&message).to_bytes().to_vec())
}

pub fn compute_rekey_mac(
    key_material: &[u8],
    info: &[u8],
    call_id: &[u8],
    rekey_generation: u32,
) -> Result<Vec<u8>, ProtocolError> {
    let mut context = Vec::with_capacity(call_id.len() + 4);
    context.extend_from_slice(call_id);
    context.extend_from_slice(&rekey_generation.to_le_bytes());

    let mac_key = HkdfSha256::derive_key_bytes(key_material, HMAC_BYTES, &context, info)?;
    let mut mac = HmacSha256::new_from_slice(&mac_key)
        .map_err(|_| ProtocolError::voip_rekey("rekey HMAC key init failed"))?;
    mac.update(&context);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Computes a rekey MAC bound to the current session root secret.
///
/// This binds the rekey MAC to the established session — only a peer that
/// already knows `current_root_secret` AND successfully encapsulates to the
/// other peer's Kyber public key can produce a valid MAC.  Without this
/// binding, an attacker who happened to obtain a signature oracle for
/// arbitrary `sign_rekey_material` inputs could forge a rekey whose MAC
/// verifies against Kyber-SS alone.
pub fn compute_rekey_mac_bound(
    current_root_secret: &[u8],
    fresh_kyber_ss: &[u8],
    info: &[u8],
    call_id: &[u8],
    rekey_generation: u32,
) -> Result<Vec<u8>, ProtocolError> {
    let mut ikm = Vec::with_capacity(current_root_secret.len() + fresh_kyber_ss.len());
    ikm.extend_from_slice(current_root_secret);
    ikm.extend_from_slice(fresh_kyber_ss);
    let result = compute_rekey_mac(&ikm, info, call_id, rekey_generation);
    CryptoInterop::secure_wipe(&mut ikm);
    result
}

fn derive_call_keys(
    root_secret: &[u8],
    call_id: &[u8],
    is_caller: bool,
    shield_mode: bool,
) -> Result<CallKeyMaterial, ProtocolError> {
    let effective_root = if shield_mode {
        let pass1 = HkdfSha256::derive_key_bytes(
            root_secret,
            ROOT_KEY_BYTES,
            call_id,
            VOIP_SHIELD_KDF_PASS1,
        )?;
        HkdfSha256::derive_key_bytes(&pass1, ROOT_KEY_BYTES, call_id, VOIP_SHIELD_KDF_PASS2)?
    } else {
        Zeroizing::new(root_secret.to_vec())
    };

    let (send_info, recv_info) = if is_caller {
        (VOIP_MEDIA_KEY_SEND_INFO, VOIP_MEDIA_KEY_RECV_INFO)
    } else {
        (VOIP_MEDIA_KEY_RECV_INFO, VOIP_MEDIA_KEY_SEND_INFO)
    };

    let (hdr_send_info, hdr_recv_info) = if is_caller {
        (VOIP_HEADER_KEY_SEND_INFO, VOIP_HEADER_KEY_RECV_INFO)
    } else {
        (VOIP_HEADER_KEY_RECV_INFO, VOIP_HEADER_KEY_SEND_INFO)
    };

    let media_send =
        HkdfSha256::derive_key_bytes(&effective_root, VOIP_MEDIA_KEY_BYTES, call_id, send_info)?;
    let media_recv =
        HkdfSha256::derive_key_bytes(&effective_root, VOIP_MEDIA_KEY_BYTES, call_id, recv_info)?;
    let header_send = HkdfSha256::derive_key_bytes(
        &effective_root,
        VOIP_HEADER_KEY_BYTES,
        call_id,
        hdr_send_info,
    )?;
    let header_recv = HkdfSha256::derive_key_bytes(
        &effective_root,
        VOIP_HEADER_KEY_BYTES,
        call_id,
        hdr_recv_info,
    )?;

    let nonce_material = HkdfSha256::derive_key_bytes(
        &effective_root,
        VOIP_NONCE_PREFIX_BYTES * 2,
        call_id,
        VOIP_NONCE_PREFIX_INFO,
    )?;
    let mut nonce_prefix_send = [0u8; VOIP_NONCE_PREFIX_BYTES];
    let mut nonce_prefix_recv = [0u8; VOIP_NONCE_PREFIX_BYTES];
    if is_caller {
        nonce_prefix_send.copy_from_slice(&nonce_material[..VOIP_NONCE_PREFIX_BYTES]);
        nonce_prefix_recv.copy_from_slice(&nonce_material[VOIP_NONCE_PREFIX_BYTES..]);
    } else {
        nonce_prefix_recv.copy_from_slice(&nonce_material[..VOIP_NONCE_PREFIX_BYTES]);
        nonce_prefix_send.copy_from_slice(&nonce_material[VOIP_NONCE_PREFIX_BYTES..]);
    }

    let mut root_handle =
        SecureMemoryHandle::allocate(ROOT_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
    root_handle
        .write(&effective_root)
        .map_err(ProtocolError::from_crypto)?;

    let mut mk_send =
        SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
    mk_send
        .write(&media_send)
        .map_err(ProtocolError::from_crypto)?;

    let mut mk_recv =
        SecureMemoryHandle::allocate(VOIP_MEDIA_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
    mk_recv
        .write(&media_recv)
        .map_err(ProtocolError::from_crypto)?;

    let mut hk_send =
        SecureMemoryHandle::allocate(VOIP_HEADER_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
    hk_send
        .write(&header_send)
        .map_err(ProtocolError::from_crypto)?;

    let mut hk_recv =
        SecureMemoryHandle::allocate(VOIP_HEADER_KEY_BYTES).map_err(ProtocolError::from_crypto)?;
    hk_recv
        .write(&header_recv)
        .map_err(ProtocolError::from_crypto)?;

    Ok(CallKeyMaterial {
        root_secret: root_handle,
        media_key_send: mk_send,
        media_key_recv: mk_recv,
        header_key_send: hk_send,
        header_key_recv: hk_recv,
        nonce_prefix_send,
        nonce_prefix_recv,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn callee_accept_with_context(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    identity_kyber_secret: &SecureMemoryHandle,
    peer_kyber_public: &[u8],
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    auth_context: &CallInitAuthContext,
) -> Result<CallAcceptOutput, ProtocolError> {
    callee_accept_with_context_and_screen_share(
        identity_ed25519_secret,
        identity_ed25519_public,
        identity_kyber_secret,
        peer_kyber_public,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_ed25519_public,
        peer_signature,
        peer_key_confirm_mac,
        auth_context,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn callee_accept_with_context_and_screen_share(
    identity_ed25519_secret: &[u8],
    identity_ed25519_public: &[u8],
    identity_kyber_secret: &SecureMemoryHandle,
    peer_kyber_public: &[u8],
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    auth_context: &CallInitAuthContext,
    peer_screen_share: Option<&ScreenShareMetadata>,
    local_screen_share: Option<&ScreenShareMetadata>,
) -> Result<CallAcceptOutput, ProtocolError> {
    if call_id.len() != CALL_ID_BYTES {
        return Err(ProtocolError::voip_call("invalid call_id size"));
    }

    verify_call_signature_with_context(
        peer_ed25519_public,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_signature,
        auth_context,
        peer_screen_share,
    )?;

    let caller_kyber_ss = KyberInterop::decapsulate(peer_kyber_ct, identity_kyber_secret)
        .map_err(ProtocolError::from_crypto)?;

    let caller_kyber_ss_bytes = caller_kyber_ss
        .read_bytes(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let expected_mac = compute_key_confirm_mac_with_context(
        &caller_kyber_ss_bytes,
        VOIP_KEY_CONFIRM_CALLER_INFO,
        call_id,
        auth_context,
    )?;
    if !CryptoInterop::constant_time_equals(peer_key_confirm_mac, &expected_mac).unwrap_or(false) {
        return Err(ProtocolError::voip_call(
            "caller key confirmation MAC mismatch",
        ));
    }

    let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let eph_public_bytes = eph_public.to_bytes().to_vec();

    let classical_ss = compute_dh(
        &eph_secret.to_bytes(),
        peer_eph_x25519_public,
        "callee_eph × caller_eph",
    )?;

    let (callee_kyber_ct, callee_kyber_ss) =
        KyberInterop::encapsulate(peer_kyber_public).map_err(ProtocolError::from_crypto)?;

    let callee_kyber_ss_bytes = callee_kyber_ss
        .read_bytes(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let mut combined_pq = Vec::with_capacity(KYBER_SHARED_SECRET_BYTES * 2);
    combined_pq.extend_from_slice(&caller_kyber_ss_bytes);
    combined_pq.extend_from_slice(&callee_kyber_ss_bytes);

    let root_secret = KyberInterop::combine_hybrid_secrets(
        &classical_ss,
        &combined_pq,
        ROOT_KEY_BYTES,
        VOIP_ROOT_SECRET_INFO,
    )?;
    CryptoInterop::secure_wipe(&mut combined_pq);

    let signature = sign_call_material_with_context(
        identity_ed25519_secret,
        call_id,
        &eph_public_bytes,
        &callee_kyber_ct,
        auth_context,
        local_screen_share,
    )?;

    let mac = compute_key_confirm_mac_with_context(
        &root_secret,
        VOIP_KEY_CONFIRM_CALLEE_INFO,
        call_id,
        auth_context,
    )?;

    let key_material = derive_call_keys(&root_secret, call_id, false, auth_context.shield_mode)?;

    Ok(CallAcceptOutput {
        ephemeral_x25519_public: eph_public_bytes,
        kyber_ciphertext: callee_kyber_ct,
        identity_ed25519_public: identity_ed25519_public.to_vec(),
        signature,
        key_confirmation_mac: mac,
        key_material,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn caller_finish_with_context(
    init_output: &CallInitOutput,
    identity_kyber_secret: &SecureMemoryHandle,
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    auth_context: &CallInitAuthContext,
) -> Result<CallKeyMaterial, ProtocolError> {
    caller_finish_with_context_and_screen_share(
        init_output,
        identity_kyber_secret,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_ed25519_public,
        peer_signature,
        peer_key_confirm_mac,
        auth_context,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn caller_finish_with_context_and_screen_share(
    init_output: &CallInitOutput,
    identity_kyber_secret: &SecureMemoryHandle,
    call_id: &[u8],
    peer_eph_x25519_public: &[u8],
    peer_kyber_ct: &[u8],
    peer_ed25519_public: &[u8],
    peer_signature: &[u8],
    peer_key_confirm_mac: &[u8],
    auth_context: &CallInitAuthContext,
    peer_screen_share: Option<&ScreenShareMetadata>,
) -> Result<CallKeyMaterial, ProtocolError> {
    if call_id.len() != CALL_ID_BYTES {
        return Err(ProtocolError::voip_call("invalid call_id size"));
    }

    verify_call_signature_with_context(
        peer_ed25519_public,
        call_id,
        peer_eph_x25519_public,
        peer_kyber_ct,
        peer_signature,
        auth_context,
        peer_screen_share,
    )?;

    let eph_priv_bytes = init_output
        .ephemeral_x25519_private
        .read_bytes(X25519_PRIVATE_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let classical_ss = compute_dh(
        &eph_priv_bytes,
        peer_eph_x25519_public,
        "caller_eph × callee_eph",
    )?;

    let callee_kyber_ss = KyberInterop::decapsulate(peer_kyber_ct, identity_kyber_secret)
        .map_err(ProtocolError::from_crypto)?;

    let caller_kyber_ss_bytes = init_output
        .kyber_shared_secret
        .read_bytes(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let callee_kyber_ss_bytes = callee_kyber_ss
        .read_bytes(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let mut combined_pq = Vec::with_capacity(KYBER_SHARED_SECRET_BYTES * 2);
    combined_pq.extend_from_slice(&caller_kyber_ss_bytes);
    combined_pq.extend_from_slice(&callee_kyber_ss_bytes);

    let root_secret = KyberInterop::combine_hybrid_secrets(
        &classical_ss,
        &combined_pq,
        ROOT_KEY_BYTES,
        VOIP_ROOT_SECRET_INFO,
    )?;
    CryptoInterop::secure_wipe(&mut combined_pq);

    let expected_mac = compute_key_confirm_mac_with_context(
        &root_secret,
        VOIP_KEY_CONFIRM_CALLEE_INFO,
        call_id,
        auth_context,
    )?;
    if !CryptoInterop::constant_time_equals(peer_key_confirm_mac, &expected_mac).unwrap_or(false) {
        return Err(ProtocolError::voip_call(
            "callee key confirmation MAC mismatch",
        ));
    }

    derive_call_keys(&root_secret, call_id, true, auth_context.shield_mode)
}

pub fn rekey_initiate(
    identity_ed25519_secret: &[u8],
    peer_kyber_public: &[u8],
    call_id: &[u8],
    current_root_secret: &SecureMemoryHandle,
    rekey_generation: u32,
) -> Result<(CallInitOutput, u32), ProtocolError> {
    if rekey_generation >= MAX_RATCHET_GENERATION {
        return Err(ProtocolError::voip_rekey("rekey generation limit reached"));
    }

    let eph_secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let eph_public = X25519PublicKey::from(&eph_secret);
    let eph_public_bytes = eph_public.to_bytes().to_vec();

    let mut eph_handle = SecureMemoryHandle::allocate(X25519_PRIVATE_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    eph_handle
        .write(&eph_secret.to_bytes())
        .map_err(ProtocolError::from_crypto)?;

    let (kyber_ct, kyber_ss) =
        KyberInterop::encapsulate(peer_kyber_public).map_err(ProtocolError::from_crypto)?;

    let new_gen = rekey_generation + 1;
    let signature = sign_rekey_material(
        identity_ed25519_secret,
        call_id,
        new_gen,
        &eph_public_bytes,
        &kyber_ct,
    )?;

    // Use `read_zeroizing` so the Vec copies of kyber_ss and root_secret
    // are auto-wiped when they go out of scope.  The underlying bytes still
    // live on the pageable heap (the source mlock'd allocation is in
    // SecureMemoryHandle), so we keep the exposure window minimal: these
    // locals are dropped immediately after the MAC derivation below.
    let kyber_ss_bytes = kyber_ss
        .read_zeroizing(KYBER_SHARED_SECRET_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let current_root_bytes = current_root_secret
        .read_zeroizing(ROOT_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let mac = compute_rekey_mac_bound(
        &current_root_bytes,
        &kyber_ss_bytes,
        VOIP_KEY_CONFIRM_CALLER_INFO,
        call_id,
        new_gen,
    )?;

    let output = CallInitOutput {
        call_id: call_id.to_vec(),
        ephemeral_x25519_public: eph_public_bytes,
        kyber_ciphertext: kyber_ct,
        identity_ed25519_public: Vec::new(),
        signature,
        key_confirmation_mac: mac,
        ephemeral_x25519_private: eph_handle,
        kyber_shared_secret: kyber_ss,
        classical_shared_secret: Zeroizing::new(Vec::new()),
    };
    Ok((output, new_gen))
}

pub fn rekey_complete(
    current_root_secret: &SecureMemoryHandle,
    classical_ss: &[u8],
    new_kyber_ss: &[u8],
    call_id: &[u8],
    is_initiator: bool,
    shield_mode: bool,
) -> Result<CallKeyMaterial, ProtocolError> {
    let old_root = current_root_secret
        .read_bytes(ROOT_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;

    let mut rekey_ikm =
        Vec::with_capacity(old_root.len() + classical_ss.len() + new_kyber_ss.len());
    rekey_ikm.extend_from_slice(&old_root);
    rekey_ikm.extend_from_slice(classical_ss);
    rekey_ikm.extend_from_slice(new_kyber_ss);

    let new_root =
        HkdfSha256::derive_key_bytes(&rekey_ikm, ROOT_KEY_BYTES, call_id, VOIP_REKEY_INFO)?;
    CryptoInterop::secure_wipe(&mut rekey_ikm);

    derive_call_keys(&new_root, call_id, is_initiator, shield_mode)
}
