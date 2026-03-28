// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, ATTACHMENT_FILE_KEY_BYTES, ATTACHMENT_HASH_BYTES, ATTACHMENT_ID_BYTES,
    ATTACHMENT_NONCE_INFO, ATTACHMENT_PROTOCOL_VERSION, ATTACHMENT_THUMBNAIL_AAD_PREFIX,
    ATTACHMENT_THUMBNAIL_CHUNK_INDEX, COLLAGE_ID_BYTES, MAX_ATTACHMENT_ALT_TEXT_CHARS,
    MAX_ATTACHMENT_CHUNK_SIZE, MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE,
    MAX_ATTACHMENT_FILENAME_BYTES, MAX_ATTACHMENT_THUMBNAIL_SIZE, MAX_ATTACHMENT_TTL_SECONDS,
    MAX_COLLAGE_ATTACHMENTS, MAX_COLLAGE_DESCRIPTION_CHARS, MAX_COLLAGE_NAME_CHARS,
    MAX_CONTACT_AVATAR_DATA_SIZE, MAX_CONTACT_DISPLAY_NAME_CHARS, MAX_CONTACT_EMAIL_CHARS,
    MAX_CONTACT_ORGANIZATION_CHARS, MAX_CONTACT_PHONE_CHARS, MAX_INLINE_ATTACHMENT_DATA_SIZE,
    MAX_LINK_PREVIEW_DESCRIPTION_CHARS, MAX_LINK_PREVIEW_DOMAIN_CHARS, MAX_LINK_PREVIEW_IMAGE_SIZE,
    MAX_LINK_PREVIEW_TITLE_CHARS, MAX_LINK_PREVIEW_URL_CHARS, MAX_LOCATION_LABEL_CHARS,
    MAX_VOICE_TRANSCRIPT_CHARS, MAX_VOICE_WAVEFORM_SAMPLES, MESSAGE_ID_BYTES,
    MIN_ATTACHMENT_TTL_SECONDS,
};
use crate::core::errors::ProtocolError;
use crate::crypto::{AesGcm, HkdfSha256};
use crate::proto::{
    AttachmentManifest, AttachmentReference, ChunkProgress, CollageManifest, ContactCard,
    ContentPolicy, InlineAttachment, LinkPreview, LocationAttachment, VoiceMessageMeta,
};
use prost::Message;
use std::collections::BTreeSet;
use std::mem::size_of;

fn validate_mime_type(mime_type: &str) -> Result<(), ProtocolError> {
    if mime_type.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type is required",
        ));
    }
    if mime_type.len() > 255 {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type too long",
        ));
    }
    if !mime_type.is_ascii() {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type must be ASCII",
        ));
    }
    let Some((type_part, subtype_part)) = mime_type.split_once('/') else {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type must contain '/'",
        ));
    };
    if type_part.is_empty() || subtype_part.is_empty() || subtype_part.contains('/') {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type must be type/subtype",
        ));
    }
    if !type_part.bytes().all(is_mime_token_byte) || !subtype_part.bytes().all(is_mime_token_byte) {
        return Err(ProtocolError::invalid_input(
            "Attachment mime_type contains invalid characters",
        ));
    }
    Ok(())
}

fn is_mime_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub fn generate_attachment_id() -> Vec<u8> {
    crate::crypto::CryptoInterop::get_random_bytes(ATTACHMENT_ID_BYTES)
}

pub fn generate_file_key() -> Vec<u8> {
    crate::crypto::CryptoInterop::get_random_bytes(ATTACHMENT_FILE_KEY_BYTES)
}

pub fn validate_manifest(manifest: &AttachmentManifest) -> Result<(), ProtocolError> {
    if manifest.version != ATTACHMENT_PROTOCOL_VERSION {
        return Err(ProtocolError::invalid_input(
            "Unsupported attachment manifest version",
        ));
    }
    if manifest.attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    validate_mime_type(&manifest.mime_type)?;
    if manifest.total_size == 0 {
        return Err(ProtocolError::invalid_input(
            "Attachment total_size must be > 0",
        ));
    }
    if manifest.chunk_size == 0 || manifest.chunk_size as usize > MAX_ATTACHMENT_CHUNK_SIZE {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk_size is out of range",
        ));
    }
    if manifest.chunk_count == 0 {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk_count must be > 0",
        ));
    }
    if manifest.file_sha256.len() != ATTACHMENT_HASH_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment file_sha256 must be 32 bytes",
        ));
    }
    if manifest.encrypted_file_key.is_empty()
        || manifest.encrypted_file_key.len() > MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE
    {
        return Err(ProtocolError::invalid_input(
            "Attachment encrypted_file_key size is out of range",
        ));
    }
    if manifest.encryption_scheme != "AES-256-GCM-SIV" {
        return Err(ProtocolError::invalid_input(
            "Unsupported attachment encryption_scheme",
        ));
    }

    let total_chunks = u64::from(manifest.chunk_count);
    let chunk_size = u64::from(manifest.chunk_size);
    let min_size = (total_chunks - 1)
        .checked_mul(chunk_size)
        .ok_or_else(|| ProtocolError::invalid_input("Attachment size overflow"))?;
    let max_size = total_chunks
        .checked_mul(chunk_size)
        .ok_or_else(|| ProtocolError::invalid_input("Attachment size overflow"))?;
    if manifest.total_size <= min_size || manifest.total_size > max_size {
        return Err(ProtocolError::invalid_input(
            "Attachment total_size does not match chunk_size/chunk_count",
        ));
    }

    validate_manifest_optional_fields(manifest)?;

    Ok(())
}

fn validate_manifest_optional_fields(manifest: &AttachmentManifest) -> Result<(), ProtocolError> {
    let has_thumbnail = manifest.encrypted_thumbnail.is_some();
    let has_nonce = manifest.thumbnail_nonce.is_some();
    let has_mime = manifest.thumbnail_mime_type.is_some();
    let has_size = manifest.thumbnail_size.is_some();

    if has_thumbnail || has_nonce || has_mime || has_size {
        if !has_thumbnail || !has_nonce || !has_mime || !has_size {
            return Err(ProtocolError::invalid_input(
                "Thumbnail fields must all be present or all absent",
            ));
        }
        let (Some(thumb), Some(nonce), Some(mime), Some(size)) = (
            manifest.encrypted_thumbnail.as_ref(),
            manifest.thumbnail_nonce.as_ref(),
            manifest.thumbnail_mime_type.as_ref(),
            manifest.thumbnail_size,
        ) else {
            return Err(ProtocolError::invalid_input(
                "Thumbnail fields must all be present or all absent",
            ));
        };
        if thumb.len() < 16 || thumb.len() > MAX_ATTACHMENT_THUMBNAIL_SIZE + 16 {
            return Err(ProtocolError::invalid_input(
                "Attachment encrypted_thumbnail size is out of range",
            ));
        }
        if nonce.len() != AES_GCM_NONCE_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment thumbnail_nonce must be 12 bytes",
            ));
        }
        validate_mime_type(mime)?;
        if size == 0 || size as usize > MAX_ATTACHMENT_THUMBNAIL_SIZE {
            return Err(ProtocolError::invalid_input(
                "Attachment thumbnail_size is out of range",
            ));
        }
    }

    if let Some(ttl) = manifest.ttl_seconds {
        validate_ttl(ttl)?;
        if manifest.created_at_unix.is_none() || manifest.created_at_unix == Some(0) {
            return Err(ProtocolError::invalid_input(
                "Attachment created_at_unix is required when ttl_seconds is set",
            ));
        }
    }

    if let Some(ref filename) = manifest.original_filename {
        validate_filename(filename)?;
    }
    if let Some(ref alt) = manifest.alt_text {
        if alt.chars().count() > MAX_ATTACHMENT_ALT_TEXT_CHARS {
            return Err(ProtocolError::invalid_input(
                "Attachment alt_text exceeds max length",
            ));
        }
    }
    if let Some(ref policy) = manifest.content_policy {
        validate_content_policy(policy, manifest.ttl_seconds)?;
    }

    if let Some(ref voice) = manifest.voice_meta {
        validate_voice_message_meta(voice)?;
    }

    Ok(())
}

fn chunk_aad(
    attachment_id: &[u8],
    mime_type: &str,
    total_size: u64,
    chunk_size: u32,
    chunk_index: u32,
    chunk_count: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(128 + mime_type.len());
    aad.extend_from_slice(b"Ecliptix-Attachment-Chunk-v1");
    aad.extend_from_slice(attachment_id);
    aad.extend_from_slice(&total_size.to_le_bytes());
    aad.extend_from_slice(&chunk_size.to_le_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&chunk_count.to_le_bytes());
    aad.extend_from_slice(mime_type.as_bytes());
    aad
}

pub fn derive_chunk_nonce(
    file_key: &[u8],
    attachment_id: &[u8],
    chunk_index: u32,
) -> Result<Vec<u8>, ProtocolError> {
    if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment file key must be 32 bytes",
        ));
    }
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    let mut salt = Vec::with_capacity(ATTACHMENT_ID_BYTES + size_of::<u32>());
    salt.extend_from_slice(attachment_id);
    salt.extend_from_slice(&chunk_index.to_le_bytes());
    HkdfSha256::derive_key_bytes(file_key, AES_GCM_NONCE_BYTES, &salt, ATTACHMENT_NONCE_INFO)
        .map(|v| v.to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_chunk(
    file_key: &[u8],
    attachment_id: &[u8],
    mime_type: &str,
    total_size: u64,
    chunk_size: u32,
    chunk_index: u32,
    chunk_count: u32,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    if plaintext.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk plaintext is empty",
        ));
    }
    if plaintext.len() > chunk_size as usize || plaintext.len() > MAX_ATTACHMENT_CHUNK_SIZE {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk plaintext is too large",
        ));
    }
    if chunk_index >= chunk_count {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk_index must be < chunk_count",
        ));
    }
    validate_mime_type(mime_type)?;

    let nonce = derive_chunk_nonce(file_key, attachment_id, chunk_index)?;
    let aad = chunk_aad(
        attachment_id,
        mime_type,
        total_size,
        chunk_size,
        chunk_index,
        chunk_count,
    );
    let ciphertext = AesGcm::encrypt(file_key, &nonce, plaintext, &aad)?;
    Ok((nonce, ciphertext))
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_chunk(
    file_key: &[u8],
    attachment_id: &[u8],
    mime_type: &str,
    total_size: u64,
    chunk_size: u32,
    chunk_index: u32,
    chunk_count: u32,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if chunk_index >= chunk_count {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk_index must be < chunk_count",
        ));
    }
    if ciphertext.len() < 16 {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk ciphertext is too small",
        ));
    }
    if ciphertext.len() > chunk_size as usize + 16 {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk ciphertext is too large",
        ));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk nonce must be 12 bytes",
        ));
    }
    validate_mime_type(mime_type)?;

    let expected_nonce = derive_chunk_nonce(file_key, attachment_id, chunk_index)?;
    if !crate::crypto::CryptoInterop::constant_time_equals(nonce, &expected_nonce).unwrap_or(false)
    {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk nonce mismatch",
        ));
    }

    let aad = chunk_aad(
        attachment_id,
        mime_type,
        total_size,
        chunk_size,
        chunk_index,
        chunk_count,
    );
    AesGcm::decrypt(file_key, nonce, ciphertext, &aad)
}

pub fn validate_chunk_shape(
    manifest: &AttachmentManifest,
    chunk_index: u32,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), ProtocolError> {
    validate_manifest(manifest)?;
    if chunk_index >= manifest.chunk_count {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk_index must be < chunk_count",
        ));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk nonce must be 12 bytes",
        ));
    }
    if ciphertext.len() < 16 || ciphertext.len() > manifest.chunk_size as usize + 16 {
        return Err(ProtocolError::invalid_input(
            "Attachment chunk ciphertext size is out of range",
        ));
    }
    Ok(())
}

// --- TTL ---

pub fn validate_ttl(ttl_seconds: u64) -> Result<(), ProtocolError> {
    if !(MIN_ATTACHMENT_TTL_SECONDS..=MAX_ATTACHMENT_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ProtocolError::invalid_input(
            "Attachment ttl_seconds is out of range",
        ));
    }
    Ok(())
}

pub const fn is_attachment_expired(created_at_unix: u64, ttl_seconds: u64, now_unix: u64) -> bool {
    now_unix >= created_at_unix.saturating_add(ttl_seconds)
}

// --- Thumbnail ---

fn thumbnail_aad(attachment_id: &[u8], thumbnail_mime_type: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + thumbnail_mime_type.len());
    aad.extend_from_slice(ATTACHMENT_THUMBNAIL_AAD_PREFIX);
    aad.extend_from_slice(attachment_id);
    aad.extend_from_slice(thumbnail_mime_type.as_bytes());
    aad
}

pub fn encrypt_thumbnail(
    file_key: &[u8],
    attachment_id: &[u8],
    thumbnail_mime_type: &str,
    thumbnail_plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment file key must be 32 bytes",
        ));
    }
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    if thumbnail_plaintext.is_empty() {
        return Err(ProtocolError::invalid_input("Thumbnail plaintext is empty"));
    }
    if thumbnail_plaintext.len() > MAX_ATTACHMENT_THUMBNAIL_SIZE {
        return Err(ProtocolError::invalid_input(
            "Thumbnail plaintext is too large",
        ));
    }
    validate_mime_type(thumbnail_mime_type)?;

    let nonce = derive_chunk_nonce(file_key, attachment_id, ATTACHMENT_THUMBNAIL_CHUNK_INDEX)?;
    let aad = thumbnail_aad(attachment_id, thumbnail_mime_type);
    let ciphertext = AesGcm::encrypt(file_key, &nonce, thumbnail_plaintext, &aad)?;
    Ok((nonce, ciphertext))
}

pub fn decrypt_thumbnail(
    file_key: &[u8],
    attachment_id: &[u8],
    thumbnail_mime_type: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment file key must be 32 bytes",
        ));
    }
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    if nonce.len() != AES_GCM_NONCE_BYTES {
        return Err(ProtocolError::invalid_input(
            "Thumbnail nonce must be 12 bytes",
        ));
    }
    if ciphertext.len() < 16 || ciphertext.len() > MAX_ATTACHMENT_THUMBNAIL_SIZE + 16 {
        return Err(ProtocolError::invalid_input(
            "Thumbnail ciphertext size is out of range",
        ));
    }
    validate_mime_type(thumbnail_mime_type)?;

    let expected_nonce =
        derive_chunk_nonce(file_key, attachment_id, ATTACHMENT_THUMBNAIL_CHUNK_INDEX)?;
    if !crate::crypto::CryptoInterop::constant_time_equals(nonce, &expected_nonce).unwrap_or(false)
    {
        return Err(ProtocolError::invalid_input("Thumbnail nonce mismatch"));
    }

    let aad = thumbnail_aad(attachment_id, thumbnail_mime_type);
    AesGcm::decrypt(file_key, nonce, ciphertext, &aad)
}

// --- Resume / Progress ---

pub fn create_chunk_progress(
    attachment_id: &[u8],
    chunk_count: u32,
) -> Result<ChunkProgress, ProtocolError> {
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    if chunk_count == 0 {
        return Err(ProtocolError::invalid_input("chunk_count must be > 0"));
    }
    Ok(ChunkProgress {
        attachment_id: attachment_id.to_vec(),
        chunk_count,
        completed_chunks: Vec::new(),
        total_bytes_transferred: 0,
        last_updated_unix: 0,
    })
}

pub fn mark_chunk_completed(
    progress: &mut ChunkProgress,
    chunk_index: u32,
    bytes_transferred: u64,
    now_unix: u64,
) -> Result<(), ProtocolError> {
    if chunk_index >= progress.chunk_count {
        return Err(ProtocolError::invalid_input(
            "chunk_index must be < chunk_count",
        ));
    }
    if !progress.completed_chunks.contains(&chunk_index) {
        progress.completed_chunks.push(chunk_index);
    }
    progress.total_bytes_transferred = progress
        .total_bytes_transferred
        .saturating_add(bytes_transferred);
    progress.last_updated_unix = now_unix;
    Ok(())
}

pub fn get_remaining_chunks(progress: &ChunkProgress) -> Vec<u32> {
    let completed: BTreeSet<u32> = progress.completed_chunks.iter().copied().collect();
    (0..progress.chunk_count)
        .filter(|i| !completed.contains(i))
        .collect()
}

pub fn is_transfer_complete(progress: &ChunkProgress) -> bool {
    let completed: BTreeSet<u32> = progress.completed_chunks.iter().copied().collect();
    u32::try_from(completed.len()).unwrap_or(0) >= progress.chunk_count
}

// --- Collage ---

pub fn generate_collage_id() -> Vec<u8> {
    crate::crypto::CryptoInterop::get_random_bytes(COLLAGE_ID_BYTES)
}

pub fn create_collage_manifest(
    manifests: &[AttachmentManifest],
) -> Result<CollageManifest, ProtocolError> {
    create_collage_manifest_with_metadata(manifests, None, None, None)
}

pub fn create_collage_manifest_with_metadata(
    manifests: &[AttachmentManifest],
    name: Option<&str>,
    description: Option<&str>,
    layout: Option<i32>,
) -> Result<CollageManifest, ProtocolError> {
    if manifests.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Collage must have at least 1 attachment",
        ));
    }
    if manifests.len() > MAX_COLLAGE_ATTACHMENTS {
        return Err(ProtocolError::invalid_input(
            "Collage exceeds max attachment count",
        ));
    }
    if let Some(name) = name {
        if name.chars().count() > MAX_COLLAGE_NAME_CHARS {
            return Err(ProtocolError::invalid_input(
                "Collage name exceeds max length",
            ));
        }
    }
    if let Some(description) = description {
        if description.chars().count() > MAX_COLLAGE_DESCRIPTION_CHARS {
            return Err(ProtocolError::invalid_input(
                "Collage description exceeds max length",
            ));
        }
    }
    if let Some(layout) = layout {
        if !(0..=3).contains(&layout) {
            return Err(ProtocolError::invalid_input(
                "Collage layout must be 0, 1, 2, or 3",
            ));
        }
    }

    let mut seen_indices = BTreeSet::new();
    let mut encoded = Vec::with_capacity(manifests.len());

    for (i, m) in manifests.iter().enumerate() {
        validate_manifest(m)?;
        let idx = m
            .collage_index
            .unwrap_or_else(|| u32::try_from(i).unwrap_or(0));
        if !seen_indices.insert(idx) {
            return Err(ProtocolError::invalid_input(
                "Collage manifests must have unique collage_index values",
            ));
        }
        let mut buf = Vec::new();
        m.encode(&mut buf)
            .map_err(|e| ProtocolError::encode(format!("CollageManifest entry encode: {e}")))?;
        encoded.push(buf);
    }

    Ok(CollageManifest {
        version: 1,
        collage_id: generate_collage_id(),
        manifests: encoded,
        display_count: u32::try_from(manifests.len()).unwrap_or(0),
        name: name.map(String::from),
        description: description.map(String::from),
        layout,
    })
}

pub fn validate_collage_manifest(
    collage: &CollageManifest,
) -> Result<Vec<AttachmentManifest>, ProtocolError> {
    if collage.version != 1 {
        return Err(ProtocolError::invalid_input(
            "Unsupported collage manifest version",
        ));
    }
    if collage.collage_id.len() != COLLAGE_ID_BYTES {
        return Err(ProtocolError::invalid_input("Collage ID must be 32 bytes"));
    }
    if collage.manifests.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Collage must have at least 1 attachment",
        ));
    }
    if collage.manifests.len() > MAX_COLLAGE_ATTACHMENTS {
        return Err(ProtocolError::invalid_input(
            "Collage exceeds max attachment count",
        ));
    }
    if collage.display_count as usize != collage.manifests.len() {
        return Err(ProtocolError::invalid_input(
            "Collage display_count does not match manifests length",
        ));
    }

    if let Some(ref name) = collage.name {
        if name.chars().count() > MAX_COLLAGE_NAME_CHARS {
            return Err(ProtocolError::invalid_input(
                "Collage name exceeds max length",
            ));
        }
    }
    if let Some(ref desc) = collage.description {
        if desc.chars().count() > MAX_COLLAGE_DESCRIPTION_CHARS {
            return Err(ProtocolError::invalid_input(
                "Collage description exceeds max length",
            ));
        }
    }
    if let Some(layout) = collage.layout {
        if !(0..=3).contains(&layout) {
            return Err(ProtocolError::invalid_input(
                "Collage layout must be 0, 1, 2, or 3",
            ));
        }
    }

    let mut decoded = Vec::with_capacity(collage.manifests.len());
    let mut seen_indices = BTreeSet::new();

    for (i, bytes) in collage.manifests.iter().enumerate() {
        let m = AttachmentManifest::decode(bytes.as_slice())
            .map_err(|e| ProtocolError::decode(format!("CollageManifest entry decode: {e}")))?;
        validate_manifest(&m)?;
        let idx = m
            .collage_index
            .unwrap_or_else(|| u32::try_from(i).unwrap_or(0));
        if !seen_indices.insert(idx) {
            return Err(ProtocolError::invalid_input(
                "Collage manifests must have unique collage_index values",
            ));
        }
        decoded.push(m);
    }

    Ok(decoded)
}

// --- Streaming ---

pub struct EncryptedChunk {
    pub chunk_index: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct StreamingEncryptor {
    file_key: Vec<u8>,
    attachment_id: Vec<u8>,
    mime_type: String,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    current_chunk_index: u32,
    buffer: Vec<u8>,
}

impl StreamingEncryptor {
    pub fn new(
        file_key: Vec<u8>,
        attachment_id: Vec<u8>,
        mime_type: String,
        total_size: u64,
        chunk_size: u32,
        chunk_count: u32,
    ) -> Result<Self, ProtocolError> {
        if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment file key must be 32 bytes",
            ));
        }
        if attachment_id.len() != ATTACHMENT_ID_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment ID must be 32 bytes",
            ));
        }
        if chunk_size == 0 || chunk_size as usize > MAX_ATTACHMENT_CHUNK_SIZE {
            return Err(ProtocolError::invalid_input(
                "Attachment chunk_size is out of range",
            ));
        }
        if chunk_count == 0 {
            return Err(ProtocolError::invalid_input(
                "Attachment chunk_count must be > 0",
            ));
        }
        if total_size == 0 {
            return Err(ProtocolError::invalid_input(
                "Attachment total_size must be > 0",
            ));
        }
        validate_mime_type(&mime_type)?;

        Ok(Self {
            file_key,
            attachment_id,
            mime_type,
            total_size,
            chunk_size,
            chunk_count,
            current_chunk_index: 0,
            buffer: Vec::with_capacity(chunk_size as usize),
        })
    }

    pub fn write(&mut self, data: &[u8]) -> Result<Vec<EncryptedChunk>, ProtocolError> {
        let mut result = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let remaining_in_chunk = self.chunk_size as usize - self.buffer.len();
            let to_copy = remaining_in_chunk.min(data.len() - offset);
            self.buffer
                .extend_from_slice(&data[offset..offset + to_copy]);
            offset += to_copy;

            if self.buffer.len() == self.chunk_size as usize {
                result.push(self.flush_buffer()?);
            }
        }

        Ok(result)
    }

    pub fn finish(mut self) -> Result<Option<EncryptedChunk>, ProtocolError> {
        if self.buffer.is_empty() {
            if self.current_chunk_index != self.chunk_count {
                return Err(ProtocolError::invalid_state(
                    "StreamingEncryptor: not all chunks emitted",
                ));
            }
            return Ok(None);
        }
        let chunk = self.flush_buffer()?;
        if self.current_chunk_index != self.chunk_count {
            return Err(ProtocolError::invalid_state(
                "StreamingEncryptor: not all chunks emitted",
            ));
        }
        Ok(Some(chunk))
    }

    fn flush_buffer(&mut self) -> Result<EncryptedChunk, ProtocolError> {
        if self.current_chunk_index >= self.chunk_count {
            return Err(ProtocolError::invalid_state(
                "StreamingEncryptor: chunk_count exceeded",
            ));
        }
        let (nonce, ciphertext) = encrypt_chunk(
            &self.file_key,
            &self.attachment_id,
            &self.mime_type,
            self.total_size,
            self.chunk_size,
            self.current_chunk_index,
            self.chunk_count,
            &self.buffer,
        )?;
        let idx = self.current_chunk_index;
        self.current_chunk_index += 1;
        self.buffer.clear();
        Ok(EncryptedChunk {
            chunk_index: idx,
            nonce,
            ciphertext,
        })
    }
}

pub struct StreamingDecryptor {
    file_key: Vec<u8>,
    attachment_id: Vec<u8>,
    mime_type: String,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    next_expected_chunk: u32,
}

impl StreamingDecryptor {
    pub fn new(
        file_key: Vec<u8>,
        attachment_id: Vec<u8>,
        mime_type: String,
        total_size: u64,
        chunk_size: u32,
        chunk_count: u32,
    ) -> Result<Self, ProtocolError> {
        if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment file key must be 32 bytes",
            ));
        }
        if attachment_id.len() != ATTACHMENT_ID_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment ID must be 32 bytes",
            ));
        }
        if chunk_size == 0 || chunk_size as usize > MAX_ATTACHMENT_CHUNK_SIZE {
            return Err(ProtocolError::invalid_input(
                "Attachment chunk_size is out of range",
            ));
        }
        if chunk_count == 0 {
            return Err(ProtocolError::invalid_input(
                "Attachment chunk_count must be > 0",
            ));
        }
        validate_mime_type(&mime_type)?;

        Ok(Self {
            file_key,
            attachment_id,
            mime_type,
            total_size,
            chunk_size,
            chunk_count,
            next_expected_chunk: 0,
        })
    }

    pub fn decrypt_next(
        &mut self,
        chunk_index: u32,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if chunk_index != self.next_expected_chunk {
            return Err(ProtocolError::invalid_input(
                "StreamingDecryptor: out-of-order chunk",
            ));
        }
        let plaintext = decrypt_chunk(
            &self.file_key,
            &self.attachment_id,
            &self.mime_type,
            self.total_size,
            self.chunk_size,
            chunk_index,
            self.chunk_count,
            nonce,
            ciphertext,
        )?;
        self.next_expected_chunk += 1;
        Ok(plaintext)
    }

    pub const fn is_complete(&self) -> bool {
        self.next_expected_chunk >= self.chunk_count
    }
}

// --- File Key Helper ---

pub fn encrypt_file_key_for_session(
    session: &crate::protocol::Session,
    file_key: &[u8],
    attachment_id: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if file_key.len() != ATTACHMENT_FILE_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment file key must be 32 bytes",
        ));
    }
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    let correlation = attachment_id_to_correlation_id(attachment_id);
    let envelope = session.encrypt(file_key, 0, 0, Some(&correlation))?;
    let mut buf = Vec::new();
    envelope
        .encode(&mut buf)
        .map_err(|e| ProtocolError::encode(format!("File key envelope encode: {e}")))?;
    Ok(buf)
}

pub fn decrypt_file_key_from_session(
    session: &crate::protocol::Session,
    encrypted_file_key: &[u8],
    attachment_id: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment ID must be 32 bytes",
        ));
    }
    let envelope = crate::proto::SecureEnvelope::decode(encrypted_file_key)
        .map_err(|e| ProtocolError::decode(format!("File key envelope decode: {e}")))?;
    let result = session.decrypt(&envelope)?;
    if result.plaintext.len() != ATTACHMENT_FILE_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Decrypted file key has invalid length",
        ));
    }
    let expected_correlation = attachment_id_to_correlation_id(attachment_id);
    if result.metadata.correlation_id.as_deref() != Some(expected_correlation.as_str()) {
        return Err(ProtocolError::invalid_input(
            "Encrypted file key does not match attachment ID",
        ));
    }
    Ok(result.plaintext)
}

fn attachment_id_to_correlation_id(attachment_id: &[u8]) -> String {
    let mut correlation = String::with_capacity(attachment_id.len() * 2);
    for b in attachment_id {
        use std::fmt::Write;
        let _ = write!(correlation, "{b:02x}");
    }
    correlation
}

const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn is_windows_reserved(name: &str) -> bool {
    let normalized = name.trim_end_matches([' ', '.']);
    let stem = normalized.split('.').next().unwrap_or("");
    let upper = stem.to_uppercase();
    WINDOWS_RESERVED_NAMES.iter().any(|r| *r == upper)
}

pub fn validate_filename(name: &str) -> Result<(), ProtocolError> {
    if name.is_empty() {
        return Err(ProtocolError::invalid_input("Filename must not be empty"));
    }
    if name.len() > MAX_ATTACHMENT_FILENAME_BYTES {
        return Err(ProtocolError::invalid_input("Filename exceeds max length"));
    }
    if name.bytes().any(|b| b == 0) {
        return Err(ProtocolError::invalid_input(
            "Filename must not contain NUL bytes",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(ProtocolError::invalid_input(
            "Filename must not contain control characters",
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(ProtocolError::invalid_input(
            "Filename must not contain path separators",
        ));
    }
    if name == "." || name == ".." {
        return Err(ProtocolError::invalid_input(
            "Filename must not be '.' or '..'",
        ));
    }
    if name.contains("..") {
        return Err(ProtocolError::invalid_input(
            "Filename must not contain '..' sequences",
        ));
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return Err(ProtocolError::invalid_input(
            "Filename must not end with '.' or space",
        ));
    }
    if is_windows_reserved(name) {
        return Err(ProtocolError::invalid_input(
            "Filename must not be a Windows reserved name",
        ));
    }
    Ok(())
}

pub fn sanitize_filename(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_control() || ch == '\0' {
            continue;
        }
        if ch == '/' || ch == '\\' {
            result.push('_');
        } else {
            result.push(ch);
        }
    }
    result = result.replace("..", "_");
    if result.len() > MAX_ATTACHMENT_FILENAME_BYTES {
        let mut end = MAX_ATTACHMENT_FILENAME_BYTES;
        while !result.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        result.truncate(end);
    }
    while result.ends_with(' ') || result.ends_with('.') {
        result.pop();
    }
    if result == "." || result == ".." {
        result.clear();
    }
    if result.is_empty() {
        return "_".to_owned();
    }
    if is_windows_reserved(&result) {
        result.insert(0, '_');
    }
    result
}

struct MagicSignature {
    mime: &'static str,
    offset: usize,
    bytes: &'static [u8],
    extra_check: Option<fn(&[u8]) -> bool>,
}

fn check_webp(header: &[u8]) -> bool {
    header.len() >= 12 && &header[8..12] == b"WEBP"
}

fn check_heic(header: &[u8]) -> bool {
    if header.len() < 12 {
        return false;
    }
    let brand = &header[8..12];
    brand == b"heic" || brand == b"heix" || brand == b"mif1"
}

fn check_wave(header: &[u8]) -> bool {
    header.len() >= 12 && &header[8..12] == b"WAVE"
}

const MAGIC_TABLE: &[MagicSignature] = &[
    MagicSignature {
        mime: "image/png",
        offset: 0,
        bytes: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        extra_check: None,
    },
    MagicSignature {
        mime: "image/webp",
        offset: 0,
        bytes: b"RIFF",
        extra_check: Some(check_webp),
    },
    MagicSignature {
        mime: "image/heic",
        offset: 4,
        bytes: b"ftyp",
        extra_check: Some(check_heic),
    },
    MagicSignature {
        mime: "image/heif",
        offset: 4,
        bytes: b"ftyp",
        extra_check: Some(check_heic),
    },
    MagicSignature {
        mime: "image/jpeg",
        offset: 0,
        bytes: &[0xFF, 0xD8, 0xFF],
        extra_check: None,
    },
    MagicSignature {
        mime: "image/gif",
        offset: 0,
        bytes: &[0x47, 0x49, 0x46, 0x38],
        extra_check: None,
    },
    MagicSignature {
        mime: "image/tiff",
        offset: 0,
        bytes: &[0x49, 0x49, 0x2A, 0x00],
        extra_check: None,
    },
    MagicSignature {
        mime: "image/bmp",
        offset: 0,
        bytes: &[0x42, 0x4D],
        extra_check: None,
    },
    MagicSignature {
        mime: "application/pdf",
        offset: 0,
        bytes: &[0x25, 0x50, 0x44, 0x46],
        extra_check: None,
    },
    MagicSignature {
        mime: "video/mp4",
        offset: 4,
        bytes: b"ftyp",
        extra_check: None,
    },
    MagicSignature {
        mime: "video/quicktime",
        offset: 4,
        bytes: b"ftyp",
        extra_check: None,
    },
    MagicSignature {
        mime: "video/webm",
        offset: 0,
        bytes: &[0x1A, 0x45, 0xDF, 0xA3],
        extra_check: None,
    },
    MagicSignature {
        mime: "audio/ogg",
        offset: 0,
        bytes: &[0x4F, 0x67, 0x67, 0x53],
        extra_check: None,
    },
    MagicSignature {
        mime: "video/ogg",
        offset: 0,
        bytes: &[0x4F, 0x67, 0x67, 0x53],
        extra_check: None,
    },
    MagicSignature {
        mime: "application/zip",
        offset: 0,
        bytes: &[0x50, 0x4B, 0x03, 0x04],
        extra_check: None,
    },
    MagicSignature {
        mime: "audio/flac",
        offset: 0,
        bytes: &[0x66, 0x4C, 0x61, 0x43],
        extra_check: None,
    },
    MagicSignature {
        mime: "audio/wav",
        offset: 0,
        bytes: b"RIFF",
        extra_check: Some(check_wave),
    },
];

fn matches_signature(header: &[u8], sig: &MagicSignature) -> bool {
    let end = sig.offset + sig.bytes.len();
    if header.len() < end {
        return false;
    }
    if header[sig.offset..end] != *sig.bytes {
        return false;
    }
    if let Some(check) = sig.extra_check {
        return check(header);
    }
    true
}

fn match_mp3(header: &[u8]) -> bool {
    if header.len() < 3 && header.len() < 2 {
        return false;
    }
    if header.len() >= 3 && header[0..3] == [0x49, 0x44, 0x33] {
        return true;
    }
    if header.len() >= 2 {
        let b0 = header[0];
        let b1 = header[1];
        if b0 == 0xFF && (b1 == 0xFB || b1 == 0xF3 || b1 == 0xF2) {
            return true;
        }
    }
    false
}

fn match_aac(header: &[u8]) -> bool {
    if header.len() < 2 {
        return false;
    }
    header[0] == 0xFF && (header[1] == 0xF1 || header[1] == 0xF9)
}

fn match_tiff_be(header: &[u8]) -> bool {
    header.len() >= 4 && header[0..4] == [0x4D, 0x4D, 0x00, 0x2A]
}

pub fn validate_magic_bytes(header: &[u8], mime_type: &str) -> Result<(), ProtocolError> {
    for sig in MAGIC_TABLE {
        if sig.mime == mime_type {
            let needed = sig.offset + sig.bytes.len();
            if let Some(check) = sig.extra_check {
                let needed = needed.max(12);
                if header.len() < needed {
                    return Err(ProtocolError::invalid_input(
                        "Header too short to validate magic bytes",
                    ));
                }
                if header[sig.offset..sig.offset + sig.bytes.len()] != *sig.bytes || !check(header)
                {
                    return Err(ProtocolError::invalid_input(
                        "Magic bytes do not match declared mime type",
                    ));
                }
                return Ok(());
            }
            if header.len() < needed {
                return Err(ProtocolError::invalid_input(
                    "Header too short to validate magic bytes",
                ));
            }
            if header[sig.offset..sig.offset + sig.bytes.len()] != *sig.bytes {
                return Err(ProtocolError::invalid_input(
                    "Magic bytes do not match declared mime type",
                ));
            }
            return Ok(());
        }
    }
    if mime_type == "audio/mpeg" || mime_type == "audio/mp3" {
        if header.len() < 2 {
            return Err(ProtocolError::invalid_input(
                "Header too short to validate magic bytes",
            ));
        }
        if !match_mp3(header) {
            return Err(ProtocolError::invalid_input(
                "Magic bytes do not match declared mime type",
            ));
        }
        return Ok(());
    }
    if mime_type == "audio/aac" {
        if header.len() < 2 {
            return Err(ProtocolError::invalid_input(
                "Header too short to validate magic bytes",
            ));
        }
        if !match_aac(header) {
            return Err(ProtocolError::invalid_input(
                "Magic bytes do not match declared mime type",
            ));
        }
        return Ok(());
    }
    if mime_type == "image/tiff" && match_tiff_be(header) {
        return Ok(());
    }
    Err(ProtocolError::invalid_input(
        "Unsupported mime type for magic byte validation",
    ))
}

pub fn detect_mime_from_magic(header: &[u8]) -> Option<&'static str> {
    if header.len() >= 12 && &header[0..4] == b"RIFF" {
        if &header[8..12] == b"WEBP" {
            return Some("image/webp");
        }
        if &header[8..12] == b"WAVE" {
            return Some("audio/wav");
        }
    }
    if header.len() >= 12 && &header[4..8] == b"ftyp" {
        let brand = &header[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"mif1" {
            return Some("image/heic");
        }
        return Some("video/mp4");
    }
    for sig in MAGIC_TABLE {
        if sig.extra_check.is_some() {
            continue;
        }
        if sig.mime == "video/mp4" || sig.mime == "video/quicktime" {
            continue;
        }
        if matches_signature(header, sig) {
            return Some(sig.mime);
        }
    }
    if match_tiff_be(header) {
        return Some("image/tiff");
    }
    if match_mp3(header) {
        return Some("audio/mpeg");
    }
    if match_aac(header) {
        return Some("audio/aac");
    }
    None
}

pub fn validate_content_policy(
    policy: &ContentPolicy,
    ttl_seconds: Option<u64>,
) -> Result<(), ProtocolError> {
    if policy.view_once && ttl_seconds.is_none() {
        return Err(ProtocolError::invalid_input(
            "view_once content policy requires ttl_seconds to be set",
        ));
    }
    Ok(())
}

pub fn validate_inline_attachment(inline: &InlineAttachment) -> Result<(), ProtocolError> {
    if inline.attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Inline attachment ID must be 32 bytes",
        ));
    }
    validate_mime_type(&inline.mime_type)?;
    if inline.data.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Inline attachment data must not be empty",
        ));
    }
    if inline.data.len() > MAX_INLINE_ATTACHMENT_DATA_SIZE {
        return Err(ProtocolError::invalid_input(
            "Inline attachment data exceeds max size",
        ));
    }
    if let Some(ref filename) = inline.original_filename {
        validate_filename(filename)?;
    }
    if let Some(ref policy) = inline.content_policy {
        validate_content_policy(policy, None)?;
    }
    Ok(())
}

pub fn create_inline_attachment(
    attachment_id: Vec<u8>,
    mime_type: String,
    data: Vec<u8>,
    original_filename: Option<String>,
    content_policy: Option<ContentPolicy>,
) -> Result<InlineAttachment, ProtocolError> {
    let inline = InlineAttachment {
        attachment_id,
        mime_type,
        data,
        original_filename,
        content_policy,
    };
    validate_inline_attachment(&inline)?;
    Ok(inline)
}

pub fn validate_attachment_reference(reference: &AttachmentReference) -> Result<(), ProtocolError> {
    if reference.attachment_id.len() != ATTACHMENT_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Attachment reference ID must be 32 bytes",
        ));
    }
    if !(0..=2).contains(&reference.reference_type) {
        return Err(ProtocolError::invalid_input(
            "Attachment reference_type must be 0, 1, or 2",
        ));
    }
    if let Some(ref mid) = reference.source_message_id {
        if mid.len() != MESSAGE_ID_BYTES {
            return Err(ProtocolError::invalid_input(
                "Attachment reference source_message_id must be 32 bytes",
            ));
        }
    }
    Ok(())
}

pub fn create_attachment_reference(
    attachment_id: Vec<u8>,
    reference_type: i32,
    source_message_id: Option<Vec<u8>>,
) -> Result<AttachmentReference, ProtocolError> {
    let reference = AttachmentReference {
        attachment_id,
        reference_type,
        source_message_id,
    };
    validate_attachment_reference(&reference)?;
    Ok(reference)
}

pub fn validate_voice_message_meta(voice: &VoiceMessageMeta) -> Result<(), ProtocolError> {
    if voice.waveform_samples.len() > MAX_VOICE_WAVEFORM_SAMPLES {
        return Err(ProtocolError::invalid_input(
            "Voice waveform_samples exceeds max count",
        ));
    }
    for s in &voice.waveform_samples {
        if !s.is_finite() || *s < 0.0 || *s > 1.0 {
            return Err(ProtocolError::invalid_input(
                "Voice waveform sample must be finite and in [0.0, 1.0]",
            ));
        }
    }
    if let Some(ref transcript) = voice.transcript {
        if transcript.chars().count() > MAX_VOICE_TRANSCRIPT_CHARS {
            return Err(ProtocolError::invalid_input(
                "Voice transcript exceeds max length",
            ));
        }
    }
    if let Some(speed) = voice.playback_speed_hint {
        if !speed.is_finite() || speed <= 0.0 {
            return Err(ProtocolError::invalid_input(
                "Voice playback_speed_hint must be finite and > 0.0",
            ));
        }
    }
    Ok(())
}

pub fn create_voice_message_meta(
    waveform_samples: Vec<f32>,
    transcript: Option<String>,
    playback_speed_hint: Option<f32>,
    is_listened: bool,
) -> Result<VoiceMessageMeta, ProtocolError> {
    let voice = VoiceMessageMeta {
        waveform_samples,
        transcript,
        playback_speed_hint,
        is_listened,
    };
    validate_voice_message_meta(&voice)?;
    Ok(voice)
}

pub fn validate_location_attachment(loc: &LocationAttachment) -> Result<(), ProtocolError> {
    if !loc.latitude.is_finite() || loc.latitude < -90.0 || loc.latitude > 90.0 {
        return Err(ProtocolError::invalid_input(
            "Location latitude must be finite and in [-90.0, 90.0]",
        ));
    }
    if !loc.longitude.is_finite() || loc.longitude < -180.0 || loc.longitude > 180.0 {
        return Err(ProtocolError::invalid_input(
            "Location longitude must be finite and in [-180.0, 180.0]",
        ));
    }
    if let Some(acc) = loc.accuracy_meters {
        if !acc.is_finite() || acc < 0.0 {
            return Err(ProtocolError::invalid_input(
                "Location accuracy_meters must be finite and >= 0.0",
            ));
        }
    }
    if let Some(ref label) = loc.label {
        if label.chars().count() > MAX_LOCATION_LABEL_CHARS {
            return Err(ProtocolError::invalid_input(
                "Location label exceeds max length",
            ));
        }
    }
    Ok(())
}

pub fn create_location_attachment(
    latitude: f64,
    longitude: f64,
    accuracy_meters: Option<f64>,
    label: Option<String>,
    timestamp_unix: Option<u64>,
) -> Result<LocationAttachment, ProtocolError> {
    let loc = LocationAttachment {
        latitude,
        longitude,
        accuracy_meters,
        label,
        timestamp_unix,
    };
    validate_location_attachment(&loc)?;
    Ok(loc)
}

pub fn validate_contact_card(card: &ContactCard) -> Result<(), ProtocolError> {
    if card.display_name.is_empty() {
        return Err(ProtocolError::invalid_input(
            "ContactCard display_name must not be empty",
        ));
    }
    if card.display_name.chars().count() > MAX_CONTACT_DISPLAY_NAME_CHARS {
        return Err(ProtocolError::invalid_input(
            "ContactCard display_name exceeds max length",
        ));
    }
    if let Some(ref phone) = card.phone {
        if phone.chars().count() > MAX_CONTACT_PHONE_CHARS {
            return Err(ProtocolError::invalid_input(
                "ContactCard phone exceeds max length",
            ));
        }
    }
    if let Some(ref email) = card.email {
        if email.chars().count() > MAX_CONTACT_EMAIL_CHARS {
            return Err(ProtocolError::invalid_input(
                "ContactCard email exceeds max length",
            ));
        }
    }
    if let Some(ref avatar) = card.avatar_data {
        if avatar.len() > MAX_CONTACT_AVATAR_DATA_SIZE {
            return Err(ProtocolError::invalid_input(
                "ContactCard avatar_data exceeds max size",
            ));
        }
    }
    if let Some(ref org) = card.organization {
        if org.chars().count() > MAX_CONTACT_ORGANIZATION_CHARS {
            return Err(ProtocolError::invalid_input(
                "ContactCard organization exceeds max length",
            ));
        }
    }
    Ok(())
}

pub fn create_contact_card(
    display_name: String,
    phone: Option<String>,
    email: Option<String>,
    avatar_data: Option<Vec<u8>>,
    organization: Option<String>,
) -> Result<ContactCard, ProtocolError> {
    let card = ContactCard {
        display_name,
        phone,
        email,
        avatar_data,
        organization,
    };
    validate_contact_card(&card)?;
    Ok(card)
}

pub fn validate_link_preview(preview: &LinkPreview) -> Result<(), ProtocolError> {
    if preview.url.is_empty() {
        return Err(ProtocolError::invalid_input(
            "LinkPreview url must not be empty",
        ));
    }
    if preview.url.chars().count() > MAX_LINK_PREVIEW_URL_CHARS {
        return Err(ProtocolError::invalid_input(
            "LinkPreview url exceeds max length",
        ));
    }
    if let Some(ref title) = preview.title {
        if title.chars().count() > MAX_LINK_PREVIEW_TITLE_CHARS {
            return Err(ProtocolError::invalid_input(
                "LinkPreview title exceeds max length",
            ));
        }
    }
    if let Some(ref desc) = preview.description {
        if desc.chars().count() > MAX_LINK_PREVIEW_DESCRIPTION_CHARS {
            return Err(ProtocolError::invalid_input(
                "LinkPreview description exceeds max length",
            ));
        }
    }
    if let Some(ref img) = preview.preview_image {
        if img.len() > MAX_LINK_PREVIEW_IMAGE_SIZE {
            return Err(ProtocolError::invalid_input(
                "LinkPreview preview_image exceeds max size",
            ));
        }
    }
    if let Some(ref mime) = preview.preview_image_mime {
        validate_mime_type(mime)?;
    }
    if let Some(ref domain) = preview.domain {
        if domain.chars().count() > MAX_LINK_PREVIEW_DOMAIN_CHARS {
            return Err(ProtocolError::invalid_input(
                "LinkPreview domain exceeds max length",
            ));
        }
    }
    Ok(())
}

pub fn create_link_preview(
    url: String,
    title: Option<String>,
    description: Option<String>,
    preview_image: Option<Vec<u8>>,
    preview_image_mime: Option<String>,
    domain: Option<String>,
) -> Result<LinkPreview, ProtocolError> {
    let preview = LinkPreview {
        url,
        title,
        description,
        preview_image,
        preview_image_mime,
        domain,
    };
    validate_link_preview(&preview)?;
    Ok(preview)
}
