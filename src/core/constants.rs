// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

/// 1:1 session wire version.
///
/// Bumped to 2 for the v3.0.0 release: `previous_chain_length` moved into both
/// AEAD associated-data blocks, so v1 and v2 peers cannot interoperate.  Every
/// version check in the crate is a strict `!=` that rejects immediately, which
/// is the point — a mixed-version peer gets an explicit version error instead
/// of an opaque AEAD failure.
pub const PROTOCOL_VERSION: u32 = 2;

pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const X25519_PRIVATE_KEY_BYTES: usize = 32;
pub const X25519_SHARED_SECRET_BYTES: usize = 32;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SECRET_KEY_BYTES: usize = 64;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
pub const KYBER_SECRET_KEY_BYTES: usize = 64;
pub const KYBER_CIPHERTEXT_BYTES: usize = 1088;
pub const KYBER_SHARED_SECRET_BYTES: usize = 32;
pub const KYBER_SEED_KEY_BYTES: usize = 32;

pub const ROOT_KEY_BYTES: usize = 32;
pub const CHAIN_KEY_BYTES: usize = 32;
pub const MESSAGE_KEY_BYTES: usize = 32;
pub const METADATA_KEY_BYTES: usize = 32;
pub const SESSION_ID_BYTES: usize = 16;
pub const HMAC_BYTES: usize = 32;
pub const IDENTITY_BINDING_HASH_BYTES: usize = 32;
pub const OPAQUE_SESSION_KEY_BYTES: usize = 32;

pub const AES_KEY_BYTES: usize = 32;
pub const AES_GCM_NONCE_BYTES: usize = 12;
pub const AES_GCM_TAG_BYTES: usize = 16;

pub const NONCE_PREFIX_BYTES: usize = 8;
pub const NONCE_COUNTER_BYTES: usize = 2;
pub const NONCE_INDEX_BYTES: usize = 2;
pub const MAX_NONCE_COUNTER: u64 = 0xFFFF;
pub const MAX_MESSAGE_INDEX: u64 = 0xFFFF;
pub const NONCE_EXHAUSTION_WARNING_PERCENT: u64 = 10;
pub const DEFAULT_MESSAGES_PER_CHAIN: u64 = 1000;
pub const MAX_SKIPPED_MESSAGE_KEYS: usize = 1000;
pub const MAX_CACHED_METADATA_KEYS: usize = 100;
/// Maximum ratchet-epoch lag for cached metadata keys.
///
/// This bounds the forward-secrecy exposure window for message metadata
/// (envelope type, message index, correlation_id, etc.) in addition to the
/// size-based [`MAX_CACHED_METADATA_KEYS`] limit.
pub const MAX_METADATA_KEY_EPOCH_AGE: u64 = 32;
/// Maximum ratchet-epoch lag for cached skipped message keys.
///
/// Mirrors [`MAX_METADATA_KEY_EPOCH_AGE`].  A skipped message key older than
/// this can never be used anyway, because the metadata key needed to parse an
/// envelope from that epoch has already been evicted.  Keeping it only widens
/// the forward-secrecy window and lets a peer pin the cache at its size limit.
pub const MAX_SKIPPED_KEY_EPOCH_AGE: u64 = MAX_METADATA_KEY_EPOCH_AGE;
pub const MAX_SEEN_NONCES: usize = 2048;
pub const MAX_SEEN_HANDSHAKE_INITS: usize = 16384;
pub const MAX_INFLIGHT_HANDSHAKE_INITS: usize = 4096;
pub const MAX_MESSAGES_PER_CHAIN: usize = 10000;
pub const MAX_ONE_TIME_PRE_KEYS_PER_BUNDLE: usize = 4096;
pub const RATCHET_OUTPUT_BYTES: usize = ROOT_KEY_BYTES + CHAIN_KEY_BYTES + METADATA_KEY_BYTES;
pub const DEFAULT_ONE_TIME_KEY_COUNT: u32 = 100;
pub const OPK_ID_MODULUS: u32 = 0xFFFF_FFFE;
pub const OPK_ID_OFFSET: u32 = 2;

pub const DEVICE_ID_BYTES: usize = 32;
pub const MIN_SESSION_TTL_SECONDS: u64 = 60;
pub const MAX_SESSION_TTL_SECONDS: u64 = 365 * 24 * 3600;

pub const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_SHARE_SIZE: usize = 65536;
pub const MAX_PROTOBUF_MESSAGE_SIZE: usize = 1024 * 1024;
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 16 * 1024;
pub const MAX_ENVELOPE_MESSAGE_SIZE: usize = 1024 * 1024;

pub const X25519_CLAMP_BYTE0: u8 = 0xF8;
pub const X25519_CLAMP_BYTE31_LOW: u8 = 0x7F;
pub const X25519_CLAMP_BYTE31_HIGH: u8 = 0x40;

pub const X3DH_INFO: &[u8] = b"Aura-X3DH";
pub const HYBRID_X3DH_INFO: &[u8] = b"Aura-Hybrid-X3DH";
pub const HYBRID_RATCHET_INFO: &[u8] = b"Aura-Hybrid-Ratchet";
pub const DH_RATCHET_INFO: &[u8] = b"Aura-DH-Ratchet";
pub const CHAIN_INIT_INFO: &[u8] = b"Aura-ChainInit";
pub const CHAIN_INFO: &[u8] = b"Aura-Chain";
pub const MESSAGE_INFO: &[u8] = b"Aura-Msg";
pub const SESSION_ID_INFO: &[u8] = b"Aura-SessionId";
pub const METADATA_KEY_INFO: &[u8] = b"Aura-MetadataKey";
pub const OPAQUE_ROOT_INFO: &[u8] = b"Aura-OPAQUE-Root";
pub const STATE_HMAC_INFO: &[u8] = b"Aura-State-HMAC";
pub const KEY_CONFIRM_INIT_INFO: &[u8] = b"Aura-KeyConfirm-I";
pub const KEY_CONFIRM_RESP_INFO: &[u8] = b"Aura-KeyConfirm-R";
pub const TRANSCRIPT_LABEL: &[u8] = b"Aura-Handshake-Transcript";
pub const IDENTITY_BINDING_INFO: &[u8] = b"Aura-Identity-Binding";
pub const HANDSHAKE_INIT_IDENTITY_BINDING_INFO: &[u8] = b"Aura-Handshake-Init-Identity-Binding";
pub const HYBRID_SALT_PREFIX: &[u8] = b"Aura-PQ-Hybrid::";

pub const X3DH_FILL_BYTE: u8 = 0xFF;
pub const X3DH_DH_COUNT: usize = 4;

pub const PURPOSE_IDENTITY_X25519: &str = "identity-x25519";
pub const PURPOSE_SIGNED_PRE_KEY: &str = "signed-pre-key";
pub const PURPOSE_IDENTITY_KYBER: &str = "identity-kyber";
pub const PURPOSE_EPHEMERAL_X25519: &str = "ephemeral-x25519";

pub const DEFAULT_MEMBERSHIP_ID: &str = "default";

pub const MAX_GROUP_MEMBERS: usize = 1024;
pub const MAX_TREE_NODES: usize = 2 * MAX_GROUP_MEMBERS - 1;
pub const MAX_CREDENTIAL_SIZE: usize = 4096;
pub const MAX_TREE_DEPTH: usize = 20;
pub const MAX_PROPOSALS_PER_COMMIT: usize = 64;
pub const MAX_CACHED_GROUP_EPOCHS: usize = 5;
pub const MAX_SENDER_KEY_GENERATION: u32 = 100_000;
pub const MAX_SKIPPED_SENDER_KEYS: usize = 256;
pub const MAX_GROUP_MESSAGE_SIZE: usize = 1024 * 1024;

pub const GROUP_ID_BYTES: usize = 32;
pub const EPOCH_SECRET_BYTES: usize = 32;
pub const INIT_SECRET_BYTES: usize = 32;
pub const JOINER_SECRET_BYTES: usize = 32;
pub const COMMIT_SECRET_BYTES: usize = 32;
pub const PATH_SECRET_BYTES: usize = 32;
pub const SENDER_KEY_BASE_BYTES: usize = 32;
pub const WELCOME_KEY_BYTES: usize = 32;
pub const CONFIRMATION_KEY_BYTES: usize = 32;
pub const REUSE_GUARD_BYTES: usize = 4;
/// Group wire version.
///
/// Bumped to 2 for the v3.0.0 release: the ratchet tree hash now binds each
/// leaf's credential and identity keys, and the franking tag is framed
/// unambiguously.  Both change bytes on the wire.
pub const GROUP_PROTOCOL_VERSION: u32 = 2;
/// Deliberately not bumped with `GROUP_PROTOCOL_VERSION`.
///
/// The authorization blob's *format* did not change, and it is already bound to
/// `group_context_hash`, which moves with the tree hash — so a v1 authorization
/// can never validate against a v2 group.
pub const GROUP_EXTERNAL_JOIN_AUTH_FORMAT_VERSION: u32 = 1;
/// Deliberately not bumped with `GROUP_PROTOCOL_VERSION`.
///
/// This is the at-rest wrapper format, which did not change.  The inner
/// `GroupProtocolState.version` is `GROUP_PROTOCOL_VERSION` and is checked on
/// restore, so an old blob already fails with an explicit version error.
pub const GROUP_SEALED_STATE_VERSION: u32 = 1;

pub const GROUP_EPOCH_SECRET_INFO: &[u8] = b"Aura-Group-EpochSecret";
pub const GROUP_SENDER_KEY_INFO: &[u8] = b"Aura-Group-SenderKey";
pub const GROUP_METADATA_KEY_INFO: &[u8] = b"Aura-Group-MetadataKey";
pub const GROUP_WELCOME_KEY_INFO: &[u8] = b"Aura-Group-WelcomeKey";
pub const GROUP_CONFIRM_KEY_INFO: &[u8] = b"Aura-Group-ConfirmKey";
pub const GROUP_INIT_SECRET_INFO: &[u8] = b"Aura-Group-InitSecret";
pub const GROUP_CHAIN_INFO: &[u8] = b"Aura-Group-Chain";
pub const GROUP_MSG_INFO: &[u8] = b"Aura-Group-Msg";
pub const GROUP_PATH_SECRET_INFO: &[u8] = b"Aura-Group-PathSecret";
pub const GROUP_NODE_KEY_INFO: &[u8] = b"Aura-Group-NodeKey";
pub const GROUP_JOINER_SECRET_INFO: &[u8] = b"Aura-Group-JoinerSecret";
pub const GROUP_HYBRID_PATH_INFO: &[u8] = b"Aura-Group-HybridPath";
pub const GROUP_STATE_HMAC_INFO: &[u8] = b"Aura-Group-StateHMAC";
pub const GROUP_EXTERNAL_JOIN_AUTH_INFO: &[u8] = b"Aura-Group-ExternalJoinAuth";
pub const GROUP_HYBRID_SALT_PREFIX: &[u8] = b"Aura-PQ-Group-Hybrid::";
pub const GROUP_PARENT_HASH_LABEL: &[u8] = b"Aura-Group-ParentHash-v2";

// Ratchet tree node hashing.  Every node hash carries one of these labels so a
// leaf hash can never be reinterpreted as a parent hash (or a blank node) even
// if every other field coincided.  `-v2` marks the framing change that made the
// leaf hash cover the occupant's credential and identity keys.
pub const GROUP_LEAF_NODE_HASH_LABEL: &[u8] = b"Aura-Group-LeafNodeHash-v2";
pub const GROUP_PARENT_NODE_HASH_LABEL: &[u8] = b"Aura-Group-ParentNodeHash-v2";
pub const GROUP_BLANK_NODE_HASH_LABEL: &[u8] = b"Aura-Group-BlankNodeHash-v2";
pub const GROUP_EXTERNAL_PUB_X25519_INFO: &[u8] = b"Aura-Group-ExternalPub-X25519";
pub const GROUP_EXTERNAL_PUB_KYBER_INFO: &[u8] = b"Aura-Group-ExternalPub-Kyber";
pub const GROUP_EXTERNAL_INIT_SECRET_INFO: &[u8] = b"Aura-Group-ExternalInitSecret";

pub const GROUP_PSK_SECRET_INFO: &[u8] = b"Aura-Group-PskSecret";
pub const GROUP_PSK_EXTRACT_INFO: &[u8] = b"Aura-Group-PskExtract";
pub const PSK_BYTES: usize = 32;

pub const GROUP_REINIT_LABEL: &[u8] = b"Aura-Group-ReInit";

pub const GROUP_SEAL_KEY_INFO: &[u8] = b"Aura-Group-SealKey";
pub const GROUP_MESSAGE_SIGNATURE_INFO: &[u8] = b"Aura-Group-MessageSignature";
pub const GROUP_FRANKING_TAG_INFO: &[u8] = b"Aura-Group-FrankingTag-v2";
pub const SEAL_KEY_BYTES: usize = 32;
pub const SEALED_AAD_SUFFIX: &[u8] = b"sealed";

pub const FRANKING_TAG_BYTES: usize = 32;
pub const FRANKING_KEY_BYTES: usize = 32;

pub const CONTENT_TYPE_NORMAL: u32 = 0;
pub const CONTENT_TYPE_SEALED: u32 = 1;
pub const CONTENT_TYPE_DISAPPEARING: u32 = 2;
pub const CONTENT_TYPE_SEALED_DISAPPEARING: u32 = 3;
pub const CONTENT_TYPE_EDIT: u32 = 4;
pub const CONTENT_TYPE_DELETE: u32 = 5;
pub const CONTENT_TYPE_REACTION: u32 = 6;
pub const CONTENT_TYPE_READ_RECEIPT: u32 = 7;
pub const CONTENT_TYPE_TYPING: u32 = 8;

pub const MAX_REACTION_EMOJI_CHARS: usize = 16;
pub const MAX_READ_RECEIPT_MESSAGE_IDS: usize = 100;
pub const MAX_MENTIONS_PER_MESSAGE: usize = 50;
pub const MAX_THREAD_DEPTH: u32 = 100;

pub const MESSAGE_ID_BYTES: usize = 32;
pub const GROUP_MSG_ID_INFO: &[u8] = b"Aura-Group-MsgId";

pub const MAX_TTL_SECONDS: u32 = 7 * 24 * 3600;
pub const MAX_FUTURE_TIMESTAMP_SKEW_SECS: u64 = 300;
pub const EXTERNAL_JOIN_AUTH_VALIDITY_SECS: u64 = 600;

pub const MESSAGE_PADDING_BLOCK_SIZE: usize = 64;

pub const RATCHET_STALLING_WARNING_THRESHOLD: u64 = 100;
pub const SENDER_KEY_EXHAUSTION_WARNING_PERCENT: u32 = 10;
pub const OTK_EXHAUSTION_WARNING_PERCENT: u32 = 10;

pub const SHIELD_MAX_MESSAGES_PER_EPOCH: u32 = 1_000;
pub const SHIELD_MAX_SKIPPED_KEYS_PER_SENDER: u32 = 4;
/// Per-sender skipped-generation budget for the default messaging tier
/// (`GroupSecurityPolicy::standard()`, used by 1:1 / direct e2e chats).
///
/// High enough to ride out an offline burst or a handful of dropped / reordered
/// delivery events without the receive chain walling on "Too many skipped
/// generations". Must stay `<= MAX_SKIPPED_SENDER_KEYS_PER_SENDER`; retained
/// out-of-order keys remain bounded by the total cache `MAX_SKIPPED_SENDER_KEYS`.
/// `shield()` deliberately keeps the tight budget of 4 for opt-in secret groups.
pub const STANDARD_MAX_SKIPPED_KEYS_PER_SENDER: u32 = 1_000;
pub const SHIELD_MIN_MESSAGES_PER_EPOCH: u32 = 10;
pub const SHIELD_MIN_SKIPPED_PER_SENDER: usize = 1;
pub const GROUP_ENHANCED_KDF_PASS1: &[u8] = b"Aura-Enhanced-Pass1";
pub const GROUP_ENHANCED_KDF_PASS2: &[u8] = b"Aura-Enhanced-Pass2";
pub const GROUP_BLAKE2B_CHAIN_PERSONALIZATION: &[u8] = b"Aura-B2Chain";

pub const SHA256_HASH_BYTES: usize = 32;
pub const HKDF_MAX_ITERATIONS: usize = 255;
pub const HKDF_MAX_OUTPUT_BYTES: usize = HKDF_MAX_ITERATIONS * SHA256_HASH_BYTES;
pub const MIN_MASTER_KEY_BYTES: usize = 32;
pub const MAX_SKIPPED_SENDER_KEYS_PER_SENDER: usize = 1_024;

pub const MKD_ED25519_INFO: &[u8] = b"aura-identity-ed25519";
pub const MKD_X25519_INFO: &[u8] = b"aura-identity-x25519";
pub const MKD_SIGNED_PRE_KEY_INFO: &[u8] = b"aura-signed-pre-key";
pub const MKD_OPK_PREFIX: &str = "aura-opk-";
pub const MKD_KYBER_SEED_1_INFO: &[u8] = b"aura-kyber-seed-1";
pub const MKD_KYBER_SEED_2_INFO: &[u8] = b"aura-kyber-seed-2";

pub const SPK_ID_INFO: &[u8] = b"Aura-SPK-ID";
pub const SPK_ID_BYTES: usize = 4;

// ── VoIP constants ──────────────────────────────────────────────────

/// VoIP wire and sealed-state version.
///
/// Bumped to 2 for v3.0.0: `VoipSessionState.root_secret` now holds the
/// unshielded call root.  It previously held the shielded one, which restore
/// then shielded again — a shield-mode call was silently dead after restore.
pub const VOIP_PROTOCOL_VERSION: u32 = 2;
pub const CALL_ID_BYTES: usize = 32;
pub const SSRC_BYTES: usize = 4;

pub const VOIP_MEDIA_KEY_BYTES: usize = 32;
pub const VOIP_MEDIA_NONCE_BYTES: usize = 12;
pub const VOIP_HEADER_KEY_BYTES: usize = 32;

pub const DEFAULT_RATCHET_INTERVAL_FRAMES: u32 = 512;
pub const DEFAULT_PQ_REKEY_INTERVAL_SECS: u32 = 60;
pub const MAX_RATCHET_GENERATION: u32 = 0x00FF_FFFF;
pub const MAX_FRAME_COUNTER: u64 = 0xFFFF_FFFF_FFFF;
pub const MAX_VOIP_FRAME_SIZE: usize = 64 * 1024;
pub const VOIP_FRAME_PADDING_BLOCK: usize = 16;
pub const MAX_SKIPPED_RATCHET_GENERATIONS: u32 = 8;
pub const MAX_VOIP_SIGNAL_MESSAGE_SIZE: usize = 64 * 1024;
pub const MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE: usize =
    MAX_VOIP_FRAME_SIZE + VOIP_FRAME_PADDING_BLOCK + AES_GCM_TAG_BYTES;
pub const MAX_VOIP_ENCRYPTED_HEADER_SIZE: usize = 4 * 1024;
pub const VOIP_CALL_INIT_TIMEOUT_SECS: u64 = 30;
pub const VOIP_CALL_ACTIVE_IDLE_TIMEOUT_SECS: u64 = 5 * 60;
pub const VOIP_CALL_MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

pub const VOIP_ROOT_SECRET_INFO: &[u8] = b"Aura-VoIP-RootSecret";
pub const VOIP_MEDIA_KEY_SEND_INFO: &[u8] = b"Aura-VoIP-MediaKey-Send";
pub const VOIP_MEDIA_KEY_RECV_INFO: &[u8] = b"Aura-VoIP-MediaKey-Recv";
pub const VOIP_HEADER_KEY_SEND_INFO: &[u8] = b"Aura-VoIP-HeaderKey-Send";
pub const VOIP_HEADER_KEY_RECV_INFO: &[u8] = b"Aura-VoIP-HeaderKey-Recv";
pub const VOIP_RATCHET_CHAIN_INFO: &[u8] = b"Aura-VoIP-RatchetChain";
pub const VOIP_FRAME_KEY_INFO: &[u8] = b"Aura-VoIP-FrameKey";
pub const VOIP_REKEY_INFO: &[u8] = b"Aura-VoIP-Rekey";
pub const VOIP_KEY_CONFIRM_CALLER_INFO: &[u8] = b"Aura-VoIP-KeyConfirm-Caller";
pub const VOIP_KEY_CONFIRM_CALLEE_INFO: &[u8] = b"Aura-VoIP-KeyConfirm-Callee";
pub const VOIP_HYBRID_SALT_PREFIX: &[u8] = b"Aura-PQ-VoIP-Hybrid::";
pub const VOIP_CALL_END_HMAC_INFO: &[u8] = b"Aura-VoIP-CallEnd-HMAC";
pub const VOIP_SHIELD_KDF_PASS1: &[u8] = b"Aura-VoIP-Shield-Pass1";
pub const VOIP_SHIELD_KDF_PASS2: &[u8] = b"Aura-VoIP-Shield-Pass2";
pub const VOIP_NONCE_PREFIX_INFO: &[u8] = b"Aura-VoIP-NoncePrefix";
pub const VOIP_NONCE_PREFIX_BYTES: usize = 4;

pub const MAX_SCREEN_SHARE_WIDTH: u32 = 7680;
pub const MAX_SCREEN_SHARE_HEIGHT: u32 = 4320;
pub const MAX_SCREEN_SHARE_FRAME_RATE: u32 = 120;
pub const MAX_CODEC_HINT_CHARS: usize = 64;
pub const MAX_AUDIO_LEVEL: u32 = 127;

pub const ATTACHMENT_PROTOCOL_VERSION: u32 = 1;
pub const ATTACHMENT_ID_BYTES: usize = 32;
pub const ATTACHMENT_FILE_KEY_BYTES: usize = 32;
pub const ATTACHMENT_HASH_BYTES: usize = 32;
pub const MAX_ATTACHMENT_MANIFEST_SIZE: usize = 16 * 1024;
pub const MAX_ATTACHMENT_CHUNK_SIZE: usize = 1024 * 1024;
const _: () = assert!(MAX_BUFFER_SIZE / 4 <= u32::MAX as usize);
#[expect(
    clippy::cast_possible_truncation,
    reason = "the adjacent compile-time assertion proves this protocol bound fits u32"
)]
pub const MAX_ATTACHMENT_CHUNK_COUNT: u32 = (MAX_BUFFER_SIZE / 4) as u32;
pub const MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE: usize = 8 * 1024;
pub const ATTACHMENT_NONCE_INFO: &[u8] = b"Aura-Attachment-Nonce";
pub const MAX_ATTACHMENT_THUMBNAIL_SIZE: usize = 64 * 1024;
pub const ATTACHMENT_THUMBNAIL_CHUNK_INDEX: u32 = 0xFFFF_FFFF;
pub const ATTACHMENT_THUMBNAIL_AAD_PREFIX: &[u8] = b"Aura-Attachment-Thumbnail-v1";
pub const MAX_ATTACHMENT_TTL_SECONDS: u64 = 30 * 24 * 3600;
pub const MIN_ATTACHMENT_TTL_SECONDS: u64 = 60;
pub const MAX_COLLAGE_ATTACHMENTS: usize = 20;
pub const COLLAGE_ID_BYTES: usize = 32;
pub const MAX_COLLAGE_MANIFEST_SIZE: usize = 512 * 1024;
pub const MAX_ATTACHMENT_FILENAME_BYTES: usize = 255;
pub const MAX_ATTACHMENT_ALT_TEXT_CHARS: usize = 1024;
pub const MAX_COLLAGE_NAME_CHARS: usize = 255;
pub const MAX_COLLAGE_DESCRIPTION_CHARS: usize = 1024;
pub const MAGIC_BYTES_MIN_HEADER: usize = 12;
pub const MAX_INLINE_ATTACHMENT_DATA_SIZE: usize = 4096;
pub const MAX_VOICE_WAVEFORM_SAMPLES: usize = 256;
pub const MAX_VOICE_TRANSCRIPT_CHARS: usize = 4096;
pub const MAX_LOCATION_LABEL_CHARS: usize = 255;
pub const MAX_CONTACT_DISPLAY_NAME_CHARS: usize = 255;
pub const MAX_CONTACT_PHONE_CHARS: usize = 255;
pub const MAX_CONTACT_EMAIL_CHARS: usize = 255;
pub const MAX_CONTACT_AVATAR_DATA_SIZE: usize = 64 * 1024;
pub const MAX_CONTACT_ORGANIZATION_CHARS: usize = 255;
pub const MAX_LINK_PREVIEW_URL_CHARS: usize = 2048;
pub const MAX_LINK_PREVIEW_TITLE_CHARS: usize = 255;
pub const MAX_LINK_PREVIEW_DESCRIPTION_CHARS: usize = 1024;
pub const MAX_LINK_PREVIEW_IMAGE_SIZE: usize = 256 * 1024;
pub const MAX_LINK_PREVIEW_DOMAIN_CHARS: usize = 255;

// ── Identity replay state (durable HandshakeInit anti-replay) ──
pub const IDENTITY_REPLAY_STATE_VERSION: u8 = 1;
pub const IDENTITY_REPLAY_STATE_AAD: &[u8] = b"aura-identity-replay-state-v1";
