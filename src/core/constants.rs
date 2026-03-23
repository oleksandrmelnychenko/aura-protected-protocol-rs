// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub const PROTOCOL_VERSION: u32 = 1;

pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const X25519_PRIVATE_KEY_BYTES: usize = 32;
pub const X25519_SHARED_SECRET_BYTES: usize = 32;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SECRET_KEY_BYTES: usize = 64;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
pub const KYBER_SECRET_KEY_BYTES: usize = 2400;
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
pub const MAX_SEEN_NONCES: usize = 2048;
pub const MAX_MESSAGES_PER_CHAIN: usize = 10000;
pub const RATCHET_OUTPUT_BYTES: usize = ROOT_KEY_BYTES + CHAIN_KEY_BYTES + METADATA_KEY_BYTES;
pub const DEFAULT_ONE_TIME_KEY_COUNT: u32 = 100;
pub const OPK_ID_MODULUS: u32 = 0xFFFF_FFFE;
pub const OPK_ID_OFFSET: u32 = 2;

pub const MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;
pub const MAX_SHARE_SIZE: usize = 65536;
pub const MAX_PROTOBUF_MESSAGE_SIZE: usize = 1024 * 1024;
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 16 * 1024;
pub const MAX_ENVELOPE_MESSAGE_SIZE: usize = 1024 * 1024;

pub const X25519_CLAMP_BYTE0: u8 = 0xF8;
pub const X25519_CLAMP_BYTE31_LOW: u8 = 0x7F;
pub const X25519_CLAMP_BYTE31_HIGH: u8 = 0x40;

pub const X3DH_INFO: &[u8] = b"Ecliptix-X3DH";
pub const HYBRID_X3DH_INFO: &[u8] = b"Ecliptix-Hybrid-X3DH";
pub const HYBRID_RATCHET_INFO: &[u8] = b"Ecliptix-Hybrid-Ratchet";
pub const DH_RATCHET_INFO: &[u8] = b"Ecliptix-DH-Ratchet";
pub const CHAIN_INIT_INFO: &[u8] = b"Ecliptix-ChainInit";
pub const CHAIN_INFO: &[u8] = b"Ecliptix-Chain";
pub const MESSAGE_INFO: &[u8] = b"Ecliptix-Msg";
pub const SESSION_ID_INFO: &[u8] = b"Ecliptix-SessionId";
pub const METADATA_KEY_INFO: &[u8] = b"Ecliptix-MetadataKey";
pub const OPAQUE_ROOT_INFO: &[u8] = b"Ecliptix-OPAQUE-Root";
pub const STATE_HMAC_INFO: &[u8] = b"Ecliptix-State-HMAC";
pub const KEY_CONFIRM_INIT_INFO: &[u8] = b"Ecliptix-KeyConfirm-I";
pub const KEY_CONFIRM_RESP_INFO: &[u8] = b"Ecliptix-KeyConfirm-R";
pub const TRANSCRIPT_LABEL: &[u8] = b"Ecliptix-Handshake-Transcript";
pub const IDENTITY_BINDING_INFO: &[u8] = b"Ecliptix-Identity-Binding";
pub const HANDSHAKE_INIT_IDENTITY_BINDING_INFO: &[u8] = b"Ecliptix-Handshake-Init-Identity-Binding";
pub const HYBRID_SALT_PREFIX: &[u8] = b"Ecliptix-PQ-Hybrid::";

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
pub const GROUP_PROTOCOL_VERSION: u32 = 1;

pub const GROUP_EPOCH_SECRET_INFO: &[u8] = b"Ecliptix-Group-EpochSecret";
pub const GROUP_SENDER_KEY_INFO: &[u8] = b"Ecliptix-Group-SenderKey";
pub const GROUP_METADATA_KEY_INFO: &[u8] = b"Ecliptix-Group-MetadataKey";
pub const GROUP_WELCOME_KEY_INFO: &[u8] = b"Ecliptix-Group-WelcomeKey";
pub const GROUP_CONFIRM_KEY_INFO: &[u8] = b"Ecliptix-Group-ConfirmKey";
pub const GROUP_INIT_SECRET_INFO: &[u8] = b"Ecliptix-Group-InitSecret";
pub const GROUP_CHAIN_INFO: &[u8] = b"Ecliptix-Group-Chain";
pub const GROUP_MSG_INFO: &[u8] = b"Ecliptix-Group-Msg";
pub const GROUP_PATH_SECRET_INFO: &[u8] = b"Ecliptix-Group-PathSecret";
pub const GROUP_NODE_KEY_INFO: &[u8] = b"Ecliptix-Group-NodeKey";
pub const GROUP_JOINER_SECRET_INFO: &[u8] = b"Ecliptix-Group-JoinerSecret";
pub const GROUP_HYBRID_PATH_INFO: &[u8] = b"Ecliptix-Group-HybridPath";
pub const GROUP_STATE_HMAC_INFO: &[u8] = b"Ecliptix-Group-StateHMAC";
pub const GROUP_EXTERNAL_JOIN_AUTH_INFO: &[u8] = b"Ecliptix-Group-ExternalJoinAuth";
pub const GROUP_HYBRID_SALT_PREFIX: &[u8] = b"Ecliptix-PQ-Group-Hybrid::";
pub const GROUP_TREE_HASH_INFO: &[u8] = b"Ecliptix-Group-TreeHash";
pub const GROUP_PARENT_HASH_LABEL: &[u8] = b"Ecliptix-Group-ParentHash";
pub const GROUP_EXTERNAL_PUB_X25519_INFO: &[u8] = b"Ecliptix-Group-ExternalPub-X25519";
pub const GROUP_EXTERNAL_PUB_KYBER_INFO: &[u8] = b"Ecliptix-Group-ExternalPub-Kyber";
pub const GROUP_EXTERNAL_INIT_SECRET_INFO: &[u8] = b"Ecliptix-Group-ExternalInitSecret";

pub const GROUP_PSK_SECRET_INFO: &[u8] = b"Ecliptix-Group-PskSecret";
pub const GROUP_PSK_EXTRACT_INFO: &[u8] = b"Ecliptix-Group-PskExtract";
pub const PSK_BYTES: usize = 32;

pub const GROUP_REINIT_LABEL: &[u8] = b"Ecliptix-Group-ReInit";

pub const GROUP_SEAL_KEY_INFO: &[u8] = b"Ecliptix-Group-SealKey";
pub const GROUP_MESSAGE_SIGNATURE_INFO: &[u8] = b"Ecliptix-Group-MessageSignature";
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

pub const MESSAGE_ID_BYTES: usize = 32;
pub const GROUP_MSG_ID_INFO: &[u8] = b"Ecliptix-Group-MsgId";

pub const MAX_TTL_SECONDS: u32 = 7 * 24 * 3600;

pub const MESSAGE_PADDING_BLOCK_SIZE: usize = 64;

pub const RATCHET_STALLING_WARNING_THRESHOLD: u64 = 100;
pub const SENDER_KEY_EXHAUSTION_WARNING_PERCENT: u32 = 10;
pub const OTK_EXHAUSTION_WARNING_PERCENT: u32 = 10;

pub const SHIELD_MAX_MESSAGES_PER_EPOCH: u32 = 1_000;
pub const SHIELD_MAX_SKIPPED_KEYS_PER_SENDER: u32 = 4;
pub const SHIELD_MIN_MESSAGES_PER_EPOCH: u32 = 10;
pub const SHIELD_MIN_SKIPPED_PER_SENDER: usize = 1;
pub const GROUP_ENHANCED_KDF_PASS1: &[u8] = b"Ecliptix-Enhanced-Pass1";
pub const GROUP_ENHANCED_KDF_PASS2: &[u8] = b"Ecliptix-Enhanced-Pass2";
pub const GROUP_BLAKE2B_CHAIN_PERSONALIZATION: &[u8] = b"Ecliptix-B2Chain";

pub const SHA256_HASH_BYTES: usize = 32;
pub const HKDF_MAX_ITERATIONS: usize = 255;
pub const HKDF_MAX_OUTPUT_BYTES: usize = HKDF_MAX_ITERATIONS * SHA256_HASH_BYTES;
pub const MIN_MASTER_KEY_BYTES: usize = 32;
pub const MAX_SKIPPED_SENDER_KEYS_PER_SENDER: usize = 32;

pub const MKD_ED25519_INFO: &[u8] = b"ecliptix-identity-ed25519";
pub const MKD_X25519_INFO: &[u8] = b"ecliptix-identity-x25519";
pub const MKD_SIGNED_PRE_KEY_INFO: &[u8] = b"ecliptix-signed-pre-key";
pub const MKD_OPK_PREFIX: &str = "ecliptix-opk-";
pub const MKD_KYBER_SEED_1_INFO: &[u8] = b"ecliptix-kyber-seed-1";
pub const MKD_KYBER_SEED_2_INFO: &[u8] = b"ecliptix-kyber-seed-2";

pub const SPK_ID_INFO: &[u8] = b"Ecliptix-SPK-ID";
pub const SPK_ID_BYTES: usize = 4;

// ── VoIP constants ──────────────────────────────────────────────────

pub const VOIP_PROTOCOL_VERSION: u32 = 1;
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
pub const VOIP_CALL_INIT_TIMEOUT_SECS: u64 = 30;
pub const VOIP_CALL_ACTIVE_IDLE_TIMEOUT_SECS: u64 = 5 * 60;
pub const VOIP_CALL_MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

pub const VOIP_ROOT_SECRET_INFO: &[u8] = b"Ecliptix-VoIP-RootSecret";
pub const VOIP_MEDIA_KEY_SEND_INFO: &[u8] = b"Ecliptix-VoIP-MediaKey-Send";
pub const VOIP_MEDIA_KEY_RECV_INFO: &[u8] = b"Ecliptix-VoIP-MediaKey-Recv";
pub const VOIP_HEADER_KEY_SEND_INFO: &[u8] = b"Ecliptix-VoIP-HeaderKey-Send";
pub const VOIP_HEADER_KEY_RECV_INFO: &[u8] = b"Ecliptix-VoIP-HeaderKey-Recv";
pub const VOIP_RATCHET_CHAIN_INFO: &[u8] = b"Ecliptix-VoIP-RatchetChain";
pub const VOIP_FRAME_KEY_INFO: &[u8] = b"Ecliptix-VoIP-FrameKey";
pub const VOIP_REKEY_INFO: &[u8] = b"Ecliptix-VoIP-Rekey";
pub const VOIP_KEY_CONFIRM_CALLER_INFO: &[u8] = b"Ecliptix-VoIP-KeyConfirm-Caller";
pub const VOIP_KEY_CONFIRM_CALLEE_INFO: &[u8] = b"Ecliptix-VoIP-KeyConfirm-Callee";
pub const VOIP_HYBRID_SALT_PREFIX: &[u8] = b"Ecliptix-PQ-VoIP-Hybrid::";
pub const VOIP_CALL_END_HMAC_INFO: &[u8] = b"Ecliptix-VoIP-CallEnd-HMAC";
pub const VOIP_SHIELD_KDF_PASS1: &[u8] = b"Ecliptix-VoIP-Shield-Pass1";
pub const VOIP_SHIELD_KDF_PASS2: &[u8] = b"Ecliptix-VoIP-Shield-Pass2";
pub const VOIP_NONCE_PREFIX_INFO: &[u8] = b"Ecliptix-VoIP-NoncePrefix";
pub const VOIP_NONCE_PREFIX_BYTES: usize = 4;
