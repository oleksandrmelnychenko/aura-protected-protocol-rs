// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

pub mod commit;
pub mod key_package;
pub mod key_schedule;
pub mod membership;
pub mod sender_key;
pub mod tree;
pub mod tree_kem;
pub mod welcome;

use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::crypto::{AesGcm, CryptoInterop, HkdfSha256, MessagePadding, SecureMemoryHandle};
use crate::identity::IdentityKeys;
use crate::interfaces::{IGroupEventHandler, ITimeProvider, SystemTimeProvider};
use crate::proto::GroupSecurityPolicy as ProtoGroupSecurityPolicy;
use crate::proto::{
    GroupApplicationMessage, GroupCommit, GroupExternalJoinAuthorization, GroupKeyPackage,
    GroupMemberSenderChain, GroupMention as ProtoGroupMention, GroupMessage, GroupMessagePolicy,
    GroupPlaintext, GroupProposal, GroupProtocolState, GroupPublicState, GroupReaction,
    GroupReadReceipt, GroupReplyContext as ProtoGroupReplyContext, GroupSenderData,
    GroupTypingIndicator, SealedGroupState,
};

pub use key_schedule::{EpochKeys, GroupKeySchedule};
pub use sender_key::{SenderKeyChain, SenderKeyStore};
pub use tree::RatchetTree;

const REPLAY_WINDOW_WORDS: usize = 16;
#[allow(clippy::cast_possible_truncation)]
const REPLAY_WINDOW_BITS: u32 = (REPLAY_WINDOW_WORDS as u32) * 64;
const REPLAY_WINDOW_ENCODED_PREFIX: [u8; 4] = [0xFF, b'R', b'W', 1];

#[derive(Clone)]
struct SenderReplayWindow {
    high_water: u32,
    bitmap: [u64; REPLAY_WINDOW_WORDS],
    initialized: bool,
}

impl Default for SenderReplayWindow {
    fn default() -> Self {
        Self {
            high_water: 0,
            bitmap: [0; REPLAY_WINDOW_WORDS],
            initialized: false,
        }
    }
}

impl SenderReplayWindow {
    const fn is_duplicate_or_too_old(&self, generation: u32) -> bool {
        if !self.initialized {
            return false;
        }
        if generation > self.high_water {
            return false;
        }
        let delta = self.high_water - generation;
        if delta >= REPLAY_WINDOW_BITS {
            return true;
        }
        let idx = delta as usize;
        let word = idx / 64;
        let bit = idx % 64;
        (self.bitmap[word] & (1u64 << bit)) != 0
    }

    fn mark_seen(&mut self, generation: u32) {
        if !self.initialized {
            self.initialized = true;
            self.high_water = generation;
            self.bitmap = [0; REPLAY_WINDOW_WORDS];
            self.bitmap[0] |= 1;
            return;
        }

        if generation > self.high_water {
            let shift = generation - self.high_water;
            self.shift_window(shift);
            self.high_water = generation;
            self.bitmap[0] |= 1;
            return;
        }

        let delta = self.high_water - generation;
        if delta >= REPLAY_WINDOW_BITS {
            return;
        }
        let idx = delta as usize;
        let word = idx / 64;
        let bit = idx % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    fn shift_window(&mut self, shift: u32) {
        if shift >= REPLAY_WINDOW_BITS {
            self.bitmap = [0; REPLAY_WINDOW_WORDS];
            return;
        }

        let shift_usize = shift as usize;
        let word_shift = shift_usize / 64;
        let bit_shift = shift_usize % 64;

        if word_shift > 0 {
            for i in (word_shift..REPLAY_WINDOW_WORDS).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for word in self.bitmap.iter_mut().take(word_shift) {
                *word = 0;
            }
        }

        if bit_shift > 0 {
            for i in (1..REPLAY_WINDOW_WORDS).rev() {
                self.bitmap[i] =
                    (self.bitmap[i] << bit_shift) | (self.bitmap[i - 1] >> (64 - bit_shift));
            }
            self.bitmap[0] <<= bit_shift;
        }
    }
}

#[derive(Clone, Debug)]
pub struct GroupSecurityPolicy {
    pub max_messages_per_epoch: u32,
    pub max_skipped_keys_per_sender: u32,
    pub block_external_join: bool,
    pub enhanced_key_schedule: bool,
    pub mandatory_franking: bool,
}

impl GroupSecurityPolicy {
    pub const fn shield() -> Self {
        Self {
            max_messages_per_epoch: SHIELD_MAX_MESSAGES_PER_EPOCH,
            max_skipped_keys_per_sender: SHIELD_MAX_SKIPPED_KEYS_PER_SENDER,
            block_external_join: true,
            enhanced_key_schedule: true,
            mandatory_franking: true,
        }
    }

    pub const fn is_shielded(&self) -> bool {
        self.enhanced_key_schedule && self.mandatory_franking && self.block_external_join
    }

    pub fn policy_bytes(&self) -> Vec<u8> {
        let proto = ProtoGroupSecurityPolicy {
            max_messages_per_epoch: self.max_messages_per_epoch,
            max_skipped_keys_per_sender: self.max_skipped_keys_per_sender,
            block_external_join: self.block_external_join,
            enhanced_key_schedule: self.enhanced_key_schedule,
            mandatory_franking: self.mandatory_franking,
        };
        proto.encode_to_vec()
    }

    fn from_proto_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::invalid_input(
                "Missing group security policy bytes",
            ));
        }
        let proto = ProtoGroupSecurityPolicy::decode(bytes)
            .map_err(|e| ProtocolError::decode(format!("GroupSecurityPolicy decode: {e}")))?;
        Ok(Self {
            max_messages_per_epoch: proto.max_messages_per_epoch,
            max_skipped_keys_per_sender: proto.max_skipped_keys_per_sender,
            block_external_join: proto.block_external_join,
            enhanced_key_schedule: proto.enhanced_key_schedule,
            mandatory_franking: proto.mandatory_franking,
        })
    }

    pub const fn effective_max_messages_per_epoch(&self) -> u32 {
        if self.max_messages_per_epoch == 0 {
            MAX_SENDER_KEY_GENERATION
        } else {
            self.max_messages_per_epoch
        }
    }

    pub const fn effective_max_skipped_per_sender(&self) -> usize {
        if self.max_skipped_keys_per_sender == 0 {
            MAX_SKIPPED_SENDER_KEYS_PER_SENDER
        } else {
            self.max_skipped_keys_per_sender as usize
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let max_msg = self.effective_max_messages_per_epoch();
        if max_msg < SHIELD_MIN_MESSAGES_PER_EPOCH {
            return Err(ProtocolError::invalid_input(format!(
                "max_messages_per_epoch too low: {max_msg} (minimum {SHIELD_MIN_MESSAGES_PER_EPOCH})"
            )));
        }
        if max_msg > MAX_SENDER_KEY_GENERATION {
            return Err(ProtocolError::invalid_input(format!(
                "max_messages_per_epoch too high: {max_msg} (maximum {MAX_SENDER_KEY_GENERATION})"
            )));
        }
        let max_skip = self.effective_max_skipped_per_sender();
        if max_skip < SHIELD_MIN_SKIPPED_PER_SENDER {
            return Err(ProtocolError::invalid_input(format!(
                "max_skipped_keys_per_sender too low: {max_skip} (minimum {SHIELD_MIN_SKIPPED_PER_SENDER})"
            )));
        }
        if max_skip > MAX_SKIPPED_SENDER_KEYS_PER_SENDER {
            return Err(ProtocolError::invalid_input(format!(
                "max_skipped_keys_per_sender too high: {max_skip} (maximum {MAX_SKIPPED_SENDER_KEYS_PER_SENDER})"
            )));
        }
        Ok(())
    }
}

impl Default for GroupSecurityPolicy {
    fn default() -> Self {
        Self::shield()
    }
}

pub trait PskResolver: Send + Sync {
    fn resolve(&self, psk_id: &[u8]) -> Option<Vec<u8>>;
}

pub struct ReInitInfo {
    pub new_group_id: Vec<u8>,
    pub new_version: u32,
}

struct GroupSessionInner {
    group_id: Vec<u8>,
    epoch: u64,
    my_leaf_idx: u32,
    tree: RatchetTree,
    epoch_keys: EpochKeys,
    init_secret: Vec<u8>,
    sender_store: SenderKeyStore,
    group_context_hash: Vec<u8>,
    my_identity_ed25519_public: Vec<u8>,
    my_identity_x25519_public: Vec<u8>,
    my_ed25519_secret: SecureMemoryHandle,
    replay_windows: BTreeMap<u32, SenderReplayWindow>,
    external_x25519_public: Vec<u8>,
    external_kyber_public: Vec<u8>,
    psk_resolver: Option<Box<dyn PskResolver>>,
    pending_reinit: Option<ReInitInfo>,
    event_handler: Option<Arc<dyn IGroupEventHandler>>,
    last_sent_message_hash: Vec<u8>,
    security_policy: GroupSecurityPolicy,
    member_roles: std::collections::HashMap<u32, i32>,
}

impl Drop for GroupSessionInner {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.group_id);
        CryptoInterop::secure_wipe(&mut self.init_secret);
        CryptoInterop::secure_wipe(&mut self.group_context_hash);
    }
}

fn ensure_no_pending_reinit(
    inner: &GroupSessionInner,
    operation: &str,
) -> Result<(), ProtocolError> {
    if inner.pending_reinit.is_some() {
        return Err(ProtocolError::group_protocol(format!(
            "{operation} blocked: group has a pending reinit and is now read-only",
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Normal,
    Sealed,
    Disappearing,
    SealedDisappearing,
    Edit,
    Delete,
    Reaction,
    ReadReceipt,
    Typing,
}

impl ContentType {
    const fn from_u32(v: u32) -> Self {
        match v {
            CONTENT_TYPE_SEALED => ContentType::Sealed,
            CONTENT_TYPE_DISAPPEARING => ContentType::Disappearing,
            CONTENT_TYPE_SEALED_DISAPPEARING => ContentType::SealedDisappearing,
            CONTENT_TYPE_EDIT => ContentType::Edit,
            CONTENT_TYPE_DELETE => ContentType::Delete,
            CONTENT_TYPE_REACTION => ContentType::Reaction,
            CONTENT_TYPE_READ_RECEIPT => ContentType::ReadReceipt,
            CONTENT_TYPE_TYPING => ContentType::Typing,
            _ => ContentType::Normal,
        }
    }

    pub const fn to_u32(self) -> u32 {
        match self {
            ContentType::Normal => CONTENT_TYPE_NORMAL,
            ContentType::Sealed => CONTENT_TYPE_SEALED,
            ContentType::Disappearing => CONTENT_TYPE_DISAPPEARING,
            ContentType::SealedDisappearing => CONTENT_TYPE_SEALED_DISAPPEARING,
            ContentType::Edit => CONTENT_TYPE_EDIT,
            ContentType::Delete => CONTENT_TYPE_DELETE,
            ContentType::Reaction => CONTENT_TYPE_REACTION,
            ContentType::ReadReceipt => CONTENT_TYPE_READ_RECEIPT,
            ContentType::Typing => CONTENT_TYPE_TYPING,
        }
    }

    const fn is_sealed(self) -> bool {
        matches!(self, ContentType::Sealed | ContentType::SealedDisappearing)
    }

    const fn is_disappearing(self) -> bool {
        matches!(
            self,
            ContentType::Disappearing | ContentType::SealedDisappearing
        )
    }

    const fn is_edit(self) -> bool {
        matches!(self, ContentType::Edit)
    }

    const fn is_delete(self) -> bool {
        matches!(self, ContentType::Delete)
    }
}

pub fn compute_message_id(
    group_id: &[u8],
    epoch: u64,
    sender_leaf: u32,
    generation: u32,
) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(GROUP_MSG_ID_INFO);
    h.update(group_id);
    h.update(epoch.to_le_bytes());
    h.update(sender_leaf.to_le_bytes());
    h.update(generation.to_le_bytes());
    h.finalize().to_vec()
}

fn encode_replay_windows_for_state(
    replay_windows: &BTreeMap<u32, SenderReplayWindow>,
) -> Vec<Vec<u8>> {
    let mut encoded = Vec::with_capacity(replay_windows.len());
    for (leaf_index, window) in replay_windows {
        if !window.initialized {
            continue;
        }
        let mut entry =
            Vec::with_capacity(REPLAY_WINDOW_ENCODED_PREFIX.len() + 8 + (REPLAY_WINDOW_WORDS * 8));
        entry.extend_from_slice(&REPLAY_WINDOW_ENCODED_PREFIX);
        entry.extend_from_slice(&leaf_index.to_le_bytes());
        entry.extend_from_slice(&window.high_water.to_le_bytes());
        for word in &window.bitmap {
            entry.extend_from_slice(&word.to_le_bytes());
        }
        encoded.push(entry);
    }
    encoded
}

fn decode_replay_windows_from_state(
    entries: Vec<Vec<u8>>,
) -> Result<BTreeMap<u32, SenderReplayWindow>, ProtocolError> {
    let expected_len = REPLAY_WINDOW_ENCODED_PREFIX.len() + 8 + (REPLAY_WINDOW_WORDS * 8);
    let mut windows = BTreeMap::new();
    for entry in entries {
        if entry.len() != expected_len {
            continue;
        }
        if entry[..REPLAY_WINDOW_ENCODED_PREFIX.len()] != REPLAY_WINDOW_ENCODED_PREFIX {
            continue;
        }
        let mut off = REPLAY_WINDOW_ENCODED_PREFIX.len();
        let leaf_index = u32::from_le_bytes(
            entry[off..off + 4]
                .try_into()
                .map_err(|_| ProtocolError::group_protocol("Replay window parse failed"))?,
        );
        off += 4;
        let high_water = u32::from_le_bytes(
            entry[off..off + 4]
                .try_into()
                .map_err(|_| ProtocolError::group_protocol("Replay window parse failed"))?,
        );
        off += 4;
        let mut bitmap = [0u64; REPLAY_WINDOW_WORDS];
        for word in &mut bitmap {
            *word = u64::from_le_bytes(
                entry[off..off + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::group_protocol("Replay window parse failed"))?,
            );
            off += 8;
        }

        let initialized = bitmap.iter().any(|word| *word != 0);
        windows.insert(
            leaf_index,
            SenderReplayWindow {
                high_water,
                bitmap,
                initialized,
            },
        );
    }
    Ok(windows)
}

pub struct MessagePolicy {
    pub content_type: ContentType,
    pub ttl_seconds: u32,
    pub frankable: bool,
    pub referenced_message_id: Vec<u8>,
    pub mentions: Vec<(u32, u32, u32)>,
    pub reply_context: Option<ReplyContext>,
}

impl Default for MessagePolicy {
    fn default() -> Self {
        Self {
            content_type: ContentType::Normal,
            ttl_seconds: 0,
            frankable: false,
            referenced_message_id: Vec::new(),
            mentions: Vec::new(),
            reply_context: None,
        }
    }
}

pub fn validate_reaction(reaction: &GroupReaction) -> Result<(), ProtocolError> {
    if reaction.message_id.len() != MESSAGE_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Reaction message_id must be 32 bytes",
        ));
    }
    if reaction.emoji.is_empty() {
        return Err(ProtocolError::invalid_input(
            "Reaction emoji must not be empty",
        ));
    }
    if reaction.emoji.chars().count() > MAX_REACTION_EMOJI_CHARS {
        return Err(ProtocolError::invalid_input(format!(
            "Reaction emoji exceeds {MAX_REACTION_EMOJI_CHARS} chars",
        )));
    }
    Ok(())
}

pub fn validate_read_receipt(receipt: &GroupReadReceipt) -> Result<(), ProtocolError> {
    if receipt.message_ids.len() > MAX_READ_RECEIPT_MESSAGE_IDS {
        return Err(ProtocolError::invalid_input(format!(
            "Read receipt exceeds {MAX_READ_RECEIPT_MESSAGE_IDS} message_ids",
        )));
    }
    for id in &receipt.message_ids {
        if id.len() != MESSAGE_ID_BYTES {
            return Err(ProtocolError::invalid_input(
                "Read receipt message_id must be 32 bytes",
            ));
        }
    }
    Ok(())
}

pub fn validate_mentions(mentions: &[ProtoGroupMention]) -> Result<(), ProtocolError> {
    if mentions.len() > MAX_MENTIONS_PER_MESSAGE {
        return Err(ProtocolError::invalid_input(format!(
            "Mentions exceed {MAX_MENTIONS_PER_MESSAGE} per message",
        )));
    }
    Ok(())
}

pub fn validate_reply_context(ctx: &ProtoGroupReplyContext) -> Result<(), ProtocolError> {
    if ctx.reply_to_message_id.len() != MESSAGE_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "reply_to_message_id must be 32 bytes",
        ));
    }
    if let Some(ref root) = ctx.thread_root_id {
        if root.len() != MESSAGE_ID_BYTES {
            return Err(ProtocolError::invalid_input(
                "thread_root_id must be 32 bytes",
            ));
        }
    }
    if let Some(depth) = ctx.depth {
        if depth > MAX_THREAD_DEPTH {
            return Err(ProtocolError::invalid_input(format!(
                "Thread depth {depth} exceeds maximum {MAX_THREAD_DEPTH}",
            )));
        }
        if depth > 0 && ctx.thread_root_id.is_none() {
            return Err(ProtocolError::invalid_input(
                "thread_root_id is required when thread depth is greater than zero",
            ));
        }
    }
    Ok(())
}

fn now_unix_secs(time_provider: &dyn ITimeProvider) -> Result<u64, ProtocolError> {
    time_provider
        .now_unix_secs()
        .map_err(|_| ProtocolError::group_protocol("system clock is before UNIX epoch"))
}

fn validate_external_join_auth_time_window(
    issued_at_unix: u64,
    expires_at_unix: u64,
    time_provider: &dyn ITimeProvider,
) -> Result<(), ProtocolError> {
    if issued_at_unix == 0 || expires_at_unix == 0 {
        return Err(ProtocolError::group_protocol(
            "External join authorization timestamps are required",
        ));
    }
    if expires_at_unix < issued_at_unix {
        return Err(ProtocolError::group_protocol(
            "External join authorization expiry is before issue time",
        ));
    }
    if expires_at_unix.saturating_sub(issued_at_unix) > EXTERNAL_JOIN_AUTH_VALIDITY_SECS {
        return Err(ProtocolError::group_protocol(
            "External join authorization validity window is too large",
        ));
    }
    let now = now_unix_secs(time_provider)?;
    if issued_at_unix > now.saturating_add(MAX_FUTURE_TIMESTAMP_SKEW_SECS) {
        return Err(ProtocolError::group_protocol(format!(
            "External join authorization issued_at {issued_at_unix} is too far in the future (now {now})"
        )));
    }
    if now > expires_at_unix {
        return Err(ProtocolError::group_protocol(format!(
            "External join authorization expired at {expires_at_unix} (now {now})"
        )));
    }
    Ok(())
}

pub(super) fn validate_external_join_auth_format_version(
    auth_format_version: u32,
) -> Result<(), ProtocolError> {
    if auth_format_version != GROUP_EXTERNAL_JOIN_AUTH_FORMAT_VERSION {
        return Err(ProtocolError::group_protocol(format!(
            "Unsupported external join authorization format version: expected {}, got {}",
            GROUP_EXTERNAL_JOIN_AUTH_FORMAT_VERSION, auth_format_version
        )));
    }
    Ok(())
}

fn validate_mentions_for_content(
    mentions: &[ProtoGroupMention],
    content: &[u8],
) -> Result<(), ProtocolError> {
    validate_mentions(mentions)?;
    let content_len = u32::try_from(content.len())
        .map_err(|_| ProtocolError::invalid_input("Message content too large"))?;
    let mut spans = Vec::with_capacity(mentions.len());
    for mention in mentions {
        if mention.length == 0 {
            return Err(ProtocolError::invalid_input(
                "Mention length must be greater than zero",
            ));
        }
        let end = mention
            .offset
            .checked_add(mention.length)
            .ok_or_else(|| ProtocolError::invalid_input("Mention offset overflow"))?;
        if end > content_len {
            return Err(ProtocolError::invalid_input(
                "Mention range exceeds message content length",
            ));
        }
        spans.push((mention.offset, end));
    }
    spans.sort_unstable();
    for pair in spans.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(ProtocolError::invalid_input(
                "Mention ranges must not overlap",
            ));
        }
    }
    Ok(())
}

fn validate_annotations_against_tree(
    tree: &RatchetTree,
    content: &[u8],
    mentions: &[ProtoGroupMention],
    reply_context: Option<&ProtoGroupReplyContext>,
) -> Result<(), ProtocolError> {
    validate_mentions_for_content(mentions, content)?;
    for mention in mentions {
        if tree.get_leaf_data(mention.leaf_index).is_none() {
            return Err(ProtocolError::invalid_input(
                "Mention leaf_index must reference an active group member",
            ));
        }
    }
    if let Some(ctx) = reply_context {
        validate_reply_context(ctx)?;
    }
    Ok(())
}

fn validate_member_role_value(role: i32) -> Result<(), ProtocolError> {
    if !(0..=2).contains(&role) {
        return Err(ProtocolError::invalid_input(
            "member role must be 0 (Member), 1 (Moderator), or 2 (Admin)",
        ));
    }
    Ok(())
}

fn prune_member_roles(
    active_leaf_indices: &[u32],
    member_roles: &mut std::collections::HashMap<u32, i32>,
) {
    let active_leaf_set: std::collections::BTreeSet<u32> =
        active_leaf_indices.iter().copied().collect();
    member_roles.retain(|leaf_index, role| {
        active_leaf_set.contains(leaf_index) && validate_member_role_value(*role).is_ok()
    });
}

pub struct SealedPayload {
    pub hint: Vec<u8>,
    pub encrypted_content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub seal_key: Vec<u8>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for SealedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedPayload")
            .field("hint_len", &self.hint.len())
            .field("encrypted_content_len", &self.encrypted_content.len())
            .field("seal_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SealedPayload {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.seal_key);
    }
}

pub struct FrankingData {
    pub franking_tag: Vec<u8>,
    pub franking_key: Vec<u8>,
    pub content: Vec<u8>,
    pub sealed_content: Vec<u8>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for FrankingData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrankingData")
            .field("franking_tag_len", &self.franking_tag.len())
            .field("franking_key", &"[REDACTED]")
            .field("content_len", &self.content.len())
            .finish()
    }
}

impl Drop for FrankingData {
    fn drop(&mut self) {
        CryptoInterop::secure_wipe(&mut self.franking_key);
    }
}

pub struct ReplyContext {
    pub reply_to_message_id: Vec<u8>,
    pub thread_root_id: Option<Vec<u8>>,
    pub depth: Option<u32>,
}

pub struct GroupDecryptResult {
    pub plaintext: Vec<u8>,
    pub sender_leaf_index: u32,
    pub generation: u32,
    pub content_type: ContentType,
    pub sealed_payload: Option<SealedPayload>,
    pub franking_data: Option<FrankingData>,
    pub ttl_seconds: u32,
    pub sent_timestamp: u64,
    pub prev_message_hash: Vec<u8>,
    pub message_id: Vec<u8>,
    pub referenced_message_id: Vec<u8>,
    pub mentions: Vec<(u32, u32, u32)>,
    pub reply_context: Option<ReplyContext>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for GroupDecryptResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupDecryptResult")
            .field("plaintext_len", &self.plaintext.len())
            .field("sender_leaf_index", &self.sender_leaf_index)
            .field("generation", &self.generation)
            .field("content_type", &self.content_type)
            .finish()
    }
}

pub struct GroupSession {
    inner: Mutex<GroupSessionInner>,
    time_provider: Arc<dyn ITimeProvider>,
}

fn ed25519_secret_to_handle(raw: Zeroizing<Vec<u8>>) -> Result<SecureMemoryHandle, ProtocolError> {
    if raw.len() != ED25519_SECRET_KEY_BYTES {
        return Err(ProtocolError::invalid_input(format!(
            "Ed25519 secret key must be {ED25519_SECRET_KEY_BYTES} bytes"
        )));
    }
    let mut handle = SecureMemoryHandle::allocate(ED25519_SECRET_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    handle.write(&raw).map_err(ProtocolError::from_crypto)?;
    Ok(handle)
}

fn validate_ed25519_secret_matches_public(
    secret: &SecureMemoryHandle,
    expected_public: &[u8],
) -> Result<(), ProtocolError> {
    if expected_public.len() != ED25519_PUBLIC_KEY_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Ed25519 public key size in sealed group state",
        ));
    }
    let mut secret_bytes = secret
        .read_bytes(ED25519_SECRET_KEY_BYTES)
        .map_err(ProtocolError::from_crypto)?;
    let signing_key = {
        let sk_array: [u8; ED25519_SECRET_KEY_BYTES] = secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 secret key size"))?;
        ed25519_dalek::SigningKey::from_keypair_bytes(&sk_array)
            .map_err(|_| ProtocolError::key_generation("Invalid Ed25519 keypair bytes"))?
    };
    CryptoInterop::secure_wipe(&mut secret_bytes);

    let actual_public = signing_key.verifying_key().to_bytes();
    let matches = CryptoInterop::constant_time_equals(actual_public.as_ref(), expected_public)?;
    if !matches {
        return Err(ProtocolError::invalid_input(
            "Ed25519 identity secret does not match sealed group state",
        ));
    }

    Ok(())
}

#[inline]
fn is_all_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in bytes {
        acc |= b;
    }
    acc == 0
}

impl GroupSession {
    fn compute_rotation_threshold(max_messages: u32, percent: u32) -> Result<u32, ProtocolError> {
        if percent == 0 || percent > 100 {
            return Err(ProtocolError::invalid_input(
                "Rotation threshold percent must be in 1..=100",
            ));
        }
        let threshold_u64 = (u64::from(max_messages) * u64::from(percent)).div_ceil(100);
        u32::try_from(threshold_u64)
            .map_err(|_| ProtocolError::invalid_state("Rotation threshold overflow"))
    }

    pub fn epoch_messages_remaining(&self) -> Result<u32, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        let policy_max = inner.security_policy.effective_max_messages_per_epoch();
        let generation = inner
            .sender_store
            .get_chain(inner.my_leaf_idx)
            .ok_or_else(|| ProtocolError::invalid_state("Missing local sender key chain"))?
            .generation();
        Ok(policy_max.saturating_sub(generation))
    }

    pub fn should_rotate_epoch_with_threshold(&self, percent: u32) -> Result<bool, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        let policy_max = inner.security_policy.effective_max_messages_per_epoch();
        let threshold = Self::compute_rotation_threshold(policy_max, percent)?;
        let generation = inner
            .sender_store
            .get_chain(inner.my_leaf_idx)
            .ok_or_else(|| ProtocolError::invalid_state("Missing local sender key chain"))?
            .generation();
        let remaining = policy_max.saturating_sub(generation);
        Ok(remaining <= threshold)
    }

    pub fn should_rotate_epoch(&self) -> Result<bool, ProtocolError> {
        self.should_rotate_epoch_with_threshold(SENDER_KEY_EXHAUSTION_WARNING_PERCENT)
    }

    pub fn rotate_epoch_if_needed(&self) -> Result<Option<Vec<u8>>, ProtocolError> {
        if !self.should_rotate_epoch()? {
            return Ok(None);
        }
        self.update().map(Some)
    }

    pub fn create(identity: &IdentityKeys, credential: Vec<u8>) -> Result<Self, ProtocolError> {
        Self::create_with_policy_and_time_provider(
            identity,
            credential,
            GroupSecurityPolicy::shield(),
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn create_with_policy(
        identity: &IdentityKeys,
        credential: Vec<u8>,
        policy: GroupSecurityPolicy,
    ) -> Result<Self, ProtocolError> {
        Self::create_with_policy_and_time_provider(
            identity,
            credential,
            policy,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn create_with_policy_and_time_provider(
        identity: &IdentityKeys,
        credential: Vec<u8>,
        policy: GroupSecurityPolicy,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        policy.validate()?;
        let (kp, x25519_priv, kyber_sec) =
            key_package::create_key_package(identity, credential.clone())?;
        let ed25519_secret_raw = identity.get_identity_ed25519_private_key_copy()?;
        let ed25519_secret = ed25519_secret_to_handle(ed25519_secret_raw)?;

        let group_id = CryptoInterop::get_random_bytes(GROUP_ID_BYTES);

        let tree = RatchetTree::new_single(
            kp.leaf_x25519_public.clone(),
            kp.leaf_kyber_public.clone(),
            x25519_priv,
            kyber_sec,
            kp.identity_ed25519_public.clone(),
            kp.identity_x25519_public.clone(),
            credential,
            kp.signature.clone(),
        )?;

        let tree_hash = tree.tree_hash()?;

        let policy_bytes = policy.policy_bytes();
        let zero_init_secret = vec![0u8; INIT_SECRET_BYTES];
        let commit_secret = CryptoInterop::get_random_bytes(COMMIT_SECRET_BYTES);
        let group_context_hash =
            GroupKeySchedule::compute_group_context_hash(&group_id, 0, &tree_hash, &policy_bytes);

        let epoch_keys = GroupKeySchedule::derive_epoch_keys(
            &zero_init_secret,
            &commit_secret,
            &group_context_hash,
            policy.enhanced_key_schedule,
        )?;

        let leaf_indices = tree.populated_leaf_indices();
        let sender_store = SenderKeyStore::new_epoch_with_policy(
            &epoch_keys.epoch_secret,
            &leaf_indices,
            &group_context_hash,
            policy.enhanced_key_schedule,
            policy.effective_max_messages_per_epoch(),
            policy.effective_max_skipped_per_sender(),
        )?;

        let init_secret = epoch_keys.init_secret.clone();

        let (_ext_x25519_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&init_secret)?;

        Ok(Self {
            inner: Mutex::new(GroupSessionInner {
                group_id,
                epoch: 0,
                my_leaf_idx: 0,
                tree,
                epoch_keys,
                init_secret,
                sender_store,
                group_context_hash,
                my_identity_ed25519_public: kp.identity_ed25519_public,
                my_identity_x25519_public: kp.identity_x25519_public,
                my_ed25519_secret: ed25519_secret,
                replay_windows: BTreeMap::new(),
                external_x25519_public: ext_x25519_pub,
                external_kyber_public: ext_kyber_pub,
                psk_resolver: None,
                pending_reinit: None,
                event_handler: None,
                last_sent_message_hash: vec![0u8; SHA256_HASH_BYTES],
                security_policy: policy,
                member_roles: std::collections::HashMap::new(),
            }),
            time_provider,
        })
    }

    pub fn set_psk_resolver(&self, resolver: Box<dyn PskResolver>) -> Result<(), ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        inner.psk_resolver = Some(resolver);
        Ok(())
    }

    pub fn pending_reinit(&self) -> Result<Option<ReInitInfo>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.pending_reinit.as_ref().map(|r| ReInitInfo {
            new_group_id: r.new_group_id.clone(),
            new_version: r.new_version,
        }))
    }

    pub fn from_welcome(
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
        identity_ed25519: &[u8],
        identity_x25519: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
    ) -> Result<Self, ProtocolError> {
        Self::from_welcome_with_time_provider(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            identity_ed25519,
            identity_x25519,
            ed25519_secret_raw,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_welcome_with_time_provider(
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
        identity_ed25519: &[u8],
        identity_x25519: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if welcome_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Welcome too large"));
        }
        let ed25519_secret = ed25519_secret_to_handle(ed25519_secret_raw)?;
        let welcome_msg = crate::proto::GroupWelcome::decode(welcome_bytes)
            .map_err(|e| ProtocolError::decode(format!("Welcome decode: {e}")))?;

        let result = welcome::process_welcome(
            &welcome_msg,
            x25519_private,
            kyber_secret,
            identity_ed25519,
            identity_x25519,
        )?;

        let security_policy = GroupSecurityPolicy::from_proto_bytes(&result.security_policy_bytes)?;
        security_policy.validate()?;
        let init_secret = result.epoch_keys.init_secret.clone();

        let (_ext_x25519_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&init_secret)?;

        Ok(Self {
            inner: Mutex::new(GroupSessionInner {
                group_id: result.group_id,
                epoch: result.epoch,
                my_leaf_idx: result.my_leaf_idx,
                tree: result.tree,
                epoch_keys: result.epoch_keys,
                init_secret,
                sender_store: result.sender_store,
                group_context_hash: result.group_context_hash,
                my_identity_ed25519_public: identity_ed25519.to_vec(),
                my_identity_x25519_public: identity_x25519.to_vec(),
                my_ed25519_secret: ed25519_secret,
                replay_windows: BTreeMap::new(),
                external_x25519_public: ext_x25519_pub,
                external_kyber_public: ext_kyber_pub,
                psk_resolver: None,
                pending_reinit: None,
                event_handler: None,
                last_sent_message_hash: vec![0u8; SHA256_HASH_BYTES],
                security_policy,
                member_roles: std::collections::HashMap::new(),
            }),
            time_provider,
        })
    }

    pub fn from_welcome_with_min_epoch(
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
        identity_ed25519: &[u8],
        identity_x25519: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
        min_epoch: u64,
    ) -> Result<Self, ProtocolError> {
        Self::from_welcome_with_min_epoch_and_time_provider(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            identity_ed25519,
            identity_x25519,
            ed25519_secret_raw,
            min_epoch,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_welcome_with_min_epoch_and_time_provider(
        welcome_bytes: &[u8],
        x25519_private: SecureMemoryHandle,
        kyber_secret: SecureMemoryHandle,
        identity_ed25519: &[u8],
        identity_x25519: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
        min_epoch: u64,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if welcome_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Welcome too large"));
        }
        let welcome_msg = crate::proto::GroupWelcome::decode(welcome_bytes)
            .map_err(|e| ProtocolError::decode(format!("Welcome decode: {e}")))?;

        if welcome_msg.epoch < min_epoch {
            return Err(ProtocolError::group_protocol(format!(
                "Stale Welcome rejected: epoch {} < min_epoch {}",
                welcome_msg.epoch, min_epoch
            )));
        }

        Self::from_welcome_with_time_provider(
            welcome_bytes,
            x25519_private,
            kyber_secret,
            identity_ed25519,
            identity_x25519,
            ed25519_secret_raw,
            time_provider,
        )
    }

    pub fn add_member(
        &self,
        key_package: &GroupKeyPackage,
    ) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
        key_package::validate_key_package(key_package)?;

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        let add_proposal = GroupProposal {
            proposal: Some(crate::proto::group_proposal::Proposal::Add(
                crate::proto::GroupAddProposal {
                    key_package: Some(key_package.clone()),
                },
            )),
        };

        let my_leaf_idx = inner.my_leaf_idx;
        let init_secret = Zeroizing::new(inner.init_secret.clone());
        let group_id = inner.group_id.clone();
        let epoch = inner.epoch;
        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let psk_resolver = inner.psk_resolver.take();
        let policy = inner.security_policy.clone();

        let commit_output = commit::create_commit(
            &mut inner.tree,
            vec![add_proposal],
            my_leaf_idx,
            init_secret.as_slice(),
            &group_id,
            epoch,
            &ed25519_sk,
            psk_resolver.as_deref(),
            &policy,
        );
        inner.psk_resolver = psk_resolver;
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        let commit_output = commit_output?;

        let new_leaf_idx = commit_output
            .added_leaf_indices
            .first()
            .copied()
            .ok_or_else(|| ProtocolError::group_protocol("No leaf added"))?;

        let welcome = welcome::create_welcome(
            &inner.tree,
            new_leaf_idx,
            &commit_output.epoch_keys,
            &commit_output.joiner_secret,
            &group_id,
            commit_output.commit.epoch,
            &commit_output.commit.confirmation_mac,
            &commit_output.group_context_hash,
            &inner.security_policy.policy_bytes(),
        )?;

        inner
            .init_secret
            .clone_from(&commit_output.epoch_keys.init_secret);
        inner.epoch = commit_output.commit.epoch;
        inner.epoch_keys = commit_output.epoch_keys;
        inner.sender_store = commit_output.new_sender_store;
        inner.group_context_hash = commit_output.group_context_hash;
        inner.replay_windows.clear();
        let active_leaf_indices = inner.tree.populated_leaf_indices();
        prune_member_roles(&active_leaf_indices, &mut inner.member_roles);

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&inner.init_secret)?;
        inner.external_x25519_public = ext_x25519_pub;
        inner.external_kyber_public = ext_kyber_pub;

        let mut commit_bytes = Vec::new();
        commit_output
            .commit
            .encode(&mut commit_bytes)
            .map_err(|e| ProtocolError::encode(format!("Commit encode: {e}")))?;

        let mut welcome_bytes = Vec::new();
        welcome
            .encode(&mut welcome_bytes)
            .map_err(|e| ProtocolError::encode(format!("Welcome encode: {e}")))?;

        Ok((commit_bytes, welcome_bytes))
    }

    pub fn remove_member(&self, removed_leaf_idx: u32) -> Result<Vec<u8>, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        let remove_proposal = GroupProposal {
            proposal: Some(crate::proto::group_proposal::Proposal::Remove(
                crate::proto::GroupRemoveProposal {
                    removed_leaf_index: removed_leaf_idx,
                },
            )),
        };

        let my_leaf_idx = inner.my_leaf_idx;
        let init_secret = Zeroizing::new(inner.init_secret.clone());
        let group_id = inner.group_id.clone();
        let epoch = inner.epoch;
        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let psk_resolver = inner.psk_resolver.take();
        let policy = inner.security_policy.clone();

        let commit_output = commit::create_commit(
            &mut inner.tree,
            vec![remove_proposal],
            my_leaf_idx,
            init_secret.as_slice(),
            &group_id,
            epoch,
            &ed25519_sk,
            psk_resolver.as_deref(),
            &policy,
        );
        inner.psk_resolver = psk_resolver;
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        let commit_output = commit_output?;

        inner
            .init_secret
            .clone_from(&commit_output.epoch_keys.init_secret);
        inner.epoch = commit_output.commit.epoch;
        inner.epoch_keys = commit_output.epoch_keys;
        inner.sender_store = commit_output.new_sender_store;
        inner.group_context_hash = commit_output.group_context_hash;
        inner.replay_windows.clear();
        let active_leaf_indices = inner.tree.populated_leaf_indices();
        prune_member_roles(&active_leaf_indices, &mut inner.member_roles);

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&inner.init_secret)?;
        inner.external_x25519_public = ext_x25519_pub;
        inner.external_kyber_public = ext_kyber_pub;

        let mut bytes = Vec::new();
        commit_output
            .commit
            .encode(&mut bytes)
            .map_err(|e| ProtocolError::encode(format!("Commit encode: {e}")))?;
        Ok(bytes)
    }

    pub fn update(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        ensure_no_pending_reinit(&inner, "update")?;

        let my_leaf_idx = inner.my_leaf_idx;
        let init_secret = Zeroizing::new(inner.init_secret.clone());
        let group_id = inner.group_id.clone();
        let epoch = inner.epoch;
        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let psk_resolver = inner.psk_resolver.take();
        let policy = inner.security_policy.clone();

        let commit_output = commit::create_commit(
            &mut inner.tree,
            vec![],
            my_leaf_idx,
            init_secret.as_slice(),
            &group_id,
            epoch,
            &ed25519_sk,
            psk_resolver.as_deref(),
            &policy,
        );
        inner.psk_resolver = psk_resolver;
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        let commit_output = commit_output?;

        inner
            .init_secret
            .clone_from(&commit_output.epoch_keys.init_secret);
        inner.epoch = commit_output.commit.epoch;
        inner.epoch_keys = commit_output.epoch_keys;
        inner.sender_store = commit_output.new_sender_store;
        inner.group_context_hash = commit_output.group_context_hash;
        inner.replay_windows.clear();

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&inner.init_secret)?;
        inner.external_x25519_public = ext_x25519_pub;
        inner.external_kyber_public = ext_kyber_pub;

        let mut bytes = Vec::new();
        commit_output
            .commit
            .encode(&mut bytes)
            .map_err(|e| ProtocolError::encode(format!("Commit encode: {e}")))?;
        Ok(bytes)
    }

    /// Create a commit that carries a single ReInit proposal, advancing the committer's
    /// epoch. Other members must process the returned bytes via [`Self::process_commit`].
    ///
    /// `new_group_id` must be exactly [`GROUP_ID_BYTES`] bytes.
    pub fn create_reinit_commit(
        &self,
        new_group_id: Vec<u8>,
        new_version: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        if new_group_id.len() != GROUP_ID_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "create_reinit_commit: new_group_id must be {} bytes, got {}",
                GROUP_ID_BYTES,
                new_group_id.len()
            )));
        }

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        ensure_no_pending_reinit(&inner, "create_reinit_commit")?;

        let my_leaf_idx = inner.my_leaf_idx;
        let init_secret = Zeroizing::new(inner.init_secret.clone());
        let group_id = inner.group_id.clone();
        let epoch = inner.epoch;
        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let psk_resolver = inner.psk_resolver.take();
        let policy = inner.security_policy.clone();

        let reinit_proposal = GroupProposal {
            proposal: Some(crate::proto::group_proposal::Proposal::ReInit(
                crate::proto::GroupReInitProposal {
                    new_group_id,
                    new_version,
                },
            )),
        };

        let commit_output = commit::create_commit(
            &mut inner.tree,
            vec![reinit_proposal],
            my_leaf_idx,
            init_secret.as_slice(),
            &group_id,
            epoch,
            &ed25519_sk,
            psk_resolver.as_deref(),
            &policy,
        );
        inner.psk_resolver = psk_resolver;
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        let commit_output = commit_output?;

        inner
            .init_secret
            .clone_from(&commit_output.epoch_keys.init_secret);
        inner.epoch = commit_output.commit.epoch;
        inner.epoch_keys = commit_output.epoch_keys;
        inner.sender_store = commit_output.new_sender_store;
        inner.group_context_hash = commit_output.group_context_hash;
        inner.replay_windows.clear();
        inner.pending_reinit = Some(ReInitInfo {
            new_group_id: commit_output
                .commit
                .proposals
                .iter()
                .find_map(|proposal| match &proposal.proposal {
                    Some(crate::proto::group_proposal::Proposal::ReInit(reinit)) => {
                        Some(reinit.new_group_id.clone())
                    }
                    _ => None,
                })
                .ok_or_else(|| ProtocolError::group_protocol("ReInit proposal missing"))?,
            new_version,
        });

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&inner.init_secret)?;
        inner.external_x25519_public = ext_x25519_pub;
        inner.external_kyber_public = ext_kyber_pub;

        let mut bytes = Vec::new();
        commit_output
            .commit
            .encode(&mut bytes)
            .map_err(|e| ProtocolError::encode(format!("Commit encode: {e}")))?;
        Ok(bytes)
    }

    pub fn process_commit(&self, commit_bytes: &[u8]) -> Result<(), ProtocolError> {
        if commit_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input(format!(
                "Commit message too large: {} bytes (max {})",
                commit_bytes.len(),
                MAX_GROUP_MESSAGE_SIZE
            )));
        }
        let commit_msg = GroupCommit::decode(commit_bytes)
            .map_err(|e| ProtocolError::decode(format!("Commit decode: {e}")))?;

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        ensure_no_pending_reinit(&inner, "process_commit")?;

        let my_leaf_idx = inner.my_leaf_idx;
        let init_secret = Zeroizing::new(inner.init_secret.clone());
        let group_id = inner.group_id.clone();
        let epoch = inner.epoch;
        let psk_resolver = inner.psk_resolver.as_deref();

        let mut tree_candidate = inner.tree.try_clone()?;
        let processed = commit::process_commit(
            &mut tree_candidate,
            &commit_msg,
            my_leaf_idx,
            init_secret.as_slice(),
            &group_id,
            epoch,
            psk_resolver,
            &inner.security_policy,
        )?;
        inner.tree = tree_candidate;

        let epoch_keys = processed.epoch_keys;

        let mut reinit_event: Option<(Vec<u8>, u32)> = None;
        for proposal in &commit_msg.proposals {
            if let Some(crate::proto::group_proposal::Proposal::ReInit(ref reinit)) =
                proposal.proposal
            {
                inner.pending_reinit = Some(ReInitInfo {
                    new_group_id: reinit.new_group_id.clone(),
                    new_version: reinit.new_version,
                });
                reinit_event = Some((reinit.new_group_id.clone(), reinit.new_version));
            }
        }

        inner.init_secret.clone_from(&epoch_keys.init_secret);
        inner.epoch = commit_msg.epoch;
        inner.epoch_keys = epoch_keys;
        inner.sender_store = processed.new_sender_store;
        inner.group_context_hash = processed.group_context_hash;
        inner.replay_windows.clear();
        inner.last_sent_message_hash = vec![0u8; SHA256_HASH_BYTES];
        let active_leaf_indices = inner.tree.populated_leaf_indices();
        prune_member_roles(&active_leaf_indices, &mut inner.member_roles);

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&inner.init_secret)?;
        inner.external_x25519_public = ext_x25519_pub;
        inner.external_kyber_public = ext_kyber_pub;

        if let Some(handler) = &inner.event_handler {
            for proposal in &commit_msg.proposals {
                match &proposal.proposal {
                    Some(crate::proto::group_proposal::Proposal::Add(add)) => {
                        if let Some(kp) = &add.key_package {
                            let leaf_idx = inner
                                .tree
                                .populated_leaf_indices()
                                .into_iter()
                                .find(|&idx| {
                                    inner.tree.get_leaf_data(idx).is_some_and(|ld| {
                                        ld.identity_ed25519_public == kp.identity_ed25519_public
                                    })
                                })
                                .unwrap_or(0);
                            handler.on_member_added(leaf_idx, &kp.identity_ed25519_public);
                        }
                    }
                    Some(crate::proto::group_proposal::Proposal::Remove(remove)) => {
                        handler.on_member_removed(remove.removed_leaf_index);
                    }
                    _ => {}
                }
            }
            handler.on_epoch_advanced(inner.epoch, inner.tree.member_count());
            if let Some((ref new_group_id, new_version)) = reinit_event {
                handler.on_reinit_proposed(new_group_id, new_version);
            }
        }

        Ok(())
    }

    pub fn export_public_state(&self) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        let confirmation_mac = GroupKeySchedule::compute_confirmation_mac(
            &inner.epoch_keys.confirmation_key,
            &inner.group_context_hash,
        )?;

        let public_state = GroupPublicState {
            version: GROUP_PROTOCOL_VERSION,
            group_id: inner.group_id.clone(),
            epoch: inner.epoch,
            tree_nodes: inner.tree.export_public(),
            group_context_hash: inner.group_context_hash.clone(),
            confirmation_mac,
            external_x25519_public: inner.external_x25519_public.clone(),
            external_kyber_public: inner.external_kyber_public.clone(),
            security_policy: inner.security_policy.policy_bytes(),
        };

        let mut bytes = Vec::new();
        public_state
            .encode(&mut bytes)
            .map_err(|e| ProtocolError::encode(format!("GroupPublicState encode: {e}")))?;
        Ok(bytes)
    }

    pub fn authorize_external_join(
        &self,
        joiner_identity_ed25519_public: &[u8],
        joiner_identity_x25519_public: &[u8],
        joiner_credential: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if joiner_identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "authorize_external_join: invalid joiner Ed25519 public key size",
            ));
        }
        if joiner_identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "authorize_external_join: invalid joiner X25519 public key size",
            ));
        }
        if joiner_credential.len() > MAX_CREDENTIAL_SIZE {
            return Err(ProtocolError::invalid_input(format!(
                "authorize_external_join: credential too large (max {MAX_CREDENTIAL_SIZE})",
            )));
        }

        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        ensure_no_pending_reinit(&inner, "authorize_external_join")?;
        if inner.security_policy.block_external_join {
            return Err(ProtocolError::group_protocol(
                "External join blocked by group security policy",
            ));
        }

        let issued_at_unix = now_unix_secs(self.time_provider.as_ref())?;
        let mut auth = GroupExternalJoinAuthorization {
            auth_format_version: GROUP_EXTERNAL_JOIN_AUTH_FORMAT_VERSION,
            group_id: inner.group_id.clone(),
            epoch: inner.epoch,
            joiner_identity_ed25519_public: joiner_identity_ed25519_public.to_vec(),
            joiner_identity_x25519_public: joiner_identity_x25519_public.to_vec(),
            joiner_credential: joiner_credential.to_vec(),
            authorizer_leaf_index: inner.my_leaf_idx,
            authorizer_signature: Vec::new(),
            group_context_hash: inner.group_context_hash.clone(),
            external_x25519_public: inner.external_x25519_public.clone(),
            external_kyber_public: inner.external_kyber_public.clone(),
            issued_at_unix,
            expires_at_unix: issued_at_unix.saturating_add(EXTERNAL_JOIN_AUTH_VALIDITY_SECS),
        };
        let mut auth_bytes = Vec::new();
        auth.encode(&mut auth_bytes)
            .map_err(|e| ProtocolError::encode(format!("External join auth encode: {e}")))?;

        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        auth.authorizer_signature = Self::ed25519_sign_group_message(&ed25519_sk, &auth_bytes)?;
        CryptoInterop::secure_wipe(&mut ed25519_sk);

        let mut signed = Vec::new();
        auth.encode(&mut signed)
            .map_err(|e| ProtocolError::encode(format!("External join auth encode: {e}")))?;
        Ok(signed)
    }

    pub fn from_external_join(
        public_state_bytes: &[u8],
        authorization_bytes: &[u8],
        identity: &IdentityKeys,
        credential: Vec<u8>,
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        Self::from_external_join_with_time_provider(
            public_state_bytes,
            authorization_bytes,
            identity,
            credential,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_external_join_with_time_provider(
        public_state_bytes: &[u8],
        authorization_bytes: &[u8],
        identity: &IdentityKeys,
        credential: Vec<u8>,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        if public_state_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Public state too large"));
        }

        let public_state = GroupPublicState::decode(public_state_bytes)
            .map_err(|e| ProtocolError::decode(format!("GroupPublicState decode: {e}")))?;
        if public_state.version != GROUP_PROTOCOL_VERSION {
            return Err(ProtocolError::group_protocol(format!(
                "External join: unsupported public state version {}",
                public_state.version
            )));
        }

        let security_policy = GroupSecurityPolicy::from_proto_bytes(&public_state.security_policy)?;
        security_policy.validate()?;
        if security_policy.block_external_join {
            return Err(ProtocolError::group_protocol(
                "External join blocked by group security policy",
            ));
        }
        if authorization_bytes.is_empty() {
            return Err(ProtocolError::group_protocol(
                "External join authorization is required",
            ));
        }
        if authorization_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input(
                "External join authorization too large",
            ));
        }

        let mut tree = RatchetTree::from_public_proto(&public_state.tree_nodes)?;

        let tree_hash = tree.tree_hash()?;
        let expected_ctx_hash = GroupKeySchedule::compute_group_context_hash(
            &public_state.group_id,
            public_state.epoch,
            &tree_hash,
            &public_state.security_policy,
        );
        let ctx_ok = CryptoInterop::constant_time_equals(
            &expected_ctx_hash,
            &public_state.group_context_hash,
        )?;
        if !ctx_ok {
            return Err(ProtocolError::group_protocol(
                "External join: group_context_hash mismatch",
            ));
        }
        Self::validate_external_join_authorization_for_public_state(
            &tree,
            &public_state,
            authorization_bytes,
            &identity.get_identity_ed25519_public(),
            &identity.get_identity_x25519_public(),
            &credential,
            time_provider.as_ref(),
        )?;

        crate::security::DhValidator::validate_x25519_public_key(
            &public_state.external_x25519_public,
        )?;
        crate::crypto::KyberInterop::validate_public_key(&public_state.external_kyber_public)
            .map_err(ProtocolError::from_crypto)?;

        let (eph_x25519_priv, eph_x25519_pub) =
            CryptoInterop::generate_x25519_keypair("external-join-eph")?;
        let mut eph_priv_bytes = eph_x25519_priv.read_bytes(X25519_PRIVATE_KEY_BYTES)?;
        let mut sk: [u8; X25519_PRIVATE_KEY_BYTES] = eph_priv_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::group_protocol("Invalid X25519 private key size"))?;
        let pk: [u8; X25519_PUBLIC_KEY_BYTES] = public_state
            .external_x25519_public
            .as_slice()
            .try_into()
            .map_err(|_| {
                ProtocolError::group_protocol("Invalid external X25519 public key size")
            })?;
        let mut dh_shared = x25519_dalek::StaticSecret::from(sk)
            .diffie_hellman(&x25519_dalek::PublicKey::from(pk))
            .to_bytes()
            .to_vec();
        CryptoInterop::secure_wipe(&mut eph_priv_bytes);
        CryptoInterop::secure_wipe(&mut sk);
        if is_all_zero(&dh_shared) {
            CryptoInterop::secure_wipe(&mut dh_shared);
            return Err(ProtocolError::group_protocol(
                "External join X25519 DH produced all-zero output (RFC 7748 section 6.1)",
            ));
        }

        let (kyber_ct, kyber_ss_handle) =
            crate::crypto::KyberInterop::encapsulate(&public_state.external_kyber_public)?;
        let mut kyber_ss = kyber_ss_handle.read_bytes(KYBER_SHARED_SECRET_BYTES)?;

        let kem_output = HkdfSha256::extract(&dh_shared, &kyber_ss);
        CryptoInterop::secure_wipe(&mut dh_shared);
        CryptoInterop::secure_wipe(&mut kyber_ss);

        let init_secret_proxy = {
            let mut z = HkdfSha256::expand(
                &kem_output,
                GROUP_EXTERNAL_INIT_SECRET_INFO,
                INIT_SECRET_BYTES,
            )?;
            std::mem::take(&mut *z)
        };

        let (kp, _leaf_x25519_priv, _leaf_kyber_sec) =
            key_package::create_key_package(identity, credential)?;

        let my_leaf_idx = tree.next_leaf_index();

        let external_init_proposal = GroupProposal {
            proposal: Some(crate::proto::group_proposal::Proposal::ExternalInit(
                crate::proto::GroupExternalInitProposal {
                    ephemeral_x25519_public: eph_x25519_pub,
                    kyber_ciphertext: kyber_ct,
                    authorization: authorization_bytes.to_vec(),
                },
            )),
        };
        let add_proposal = GroupProposal {
            proposal: Some(crate::proto::group_proposal::Proposal::Add(
                crate::proto::GroupAddProposal {
                    key_package: Some(kp.clone()),
                },
            )),
        };

        let mut ed25519_sk = identity.get_identity_ed25519_private_key_copy()?;
        let commit_output = commit::create_commit(
            &mut tree,
            vec![external_init_proposal, add_proposal],
            my_leaf_idx,
            &init_secret_proxy,
            &public_state.group_id,
            public_state.epoch,
            &ed25519_sk,
            None,
            &security_policy,
        );
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        let commit_output = commit_output?;
        let ed25519_secret_raw = identity.get_identity_ed25519_private_key_copy()?;
        let ed25519_secret = ed25519_secret_to_handle(ed25519_secret_raw)?;

        let new_init_secret = commit_output.epoch_keys.init_secret.clone();

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&new_init_secret)?;

        let session = Self {
            inner: Mutex::new(GroupSessionInner {
                group_id: public_state.group_id,
                epoch: commit_output.commit.epoch,
                my_leaf_idx,
                tree,
                epoch_keys: commit_output.epoch_keys,
                init_secret: new_init_secret,
                sender_store: commit_output.new_sender_store,
                group_context_hash: commit_output.group_context_hash,
                my_identity_ed25519_public: kp.identity_ed25519_public,
                my_identity_x25519_public: kp.identity_x25519_public,
                my_ed25519_secret: ed25519_secret,
                replay_windows: BTreeMap::new(),
                external_x25519_public: ext_x25519_pub,
                external_kyber_public: ext_kyber_pub,
                psk_resolver: None,
                pending_reinit: None,
                event_handler: None,
                last_sent_message_hash: vec![0u8; SHA256_HASH_BYTES],
                security_policy,
                member_roles: std::collections::HashMap::new(),
            }),
            time_provider,
        };

        let mut commit_bytes = Vec::new();
        commit_output
            .commit
            .encode(&mut commit_bytes)
            .map_err(|e| ProtocolError::encode(format!("Commit encode: {e}")))?;

        Ok((session, commit_bytes))
    }

    fn validate_external_join_authorization_for_public_state(
        tree: &RatchetTree,
        public_state: &GroupPublicState,
        authorization_bytes: &[u8],
        joiner_identity_ed25519_public: &[u8],
        joiner_identity_x25519_public: &[u8],
        joiner_credential: &[u8],
        time_provider: &dyn ITimeProvider,
    ) -> Result<(), ProtocolError> {
        let auth = GroupExternalJoinAuthorization::decode(authorization_bytes)
            .map_err(|e| ProtocolError::decode(format!("External join auth decode: {e}")))?;
        validate_external_join_auth_format_version(auth.auth_format_version)?;
        if auth.group_id != public_state.group_id {
            return Err(ProtocolError::group_protocol(
                "External join authorization group_id mismatch",
            ));
        }
        if auth.epoch != public_state.epoch {
            return Err(ProtocolError::group_protocol(format!(
                "External join authorization epoch mismatch: expected {}, got {}",
                public_state.epoch, auth.epoch
            )));
        }
        if auth.joiner_identity_ed25519_public != joiner_identity_ed25519_public
            || auth.joiner_identity_x25519_public != joiner_identity_x25519_public
            || auth.joiner_credential != joiner_credential
        {
            return Err(ProtocolError::group_protocol(
                "External join authorization does not match joiner identity",
            ));
        }
        if auth.group_context_hash != public_state.group_context_hash {
            return Err(ProtocolError::group_protocol(
                "External join authorization group_context_hash mismatch",
            ));
        }
        if auth.external_x25519_public != public_state.external_x25519_public
            || auth.external_kyber_public != public_state.external_kyber_public
        {
            return Err(ProtocolError::group_protocol(
                "External join authorization external init key mismatch",
            ));
        }
        validate_external_join_auth_time_window(
            auth.issued_at_unix,
            auth.expires_at_unix,
            time_provider,
        )?;
        let authorizer_leaf = tree
            .get_leaf_data(auth.authorizer_leaf_index)
            .ok_or_else(|| {
                ProtocolError::group_protocol("External join authorizer leaf is blank")
            })?;
        let mut auth_for_verify = auth.clone();
        auth_for_verify.authorizer_signature.clear();
        let mut auth_bytes = Vec::new();
        auth_for_verify
            .encode(&mut auth_bytes)
            .map_err(|e| ProtocolError::encode(format!("External join auth encode: {e}")))?;
        Self::ed25519_verify_group_message_with_context(
            &authorizer_leaf.identity_ed25519_public,
            &auth.authorizer_signature,
            &auth_bytes,
            "External join authorization signature verification failed",
        )
    }

    fn build_group_plaintext(
        &self,
        content: &[u8],
        policy: &MessagePolicy,
        message_key: &[u8],
        actual_plaintext: Option<&[u8]>,
    ) -> Result<(GroupPlaintext, Vec<u8>), ProtocolError> {
        let now = now_unix_secs(self.time_provider.as_ref())?;

        #[allow(clippy::cast_possible_wrap)]
        let content_type_i32 = policy.content_type.to_u32() as i32;
        let proto_policy = GroupMessagePolicy {
            content_type: content_type_i32,
            ttl_seconds: policy.ttl_seconds,
            sent_timestamp: now,
        };

        let proto_mentions: Vec<ProtoGroupMention> = policy
            .mentions
            .iter()
            .map(|&(leaf_index, offset, length)| ProtoGroupMention {
                leaf_index,
                offset,
                length,
            })
            .collect();

        let proto_reply = policy
            .reply_context
            .as_ref()
            .map(|rc| ProtoGroupReplyContext {
                reply_to_message_id: rc.reply_to_message_id.clone(),
                thread_root_id: rc.thread_root_id.clone(),
                depth: rc.depth,
            });

        let mut gpt = GroupPlaintext {
            content: content.to_vec(),
            policy: Some(proto_policy),
            franking_key: Vec::new(),
            sealed_content: Vec::new(),
            sealed_nonce: Vec::new(),
            prev_message_hash: Vec::new(),
            referenced_message_id: policy.referenced_message_id.clone(),
            mentions: proto_mentions,
            reply_context: proto_reply,
        };

        if policy.content_type.is_sealed() {
            let real_pt = actual_plaintext.ok_or_else(|| {
                ProtocolError::invalid_input("Sealed message requires actual_plaintext")
            })?;
            let mut seal_key = {
                let mut z = HkdfSha256::expand(message_key, GROUP_SEAL_KEY_INFO, SEAL_KEY_BYTES)?;
                std::mem::take(&mut *z)
            };
            let sealed_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
            let sealed_ct = AesGcm::encrypt(&seal_key, &sealed_nonce, real_pt, SEALED_AAD_SUFFIX)?;
            CryptoInterop::secure_wipe(&mut seal_key);
            gpt.sealed_content = sealed_ct;
            gpt.sealed_nonce = sealed_nonce;
        }

        let mut franking_tag = Vec::new();
        if policy.frankable {
            let fk = CryptoInterop::get_random_bytes(FRANKING_KEY_BYTES);
            let mut mac = Hmac::<Sha256>::new_from_slice(&fk)
                .map_err(|e| ProtocolError::franking_failed(format!("HMAC init: {e}")))?;
            mac.update(content);
            if !gpt.sealed_content.is_empty() {
                mac.update(&gpt.sealed_content);
            }
            franking_tag = mac.finalize().into_bytes().to_vec();
            gpt.franking_key = fk;
        }

        Ok((gpt, franking_tag))
    }

    #[allow(clippy::type_complexity)]
    fn parse_group_plaintext(
        &self,
        gpt: &GroupPlaintext,
        seal_key: &[u8],
        franking_tag_wire: &[u8],
        mandatory_franking: bool,
    ) -> Result<
        (
            Vec<u8>,
            ContentType,
            Option<SealedPayload>,
            Option<FrankingData>,
            u32,
            u64,
            Vec<u8>,
        ),
        ProtocolError,
    > {
        let policy = gpt.policy.as_ref();
        let content_type_raw = policy.map_or(0, |p| p.content_type);
        #[allow(clippy::cast_sign_loss)]
        let content_type = ContentType::from_u32(content_type_raw as u32);
        let ttl_seconds = policy.map_or(0, |p| p.ttl_seconds);
        let sent_timestamp = policy.map_or(0, |p| p.sent_timestamp);

        if content_type.is_disappearing() && ttl_seconds > 0 {
            let now = now_unix_secs(self.time_provider.as_ref())?;

            if sent_timestamp > now.saturating_add(MAX_FUTURE_TIMESTAMP_SKEW_SECS) {
                return Err(ProtocolError::invalid_input(format!(
                    "sent_timestamp {sent_timestamp} is too far in the future (now {now})"
                )));
            }

            let expiry = sent_timestamp.saturating_add(u64::from(ttl_seconds));
            if now > expiry {
                return Err(ProtocolError::message_expired(format!(
                    "TTL {ttl_seconds}s expired (sent {sent_timestamp}, now {now})"
                )));
            }
        }

        let sealed_payload = if content_type.is_sealed() && !gpt.sealed_content.is_empty() {
            Some(SealedPayload {
                hint: gpt.content.clone(),
                encrypted_content: gpt.sealed_content.clone(),
                nonce: gpt.sealed_nonce.clone(),
                seal_key: seal_key.to_vec(),
            })
        } else {
            None
        };

        if mandatory_franking && gpt.franking_key.is_empty() {
            return Err(ProtocolError::franking_failed(
                "Group security policy requires franking on every message",
            ));
        }

        if !gpt.franking_key.is_empty() && franking_tag_wire.is_empty() {
            return Err(ProtocolError::franking_failed(
                "Message contains franking_key but franking_tag is missing on wire",
            ));
        }

        let franking_data = if !gpt.franking_key.is_empty() && !franking_tag_wire.is_empty() {
            let mut mac = Hmac::<Sha256>::new_from_slice(&gpt.franking_key)
                .map_err(|e| ProtocolError::franking_failed(format!("HMAC init: {e}")))?;
            mac.update(&gpt.content);
            if !gpt.sealed_content.is_empty() {
                mac.update(&gpt.sealed_content);
            }
            let computed = mac.finalize().into_bytes().to_vec();
            let tag_valid =
                CryptoInterop::constant_time_equals(&computed, franking_tag_wire).unwrap_or(false);
            if !tag_valid {
                return Err(ProtocolError::franking_failed(
                    "Franking tag mismatch on decrypt",
                ));
            }
            Some(FrankingData {
                franking_tag: franking_tag_wire.to_vec(),
                franking_key: gpt.franking_key.clone(),
                content: gpt.content.clone(),
                sealed_content: gpt.sealed_content.clone(),
            })
        } else {
            None
        };

        let referenced_message_id = gpt.referenced_message_id.clone();
        if (content_type.is_edit() || content_type.is_delete())
            && referenced_message_id.len() != MESSAGE_ID_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Edit/Delete message missing valid referenced_message_id",
            ));
        }

        Ok((
            gpt.content.clone(),
            content_type,
            sealed_payload,
            franking_data,
            ttl_seconds,
            sent_timestamp,
            referenced_message_id,
        ))
    }

    fn build_state_aad(version_le: &[u8], dek_nonce: &[u8], encrypted_dek: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(version_le.len() + dek_nonce.len() + encrypted_dek.len());
        aad.extend_from_slice(version_le);
        aad.extend_from_slice(dek_nonce);
        aad.extend_from_slice(encrypted_dek);
        aad
    }

    const SENDER_AAD_BYTES: usize = GROUP_ID_BYTES + size_of::<u64>();
    const PAYLOAD_AAD_BYTES: usize = GROUP_ID_BYTES + size_of::<u64>() + size_of::<u32>() * 3;

    fn build_sender_aad(
        group_id: &[u8],
        epoch: u64,
    ) -> Result<[u8; Self::SENDER_AAD_BYTES], ProtocolError> {
        if group_id.len() != GROUP_ID_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "group_id length must be exactly {GROUP_ID_BYTES} bytes, got {}",
                group_id.len()
            )));
        }
        let mut aad = [0u8; Self::SENDER_AAD_BYTES];
        aad[..GROUP_ID_BYTES].copy_from_slice(group_id);
        let epoch_off = GROUP_ID_BYTES;
        aad[epoch_off..epoch_off + size_of::<u64>()].copy_from_slice(&epoch.to_le_bytes());
        Ok(aad)
    }

    fn build_payload_aad(
        group_id: &[u8],
        epoch: u64,
        leaf_idx: u32,
        generation: u32,
    ) -> Result<[u8; Self::PAYLOAD_AAD_BYTES], ProtocolError> {
        if group_id.len() != GROUP_ID_BYTES {
            return Err(ProtocolError::invalid_input(format!(
                "group_id length must be exactly {GROUP_ID_BYTES} bytes, got {}",
                group_id.len()
            )));
        }
        let mut aad = [0u8; Self::PAYLOAD_AAD_BYTES];
        aad[..GROUP_ID_BYTES].copy_from_slice(group_id);
        let mut off = GROUP_ID_BYTES;
        aad[off..off + size_of::<u64>()].copy_from_slice(&epoch.to_le_bytes());
        off += size_of::<u64>();
        aad[off..off + size_of::<u32>()].copy_from_slice(&leaf_idx.to_le_bytes());
        off += size_of::<u32>();
        aad[off..off + size_of::<u32>()].copy_from_slice(&generation.to_le_bytes());
        off += size_of::<u32>();
        aad[off..off + size_of::<u32>()].copy_from_slice(&GROUP_PROTOCOL_VERSION.to_le_bytes());
        Ok(aad)
    }

    fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
        #[allow(clippy::cast_possible_truncation)]
        let len = bytes.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    fn build_app_signature_input(
        group_id: &[u8],
        epoch: u64,
        app_msg: &GroupApplicationMessage,
    ) -> Vec<u8> {
        const LEN_PREFIX_COUNT: usize = 6;
        let mut input = Vec::with_capacity(
            GROUP_MESSAGE_SIGNATURE_INFO.len()
                + size_of::<u32>()
                + size_of::<u64>()
                + LEN_PREFIX_COUNT * size_of::<u32>()
                + group_id.len()
                + app_msg.encrypted_sender_data.len()
                + app_msg.sender_data_nonce.len()
                + app_msg.encrypted_payload.len()
                + app_msg.payload_nonce.len()
                + app_msg.franking_tag.len(),
        );
        input.extend_from_slice(GROUP_MESSAGE_SIGNATURE_INFO);
        input.extend_from_slice(&GROUP_PROTOCOL_VERSION.to_le_bytes());
        input.extend_from_slice(&epoch.to_le_bytes());
        Self::append_len_prefixed(&mut input, group_id);
        Self::append_len_prefixed(&mut input, &app_msg.encrypted_sender_data);
        Self::append_len_prefixed(&mut input, &app_msg.sender_data_nonce);
        Self::append_len_prefixed(&mut input, &app_msg.encrypted_payload);
        Self::append_len_prefixed(&mut input, &app_msg.payload_nonce);
        Self::append_len_prefixed(&mut input, &app_msg.franking_tag);
        input
    }

    fn ed25519_sign_group_message(
        secret_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
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

    fn ed25519_verify_group_message_with_context(
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
        context: &str,
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
            .map_err(|_| ProtocolError::peer_pub_key("Invalid sender Ed25519 public key"))?;
        let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 signature size"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        vk.verify_strict(message, &sig)
            .map_err(|_| ProtocolError::group_protocol(context))
    }

    fn ed25519_verify_group_message(
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), ProtocolError> {
        Self::ed25519_verify_group_message_with_context(
            public_key,
            signature,
            message,
            "Group sender signature verification failed",
        )
    }

    fn encrypt_internal(
        &self,
        content: &[u8],
        policy: &MessagePolicy,
        actual_plaintext: Option<&[u8]>,
    ) -> Result<Vec<u8>, ProtocolError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        if policy.content_type.is_edit() || policy.content_type.is_delete() {
            if policy.referenced_message_id.len() != MESSAGE_ID_BYTES {
                return Err(ProtocolError::invalid_input(
                    "Edit/Delete requires a 32-byte referenced_message_id",
                ));
            }
        } else if !policy.referenced_message_id.is_empty() {
            return Err(ProtocolError::invalid_input(
                "referenced_message_id must be empty for non-Edit/Delete messages",
            ));
        }

        let franking_override = inner.security_policy.mandatory_franking && !policy.frankable;
        let effective_policy;
        let policy = if franking_override {
            effective_policy = MessagePolicy {
                content_type: policy.content_type,
                ttl_seconds: policy.ttl_seconds,
                frankable: true,
                referenced_message_id: policy.referenced_message_id.clone(),
                mentions: policy.mentions.clone(),
                reply_context: policy.reply_context.as_ref().map(|rc| ReplyContext {
                    reply_to_message_id: rc.reply_to_message_id.clone(),
                    thread_root_id: rc.thread_root_id.clone(),
                    depth: rc.depth,
                }),
            };
            &effective_policy
        } else {
            policy
        };
        let proto_mentions: Vec<ProtoGroupMention> = policy
            .mentions
            .iter()
            .map(|&(leaf_index, offset, length)| ProtoGroupMention {
                leaf_index,
                offset,
                length,
            })
            .collect();
        let proto_reply = policy
            .reply_context
            .as_ref()
            .map(|rc| ProtoGroupReplyContext {
                reply_to_message_id: rc.reply_to_message_id.clone(),
                thread_root_id: rc.thread_root_id.clone(),
                depth: rc.depth,
            });
        validate_annotations_against_tree(
            &inner.tree,
            content,
            &proto_mentions,
            proto_reply.as_ref(),
        )?;

        let my_leaf_idx = inner.my_leaf_idx;

        let policy_max = inner.security_policy.effective_max_messages_per_epoch();
        if let Some(chain) = inner.sender_store.get_chain(my_leaf_idx) {
            if chain.generation() >= policy_max {
                return Err(ProtocolError::group_protocol(
                    "Epoch rotation required: message limit reached by security policy",
                ));
            }
        }

        let (generation, mut message_key) = inner.sender_store.next_own_message_key(my_leaf_idx)?;

        let remaining = policy_max.saturating_sub(generation.saturating_add(1));
        let warning_threshold =
            Self::compute_rotation_threshold(policy_max, SENDER_KEY_EXHAUSTION_WARNING_PERCENT)?;
        if remaining <= warning_threshold {
            if let Some(handler) = &inner.event_handler {
                handler.on_sender_key_exhaustion_warning(remaining, policy_max);
            }
        }

        let (mut group_plaintext, franking_tag) =
            self.build_group_plaintext(content, policy, &message_key, actual_plaintext)?;

        group_plaintext
            .prev_message_hash
            .clone_from(&inner.last_sent_message_hash);

        let mut pt_bytes = Vec::new();
        group_plaintext
            .encode(&mut pt_bytes)
            .map_err(|e| ProtocolError::encode(format!("GroupPlaintext encode: {e}")))?;
        let padded = MessagePadding::pad(&pt_bytes);

        let payload_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);

        let aad =
            Self::build_payload_aad(&inner.group_id, inner.epoch, inner.my_leaf_idx, generation)?;

        let encrypted_payload = AesGcm::encrypt(&message_key, &payload_nonce, &padded, &aad)?;
        CryptoInterop::secure_wipe(&mut message_key);

        {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&encrypted_payload);
            hasher.update(&payload_nonce);
            inner.last_sent_message_hash = hasher.finalize().to_vec();
        }

        let reuse_guard = CryptoInterop::get_random_bytes(REUSE_GUARD_BYTES);
        let sender_data = GroupSenderData {
            sender_leaf_index: inner.my_leaf_idx,
            generation,
            reuse_guard: reuse_guard.clone(),
        };

        let mut sender_data_bytes = Vec::new();
        sender_data
            .encode(&mut sender_data_bytes)
            .map_err(|e| ProtocolError::encode(format!("SenderData encode: {e}")))?;

        let mut sender_data_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        for i in 0..REUSE_GUARD_BYTES {
            sender_data_nonce[i] ^= reuse_guard[i];
        }

        let sender_aad = Self::build_sender_aad(&inner.group_id, inner.epoch)?;

        let encrypted_sender_data = AesGcm::encrypt(
            &inner.epoch_keys.metadata_key,
            &sender_data_nonce,
            &sender_data_bytes,
            &sender_aad,
        )?;

        let mut app_msg = GroupApplicationMessage {
            encrypted_sender_data,
            sender_data_nonce,
            encrypted_payload,
            payload_nonce,
            franking_tag,
            sender_signature: Vec::new(),
        };

        let signature_input =
            Self::build_app_signature_input(&inner.group_id, inner.epoch, &app_msg);
        let mut ed25519_sk = inner
            .my_ed25519_secret
            .read_bytes(ED25519_SECRET_KEY_BYTES)
            .map_err(ProtocolError::from_crypto)?;
        let signature = Self::ed25519_sign_group_message(&ed25519_sk, &signature_input);
        CryptoInterop::secure_wipe(&mut ed25519_sk);
        app_msg.sender_signature = signature?;

        let group_msg = GroupMessage {
            version: GROUP_PROTOCOL_VERSION,
            group_id: inner.group_id.clone(),
            epoch: inner.epoch,
            content: Some(crate::proto::group_message::Content::Application(app_msg)),
        };

        let mut bytes = Vec::new();
        group_msg
            .encode(&mut bytes)
            .map_err(|e| ProtocolError::encode(format!("GroupMessage encode: {e}")))?;
        Ok(bytes)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.encrypt_internal(plaintext, &MessagePolicy::default(), None)
    }

    pub fn encrypt_with_auto_rotate(
        &self,
        plaintext: &[u8],
    ) -> Result<(Option<Vec<u8>>, Vec<u8>), ProtocolError> {
        let rotation_commit = self.rotate_epoch_if_needed()?;
        let ciphertext = self.encrypt(plaintext)?;
        Ok((rotation_commit, ciphertext))
    }

    pub fn encrypt_sealed(&self, plaintext: &[u8], hint: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.encrypt_internal(
            hint,
            &MessagePolicy {
                content_type: ContentType::Sealed,
                ..MessagePolicy::default()
            },
            Some(plaintext),
        )
    }

    pub fn encrypt_disappearing(
        &self,
        plaintext: &[u8],
        ttl_seconds: u32,
    ) -> Result<Vec<u8>, ProtocolError> {
        if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
            return Err(ProtocolError::invalid_input(format!(
                "TTL must be 1..{MAX_TTL_SECONDS}, got {ttl_seconds}"
            )));
        }
        self.encrypt_internal(
            plaintext,
            &MessagePolicy {
                content_type: ContentType::Disappearing,
                ttl_seconds,
                ..MessagePolicy::default()
            },
            None,
        )
    }

    pub fn encrypt_frankable(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.encrypt_internal(
            plaintext,
            &MessagePolicy {
                content_type: ContentType::Normal,
                frankable: true,
                ..MessagePolicy::default()
            },
            None,
        )
    }

    pub fn encrypt_with_policy(
        &self,
        plaintext: &[u8],
        policy: &MessagePolicy,
    ) -> Result<Vec<u8>, ProtocolError> {
        if policy.content_type.is_sealed() {
            self.encrypt_internal(b"", policy, Some(plaintext))
        } else {
            self.encrypt_internal(plaintext, policy, None)
        }
    }

    pub fn encrypt_edit(
        &self,
        new_content: &[u8],
        target_message_id: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        self.encrypt_internal(
            new_content,
            &MessagePolicy {
                content_type: ContentType::Edit,
                referenced_message_id: target_message_id.to_vec(),
                ..MessagePolicy::default()
            },
            None,
        )
    }

    pub fn encrypt_delete(&self, target_message_id: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.encrypt_internal(
            b"",
            &MessagePolicy {
                content_type: ContentType::Delete,
                referenced_message_id: target_message_id.to_vec(),
                ..MessagePolicy::default()
            },
            None,
        )
    }

    pub fn reveal_sealed(sealed: &SealedPayload) -> Result<Vec<u8>, ProtocolError> {
        AesGcm::decrypt(
            &sealed.seal_key,
            &sealed.nonce,
            &sealed.encrypted_content,
            SEALED_AAD_SUFFIX,
        )
    }

    pub fn verify_franking(data: &FrankingData) -> Result<bool, ProtocolError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&data.franking_key)
            .map_err(|e| ProtocolError::franking_failed(format!("HMAC init: {e}")))?;
        mac.update(&data.content);
        if !data.sealed_content.is_empty() {
            mac.update(&data.sealed_content);
        }
        let computed = mac.finalize().into_bytes().to_vec();
        Ok(CryptoInterop::constant_time_equals(
            &computed,
            &data.franking_tag,
        )?)
    }

    pub fn decrypt(&self, message_bytes: &[u8]) -> Result<GroupDecryptResult, ProtocolError> {
        if message_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input(format!(
                "Group message too large: {} bytes (max {})",
                message_bytes.len(),
                MAX_GROUP_MESSAGE_SIZE
            )));
        }
        let group_msg = GroupMessage::decode(message_bytes)
            .map_err(|e| ProtocolError::decode(format!("GroupMessage decode: {e}")))?;

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        if group_msg.group_id != inner.group_id {
            return Err(ProtocolError::group_protocol("Group ID mismatch"));
        }
        if group_msg.epoch != inner.epoch {
            return Err(ProtocolError::group_protocol(format!(
                "Epoch mismatch: expected {}, got {}",
                inner.epoch, group_msg.epoch
            )));
        }

        let Some(crate::proto::group_message::Content::Application(app_msg)) = group_msg.content
        else {
            return Err(ProtocolError::group_protocol(
                "Expected application message",
            ));
        };

        let sender_aad = Self::build_sender_aad(&inner.group_id, inner.epoch)?;

        let sender_data_bytes = AesGcm::decrypt(
            &inner.epoch_keys.metadata_key,
            &app_msg.sender_data_nonce,
            &app_msg.encrypted_sender_data,
            &sender_aad,
        )?;

        let sender_data = GroupSenderData::decode(sender_data_bytes.as_slice())
            .map_err(|e| ProtocolError::decode(format!("SenderData decode: {e}")))?;

        if sender_data.sender_leaf_index == inner.my_leaf_idx {
            return Err(ProtocolError::group_protocol(
                "Cannot decrypt own group message",
            ));
        }

        let sender_leaf = inner
            .tree
            .get_leaf_data(sender_data.sender_leaf_index)
            .ok_or_else(|| {
                ProtocolError::group_protocol(format!(
                    "Unknown sender leaf index {}",
                    sender_data.sender_leaf_index
                ))
            })?;
        let mut app_for_verify = app_msg.clone();
        app_for_verify.sender_signature.clear();
        let signature_input =
            Self::build_app_signature_input(&inner.group_id, inner.epoch, &app_for_verify);
        Self::ed25519_verify_group_message(
            &sender_leaf.identity_ed25519_public,
            &app_msg.sender_signature,
            &signature_input,
        )?;

        let replay_rejected = {
            let replay = inner
                .replay_windows
                .entry(sender_data.sender_leaf_index)
                .or_default();
            replay.is_duplicate_or_too_old(sender_data.generation)
        };
        if replay_rejected {
            return Err(ProtocolError::replay_attack("Duplicate group message"));
        }

        let mut message_key = inner
            .sender_store
            .get_message_key(sender_data.sender_leaf_index, sender_data.generation)?;

        let aad = Self::build_payload_aad(
            &inner.group_id,
            inner.epoch,
            sender_data.sender_leaf_index,
            sender_data.generation,
        )?;

        let padded_plaintext = AesGcm::decrypt(
            &message_key,
            &app_msg.payload_nonce,
            &app_msg.encrypted_payload,
            &aad,
        )?;

        let mut seal_key = {
            let mut z = HkdfSha256::expand(&message_key, GROUP_SEAL_KEY_INFO, SEAL_KEY_BYTES)?;
            std::mem::take(&mut *z)
        };
        CryptoInterop::secure_wipe(&mut message_key);

        let pt_bytes = MessagePadding::unpad(&padded_plaintext)?;
        let group_plaintext = GroupPlaintext::decode(pt_bytes.as_slice())
            .map_err(|e| ProtocolError::decode(format!("GroupPlaintext decode: {e}")))?;
        validate_annotations_against_tree(
            &inner.tree,
            &group_plaintext.content,
            &group_plaintext.mentions,
            group_plaintext.reply_context.as_ref(),
        )?;

        let prev_message_hash = group_plaintext.prev_message_hash.clone();

        let mentions: Vec<(u32, u32, u32)> = group_plaintext
            .mentions
            .iter()
            .map(|m| (m.leaf_index, m.offset, m.length))
            .collect();

        let reply_context = group_plaintext
            .reply_context
            .as_ref()
            .map(|rc| ReplyContext {
                reply_to_message_id: rc.reply_to_message_id.clone(),
                thread_root_id: rc.thread_root_id.clone(),
                depth: rc.depth,
            });

        let (
            plaintext,
            content_type,
            sealed_payload,
            franking_data,
            ttl_seconds,
            sent_timestamp,
            referenced_message_id,
        ) = self.parse_group_plaintext(
            &group_plaintext,
            &seal_key,
            &app_msg.franking_tag,
            inner.security_policy.mandatory_franking,
        )?;

        if sealed_payload.is_none() {
            CryptoInterop::secure_wipe(&mut seal_key);
        }

        inner
            .replay_windows
            .entry(sender_data.sender_leaf_index)
            .or_default()
            .mark_seen(sender_data.generation);

        let message_id = compute_message_id(
            &inner.group_id,
            inner.epoch,
            sender_data.sender_leaf_index,
            sender_data.generation,
        );

        Ok(GroupDecryptResult {
            plaintext,
            sender_leaf_index: sender_data.sender_leaf_index,
            generation: sender_data.generation,
            content_type,
            sealed_payload,
            franking_data,
            ttl_seconds,
            sent_timestamp,
            prev_message_hash,
            message_id,
            referenced_message_id,
            mentions,
            reply_context,
        })
    }

    pub fn encrypt_reaction(
        &self,
        message_id: &[u8],
        emoji: &str,
        remove: bool,
    ) -> Result<Vec<u8>, ProtocolError> {
        let reaction = GroupReaction {
            message_id: message_id.to_vec(),
            emoji: emoji.to_string(),
            remove,
        };
        validate_reaction(&reaction)?;
        let mut content = Vec::new();
        reaction
            .encode(&mut content)
            .map_err(|e| ProtocolError::encode(format!("GroupReaction encode: {e}")))?;
        self.encrypt_with_policy(
            &content,
            &MessagePolicy {
                content_type: ContentType::Reaction,
                ..MessagePolicy::default()
            },
        )
    }

    pub fn encrypt_read_receipt(
        &self,
        message_ids: &[Vec<u8>],
        timestamp: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let receipt = GroupReadReceipt {
            message_ids: message_ids.to_vec(),
            timestamp,
        };
        validate_read_receipt(&receipt)?;
        let mut content = Vec::new();
        receipt
            .encode(&mut content)
            .map_err(|e| ProtocolError::encode(format!("GroupReadReceipt encode: {e}")))?;
        self.encrypt_with_policy(
            &content,
            &MessagePolicy {
                content_type: ContentType::ReadReceipt,
                ..MessagePolicy::default()
            },
        )
    }

    pub fn encrypt_typing(&self, is_typing: bool) -> Result<Vec<u8>, ProtocolError> {
        let indicator = GroupTypingIndicator { is_typing };
        let mut content = Vec::new();
        indicator
            .encode(&mut content)
            .map_err(|e| ProtocolError::encode(format!("GroupTypingIndicator encode: {e}")))?;
        self.encrypt_with_policy(
            &content,
            &MessagePolicy {
                content_type: ContentType::Typing,
                ..MessagePolicy::default()
            },
        )
    }

    pub fn set_member_role(&self, leaf_index: u32, role: i32) -> Result<(), ProtocolError> {
        let _ = (leaf_index, role);
        Err(ProtocolError::invalid_state(
            "member role APIs are disabled because roles are not protocol-authoritative",
        ))
    }

    pub fn get_member_role(&self, leaf_index: u32) -> Result<i32, ProtocolError> {
        let _ = leaf_index;
        Err(ProtocolError::invalid_state(
            "member role APIs are disabled because roles are not protocol-authoritative",
        ))
    }

    pub fn is_admin(&self, leaf_index: u32) -> Result<bool, ProtocolError> {
        let _ = leaf_index;
        Err(ProtocolError::invalid_state(
            "member role APIs are disabled because roles are not protocol-authoritative",
        ))
    }

    pub fn set_event_handler(&self, handler: Arc<dyn IGroupEventHandler>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.event_handler = Some(handler);
        }
    }

    pub fn group_id(&self) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.group_id.clone())
    }

    pub fn epoch(&self) -> Result<u64, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.epoch)
    }

    pub fn my_leaf_index(&self) -> Result<u32, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.my_leaf_idx)
    }

    pub fn member_count(&self) -> Result<u32, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.tree.member_count())
    }

    pub fn member_leaf_indices(&self) -> Result<Vec<u32>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.tree.populated_leaf_indices())
    }

    pub fn my_identity_ed25519_public(&self) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.my_identity_ed25519_public.clone())
    }

    pub fn security_policy(&self) -> Result<GroupSecurityPolicy, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.security_policy.clone())
    }

    pub fn is_shielded(&self) -> Result<bool, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.security_policy.is_shielded())
    }

    pub fn my_identity_x25519_public(&self) -> Result<Vec<u8>, ProtocolError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;
        Ok(inner.my_identity_x25519_public.clone())
    }

    pub fn export_sealed_state(
        &self,
        key: &[u8],
        external_counter: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        if key.len() != AES_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "State encryption key must be 32 bytes",
            ));
        }
        if external_counter == 0 {
            return Err(ProtocolError::invalid_input(
                "External sealed-state counter must be > 0",
            ));
        }

        let inner = self
            .inner
            .lock()
            .map_err(|_| ProtocolError::invalid_state("GroupSession lock poisoned"))?;

        let sender_chains: Vec<GroupMemberSenderChain> = inner
            .sender_store
            .export_chains()
            .into_iter()
            .map(
                |(leaf_index, chain_key, generation)| GroupMemberSenderChain {
                    leaf_index,
                    chain_key,
                    generation,
                },
            )
            .collect();

        let tree_nodes = inner.tree.export_with_private_keys();

        let mut state = GroupProtocolState {
            version: GROUP_PROTOCOL_VERSION,
            group_id: inner.group_id.clone(),
            epoch: inner.epoch,
            my_leaf_index: inner.my_leaf_idx,
            tree_nodes,
            epoch_secret: inner.epoch_keys.epoch_secret.clone(),
            init_secret: inner.init_secret.clone(),
            metadata_key: inner.epoch_keys.metadata_key.clone(),
            confirmation_key: inner.epoch_keys.confirmation_key.clone(),
            welcome_key: inner.epoch_keys.welcome_key.clone(),
            sender_chains,
            my_identity_ed25519_public: inner.my_identity_ed25519_public.clone(),
            my_identity_x25519_public: inner.my_identity_x25519_public.clone(),
            group_context_hash: inner.group_context_hash.clone(),
            seen_message_ids: encode_replay_windows_for_state(&inner.replay_windows),
            state_hmac: vec![],
            state_counter: 0,
            nonce_counter: 0,
            created_at: None,
            security_policy: inner.security_policy.policy_bytes(),
            member_roles: inner.member_roles.iter().map(|(&k, &v)| (k, v)).collect(),
        };

        let mut tmp = Vec::new();
        let enc_hmac_input = state
            .encode(&mut tmp)
            .map_err(|e| ProtocolError::encode(format!("GroupState encode: {e}")));
        if enc_hmac_input.is_err() {
            Self::wipe_group_state_secrets(&mut state);
        }
        enc_hmac_input?;

        let mut hmac_key = {
            let mut z =
                HkdfSha256::expand(key, GROUP_STATE_HMAC_INFO, HMAC_BYTES).inspect_err(|_| {
                    Self::wipe_group_state_secrets(&mut state);
                })?;
            std::mem::take(&mut *z)
        };
        state.state_hmac = Self::compute_group_state_hmac(&hmac_key, &tmp).inspect_err(|_| {
            Self::wipe_group_state_secrets(&mut state);
        })?;
        CryptoInterop::secure_wipe(&mut hmac_key);
        CryptoInterop::secure_wipe(&mut tmp);

        let mut plaintext_state = Vec::new();
        let enc_payload = state
            .encode(&mut plaintext_state)
            .map_err(|e| ProtocolError::encode(format!("GroupState encode: {e}")));
        Self::wipe_group_state_secrets(&mut state);
        enc_payload?;

        drop(inner);

        let mut dek = CryptoInterop::get_random_bytes(AES_KEY_BYTES);
        let dek_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);
        let state_nonce = CryptoInterop::get_random_bytes(AES_GCM_NONCE_BYTES);

        let mut dek_aad = Vec::with_capacity(12);
        dek_aad.extend_from_slice(&GROUP_SEALED_STATE_VERSION.to_le_bytes());
        dek_aad.extend_from_slice(&external_counter.to_le_bytes());
        let encrypted_dek = AesGcm::encrypt(key, &dek_nonce, &dek, &dek_aad).inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut dek);
            CryptoInterop::secure_wipe(&mut plaintext_state);
        })?;

        let state_aad = Self::build_state_aad(&dek_aad, &dek_nonce, &encrypted_dek);

        let encrypted_state = AesGcm::encrypt(&dek, &state_nonce, &plaintext_state, &state_aad)
            .inspect_err(|_e| {
                CryptoInterop::secure_wipe(&mut dek);
                CryptoInterop::secure_wipe(&mut plaintext_state);
            })?;
        CryptoInterop::secure_wipe(&mut dek);
        CryptoInterop::secure_wipe(&mut plaintext_state);

        let sealed = SealedGroupState {
            version: GROUP_SEALED_STATE_VERSION,
            dek_nonce,
            state_nonce,
            encrypted_dek,
            encrypted_state,
            external_counter,
        };

        let mut output = Vec::new();
        sealed
            .encode(&mut output)
            .map_err(|e| ProtocolError::encode(format!("SealedGroupState encode: {e}")))?;
        Ok(output)
    }

    pub fn from_sealed_state(
        sealed_data: &[u8],
        key: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
    ) -> Result<Self, ProtocolError> {
        Self::from_sealed_state_with_time_provider(
            sealed_data,
            key,
            ed25519_secret_raw,
            min_external_counter,
            Arc::new(SystemTimeProvider),
        )
    }

    pub fn from_sealed_state_with_time_provider(
        sealed_data: &[u8],
        key: &[u8],
        ed25519_secret_raw: Zeroizing<Vec<u8>>,
        min_external_counter: u64,
        time_provider: Arc<dyn ITimeProvider>,
    ) -> Result<Self, ProtocolError> {
        if key.len() != AES_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "State encryption key must be 32 bytes",
            ));
        }
        if sealed_data.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Sealed group state too large"));
        }

        let ed25519_secret = ed25519_secret_to_handle(ed25519_secret_raw)?;

        let sealed = SealedGroupState::decode(sealed_data)
            .map_err(|e| ProtocolError::decode(format!("SealedGroupState decode: {e}")))?;
        if sealed.version != GROUP_SEALED_STATE_VERSION {
            return Err(ProtocolError::invalid_input(format!(
                "Unsupported sealed group state version: expected {}, got {}",
                GROUP_SEALED_STATE_VERSION, sealed.version
            )));
        }
        if sealed.dek_nonce.len() != AES_GCM_NONCE_BYTES
            || sealed.state_nonce.len() != AES_GCM_NONCE_BYTES
        {
            return Err(ProtocolError::invalid_input(
                "Invalid nonce size in sealed group state",
            ));
        }
        if sealed.external_counter == 0 {
            return Err(ProtocolError::invalid_input(
                "Sealed group state external counter must be > 0",
            ));
        }
        if sealed.external_counter <= min_external_counter {
            return Err(ProtocolError::invalid_state(
                "Group sealed state rollback detected by external counter",
            ));
        }

        let mut dek_aad = Vec::with_capacity(12);
        dek_aad.extend_from_slice(&sealed.version.to_le_bytes());
        dek_aad.extend_from_slice(&sealed.external_counter.to_le_bytes());
        let mut dek = AesGcm::decrypt(key, &sealed.dek_nonce, &sealed.encrypted_dek, &dek_aad)?;

        let state_aad = Self::build_state_aad(&dek_aad, &sealed.dek_nonce, &sealed.encrypted_dek);

        let mut plaintext_state = AesGcm::decrypt(
            &dek,
            &sealed.state_nonce,
            &sealed.encrypted_state,
            &state_aad,
        )
        .inspect_err(|_e| {
            CryptoInterop::secure_wipe(&mut dek);
        })?;
        CryptoInterop::secure_wipe(&mut dek);

        let mut state = GroupProtocolState::decode(plaintext_state.as_slice()).map_err(|e| {
            CryptoInterop::secure_wipe(&mut plaintext_state);
            ProtocolError::decode(format!("GroupProtocolState decode: {e}"))
        })?;
        CryptoInterop::secure_wipe(&mut plaintext_state);

        let mut hmac_key = {
            let mut z =
                HkdfSha256::expand(key, GROUP_STATE_HMAC_INFO, HMAC_BYTES).inspect_err(|_| {
                    Self::wipe_group_state_secrets(&mut state);
                })?;
            std::mem::take(&mut *z)
        };

        let saved_hmac = std::mem::take(&mut state.state_hmac);
        let mut hmac_buf = Vec::new();
        state.encode(&mut hmac_buf).map_err(|e| {
            Self::wipe_group_state_secrets(&mut state);
            ProtocolError::encode(format!("GroupState encode for HMAC: {e}"))
        })?;
        let expected_hmac =
            Self::compute_group_state_hmac(&hmac_key, &hmac_buf).inspect_err(|_| {
                CryptoInterop::secure_wipe(&mut hmac_key);
                CryptoInterop::secure_wipe(&mut hmac_buf);
                Self::wipe_group_state_secrets(&mut state);
            })?;
        CryptoInterop::secure_wipe(&mut hmac_key);
        CryptoInterop::secure_wipe(&mut hmac_buf);

        let hmac_ok = CryptoInterop::constant_time_equals(&expected_hmac, &saved_hmac)?;
        if !hmac_ok {
            Self::wipe_group_state_secrets(&mut state);
            return Err(ProtocolError::invalid_state(
                "Group state HMAC verification failed — possible rollback attack",
            ));
        }
        state.state_hmac = saved_hmac;
        if state.version != GROUP_PROTOCOL_VERSION {
            Self::wipe_group_state_secrets(&mut state);
            return Err(ProtocolError::invalid_input(format!(
                "Unsupported group protocol state version: expected {}, got {}",
                GROUP_PROTOCOL_VERSION, state.version
            )));
        }
        validate_ed25519_secret_matches_public(&ed25519_secret, &state.my_identity_ed25519_public)
            .inspect_err(|_| {
                Self::wipe_group_state_secrets(&mut state);
            })?;

        let tree =
            RatchetTree::from_proto(&state.tree_nodes, state.my_leaf_index).inspect_err(|_| {
                Self::wipe_group_state_secrets(&mut state);
            })?;
        for tn in &mut state.tree_nodes {
            CryptoInterop::secure_wipe(&mut tn.x25519_private);
            CryptoInterop::secure_wipe(&mut tn.kyber_secret);
        }

        let epoch_keys = EpochKeys {
            epoch_secret: std::mem::take(&mut state.epoch_secret),
            metadata_key: std::mem::take(&mut state.metadata_key),
            welcome_key: std::mem::take(&mut state.welcome_key),
            confirmation_key: std::mem::take(&mut state.confirmation_key),
            init_secret: std::mem::take(&mut state.init_secret),
        };

        let security_policy = GroupSecurityPolicy::from_proto_bytes(&state.security_policy)?;
        security_policy.validate()?;

        let mut chains = std::collections::BTreeMap::new();
        for sc in std::mem::take(&mut state.sender_chains) {
            let chain = SenderKeyChain::from_state_with_policy(
                sc.leaf_index,
                sc.chain_key,
                sc.generation,
                security_policy.enhanced_key_schedule,
                security_policy.effective_max_messages_per_epoch(),
                security_policy.effective_max_skipped_per_sender(),
            )?;
            chains.insert(sc.leaf_index, chain);
        }
        let sender_store =
            SenderKeyStore::from_chains(chains, security_policy.effective_max_skipped_per_sender());

        let replay_windows =
            decode_replay_windows_from_state(std::mem::take(&mut state.seen_message_ids))?;

        let (_ext_priv, ext_x25519_pub, _ext_kyber_sec, ext_kyber_pub) =
            GroupKeySchedule::derive_external_keypairs(&epoch_keys.init_secret)?;

        let init_secret = epoch_keys.init_secret.clone();
        let mut member_roles: std::collections::HashMap<u32, i32> =
            state.member_roles.into_iter().collect();
        let active_leaf_indices = tree.populated_leaf_indices();
        prune_member_roles(&active_leaf_indices, &mut member_roles);

        Ok(Self {
            inner: Mutex::new(GroupSessionInner {
                group_id: std::mem::take(&mut state.group_id),
                epoch: state.epoch,
                my_leaf_idx: state.my_leaf_index,
                tree,
                epoch_keys,
                init_secret,
                sender_store,
                group_context_hash: std::mem::take(&mut state.group_context_hash),
                my_identity_ed25519_public: std::mem::take(&mut state.my_identity_ed25519_public),
                my_identity_x25519_public: std::mem::take(&mut state.my_identity_x25519_public),
                my_ed25519_secret: ed25519_secret,
                replay_windows,
                external_x25519_public: ext_x25519_pub,
                external_kyber_public: ext_kyber_pub,
                psk_resolver: None,
                pending_reinit: None,
                event_handler: None,
                last_sent_message_hash: vec![0u8; SHA256_HASH_BYTES],
                security_policy,
                member_roles,
            }),
            time_provider,
        })
    }

    pub fn sealed_state_external_counter(sealed_data: &[u8]) -> Result<u64, ProtocolError> {
        if sealed_data.len() > MAX_GROUP_MESSAGE_SIZE {
            return Err(ProtocolError::invalid_input("Sealed group state too large"));
        }
        let sealed = SealedGroupState::decode(sealed_data)
            .map_err(|e| ProtocolError::decode(format!("SealedGroupState decode: {e}")))?;
        Ok(sealed.external_counter)
    }

    fn wipe_group_state_secrets(state: &mut GroupProtocolState) {
        CryptoInterop::secure_wipe(&mut state.epoch_secret);
        CryptoInterop::secure_wipe(&mut state.init_secret);
        CryptoInterop::secure_wipe(&mut state.metadata_key);
        CryptoInterop::secure_wipe(&mut state.confirmation_key);
        CryptoInterop::secure_wipe(&mut state.welcome_key);
        CryptoInterop::secure_wipe(&mut state.state_hmac);
        for sc in &mut state.sender_chains {
            CryptoInterop::secure_wipe(&mut sc.chain_key);
        }
        for tn in &mut state.tree_nodes {
            CryptoInterop::secure_wipe(&mut tn.x25519_private);
            CryptoInterop::secure_wipe(&mut tn.kyber_secret);
        }
    }

    fn compute_group_state_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| ProtocolError::group_protocol(format!("HMAC init: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_replay_windows_from_state, encode_replay_windows_for_state, prune_member_roles,
        validate_mentions_for_content, validate_reply_context, SenderReplayWindow,
    };
    use crate::core::constants::MESSAGE_ID_BYTES;
    use crate::proto::{
        GroupMention as ProtoGroupMention, GroupReplyContext as ProtoGroupReplyContext,
    };
    use std::collections::BTreeMap;

    #[test]
    fn replay_window_marks_duplicates_and_old_entries() {
        let mut window = SenderReplayWindow::default();
        assert!(!window.is_duplicate_or_too_old(10));
        window.mark_seen(10);
        assert!(window.is_duplicate_or_too_old(10));
        assert!(!window.is_duplicate_or_too_old(9));
        window.mark_seen(9);
        assert!(window.is_duplicate_or_too_old(9));
        window.mark_seen(3000);
        assert!(window.is_duplicate_or_too_old(10));
    }

    #[test]
    fn replay_windows_roundtrip_in_state_entries() {
        let mut windows = BTreeMap::new();
        let mut window = SenderReplayWindow::default();
        window.mark_seen(42);
        window.mark_seen(41);
        windows.insert(7, window);

        let encoded = encode_replay_windows_for_state(&windows);
        let decoded = decode_replay_windows_from_state(encoded).unwrap();
        let restored = decoded.get(&7).unwrap();
        assert!(restored.is_duplicate_or_too_old(42));
        assert!(restored.is_duplicate_or_too_old(41));
        assert!(!restored.is_duplicate_or_too_old(43));
    }

    #[test]
    fn mention_validation_rejects_zero_length_out_of_bounds_and_overlap() {
        let content = b"hello world";

        let zero_length = vec![ProtoGroupMention {
            leaf_index: 0,
            offset: 0,
            length: 0,
        }];
        assert!(validate_mentions_for_content(&zero_length, content).is_err());

        let out_of_bounds = vec![ProtoGroupMention {
            leaf_index: 0,
            offset: 9,
            length: 3,
        }];
        assert!(validate_mentions_for_content(&out_of_bounds, content).is_err());

        let overlap = vec![
            ProtoGroupMention {
                leaf_index: 0,
                offset: 0,
                length: 5,
            },
            ProtoGroupMention {
                leaf_index: 1,
                offset: 4,
                length: 2,
            },
        ];
        assert!(validate_mentions_for_content(&overlap, content).is_err());
    }

    #[test]
    fn reply_context_requires_thread_root_for_nonzero_depth() {
        let invalid = ProtoGroupReplyContext {
            reply_to_message_id: vec![0xAA; MESSAGE_ID_BYTES],
            thread_root_id: None,
            depth: Some(1),
        };
        assert!(validate_reply_context(&invalid).is_err());

        let valid = ProtoGroupReplyContext {
            reply_to_message_id: vec![0xAA; MESSAGE_ID_BYTES],
            thread_root_id: Some(vec![0xBB; MESSAGE_ID_BYTES]),
            depth: Some(1),
        };
        assert!(validate_reply_context(&valid).is_ok());
    }

    #[test]
    fn prune_member_roles_removes_inactive_and_invalid_entries() {
        let active_leaf_indices = vec![0, 2];
        let mut member_roles = std::collections::HashMap::from([(0, 2), (1, 1), (2, 7)]);

        prune_member_roles(&active_leaf_indices, &mut member_roles);

        assert_eq!(member_roles.len(), 1);
        assert_eq!(member_roles.get(&0), Some(&2));
        assert!(!member_roles.contains_key(&1));
        assert!(!member_roles.contains_key(&2));
    }
}
