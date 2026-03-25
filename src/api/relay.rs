// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::collections::HashSet;
use std::mem::size_of;

use prost::Message;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::proto::e2e::{CryptoEnvelope, CryptoPayloadType};
use crate::proto::{
    GroupApplicationMessage, GroupCommit, GroupKeyPackage, GroupMessage, GroupWelcome, PreKeyBundle,
};
use crate::protocol::group::key_package;
use crate::protocol::handshake::validate_bundle;

#[derive(Debug, Clone)]
pub struct GroupMemberRecord {
    pub leaf_index: u32,
    pub identity_ed25519_public: Vec<u8>,
    pub identity_x25519_public: Vec<u8>,
    pub credential: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GroupRoster {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub members: Vec<GroupMemberRecord>,
}

impl GroupRoster {
    pub fn new(group_id: Vec<u8>, creator: GroupMemberRecord) -> Self {
        Self {
            group_id,
            epoch: 0,
            members: vec![creator],
        }
    }

    pub fn find_member(&self, leaf_index: u32) -> Option<&GroupMemberRecord> {
        self.members.iter().find(|m| m.leaf_index == leaf_index)
    }

    pub fn find_member_by_identity(&self, identity_ed25519: &[u8]) -> Option<&GroupMemberRecord> {
        self.members
            .iter()
            .find(|m| m.identity_ed25519_public == identity_ed25519)
    }

    pub fn leaf_indices(&self) -> Vec<u32> {
        self.members.iter().map(|m| m.leaf_index).collect()
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}

fn validate_commit_for_relay_core(
    commit_bytes: &[u8],
    roster: &GroupRoster,
) -> Result<RelayCommitInfo, ProtocolError> {
    if commit_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("Commit too large"));
    }

    let commit = GroupCommit::decode(commit_bytes)
        .map_err(|e| ProtocolError::decode(format!("Commit decode: {e}")))?;

    if commit.epoch != roster.epoch + 1 {
        return Err(ProtocolError::group_protocol(format!(
            "Commit epoch mismatch: expected {}, got {}",
            roster.epoch + 1,
            commit.epoch
        )));
    }

    if roster.find_member(commit.committer_leaf_index).is_none() {
        return Err(ProtocolError::group_membership(format!(
            "Committer leaf {} is not a group member",
            commit.committer_leaf_index
        )));
    }

    if commit.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol("Commit group_id mismatch"));
    }

    if commit.proposals.len() > MAX_PROPOSALS_PER_COMMIT {
        return Err(ProtocolError::group_protocol(format!(
            "Commit has too many proposals: {} > {}",
            commit.proposals.len(),
            MAX_PROPOSALS_PER_COMMIT
        )));
    }

    if commit.update_path.is_none() {
        return Err(ProtocolError::group_protocol("Commit missing update_path"));
    }

    let committer = roster
        .find_member(commit.committer_leaf_index)
        .ok_or_else(|| {
            ProtocolError::group_membership(format!(
                "Committer leaf {} is not a group member",
                commit.committer_leaf_index
            ))
        })?;
    let mut commit_for_verify = commit.clone();
    let signature = std::mem::take(&mut commit_for_verify.committer_signature);
    let mut commit_bytes_for_verify = Vec::new();
    commit_for_verify
        .encode(&mut commit_bytes_for_verify)
        .map_err(|e| ProtocolError::encode(format!("Commit encode for verify: {e}")))?;
    verify_ed25519_message(
        &committer.identity_ed25519_public,
        &signature,
        &commit_bytes_for_verify,
        "Committer Ed25519 signature verification failed",
    )?;

    let mut added_identities = Vec::new();
    let mut removed_leaves = Vec::new();

    for proposal in &commit.proposals {
        match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::Add(add)) => {
                let kp = add.key_package.as_ref().ok_or_else(|| {
                    ProtocolError::group_membership("Add proposal missing key package")
                })?;
                key_package::validate_key_package(kp)?;
                added_identities.push(kp.identity_ed25519_public.clone());
            }
            Some(crate::proto::group_proposal::Proposal::Remove(remove)) => {
                if roster.find_member(remove.removed_leaf_index).is_none() {
                    return Err(ProtocolError::group_membership(format!(
                        "Remove: leaf {} is not a member",
                        remove.removed_leaf_index
                    )));
                }
                if remove.removed_leaf_index == commit.committer_leaf_index {
                    return Err(ProtocolError::group_membership(
                        "Cannot remove the committer",
                    ));
                }
                removed_leaves.push(remove.removed_leaf_index);
            }
            Some(
                crate::proto::group_proposal::Proposal::Update(_)
                | crate::proto::group_proposal::Proposal::ExternalInit(_)
                | crate::proto::group_proposal::Proposal::Psk(_)
                | crate::proto::group_proposal::Proposal::ReInit(_),
            ) => {}
            None => {
                return Err(ProtocolError::group_membership("Empty proposal"));
            }
        }
    }

    Ok(RelayCommitInfo {
        committer_leaf_index: commit.committer_leaf_index,
        new_epoch: commit.epoch,
        added_identities,
        removed_leaves,
    })
}

fn validate_group_message_for_relay_core(
    message_bytes: &[u8],
    roster: &GroupRoster,
) -> Result<GroupMessage, ProtocolError> {
    if message_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("GroupMessage too large"));
    }

    let msg = GroupMessage::decode(message_bytes)
        .map_err(|e| ProtocolError::decode(format!("GroupMessage decode: {e}")))?;
    if msg.version != GROUP_PROTOCOL_VERSION {
        return Err(ProtocolError::group_protocol(format!(
            "GroupMessage protocol version mismatch: expected {}, got {}",
            GROUP_PROTOCOL_VERSION, msg.version
        )));
    }

    if msg.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol(
            "GroupMessage group_id mismatch",
        ));
    }

    if msg.epoch != roster.epoch {
        return Err(ProtocolError::group_protocol(format!(
            "GroupMessage epoch mismatch: expected {}, got {}",
            roster.epoch, msg.epoch
        )));
    }

    match &msg.content {
        Some(crate::proto::group_message::Content::Application(_)) => Ok(msg),
        _ => Err(ProtocolError::group_protocol(
            "Expected application message content",
        )),
    }
}

pub fn validate_commit_for_relay_strict(
    commit_bytes: &[u8],
    roster: &GroupRoster,
    expected_sender_identity_ed25519: &[u8],
) -> Result<RelayCommitInfo, ProtocolError> {
    let info = validate_commit_for_relay_core(commit_bytes, roster)?;
    let committer = roster
        .find_member(info.committer_leaf_index)
        .ok_or_else(|| {
            ProtocolError::group_membership(format!(
                "Committer leaf {} is not a group member",
                info.committer_leaf_index
            ))
        })?;

    bind_sender_identity(committer, expected_sender_identity_ed25519)?;

    Ok(info)
}

pub fn validate_group_message_for_relay_strict(
    message_bytes: &[u8],
    roster: &GroupRoster,
    sender_leaf_index: u32,
    expected_sender_identity_ed25519: &[u8],
) -> Result<(), ProtocolError> {
    let msg = validate_group_message_for_relay_core(message_bytes, roster)?;
    let Some(crate::proto::group_message::Content::Application(app)) = &msg.content else {
        return Err(ProtocolError::group_protocol(
            "Expected application message content",
        ));
    };

    let sender = roster.find_member(sender_leaf_index).ok_or_else(|| {
        ProtocolError::group_membership(format!(
            "Sender leaf {sender_leaf_index} is not a group member"
        ))
    })?;

    bind_sender_identity(sender, expected_sender_identity_ed25519)?;

    let mut app_for_verify = app.clone();
    let signature = std::mem::take(&mut app_for_verify.sender_signature);
    let signature_input = build_app_signature_input(&msg.group_id, msg.epoch, &app_for_verify);
    verify_ed25519_message(
        &sender.identity_ed25519_public,
        &signature,
        &signature_input,
        "Sender Ed25519 signature verification failed",
    )?;

    Ok(())
}

pub fn validate_key_package_for_storage(
    key_package_bytes: &[u8],
) -> Result<GroupKeyPackage, ProtocolError> {
    if key_package_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("KeyPackage too large"));
    }
    let kp = GroupKeyPackage::decode(key_package_bytes)
        .map_err(|e| ProtocolError::decode(format!("KeyPackage decode: {e}")))?;
    key_package::validate_key_package(&kp)?;
    Ok(kp)
}

pub fn validate_prekey_bundle_for_storage(
    prekey_bundle_bytes: &[u8],
) -> Result<PreKeyBundle, ProtocolError> {
    if prekey_bundle_bytes.len() > MAX_PROTOBUF_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("PreKeyBundle too large"));
    }
    let bundle = PreKeyBundle::decode(prekey_bundle_bytes)
        .map_err(|e| ProtocolError::decode(format!("PreKeyBundle decode: {e}")))?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

#[derive(Debug)]
pub struct RelayCommitInfo {
    pub committer_leaf_index: u32,
    pub new_epoch: u64,
    pub added_identities: Vec<Vec<u8>>,
    pub removed_leaves: Vec<u32>,
}

pub fn commit_recipients(roster: &GroupRoster, committer_leaf_index: u32) -> Vec<u32> {
    roster
        .members
        .iter()
        .filter(|m| m.leaf_index != committer_leaf_index)
        .map(|m| m.leaf_index)
        .collect()
}

pub fn message_recipients(roster: &GroupRoster) -> Vec<u32> {
    roster.leaf_indices()
}

pub fn apply_commit_to_roster(
    roster: &mut GroupRoster,
    info: &RelayCommitInfo,
    added_members: Vec<GroupMemberRecord>,
) -> Result<(), ProtocolError> {
    let Some(expected_epoch) = roster.epoch.checked_add(1) else {
        return Err(ProtocolError::group_protocol("Roster epoch overflow"));
    };
    if info.new_epoch != expected_epoch {
        return Err(ProtocolError::group_protocol(format!(
            "Roster epoch update mismatch: expected {}, got {}",
            expected_epoch, info.new_epoch
        )));
    }

    let mut updated_roster = roster.clone();

    for &leaf_idx in &info.removed_leaves {
        if updated_roster.find_member(leaf_idx).is_none() {
            return Err(ProtocolError::group_membership(format!(
                "Removed leaf {leaf_idx} is not present in roster"
            )));
        }
        updated_roster.members.retain(|m| m.leaf_index != leaf_idx);
    }

    let mut expected_added = info.added_identities.clone();
    let mut seen_leaf_indices = HashSet::new();
    let mut seen_identities = HashSet::new();
    for member in &updated_roster.members {
        seen_leaf_indices.insert(member.leaf_index);
        seen_identities.insert(member.identity_ed25519_public.clone());
    }
    let Some(projected_member_count) = updated_roster
        .members
        .len()
        .checked_add(expected_added.len())
    else {
        return Err(ProtocolError::group_membership(
            "Updated roster member count overflow",
        ));
    };
    if projected_member_count > MAX_GROUP_MEMBERS {
        return Err(ProtocolError::group_membership(format!(
            "Updated roster would exceed max members: {projected_member_count} > {MAX_GROUP_MEMBERS}"
        )));
    }

    for member in added_members {
        if member.identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid Ed25519 key size in added member",
            ));
        }
        if member.identity_x25519_public.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(ProtocolError::invalid_input(
                "Invalid X25519 key size in added member",
            ));
        }
        if member.credential.is_empty() || member.credential.len() > MAX_CREDENTIAL_SIZE {
            return Err(ProtocolError::invalid_input(
                "Invalid credential size in added member",
            ));
        }

        let mut found = false;
        let mut i = 0usize;
        while i < expected_added.len() {
            if expected_added[i] == member.identity_ed25519_public {
                expected_added.swap_remove(i);
                found = true;
                break;
            }
            i += 1;
        }
        if !found {
            return Err(ProtocolError::group_membership(
                "Added member identity not present in commit Add proposals",
            ));
        }

        if !seen_leaf_indices.insert(member.leaf_index) {
            return Err(ProtocolError::group_membership(
                "Duplicate leaf index in updated roster",
            ));
        }
        if !seen_identities.insert(member.identity_ed25519_public.clone()) {
            return Err(ProtocolError::group_membership(
                "Duplicate identity in updated roster",
            ));
        }
        updated_roster.members.push(member);
    }

    if !expected_added.is_empty() {
        return Err(ProtocolError::group_membership(
            "Missing added member records for commit Add proposals",
        ));
    }

    updated_roster.epoch = info.new_epoch;
    *roster = updated_roster;

    Ok(())
}

pub fn extract_welcome_target(welcome_bytes: &[u8]) -> Result<(Vec<u8>, u64, u32), ProtocolError> {
    if welcome_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("Welcome too large"));
    }
    let welcome = GroupWelcome::decode(welcome_bytes)
        .map_err(|e| ProtocolError::decode(format!("Welcome decode: {e}")))?;
    if welcome.group_id.len() != GROUP_ID_BYTES {
        return Err(ProtocolError::invalid_input(
            "Invalid Welcome group_id size",
        ));
    }

    Ok((welcome.group_id, welcome.epoch, welcome.target_leaf_index))
}

fn bind_sender_identity(
    member: &GroupMemberRecord,
    expected_sender_identity_ed25519: &[u8],
) -> Result<(), ProtocolError> {
    if member.identity_ed25519_public != expected_sender_identity_ed25519 {
        return Err(ProtocolError::group_membership(
            "Sender identity does not match roster leaf",
        ));
    }
    Ok(())
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
    append_len_prefixed(&mut input, group_id);
    append_len_prefixed(&mut input, &app_msg.encrypted_sender_data);
    append_len_prefixed(&mut input, &app_msg.sender_data_nonce);
    append_len_prefixed(&mut input, &app_msg.encrypted_payload);
    append_len_prefixed(&mut input, &app_msg.payload_nonce);
    append_len_prefixed(&mut input, &app_msg.franking_tag);
    input
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("length prefix exceeds u32");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn verify_ed25519_message(
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
        .map_err(|_| ProtocolError::group_protocol("Invalid Ed25519 public key"))?;
    let sig_array: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| ProtocolError::invalid_input("Invalid Ed25519 signature size"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    vk.verify_strict(message, &sig)
        .map_err(|_| ProtocolError::group_protocol(context))
}

const MAX_DEVICE_ID_BYTES: usize = 16;
const MAX_CRYPTO_ENVELOPE_SIZE: usize = MAX_GROUP_MESSAGE_SIZE + 256;

pub fn validate_crypto_envelope(envelope_bytes: &[u8]) -> Result<CryptoEnvelope, ProtocolError> {
    if envelope_bytes.len() > MAX_CRYPTO_ENVELOPE_SIZE {
        return Err(ProtocolError::invalid_input("CryptoEnvelope too large"));
    }

    let envelope = CryptoEnvelope::decode(envelope_bytes)
        .map_err(|e| ProtocolError::decode(format!("CryptoEnvelope decode: {e}")))?;

    if envelope.sender_device_id.is_empty() || envelope.sender_device_id.len() > MAX_DEVICE_ID_BYTES
    {
        return Err(ProtocolError::invalid_input(
            "Invalid sender_device_id size",
        ));
    }

    let Ok(payload_type_enum) = CryptoPayloadType::try_from(envelope.payload_type) else {
        return Err(ProtocolError::invalid_input("CryptoPayloadType is unknown"));
    };
    if payload_type_enum == CryptoPayloadType::CryptoPayloadUnspecified {
        return Err(ProtocolError::invalid_input(
            "CryptoPayloadType must be specified",
        ));
    }

    if envelope.encrypted_payload.is_empty() {
        return Err(ProtocolError::invalid_input("encrypted_payload is empty"));
    }

    if envelope.encrypted_payload.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("encrypted_payload too large"));
    }

    let needs_group_id = payload_type_enum == CryptoPayloadType::CryptoPayloadGroupMessage
        || payload_type_enum == CryptoPayloadType::CryptoPayloadGroupCommit;

    if needs_group_id && envelope.group_id.is_empty() {
        return Err(ProtocolError::invalid_input(
            "group_id required for group message/commit",
        ));
    }
    if needs_group_id && envelope.group_id.len() != GROUP_ID_BYTES {
        return Err(ProtocolError::invalid_input("Invalid group_id size"));
    }

    Ok(envelope)
}

pub fn route_crypto_envelope(
    envelope: &CryptoEnvelope,
    roster: &GroupRoster,
) -> Result<Vec<u8>, ProtocolError> {
    if envelope.group_id.is_empty() {
        return Err(ProtocolError::invalid_input(
            "group_id required for routing",
        ));
    }

    if envelope.group_id != roster.group_id {
        return Err(ProtocolError::group_protocol(
            "group_id mismatch with roster",
        ));
    }

    Ok(envelope.group_id.clone())
}

pub fn crypto_envelope_recipients(envelope: &CryptoEnvelope, roster: &GroupRoster) -> Vec<u32> {
    if !envelope.recipient_device_id.is_empty() {
        return vec![];
    }
    roster
        .members
        .iter()
        .filter(|m| m.credential != envelope.sender_device_id)
        .map(|m| m.leaf_index)
        .collect()
}

// ── VoIP relay validation ───────────────────────────────────────────

use crate::proto::{VoipEnvelope, VoipSignalType};

const MAX_VOIP_ENVELOPE_SIZE: usize = 16 * 1024;

pub fn validate_voip_envelope(envelope_bytes: &[u8]) -> Result<VoipEnvelope, ProtocolError> {
    if envelope_bytes.len() > MAX_VOIP_ENVELOPE_SIZE {
        return Err(ProtocolError::voip_call("VoIP envelope too large"));
    }

    let envelope = VoipEnvelope::decode(envelope_bytes)
        .map_err(|e| ProtocolError::decode(format!("VoipEnvelope decode: {e}")))?;

    if envelope.sender_device_id.is_empty() || envelope.sender_device_id.len() > MAX_DEVICE_ID_BYTES
    {
        return Err(ProtocolError::voip_call(
            "invalid sender_device_id in VoIP envelope",
        ));
    }

    if envelope.recipient_device_id.is_empty()
        || envelope.recipient_device_id.len() > MAX_DEVICE_ID_BYTES
    {
        return Err(ProtocolError::voip_call(
            "invalid recipient_device_id in VoIP envelope",
        ));
    }

    let Ok(signal_type) = VoipSignalType::try_from(envelope.signal_type) else {
        return Err(ProtocolError::voip_call("VoipSignalType is unknown"));
    };
    if signal_type == VoipSignalType::VoipSignalUnspecified {
        return Err(ProtocolError::voip_call("VoipSignalType must be specified"));
    }

    if envelope.call_id.len() != CALL_ID_BYTES {
        return Err(ProtocolError::voip_call("invalid call_id in VoIP envelope"));
    }

    if envelope.encrypted_payload.is_empty() {
        return Err(ProtocolError::voip_call(
            "encrypted_payload is empty in VoIP envelope",
        ));
    }

    Ok(envelope)
}

pub fn route_voip_envelope(envelope: &VoipEnvelope) -> Result<Vec<u8>, ProtocolError> {
    if envelope.recipient_device_id.is_empty() {
        return Err(ProtocolError::voip_call(
            "recipient_device_id required for VoIP routing",
        ));
    }
    Ok(envelope.recipient_device_id.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallLifecycleState {
    Initiated,
    Active,
    Rekeying,
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCall {
    pub call_id: Vec<u8>,
    pub caller_device_id: Vec<u8>,
    pub callee_device_id: Vec<u8>,
    pub state: CallLifecycleState,
    pub started_at: u64,
    pub last_activity_at: u64,
    pub rekey_generation: u32,
    pub pending_rekey_from: Option<Vec<u8>>,
}

pub type ManagedCall = ActiveCall;

impl ActiveCall {
    pub const fn new(
        call_id: Vec<u8>,
        caller_device_id: Vec<u8>,
        callee_device_id: Vec<u8>,
        started_at: u64,
    ) -> Self {
        Self {
            call_id,
            caller_device_id,
            callee_device_id,
            state: CallLifecycleState::Initiated,
            started_at,
            last_activity_at: started_at,
            rekey_generation: 0,
            pending_rekey_from: None,
        }
    }

    fn peer_device_id(&self, sender_device_id: &[u8]) -> Option<&[u8]> {
        if sender_device_id == self.caller_device_id {
            Some(&self.callee_device_id)
        } else if sender_device_id == self.callee_device_id {
            Some(&self.caller_device_id)
        } else {
            None
        }
    }

    pub const fn is_expired(&self, server_timestamp: u64) -> bool {
        let session_age = server_timestamp.saturating_sub(self.started_at);
        if session_age > VOIP_CALL_MAX_LIFETIME_SECS {
            return true;
        }

        let idle_age = server_timestamp.saturating_sub(self.last_activity_at);
        match self.state {
            CallLifecycleState::Initiated => idle_age > VOIP_CALL_INIT_TIMEOUT_SECS,
            CallLifecycleState::Active | CallLifecycleState::Rekeying => {
                idle_age > VOIP_CALL_ACTIVE_IDLE_TIMEOUT_SECS
            }
            CallLifecycleState::Ended => true,
        }
    }

    pub const fn touch(&mut self, server_timestamp: u64) {
        self.last_activity_at = server_timestamp;
    }
}

pub trait VoipCallStore: Send + Sync {
    fn register_call(&self, call: &ActiveCall) -> Result<(), ProtocolError>;
    fn find_call(&self, call_id: &[u8]) -> Result<Option<ActiveCall>, ProtocolError>;
    fn update_call(&self, call: &ActiveCall) -> Result<(), ProtocolError>;
    fn remove_call(&self, call_id: &[u8]) -> Result<(), ProtocolError>;

    /// Atomically replace `current` with `next` for a single call lifecycle record.
    ///
    /// Required semantics:
    /// - `(None, Some(call))` inserts `call` only if no record with `call.call_id` exists.
    /// - `(Some(call), Some(next))` updates only if the stored record still equals `call`.
    /// - `(Some(call), None)` removes only if the stored record still equals `call`.
    /// - Return `Ok(false)` on compare-and-swap mismatch without mutating store state.
    fn compare_exchange_call(
        &self,
        current: Option<&ActiveCall>,
        next: Option<&ActiveCall>,
    ) -> Result<bool, ProtocolError>;
}

const MAX_VOIP_CALL_COMPARE_EXCHANGE_RETRIES: usize = 8;

pub fn validate_call_init_for_relay(envelope: &VoipEnvelope) -> Result<(), ProtocolError> {
    if envelope.signal_type != VoipSignalType::VoipSignalCallInit as i32 {
        return Err(ProtocolError::voip_call("expected VOIP_SIGNAL_CALL_INIT"));
    }
    if envelope.sender_device_id == envelope.recipient_device_id {
        return Err(ProtocolError::voip_call(
            "caller and callee device_id must differ",
        ));
    }
    Ok(())
}

pub fn validate_call_signal_for_relay(
    envelope: &VoipEnvelope,
    store: &dyn VoipCallStore,
) -> Result<ActiveCall, ProtocolError> {
    let call = store
        .find_call(&envelope.call_id)?
        .ok_or_else(|| ProtocolError::voip_call("call not found"))?;

    let expected_target = call
        .peer_device_id(&envelope.sender_device_id)
        .ok_or_else(|| ProtocolError::voip_call("sender is not a participant of this call"))?;

    if envelope.recipient_device_id != expected_target {
        return Err(ProtocolError::voip_call(
            "recipient is not the peer participant of this call",
        ));
    }

    Ok(call)
}

pub fn process_voip_signal(
    envelope: &VoipEnvelope,
    store: &dyn VoipCallStore,
    server_timestamp: u64,
) -> Result<VoipRelayAction, ProtocolError> {
    let sig = envelope.signal_type;

    if sig == VoipSignalType::VoipSignalCallInit as i32 {
        validate_call_init_for_relay(envelope)?;
        let new_call = ActiveCall::new(
            envelope.call_id.clone(),
            envelope.sender_device_id.clone(),
            envelope.recipient_device_id.clone(),
            server_timestamp,
        );
        if !store.compare_exchange_call(None, Some(&new_call))? {
            return Err(ProtocolError::voip_call("call_id already exists"));
        }
        return Ok(VoipRelayAction::Forward(
            envelope.recipient_device_id.clone(),
        ));
    }

    for _ in 0..MAX_VOIP_CALL_COMPARE_EXCHANGE_RETRIES {
        let mut call = validate_call_signal_for_relay(envelope, store)?;
        if call.is_expired(server_timestamp) {
            if store.compare_exchange_call(Some(&call), None)? {
                return Err(ProtocolError::voip_call("call expired on relay"));
            }
            continue;
        }

        if sig == VoipSignalType::VoipSignalCallAccept as i32 {
            if envelope.sender_device_id != call.callee_device_id {
                return Err(ProtocolError::voip_call("only callee can accept"));
            }
            if call.state != CallLifecycleState::Initiated {
                return Err(ProtocolError::voip_call(
                    "call accept is only valid for initiated calls",
                ));
            }
            let target = call.caller_device_id.clone();
            let current = call.clone();
            call.state = CallLifecycleState::Active;
            call.pending_rekey_from = None;
            call.touch(server_timestamp);
            if store.compare_exchange_call(Some(&current), Some(&call))? {
                return Ok(VoipRelayAction::Forward(target));
            }
            continue;
        }

        if sig == VoipSignalType::VoipSignalCallReject as i32 {
            if envelope.sender_device_id != call.callee_device_id {
                return Err(ProtocolError::voip_call("only callee can reject"));
            }
            if call.state != CallLifecycleState::Initiated {
                return Err(ProtocolError::voip_call(
                    "call reject is only valid for initiated calls",
                ));
            }
            let target = call.caller_device_id.clone();
            if store.compare_exchange_call(Some(&call), None)? {
                return Ok(VoipRelayAction::ForwardAndRemove(target));
            }
            continue;
        }

        if sig == VoipSignalType::VoipSignalCallEnd as i32 {
            if call.state == CallLifecycleState::Ended {
                return Err(ProtocolError::voip_call("call already ended"));
            }
            let target = if envelope.sender_device_id == call.caller_device_id {
                call.callee_device_id.clone()
            } else {
                call.caller_device_id.clone()
            };
            if store.compare_exchange_call(Some(&call), None)? {
                return Ok(VoipRelayAction::ForwardAndRemove(target));
            }
            continue;
        }

        if sig == VoipSignalType::VoipSignalRekey as i32
            || sig == VoipSignalType::VoipSignalRekeyAck as i32
        {
            let target = if envelope.sender_device_id == call.caller_device_id {
                call.callee_device_id.clone()
            } else {
                call.caller_device_id.clone()
            };

            if sig == VoipSignalType::VoipSignalRekey as i32 {
                if call.state != CallLifecycleState::Active {
                    return Err(ProtocolError::voip_call(
                        "rekey is only valid for active calls",
                    ));
                }
                let current = call.clone();
                call.state = CallLifecycleState::Rekeying;
                call.pending_rekey_from = Some(envelope.sender_device_id.clone());
                call.touch(server_timestamp);
                if store.compare_exchange_call(Some(&current), Some(&call))? {
                    return Ok(VoipRelayAction::Forward(target));
                }
                continue;
            }

            if call.state != CallLifecycleState::Rekeying {
                return Err(ProtocolError::voip_call(
                    "rekey ack is only valid during rekeying",
                ));
            }
            let pending_rekey_from = call.pending_rekey_from.clone().ok_or_else(|| {
                ProtocolError::voip_call("missing pending rekey initiator for rekey ack")
            })?;
            if envelope.sender_device_id == pending_rekey_from {
                return Err(ProtocolError::voip_call(
                    "rekey ack must come from the non-initiating peer",
                ));
            }
            if envelope.recipient_device_id != pending_rekey_from {
                return Err(ProtocolError::voip_call(
                    "rekey ack recipient does not match pending rekey initiator",
                ));
            }
            let current = call.clone();
            call.state = CallLifecycleState::Active;
            call.rekey_generation = call
                .rekey_generation
                .checked_add(1)
                .ok_or_else(|| ProtocolError::voip_call("relay rekey generation overflow"))?;
            call.pending_rekey_from = None;
            call.touch(server_timestamp);
            if store.compare_exchange_call(Some(&current), Some(&call))? {
                return Ok(VoipRelayAction::Forward(target));
            }
            continue;
        }

        if sig == VoipSignalType::VoipSignalCallAccept as i32
            && call.state == CallLifecycleState::Ended
        {
            return Err(ProtocolError::voip_call("cannot accept an ended call"));
        }

        if sig == VoipSignalType::VoipSignalCallReject as i32
            && call.state == CallLifecycleState::Ended
        {
            return Err(ProtocolError::voip_call("cannot reject an ended call"));
        }

        if call.state == CallLifecycleState::Ended {
            return Err(ProtocolError::voip_call("call already ended"));
        }

        return Err(ProtocolError::voip_call("unknown VoIP signal type"));
    }

    Err(ProtocolError::invalid_state(
        "VoIP call state changed concurrently; retry signal",
    ))
}

#[derive(Debug)]
pub enum VoipRelayAction {
    Forward(Vec<u8>),
    ForwardAndRemove(Vec<u8>),
}

impl VoipRelayAction {
    pub fn target_device_id(&self) -> &[u8] {
        match self {
            Self::Forward(t) | Self::ForwardAndRemove(t) => t,
        }
    }

    pub const fn removes_call(&self) -> bool {
        matches!(self, Self::ForwardAndRemove(_))
    }
}

pub trait PendingEventStore: Send + Sync {
    fn store_event(
        &self,
        device_id: &[u8],
        event_id: &str,
        server_timestamp: u64,
        envelope_bytes: &[u8],
    ) -> Result<(), ProtocolError>;

    fn fetch_events(
        &self,
        device_id: &[u8],
        after_event_id: &str,
        max_events: u32,
    ) -> Result<Vec<StoredPendingEvent>, ProtocolError>;

    fn ack_events(&self, device_id: &[u8], event_ids: &[String]) -> Result<u64, ProtocolError>;
}

#[derive(Debug, Clone)]
pub struct StoredPendingEvent {
    pub event_id: String,
    pub server_timestamp: u64,
    pub envelope_bytes: Vec<u8>,
}
