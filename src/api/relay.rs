// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use prost::Message;

use crate::core::constants::*;
use crate::core::errors::ProtocolError;
use crate::proto::e2e::{CryptoEnvelope, CryptoPayloadType};
use crate::proto::{GroupCommit, GroupKeyPackage, GroupMessage, GroupWelcome};
use crate::protocol::group::key_package;

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

pub fn validate_commit_for_relay(
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

    if commit.update_path.is_none() {
        return Err(ProtocolError::group_protocol("Commit missing update_path"));
    }

    let mut added_identities = Vec::new();
    let mut removed_leaves = Vec::new();

    for proposal in &commit.proposals {
        match &proposal.proposal {
            Some(crate::proto::group_proposal::Proposal::Add(add)) => {
                let kp = add.key_package.as_ref().ok_or_else(|| {
                    ProtocolError::group_membership("Add proposal missing key package")
                })?;
                if kp.identity_ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES {
                    return Err(ProtocolError::invalid_input(
                        "Invalid Ed25519 key size in Add",
                    ));
                }
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

pub fn validate_group_message_for_relay(
    message_bytes: &[u8],
    roster: &GroupRoster,
) -> Result<(), ProtocolError> {
    if message_bytes.len() > MAX_GROUP_MESSAGE_SIZE {
        return Err(ProtocolError::invalid_input("GroupMessage too large"));
    }

    let msg = GroupMessage::decode(message_bytes)
        .map_err(|e| ProtocolError::decode(format!("GroupMessage decode: {e}")))?;

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
        Some(crate::proto::group_message::Content::Application(_)) => Ok(()),
        _ => Err(ProtocolError::group_protocol(
            "Expected application message content",
        )),
    }
}

pub fn validate_key_package_for_storage(
    key_package_bytes: &[u8],
) -> Result<GroupKeyPackage, ProtocolError> {
    let kp = GroupKeyPackage::decode(key_package_bytes)
        .map_err(|e| ProtocolError::decode(format!("KeyPackage decode: {e}")))?;
    key_package::validate_key_package(&kp)?;
    Ok(kp)
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
    for &leaf_idx in &info.removed_leaves {
        roster.members.retain(|m| m.leaf_index != leaf_idx);
    }

    for member in added_members {
        roster.members.push(member);
    }

    roster.epoch = info.new_epoch;

    Ok(())
}

pub fn extract_welcome_target(welcome_bytes: &[u8]) -> Result<(Vec<u8>, u64, u32), ProtocolError> {
    let welcome = GroupWelcome::decode(welcome_bytes)
        .map_err(|e| ProtocolError::decode(format!("Welcome decode: {e}")))?;

    Ok((welcome.group_id, welcome.epoch, welcome.target_leaf_index))
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

    if envelope.payload_type == CryptoPayloadType::CryptoPayloadUnspecified as i32 {
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

    let payload_type = envelope.payload_type;
    let needs_group_id = payload_type == CryptoPayloadType::CryptoPayloadGroupMessage as i32
        || payload_type == CryptoPayloadType::CryptoPayloadGroupCommit as i32;

    if needs_group_id && envelope.group_id.is_empty() {
        return Err(ProtocolError::invalid_input(
            "group_id required for group message/commit",
        ));
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

    if envelope.signal_type == VoipSignalType::VoipSignalUnspecified as i32 {
        return Err(ProtocolError::voip_call("VoipSignalType must be specified"));
    }

    if envelope.call_id.is_empty() || envelope.call_id.len() > 64 {
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

#[derive(Debug, Clone)]
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
}

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
        if store.find_call(&envelope.call_id)?.is_some() {
            return Err(ProtocolError::voip_call("call_id already exists"));
        }

        let new_call = ActiveCall::new(
            envelope.call_id.clone(),
            envelope.sender_device_id.clone(),
            envelope.recipient_device_id.clone(),
            server_timestamp,
        );
        store.register_call(&new_call)?;
        return Ok(VoipRelayAction::Forward(
            envelope.recipient_device_id.clone(),
        ));
    }

    let mut call = validate_call_signal_for_relay(envelope, store)?;
    if call.is_expired(server_timestamp) {
        store.remove_call(&call.call_id)?;
        return Err(ProtocolError::voip_call("call expired on relay"));
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
        call.state = CallLifecycleState::Active;
        call.pending_rekey_from = None;
        call.touch(server_timestamp);
        store.update_call(&call)?;
        return Ok(VoipRelayAction::Forward(call.caller_device_id));
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
        store.remove_call(&call.call_id)?;
        return Ok(VoipRelayAction::ForwardAndRemove(call.caller_device_id));
    }

    if sig == VoipSignalType::VoipSignalCallEnd as i32 {
        if call.state == CallLifecycleState::Ended {
            return Err(ProtocolError::voip_call("call already ended"));
        }
        call.state = CallLifecycleState::Ended;
        store.remove_call(&call.call_id)?;
        let target = if envelope.sender_device_id == call.caller_device_id {
            call.callee_device_id
        } else {
            call.caller_device_id
        };
        return Ok(VoipRelayAction::ForwardAndRemove(target));
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
            call.state = CallLifecycleState::Rekeying;
            call.pending_rekey_from = Some(envelope.sender_device_id.clone());
            call.touch(server_timestamp);
            store.update_call(&call)?;
            return Ok(VoipRelayAction::Forward(target));
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
        call.state = CallLifecycleState::Active;
        call.rekey_generation = call
            .rekey_generation
            .checked_add(1)
            .ok_or_else(|| ProtocolError::voip_call("relay rekey generation overflow"))?;
        call.pending_rekey_from = None;
        call.touch(server_timestamp);
        store.update_call(&call)?;
        return Ok(VoipRelayAction::Forward(target));
    }

    if sig == VoipSignalType::VoipSignalCallAccept as i32 && call.state == CallLifecycleState::Ended
    {
        return Err(ProtocolError::voip_call("cannot accept an ended call"));
    }

    if sig == VoipSignalType::VoipSignalCallReject as i32 && call.state == CallLifecycleState::Ended
    {
        return Err(ProtocolError::voip_call("cannot reject an ended call"));
    }

    if call.state == CallLifecycleState::Ended {
        return Err(ProtocolError::voip_call("call already ended"));
    }

    Err(ProtocolError::voip_call("unknown VoIP signal type"))
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
