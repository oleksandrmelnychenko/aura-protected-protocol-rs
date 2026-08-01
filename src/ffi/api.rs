// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(
    clippy::borrow_as_ptr,
    clippy::manual_let_else,
    clippy::missing_safety_doc,
    clippy::single_match_else,
    clippy::too_many_arguments,
    unsafe_code
)]
// # FFI Safety Contract
//
// All `pub unsafe extern "C"` functions in this module share these preconditions:
//   - `out_error` (when present) must be either null or point to a valid `AuraError`.
//   - `out_buf` / `out_*` output pointers must be either null or point to writable memory.
//   - `handle` pointers must originate from the corresponding `_create` / `_start` function.
//   - `(data, length)` pairs must form valid, readable slices (or `data` must be null when
//     `length == 0`).
//   - Handle pointers passed to `_destroy` must not be used after the call.
//
// All functions use `ffi_catch_panic!` to convert Rust panics into error codes, preventing
// unwinding across the FFI boundary.

use prost::Message;
use std::ffi::CString;
use std::mem::size_of;
use std::os::raw::{c_char, c_void};
use std::sync::{Arc, Mutex};

use crate::api::{SealedStateCounterTracker, SealedStateSlot};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

use crate::core::constants::{
    AES_GCM_NONCE_BYTES, AES_GCM_TAG_BYTES, AES_KEY_BYTES, ATTACHMENT_FILE_KEY_BYTES,
    ATTACHMENT_HASH_BYTES, ATTACHMENT_ID_BYTES, ATTACHMENT_PROTOCOL_VERSION, CALL_ID_BYTES,
    DEFAULT_ONE_TIME_KEY_COUNT, DEVICE_ID_BYTES, ED25519_PUBLIC_KEY_BYTES, HMAC_BYTES,
    KYBER_PUBLIC_KEY_BYTES, MAX_ATTACHMENT_CHUNK_SIZE, MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE,
    MAX_ATTACHMENT_FILENAME_BYTES, MAX_ATTACHMENT_MANIFEST_SIZE, MAX_ATTACHMENT_THUMBNAIL_SIZE,
    MAX_BUFFER_SIZE, MAX_COLLAGE_ATTACHMENTS, MAX_COLLAGE_DESCRIPTION_CHARS,
    MAX_COLLAGE_MANIFEST_SIZE, MAX_COLLAGE_NAME_CHARS, MAX_CONTACT_AVATAR_DATA_SIZE,
    MAX_CONTACT_DISPLAY_NAME_CHARS, MAX_CONTACT_EMAIL_CHARS, MAX_CONTACT_ORGANIZATION_CHARS,
    MAX_CONTACT_PHONE_CHARS, MAX_ENVELOPE_MESSAGE_SIZE, MAX_GROUP_MESSAGE_SIZE,
    MAX_HANDSHAKE_MESSAGE_SIZE, MAX_INLINE_ATTACHMENT_DATA_SIZE,
    MAX_LINK_PREVIEW_DESCRIPTION_CHARS, MAX_LINK_PREVIEW_DOMAIN_CHARS, MAX_LINK_PREVIEW_IMAGE_SIZE,
    MAX_LINK_PREVIEW_TITLE_CHARS, MAX_LINK_PREVIEW_URL_CHARS, MAX_LOCATION_LABEL_CHARS,
    MAX_VOICE_TRANSCRIPT_CHARS, MAX_VOICE_WAVEFORM_SAMPLES, MAX_VOIP_ENCRYPTED_HEADER_SIZE,
    MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE, MAX_VOIP_SIGNAL_MESSAGE_SIZE, MESSAGE_ID_BYTES,
    PROTOCOL_VERSION, PSK_BYTES, ROOT_KEY_BYTES, X25519_PUBLIC_KEY_BYTES,
};
use crate::core::errors::ProtocolError;
use crate::crypto::SecureMemoryHandle;
use crate::crypto::{CryptoInterop, KyberInterop};
use crate::identity::IdentityKeys;
use crate::interfaces::{
    IGroupEventHandler, IIdentityEventHandler, IProtocolEventHandler, ITimeProvider,
    SystemTimeProvider,
};
use crate::proto::{
    AttachmentManifest, AttachmentReference, CallMediaType, ChunkProgress, CollageManifest,
    ContactCard, ContentPolicy, InlineAttachment, LinkPreview, LocationAttachment, OneTimePreKey,
    PreKeyBundle, ScreenShareMetadata, SecureEnvelope, SessionMetadataResponse, VoiceMessageMeta,
};
use crate::protocol::attachment::{StreamingDecryptor, StreamingEncryptor};
use crate::protocol::group::{
    GroupDecryptResult, GroupSecurityPolicy, GroupSecurityTier, GroupSession,
};
use crate::protocol::{HandshakeInitiator, HandshakeResponder, Session};

/// Upper bound for message-ID count accepted via FFI (prevents overflow in
/// `message_id_count * MESSAGE_ID_BYTES` and limits total allocation size).
const MAX_READ_RECEIPT_IDS_FFI: usize = 10_000;

/// RAII guard that resets an `AtomicBool` busy-flag on drop.
struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Try to acquire the busy-flag on a handle.  Returns `Ok(BusyGuard)` on
/// success or `Err(())` if the handle is already in use by another call.
fn try_acquire_busy(flag: &AtomicBool) -> Result<BusyGuard<'_>, ()> {
    if flag
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        Ok(BusyGuard(flag))
    } else {
        Err(())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuraErrorCode {
    AuraSuccess = 0,
    AuraErrorGeneric = 1,
    AuraErrorInvalidInput = 2,
    AuraErrorKeyGeneration = 3,
    AuraErrorDeriveKey = 4,
    AuraErrorHandshake = 5,
    AuraErrorEncryption = 6,
    AuraErrorDecryption = 7,
    AuraErrorDecode = 8,
    AuraErrorEncode = 9,
    AuraErrorBufferTooSmall = 10,
    AuraErrorObjectDisposed = 11,
    AuraErrorPrepareLocal = 12,
    AuraErrorOutOfMemory = 13,
    AuraErrorCryptoFailure = 14,
    AuraErrorNullPointer = 15,
    AuraErrorInvalidState = 16,
    AuraErrorReplayAttack = 17,
    AuraErrorSessionExpired = 18,
    AuraErrorPqMissing = 19,
    AuraErrorGroupProtocol = 20,
    AuraErrorGroupMembership = 21,
    AuraErrorTreeIntegrity = 22,
    AuraErrorWelcome = 23,
    AuraErrorMessageExpired = 24,
    AuraErrorFranking = 25,
    AuraErrorVoipCall = 26,
    AuraErrorVoipMedia = 27,
    AuraErrorVoipRekey = 28,
    AuraErrorBusy = 29,
}

#[repr(C)]
pub struct AuraBuffer {
    pub data: *mut u8,
    pub length: usize,
}

#[repr(C)]
pub struct AuraError {
    pub code: AuraErrorCode,
    pub message: *mut c_char,
}

#[repr(C)]
pub struct AuraSessionConfig {
    pub max_messages_per_chain: u32,
}

#[repr(C)]
pub enum AuraEnvelopeType {
    AuraEnvelopeRequest = 0,
    AuraEnvelopeResponse = 1,
    AuraEnvelopeNotification = 2,
    AuraEnvelopeHeartbeat = 3,
    AuraEnvelopeErrorResponse = 4,
}

pub struct AuraIdentityState {
    pub keys: IdentityKeys,
    pub time_provider: Arc<dyn ITimeProvider>,
}

struct ManualTimeProvider {
    now_unix: Mutex<u64>,
}

impl ITimeProvider for ManualTimeProvider {
    fn now_unix_secs(&self) -> Result<u64, ProtocolError> {
        self.now_unix
            .lock()
            .map(|guard| *guard)
            .map_err(|_| ProtocolError::invalid_state("manual time provider mutex poisoned"))
    }
}

enum AuraTimeProvider {
    Manual(Arc<ManualTimeProvider>),
}

impl AuraTimeProvider {
    fn as_trait_arc(&self) -> Arc<dyn ITimeProvider> {
        match self {
            Self::Manual(provider) => provider.clone(),
        }
    }
}

fn default_time_provider() -> Arc<dyn ITimeProvider> {
    Arc::new(SystemTimeProvider)
}

pub struct AuraIdentityHandle {
    pub inner: Option<AuraIdentityState>,
    pub in_use: AtomicBool,
}
pub struct AuraTimeProviderHandle(Option<AuraTimeProvider>);
pub struct AuraSessionHandle {
    pub inner: Option<Session>,
    pub in_use: AtomicBool,
}
pub struct AuraHandshakeInitiatorHandle(pub Option<HandshakeInitiator>);
pub struct AuraHandshakeResponderHandle(pub Option<HandshakeResponder>);
pub struct AuraGroupSessionHandle {
    pub inner: Option<GroupSession>,
    pub in_use: AtomicBool,
}
pub struct AuraSealedStateCounterTrackerHandle(pub Option<SealedStateCounterTracker>);
pub struct AuraSealedStateSlotHandle(pub Option<SealedStateSlot>);

pub struct AuraVoipSessionHandle {
    pub inner: Option<crate::protocol::voip::VoipSession>,
    pub in_use: AtomicBool,
}

pub struct AuraStreamingEncryptorHandle {
    pub inner: Option<StreamingEncryptor>,
    pub in_use: AtomicBool,
}

pub struct AuraStreamingDecryptorHandle {
    pub inner: Option<StreamingDecryptor>,
    pub in_use: AtomicBool,
}

#[repr(C)]
pub struct AuraEncryptedFrame {
    pub call_id: AuraBuffer,
    pub ssrc: u32,
    pub frame_counter: u64,
    pub ratchet_generation: u32,
    pub encrypted_payload: AuraBuffer,
    pub nonce: AuraBuffer,
    pub encrypted_header: AuraBuffer,
}

#[repr(C)]
pub struct AuraDecryptedFrame {
    pub payload: AuraBuffer,
    pub payload_type: u8,
    pub ssrc: u32,
    pub timestamp: u32,
    pub sequence_number: u16,
    pub frame_counter: u64,
    pub ratchet_generation: u32,
}

/// Releases all FFI-owned sub-buffers of an [`AuraEncryptedFrame`] (zeroizing
/// their contents) before zeroing scalar fields.  Must be used when a caller
/// reuses the same frame across multiple FFI calls, otherwise prior
/// allocations would leak unzeroed on the heap.
unsafe fn clear_encrypted_frame(frame: *mut AuraEncryptedFrame) {
    if frame.is_null() {
        return;
    }
    aura_buffer_release(std::ptr::addr_of_mut!((*frame).call_id));
    aura_buffer_release(std::ptr::addr_of_mut!((*frame).encrypted_payload));
    aura_buffer_release(std::ptr::addr_of_mut!((*frame).nonce));
    aura_buffer_release(std::ptr::addr_of_mut!((*frame).encrypted_header));
    (*frame).ssrc = 0;
    (*frame).frame_counter = 0;
    (*frame).ratchet_generation = 0;
}

/// Releases the FFI-owned plaintext payload of an [`AuraDecryptedFrame`]
/// (zeroizing it) before zeroing scalar fields.  Required before reuse so the
/// decrypted media payload is wiped rather than leaked.
unsafe fn clear_decrypted_frame(frame: *mut AuraDecryptedFrame) {
    if frame.is_null() {
        return;
    }
    aura_buffer_release(std::ptr::addr_of_mut!((*frame).payload));
    (*frame).payload_type = 0;
    (*frame).ssrc = 0;
    (*frame).timestamp = 0;
    (*frame).sequence_number = 0;
    (*frame).frame_counter = 0;
    (*frame).ratchet_generation = 0;
}

pub struct AuraKeyPackageSecretsHandle {
    pub x25519_private: SecureMemoryHandle,
    pub kyber_secret: SecureMemoryHandle,
}

#[repr(C)]
pub struct AuraGroupSecurityPolicy {
    pub max_messages_per_epoch: u32,
    pub max_skipped_keys_per_sender: u32,
    pub block_external_join: u8,
    pub enhanced_key_schedule: u8,
    pub mandatory_franking: u8,
}

/// Versioned security-tier identifiers returned by
/// [`aura_group_get_security_tier`].
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuraGroupSecurityTier {
    AuraGroupSecurityTierCustom = 0,
    AuraGroupSecurityTierStandard = 1,
    AuraGroupSecurityTierShieldV1 = 2,
}

impl From<GroupSecurityTier> for AuraGroupSecurityTier {
    fn from(value: GroupSecurityTier) -> Self {
        match value {
            GroupSecurityTier::Custom => Self::AuraGroupSecurityTierCustom,
            GroupSecurityTier::Standard => Self::AuraGroupSecurityTierStandard,
            GroupSecurityTier::ShieldV1 => Self::AuraGroupSecurityTierShieldV1,
        }
    }
}

/// Catches Rust panics at the FFI boundary and converts them to error codes.
///
/// **Limitation (MEM-005):** After catching a panic the handle's inner `Option`
/// is *not* automatically poisoned (set to `None`), because this macro does not
/// have access to the handle pointer.  Callers that resume using the same handle
/// after a panic-triggered error will be caught by the state-machine checks in
/// `require_session_mut`, `require_group_mut`, etc., which return
/// `AuraErrorObjectDisposed` when the inner value is inconsistent.  A future
/// refactor may add per-handle poison flags for stronger safety guarantees.
macro_rules! ffi_catch_panic {
    ($out_error:expr, $body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => {
                unsafe {
                    write_error(
                        $out_error,
                        AuraErrorCode::AuraErrorGeneric,
                        "Internal panic caught at FFI boundary",
                    );
                }
                AuraErrorCode::AuraErrorGeneric
            }
        }
    };
}

macro_rules! ffi_catch_panic_value {
    ($default:expr, $body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => $default,
        }
    };
}

/// Invokes a C callback function pointer inside `catch_unwind` so that any
/// panic triggered by the caller's code (e.g. Swift/ObjC shim re-entering
/// Rust with an invalid argument) is contained instead of unwinding across
/// the `extern "C"` boundary — which is undefined behavior with the default
/// `panic = unwind` profile.
///
/// The callback's return value (if any) is ignored because these handlers
/// are fire-and-forget event notifications.
macro_rules! invoke_c_callback {
    ($body:expr) => {{
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { $body }));
    }};
}

const fn error_code_from_protocol(e: &ProtocolError) -> AuraErrorCode {
    match e {
        ProtocolError::Generic(_) => AuraErrorCode::AuraErrorGeneric,
        ProtocolError::KeyGeneration(_) => AuraErrorCode::AuraErrorKeyGeneration,
        ProtocolError::DeriveKey(_) => AuraErrorCode::AuraErrorDeriveKey,
        ProtocolError::InvalidInput(_) | ProtocolError::PeerPubKey(_) => {
            AuraErrorCode::AuraErrorInvalidInput
        }
        ProtocolError::PrepareLocal(_) => AuraErrorCode::AuraErrorPrepareLocal,
        ProtocolError::Handshake(_) => AuraErrorCode::AuraErrorHandshake,
        ProtocolError::Decode(_) => AuraErrorCode::AuraErrorDecode,
        ProtocolError::Encode(_) => AuraErrorCode::AuraErrorEncode,
        ProtocolError::BufferTooSmall(_) => AuraErrorCode::AuraErrorBufferTooSmall,
        ProtocolError::ObjectDisposed => AuraErrorCode::AuraErrorObjectDisposed,
        ProtocolError::ReplayAttack(_) => AuraErrorCode::AuraErrorReplayAttack,
        ProtocolError::InvalidState(_) => AuraErrorCode::AuraErrorInvalidState,
        ProtocolError::NullPointer => AuraErrorCode::AuraErrorNullPointer,
        ProtocolError::Crypto(_) => AuraErrorCode::AuraErrorCryptoFailure,
        ProtocolError::GroupProtocol(_) => AuraErrorCode::AuraErrorGroupProtocol,
        ProtocolError::GroupMembership(_) => AuraErrorCode::AuraErrorGroupMembership,
        ProtocolError::TreeIntegrity(_) => AuraErrorCode::AuraErrorTreeIntegrity,
        ProtocolError::WelcomeError(_) => AuraErrorCode::AuraErrorWelcome,
        ProtocolError::MessageExpired(_) => AuraErrorCode::AuraErrorMessageExpired,
        ProtocolError::FrankingFailed(_) => AuraErrorCode::AuraErrorFranking,
        ProtocolError::VoipCall(_) => AuraErrorCode::AuraErrorVoipCall,
        ProtocolError::VoipMedia(_) => AuraErrorCode::AuraErrorVoipMedia,
        ProtocolError::VoipRekey(_) => AuraErrorCode::AuraErrorVoipRekey,
    }
}

/// # Safety
/// `out_error` must be null or point to a valid, writable `AuraError`.  If `(*out_error).message`
/// is non-null it must have been allocated by `CString::into_raw`.
unsafe fn write_error(out_error: *mut AuraError, code: AuraErrorCode, msg: &str) {
    if out_error.is_null() {
        return;
    }
    if !(*out_error).message.is_null() {
        drop(CString::from_raw((*out_error).message));
        (*out_error).message = std::ptr::null_mut();
    }
    let c_msg = CString::new(msg).unwrap_or_else(|_| c"error".to_owned());
    (*out_error).code = code;
    (*out_error).message = c_msg.into_raw();
}

/// # Safety
/// Same preconditions as [`write_error`].
unsafe fn write_protocol_error(out_error: *mut AuraError, e: &ProtocolError) -> AuraErrorCode {
    let code = error_code_from_protocol(e);
    write_error(out_error, code, &e.to_string());
    code
}

const fn max_utf8_bytes(max_chars: usize) -> usize {
    max_chars.saturating_mul(4)
}

/// # Safety
/// Same preconditions as [`write_error`].
unsafe fn ensure_ffi_len_at_most(
    out_error: *mut AuraError,
    length: usize,
    max: usize,
    label: &str,
) -> Result<(), AuraErrorCode> {
    if length > max {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorInvalidInput,
            &format!("{label} length exceeds maximum"),
        );
        return Err(AuraErrorCode::AuraErrorInvalidInput);
    }
    Ok(())
}

/// # Safety
/// Same preconditions as [`write_error`].
unsafe fn ensure_ffi_len_exact(
    out_error: *mut AuraError,
    length: usize,
    expected: usize,
    label: &str,
) -> Result<(), AuraErrorCode> {
    if length != expected {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorInvalidInput,
            &format!("{label} length is invalid"),
        );
        return Err(AuraErrorCode::AuraErrorInvalidInput);
    }
    Ok(())
}

/// # Safety
/// `out` must be null or point to a valid, writable `AuraBuffer`.
/// The previous contents of `out` are not read or released because callers may
/// pass uninitialized storage.
unsafe fn write_buffer(out: *mut AuraBuffer, bytes: Vec<u8>) {
    if out.is_null() {
        return;
    }
    if bytes.is_empty() {
        (*out).data = std::ptr::null_mut();
        (*out).length = 0;
        return;
    }
    let len = bytes.len();
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    (*out).data = Box::into_raw(boxed).cast::<u8>();
    (*out).length = len;
}

/// # Safety
/// `out` must be null or point to a valid writable `*mut T`. `new_handle` must
/// be a heap allocation previously created by `Box::into_raw` for `T`, or null.
/// The previous value in `out` is not read or destroyed because callers may
/// pass uninitialized storage.
unsafe fn replace_out_handle<T>(out: *mut *mut T, new_handle: *mut T) {
    if out.is_null() {
        if !new_handle.is_null() {
            drop(Box::from_raw(new_handle));
        }
        return;
    }
    *out = new_handle;
}

/// # Safety
/// `handle` must be null or point to a live `AuraIdentityHandle` created by `aura_identity_create*`.
///
/// Acquires the handle's busy-flag; the returned [`BusyGuard`] releases it on
/// drop, preventing concurrent access from multiple FFI calls (which would
/// otherwise race on `IdentityKeys` internals including `SecureMemoryHandle`
/// entries and event-handler `Arc`s).
unsafe fn require_identity_ref<'a>(
    handle: *const AuraIdentityHandle,
    out_error: *mut AuraError,
) -> Result<(BusyGuard<'a>, &'a IdentityKeys), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "identity handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    let keys = (*handle)
        .inner
        .as_ref()
        .map(|state| &state.keys)
        .ok_or_else(|| {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already destroyed",
            );
            AuraErrorCode::AuraErrorObjectDisposed
        })?;
    Ok((guard, keys))
}

unsafe fn require_counter_tracker_mut<'a>(
    handle: *mut AuraSealedStateCounterTrackerHandle,
    out_error: *mut AuraError,
) -> Result<&'a mut SealedStateCounterTracker, AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "counter tracker handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    (*handle).0.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorObjectDisposed,
            "counter tracker handle already destroyed",
        );
        AuraErrorCode::AuraErrorObjectDisposed
    })
}

unsafe fn require_sealed_state_slot_mut<'a>(
    handle: *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> Result<&'a mut SealedStateSlot, AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "sealed-state slot handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    (*handle).0.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorObjectDisposed,
            "sealed-state slot handle already destroyed",
        );
        AuraErrorCode::AuraErrorObjectDisposed
    })
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `AuraIdentityHandle`.
///
/// Acquires the handle's busy-flag; the returned [`BusyGuard`] releases it on
/// drop, preventing concurrent access from multiple FFI calls.
unsafe fn require_identity_mut<'a>(
    handle: *mut AuraIdentityHandle,
    out_error: *mut AuraError,
) -> Result<(BusyGuard<'a>, &'a mut IdentityKeys), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "identity handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    let keys = (*handle)
        .inner
        .as_mut()
        .map(|state| &mut state.keys)
        .ok_or_else(|| {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already destroyed",
            );
            AuraErrorCode::AuraErrorObjectDisposed
        })?;
    Ok((guard, keys))
}

/// # Safety
/// `handle` must be null or point to a live `AuraIdentityHandle`.
///
/// Acquires the handle's busy-flag for the duration of the brief read; the
/// guard is released before returning because the cloned `Arc` does not
/// borrow from the handle.
unsafe fn clone_identity_time_provider(
    handle: *const AuraIdentityHandle,
    out_error: *mut AuraError,
) -> Result<Arc<dyn ITimeProvider>, AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let _guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "identity handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    (*handle)
        .inner
        .as_ref()
        .map(|state| state.time_provider.clone())
        .ok_or_else(|| {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already destroyed",
            );
            AuraErrorCode::AuraErrorObjectDisposed
        })
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `AuraIdentityHandle`.
///
/// Acquires and releases the handle's busy-flag internally.
unsafe fn replace_identity_time_provider(
    handle: *mut AuraIdentityHandle,
    time_provider: Arc<dyn ITimeProvider>,
    out_error: *mut AuraError,
) -> Result<(), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let _guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "identity handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    match (*handle).inner.as_mut() {
        Some(state) => {
            state.time_provider = time_provider;
            Ok(())
        }
        None => {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already destroyed",
            );
            Err(AuraErrorCode::AuraErrorObjectDisposed)
        }
    }
}

/// # Safety
/// `handle` must be null or point to a live `AuraTimeProviderHandle`. A null
/// handle means "use the default system clock".
unsafe fn clone_time_provider_or_default(
    handle: *const AuraTimeProviderHandle,
    out_error: *mut AuraError,
) -> Result<Arc<dyn ITimeProvider>, AuraErrorCode> {
    if handle.is_null() {
        return Ok(default_time_provider());
    }
    (*handle)
        .0
        .as_ref()
        .map(AuraTimeProvider::as_trait_arc)
        .ok_or_else(|| {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "time provider handle already destroyed",
            );
            AuraErrorCode::AuraErrorObjectDisposed
        })
}

/// # Safety
/// `handle` must be null or point to a live `AuraTimeProviderHandle`.
unsafe fn require_manual_time_provider<'a>(
    handle: *mut AuraTimeProviderHandle,
    out_error: *mut AuraError,
) -> Result<&'a Arc<ManualTimeProvider>, AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "time provider handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    match (*handle).0.as_ref() {
        Some(AuraTimeProvider::Manual(provider)) => Ok(provider),
        None => {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "time provider handle already destroyed",
            );
            Err(AuraErrorCode::AuraErrorObjectDisposed)
        }
    }
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `AuraSessionHandle`.
///
/// Acquires the handle's busy-flag; the returned [`BusyGuard`] releases it on
/// drop, preventing concurrent access from multiple FFI calls.
unsafe fn require_session_mut<'a>(
    handle: *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> Result<(BusyGuard<'a>, &'a mut Session), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "session handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    let inner = (*handle).inner.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorObjectDisposed,
            "handle already destroyed",
        );
        AuraErrorCode::AuraErrorObjectDisposed
    })?;
    Ok((guard, inner))
}

/// # Safety
/// `handle` must be null or point to a live, exclusively-owned `AuraGroupSessionHandle`.
///
/// Acquires the handle's busy-flag; the returned [`BusyGuard`] releases it on
/// drop, preventing concurrent access from multiple FFI calls.
unsafe fn require_group_mut<'a>(
    handle: *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> Result<(BusyGuard<'a>, &'a mut GroupSession), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "handle is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "group session handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    let inner = (*handle).inner.as_mut().ok_or_else(|| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorObjectDisposed,
            "handle already destroyed",
        );
        AuraErrorCode::AuraErrorObjectDisposed
    })?;
    Ok((guard, inner))
}

/// # Safety
/// `handle` must be null or point to a live `AuraGroupSessionHandle`.
const unsafe fn group_ref_or_none<'a>(
    handle: *const AuraGroupSessionHandle,
) -> Option<&'a GroupSession> {
    if handle.is_null() {
        return None;
    }
    (*handle).inner.as_ref()
}

#[no_mangle]
pub extern "C" fn aura_version() -> *const c_char {
    static VERSION: &[u8] = b"2.0.0\0";
    VERSION.as_ptr().cast::<c_char>()
}

#[no_mangle]
pub extern "C" fn aura_init() -> AuraErrorCode {
    ffi_catch_panic_value!(AuraErrorCode::AuraErrorCryptoFailure, {
        let _ = CryptoInterop::initialize();
        KyberInterop::install_rng();
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub const extern "C" fn aura_shutdown() {}

/// # Safety
/// See module-level FFI safety contract.  `out_handle` must point to writable `*mut AuraIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_create(
    out_handle: *mut *mut AuraIdentityHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        match IdentityKeys::create(DEFAULT_ONE_TIME_KEY_COUNT) {
            Ok(keys) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraIdentityHandle {
                        inner: Some(AuraIdentityState {
                            keys,
                            time_provider: default_time_provider(),
                        }),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(seed, seed_length)` must form a valid readable slice.
/// `out_handle` must point to writable `*mut AuraIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_create_from_seed(
    seed: *const u8,
    seed_length: usize,
    out_handle: *mut *mut AuraIdentityHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if seed.is_null() || seed_length == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "seed is null or empty",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if seed_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "input too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let seed_slice = std::slice::from_raw_parts(seed, seed_length);
        match IdentityKeys::create_from_master_key(
            seed_slice,
            crate::core::constants::DEFAULT_MEMBERSHIP_ID,
            DEFAULT_ONE_TIME_KEY_COUNT,
        ) {
            Ok(keys) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraIdentityHandle {
                        inner: Some(AuraIdentityState {
                            keys,
                            time_provider: default_time_provider(),
                        }),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(seed, seed_length)` and `(membership_id, membership_id_length)`
/// must form valid readable slices.  `out_handle` must point to writable `*mut AuraIdentityHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_create_with_context(
    seed: *const u8,
    seed_length: usize,
    membership_id: *const c_char,
    membership_id_length: usize,
    out_handle: *mut *mut AuraIdentityHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if seed.is_null() || seed_length == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "seed is null or empty",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if seed_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "input too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if membership_id.is_null() || membership_id_length == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "membership_id is null or empty",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if membership_id_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "input too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let seed_slice = std::slice::from_raw_parts(seed, seed_length);
        let mid_bytes =
            std::slice::from_raw_parts(membership_id.cast::<u8>(), membership_id_length);
        let Ok(mid_str) = std::str::from_utf8(mid_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "membership_id is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };

        match IdentityKeys::create_from_master_key(seed_slice, mid_str, DEFAULT_ONE_TIME_KEY_COUNT)
        {
            Ok(keys) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraIdentityHandle {
                        inner: Some(AuraIdentityState {
                            keys,
                            time_provider: default_time_provider(),
                        }),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `out_handle` must point to writable
/// `*mut AuraTimeProviderHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_time_provider_manual_create(
    initial_now_unix: u64,
    out_handle: *mut *mut AuraTimeProviderHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let provider = AuraTimeProvider::Manual(Arc::new(ManualTimeProvider {
            now_unix: Mutex::new(initial_now_unix),
        }));
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraTimeProviderHandle(Some(provider)))),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_time_provider_manual_set_now_unix(
    handle: *mut AuraTimeProviderHandle,
    now_unix: u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        let provider = match require_manual_time_provider(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match provider.now_unix.lock() {
            Ok(mut guard) => {
                if now_unix < *guard {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "manual time provider: clock must not go backwards",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                }
                *guard = now_unix;
                AuraErrorCode::AuraSuccess
            }
            Err(_) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidState,
                    "manual time provider mutex poisoned",
                );
                AuraErrorCode::AuraErrorInvalidState
            }
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. Passing NULL as `time_provider_handle`
/// resets the identity to the default system clock.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_set_time_provider(
    handle: *mut AuraIdentityHandle,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match replace_identity_time_provider(handle, time_provider, out_error) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(code) => code,
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_get_x25519_public(
    handle: *const AuraIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if out_key_length < X25519_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorBufferTooSmall,
                "Buffer too small for X25519 public key",
            );
            return AuraErrorCode::AuraErrorBufferTooSmall;
        }
        let (_identity_guard, identity) = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_identity_x25519_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_get_ed25519_public(
    handle: *const AuraIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if out_key_length < ED25519_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorBufferTooSmall,
                "Buffer too small for Ed25519 public key",
            );
            return AuraErrorCode::AuraErrorBufferTooSmall;
        }
        let (_identity_guard, identity) = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_identity_ed25519_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_get_kyber_public(
    handle: *const AuraIdentityHandle,
    out_key: *mut u8,
    out_key_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if out_key_length < KYBER_PUBLIC_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorBufferTooSmall,
                "Buffer too small for Kyber public key",
            );
            return AuraErrorCode::AuraErrorBufferTooSmall;
        }
        let (_identity_guard, identity) = match require_identity_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pk = identity.get_kyber_public();
        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_key, pk.len());
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from `aura_identity_create`,
/// or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_identity_destroy(handle_ptr: *mut *mut AuraIdentityHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract. `handle_ptr` must point to a handle
/// from `aura_time_provider_manual_create`, or be null.
#[no_mangle]
pub unsafe extern "C" fn aura_time_provider_destroy(handle_ptr: *mut *mut AuraTimeProviderHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_prekey_bundle_create(
    identity_keys: *const AuraIdentityHandle,
    out_bundle: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_bundle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_bundle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_identity_guard, identity) = match require_identity_ref(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };

        let bundle = match identity.create_public_bundle() {
            Ok(b) => b,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let opks: Vec<OneTimePreKey> = bundle
            .one_time_pre_keys()
            .iter()
            .map(|opk| OneTimePreKey {
                one_time_pre_key_id: opk.id(),
                public_key: opk.public_key_vec(),
            })
            .collect();

        let proto_bundle = PreKeyBundle {
            version: PROTOCOL_VERSION,
            identity_ed25519_public: bundle.identity_ed25519_public().to_vec(),
            identity_x25519_public: bundle.identity_x25519_public().to_vec(),
            identity_x25519_signature: bundle.identity_x25519_signature().to_vec(),
            signed_pre_key_id: bundle.signed_pre_key_id(),
            signed_pre_key_public: bundle.signed_pre_key_public().to_vec(),
            signed_pre_key_signature: bundle.signed_pre_key_signature().to_vec(),
            one_time_pre_keys: opks,
            kyber_public: bundle.kyber_public().unwrap_or(&[]).to_vec(),
        };

        let mut buf = Vec::new();
        if let Err(e) = proto_bundle.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("Failed to encode PreKeyBundle: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }

        write_buffer(out_bundle, buf);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(peer_prekey_bundle, peer_prekey_bundle_length)` must form
/// a valid readable slice.  `out_handle` must point to writable `*mut AuraHandshakeInitiatorHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_initiator_start(
    identity_keys: *mut AuraIdentityHandle,
    peer_prekey_bundle: *const u8,
    peer_prekey_bundle_length: usize,
    config: *const AuraSessionConfig,
    out_handle: *mut *mut AuraHandshakeInitiatorHandle,
    out_handshake_init: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if peer_prekey_bundle.is_null() || out_handle.is_null() || out_handshake_init.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if peer_prekey_bundle_length > MAX_HANDSHAKE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "peer_prekey_bundle too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let bundle_bytes =
            std::slice::from_raw_parts(peer_prekey_bundle, peer_prekey_bundle_length);
        let peer_bundle = match PreKeyBundle::decode(bundle_bytes) {
            Ok(b) => b,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("Failed to decode PreKeyBundle: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        let max_msgs = if config.is_null() {
            #[allow(clippy::cast_possible_truncation)]
            {
                crate::core::constants::DEFAULT_MESSAGES_PER_CHAIN as u32
            }
        } else {
            (*config).max_messages_per_chain
        };

        let time_provider = match clone_identity_time_provider(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, ik) = match require_identity_mut(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match HandshakeInitiator::start_with_time_provider(
            ik,
            &peer_bundle,
            max_msgs,
            time_provider,
        ) {
            Ok(initiator) => {
                write_buffer(out_handshake_init, initiator.encoded_message().to_vec());
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraHandshakeInitiatorHandle(Some(initiator)))),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(handshake_ack, handshake_ack_length)` must form a valid
/// readable slice.  `out_session` must point to writable `*mut AuraSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_initiator_finish(
    handle: *mut AuraHandshakeInitiatorHandle,
    handshake_ack: *const u8,
    handshake_ack_length: usize,
    out_session: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if handshake_ack.is_null() || out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if handshake_ack_length > MAX_HANDSHAKE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "handshake_ack too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let handle_ref = &mut *handle;
        let Some(initiator) = handle_ref.0.take() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already consumed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        let ack_bytes = std::slice::from_raw_parts(handshake_ack, handshake_ack_length);
        match initiator.finish(ack_bytes) {
            Ok(session) => {
                replace_out_handle(
                    out_session,
                    Box::into_raw(Box::new(AuraSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `aura_handshake_initiator_start`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_initiator_destroy(
    handle_ptr: *mut *mut AuraHandshakeInitiatorHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(local_prekey_bundle, local_prekey_bundle_length)` and
/// `(handshake_init, handshake_init_length)` must form valid readable slices.
/// `out_handle` must point to writable `*mut AuraHandshakeResponderHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_responder_start(
    identity_keys: *mut AuraIdentityHandle,
    local_prekey_bundle: *const u8,
    local_prekey_bundle_length: usize,
    handshake_init: *const u8,
    handshake_init_length: usize,
    config: *const AuraSessionConfig,
    out_handle: *mut *mut AuraHandshakeResponderHandle,
    out_handshake_ack: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if local_prekey_bundle.is_null()
            || handshake_init.is_null()
            || out_handle.is_null()
            || out_handshake_ack.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if local_prekey_bundle_length > MAX_HANDSHAKE_MESSAGE_SIZE
            || handshake_init_length > MAX_HANDSHAKE_MESSAGE_SIZE
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Message too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let bundle_bytes =
            std::slice::from_raw_parts(local_prekey_bundle, local_prekey_bundle_length);
        let local_bundle = match PreKeyBundle::decode(bundle_bytes) {
            Ok(b) => b,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("Failed to decode local PreKeyBundle: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        let init_bytes = std::slice::from_raw_parts(handshake_init, handshake_init_length);
        let max_msgs = if config.is_null() {
            #[allow(clippy::cast_possible_truncation)]
            {
                crate::core::constants::DEFAULT_MESSAGES_PER_CHAIN as u32
            }
        } else {
            (*config).max_messages_per_chain
        };

        let time_provider = match clone_identity_time_provider(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, ik) = match require_identity_mut(identity_keys, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match HandshakeResponder::process_with_replay_guard_and_time_provider(
            ik,
            &local_bundle,
            init_bytes,
            max_msgs,
            None,
            time_provider,
        ) {
            Ok(responder) => {
                write_buffer(out_handshake_ack, responder.encoded_ack().to_vec());
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraHandshakeResponderHandle(Some(responder)))),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `out_session` must point to writable `*mut AuraSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_responder_finish(
    handle: *mut AuraHandshakeResponderHandle,
    out_session: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let handle_ref = &mut *handle;
        let Some(responder) = handle_ref.0.take() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "handle already consumed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        match responder.finish() {
            Ok(session) => {
                replace_out_handle(
                    out_session,
                    Box::into_raw(Box::new(AuraSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `aura_handshake_responder_start`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_handshake_responder_destroy(
    handle_ptr: *mut *mut AuraHandshakeResponderHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` and
/// `(correlation_id, correlation_id_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_session_encrypt(
    handle: *mut AuraSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    envelope_type: AuraEnvelopeType,
    envelope_id: u32,
    correlation_id: *const c_char,
    correlation_id_length: usize,
    out_encrypted_envelope: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_encrypted_envelope.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let payload = std::slice::from_raw_parts(plaintext, plaintext_length);

        if correlation_id_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "correlation_id too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let corr_id: Option<&str> = if !correlation_id.is_null() && correlation_id_length > 0 {
            let bytes =
                std::slice::from_raw_parts(correlation_id.cast::<u8>(), correlation_id_length);
            if let Ok(s) = std::str::from_utf8(bytes) {
                Some(s)
            } else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "correlation_id is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            }
        } else {
            None
        };

        let env_type_i32 = envelope_type as i32;

        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let envelope = match session.encrypt(payload, env_type_i32, envelope_id, corr_id) {
            Ok(e) => e,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut buf = Vec::new();
        if let Err(e) = envelope.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("Failed to encode SecureEnvelope: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }

        write_buffer(out_encrypted_envelope, buf);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(encrypted_envelope, encrypted_envelope_length)` must
/// form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_session_decrypt(
    handle: *mut AuraSessionHandle,
    encrypted_envelope: *const u8,
    encrypted_envelope_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_metadata: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_envelope.is_null() || out_plaintext.is_null() || out_metadata.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if encrypted_envelope_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Envelope too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };

        let env_bytes = std::slice::from_raw_parts(encrypted_envelope, encrypted_envelope_length);
        let envelope = match SecureEnvelope::decode(env_bytes) {
            Ok(e) => e,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("Failed to decode SecureEnvelope: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };
        let result = match session.decrypt(&envelope) {
            Ok(r) => r,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut meta_buf = Vec::new();
        if let Err(e) = result.metadata.encode(&mut meta_buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("Failed to encode EnvelopeMetadata: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }

        write_buffer(out_plaintext, result.plaintext);
        write_buffer(out_metadata, meta_buf);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_session_nonce_remaining(
    handle: *mut AuraSessionHandle,
    out_remaining: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_remaining.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_remaining is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.nonce_remaining() {
            Ok(remaining) => {
                std::ptr::write(out_remaining, remaining);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `aura_handshake_*_finish`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_session_destroy(handle_ptr: *mut *mut AuraSessionHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// See module-level FFI safety contract.  `(encrypted_envelope, encrypted_envelope_length)` must
/// form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_envelope_validate(
    encrypted_envelope: *const u8,
    encrypted_envelope_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_envelope.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "encrypted_envelope is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if encrypted_envelope_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Envelope exceeds maximum allowed size",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let bytes = std::slice::from_raw_parts(encrypted_envelope, encrypted_envelope_length);
        match crate::api::AuraProtocol::validate_envelope(bytes) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(opaque_session_key, opaque_session_key_length)` and
/// `(user_context, user_context_length)` must form valid readable slices.
/// `(out_root_key, out_root_key_length)` must form a valid writable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_derive_root_key(
    opaque_session_key: *const u8,
    opaque_session_key_length: usize,
    user_context: *const u8,
    user_context_length: usize,
    out_root_key: *mut u8,
    out_root_key_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if opaque_session_key.is_null() || user_context.is_null() || out_root_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if out_root_key_length < ROOT_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorBufferTooSmall,
                "Output buffer too small for derived root key",
            );
            return AuraErrorCode::AuraErrorBufferTooSmall;
        }
        if opaque_session_key_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "opaque_session_key too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if user_context_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "user_context too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let ikm = std::slice::from_raw_parts(opaque_session_key, opaque_session_key_length);
        let ctx = std::slice::from_raw_parts(user_context, user_context_length);

        match crate::api::AuraProtocol::derive_root_key(ikm, ctx, out_root_key_length) {
            Ok(key) => {
                std::ptr::copy_nonoverlapping(key.as_ptr(), out_root_key, key.len());
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(secret, secret_length)` and `(auth_key, auth_key_length)`
/// must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_shamir_split(
    secret: *const u8,
    secret_length: usize,
    threshold: u8,
    share_count: u8,
    auth_key: *const u8,
    auth_key_length: usize,
    out_shares: *mut AuraBuffer,
    out_share_length: *mut usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if secret.is_null() || out_shares.is_null() || out_share_length.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if secret_length == 0 || secret_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Secret length invalid",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        if auth_key.is_null() || auth_key_length != HMAC_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "auth_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let secret_slice = std::slice::from_raw_parts(secret, secret_length);
        let auth_key_slice = std::slice::from_raw_parts(auth_key, auth_key_length);

        let shares = match crate::api::AuraProtocol::shamir_split(
            secret_slice,
            threshold,
            share_count,
            auth_key_slice,
        ) {
            Ok(s) => s,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let data_share_count = shares.len().saturating_sub(1);
        if data_share_count == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                "No shares generated",
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let data_share_len = shares[0].len();

        let Some(auth_tag) = shares.last() else {
            write_error(out_error, AuraErrorCode::AuraErrorGeneric, "Empty shares");
            return AuraErrorCode::AuraErrorGeneric;
        };
        let Some(total_len) =
            data_share_count.checked_mul(data_share_len.saturating_add(auth_tag.len()))
        else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Share size overflow",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let mut flat = Vec::with_capacity(total_len);
        for ds in &shares[..data_share_count] {
            flat.extend_from_slice(ds);
            flat.extend_from_slice(auth_tag);
        }
        *out_share_length = data_share_len + auth_tag.len();
        write_buffer(out_shares, flat);

        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(shares, shares_length)` and `(auth_key, auth_key_length)`
/// must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_shamir_reconstruct(
    shares: *const u8,
    shares_length: usize,
    share_length: usize,
    share_count: usize,
    auth_key: *const u8,
    auth_key_length: usize,
    out_secret: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if shares.is_null() || out_secret.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "shares or out_secret is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if share_length == 0 || share_count == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "share_length and share_count must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        if auth_key.is_null() || auth_key_length != HMAC_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "auth_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let expected_len = share_count.saturating_mul(share_length);
        if shares_length != expected_len {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "shares_length must equal share_count * share_length",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if share_length <= HMAC_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "share_length must be larger than the embedded auth tag",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let flat_slice = std::slice::from_raw_parts(shares, shares_length);
        let auth_key_slice = std::slice::from_raw_parts(auth_key, auth_key_length);
        let data_share_len = share_length - HMAC_BYTES;

        let mut auth_tag: Option<Vec<u8>> = None;
        let mut all_shares: Vec<Vec<u8>> = Vec::with_capacity(share_count + 1);
        for i in 0..share_count {
            let start = i * share_length;
            let data_end = start + data_share_len;
            let end = start + share_length;
            let share = flat_slice[start..data_end].to_vec();
            let share_tag = flat_slice[data_end..end].to_vec();
            if let Some(existing) = &auth_tag {
                if existing != &share_tag {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "All Shamir shares must carry the same auth tag",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                }
            } else {
                auth_tag = Some(share_tag);
            }
            all_shares.push(share);
        }
        if let Some(tag) = auth_tag {
            all_shares.push(tag);
        } else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Missing embedded auth tag",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        match crate::api::AuraProtocol::shamir_reconstruct(&all_shares, auth_key_slice, share_count)
        {
            Ok(secret) => {
                write_buffer(out_secret, secret);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_generate_id(
    out_attachment_id: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_attachment_id.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_attachment_id is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        write_buffer(
            out_attachment_id,
            crate::protocol::attachment::generate_attachment_id(),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_generate_file_key(
    out_file_key: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_file_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_file_key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        write_buffer(
            out_file_key,
            crate::protocol::attachment::generate_file_key(),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_encrypt_chunk(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const c_char,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_index: u32,
    chunk_count: u32,
    plaintext: *const u8,
    plaintext_length: usize,
    out_nonce: *mut AuraBuffer,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || mime_type.is_null()
            || plaintext.is_null()
            || out_nonce.is_null()
            || out_ciphertext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if file_key_length != ATTACHMENT_FILE_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment file_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment ID must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if plaintext_length == 0 || plaintext_length > MAX_ATTACHMENT_CHUNK_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment plaintext chunk size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let file_key_slice = std::slice::from_raw_parts(file_key, file_key_length);
        let attachment_id_slice = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_slice = std::slice::from_raw_parts(mime_type.cast::<u8>(), mime_type_length);
        let Ok(mime_type) = std::str::from_utf8(mime_slice) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "mime_type must be valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let plaintext_slice = std::slice::from_raw_parts(plaintext, plaintext_length);

        match crate::protocol::attachment::encrypt_chunk(
            file_key_slice,
            attachment_id_slice,
            mime_type,
            total_size,
            chunk_size,
            chunk_index,
            chunk_count,
            plaintext_slice,
        ) {
            Ok((nonce, ciphertext)) => {
                write_buffer(out_nonce, nonce);
                write_buffer(out_ciphertext, ciphertext);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_decrypt_chunk(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const c_char,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_index: u32,
    chunk_count: u32,
    nonce: *const u8,
    nonce_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || mime_type.is_null()
            || nonce.is_null()
            || ciphertext.is_null()
            || out_plaintext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if file_key_length != ATTACHMENT_FILE_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment file_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment ID must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if nonce_length != AES_GCM_NONCE_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment nonce must be 12 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if ciphertext_length == 0 || ciphertext_length > MAX_ATTACHMENT_CHUNK_SIZE + 16 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment ciphertext chunk size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let file_key_slice = std::slice::from_raw_parts(file_key, file_key_length);
        let attachment_id_slice = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_slice = std::slice::from_raw_parts(mime_type.cast::<u8>(), mime_type_length);
        let Ok(mime_type) = std::str::from_utf8(mime_slice) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "mime_type must be valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let nonce_slice = std::slice::from_raw_parts(nonce, nonce_length);
        let ciphertext_slice = std::slice::from_raw_parts(ciphertext, ciphertext_length);

        match crate::protocol::attachment::decrypt_chunk(
            file_key_slice,
            attachment_id_slice,
            mime_type,
            total_size,
            chunk_size,
            chunk_index,
            chunk_count,
            nonce_slice,
            ciphertext_slice,
        ) {
            Ok(plaintext) => {
                write_buffer(out_plaintext, plaintext);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_manifest_create(
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const c_char,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    file_sha256: *const u8,
    file_sha256_length: usize,
    encrypted_file_key: *const u8,
    encrypted_file_key_length: usize,
    out_manifest: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if attachment_id.is_null()
            || mime_type.is_null()
            || file_sha256.is_null()
            || encrypted_file_key.is_null()
            || out_manifest.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES
            || file_sha256_length != ATTACHMENT_HASH_BYTES
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment ID and file_sha256 must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if encrypted_file_key_length == 0
            || encrypted_file_key_length > MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "encrypted_file_key size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let attachment_id_slice = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_slice = std::slice::from_raw_parts(mime_type.cast::<u8>(), mime_type_length);
        let Ok(mime_type_str) = std::str::from_utf8(mime_slice) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "mime_type must be valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let mime_type = mime_type_str.to_owned();
        let file_sha256_slice = std::slice::from_raw_parts(file_sha256, file_sha256_length);
        let encrypted_file_key_slice =
            std::slice::from_raw_parts(encrypted_file_key, encrypted_file_key_length);

        let manifest = AttachmentManifest {
            version: ATTACHMENT_PROTOCOL_VERSION,
            attachment_id: attachment_id_slice.to_vec(),
            mime_type,
            total_size,
            chunk_size,
            chunk_count,
            file_sha256: file_sha256_slice.to_vec(),
            encrypted_file_key: encrypted_file_key_slice.to_vec(),
            encryption_scheme: "AES-256-GCM-SIV".to_owned(),
            collage_index: None,
            encrypted_thumbnail: None,
            thumbnail_nonce: None,
            thumbnail_mime_type: None,
            thumbnail_size: None,
            ttl_seconds: None,
            created_at_unix: None,
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };
        if let Err(e) = crate::protocol::attachment::validate_manifest(&manifest) {
            return write_protocol_error(out_error, &e);
        }
        let mut bytes = Vec::new();
        if let Err(e) = manifest.encode(&mut bytes) {
            return write_protocol_error(
                out_error,
                &ProtocolError::encode(format!("AttachmentManifest encode: {e}")),
            );
        }
        write_buffer(out_manifest, bytes);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_manifest_validate(
    manifest_bytes: *const u8,
    manifest_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if manifest_bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "manifest_bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if manifest_length == 0 || manifest_length > MAX_ATTACHMENT_MANIFEST_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment manifest size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let bytes = std::slice::from_raw_parts(manifest_bytes, manifest_length);
        let manifest = match AttachmentManifest::decode(bytes) {
            Ok(v) => v,
            Err(e) => {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode(format!("AttachmentManifest decode: {e}")),
                )
            }
        };
        match crate::protocol::attachment::validate_manifest(&manifest) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_chunk_validate(
    manifest_bytes: *const u8,
    manifest_length: usize,
    chunk_index: u32,
    nonce: *const u8,
    nonce_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if manifest_bytes.is_null() || nonce.is_null() || ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if manifest_length == 0 || manifest_length > MAX_ATTACHMENT_MANIFEST_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Attachment manifest size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let manifest_slice = std::slice::from_raw_parts(manifest_bytes, manifest_length);
        let manifest = match AttachmentManifest::decode(manifest_slice) {
            Ok(v) => v,
            Err(e) => {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode(format!("AttachmentManifest decode: {e}")),
                )
            }
        };
        let nonce_slice = std::slice::from_raw_parts(nonce, nonce_length);
        let ciphertext_slice = std::slice::from_raw_parts(ciphertext, ciphertext_length);
        match crate::protocol::attachment::validate_chunk_shape(
            &manifest,
            chunk_index,
            nonce_slice,
            ciphertext_slice,
        ) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Zeroizes and frees the `data` payload of an [`AuraBuffer`].
///
/// # Safety
/// `buffer` must be null or point to a writable `AuraBuffer`.  The `data`
/// field must be null or point to a heap block previously produced by this
/// FFI layer (either by `write_buffer` inside the library, or by
/// [`aura_buffer_alloc`]).  **Never** assign a `malloc`/`new`/Swift-allocated
/// pointer into `.data` — the Rust global allocator would attempt to free
/// memory it did not allocate, which is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn aura_buffer_release(buffer: *mut AuraBuffer) {
    if buffer.is_null() {
        return;
    }
    let buf = &mut *buffer;
    let old_data = std::ptr::replace(&mut buf.data, std::ptr::null_mut());
    let old_len = std::mem::replace(&mut buf.length, 0);
    if !old_data.is_null() && old_len > 0 {
        let slice = std::slice::from_raw_parts_mut(old_data, old_len);
        slice.zeroize();
        drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
    }
}

#[no_mangle]
pub extern "C" fn aura_buffer_alloc(capacity: usize) -> *mut AuraBuffer {
    if capacity == 0 {
        return std::ptr::null_mut();
    }
    let data: Box<[u8]> = vec![0u8; capacity].into_boxed_slice();
    let ptr = Box::into_raw(data).cast::<u8>();
    let buf = Box::new(AuraBuffer {
        data: ptr,
        length: capacity,
    });
    Box::into_raw(buf)
}

/// Zeroizes the `data` payload, frees it, then frees the [`AuraBuffer`] box
/// itself (for buffers obtained from [`aura_buffer_alloc`]).
///
/// # Safety
/// `buffer` must be null or a pointer previously returned by
/// [`aura_buffer_alloc`].  Do not pass buffers embedded in other FFI
/// structs (e.g. fields of `AuraEncryptedFrame`) — use
/// [`aura_buffer_release`] on those instead, since the outer struct is not
/// a separate heap allocation.  The same allocator-ownership rules as
/// [`aura_buffer_release`] apply to the `.data` field.
#[no_mangle]
pub unsafe extern "C" fn aura_buffer_free(buffer: *mut AuraBuffer) {
    if buffer.is_null() {
        return;
    }
    let mut buf = Box::from_raw(buffer);
    if !buf.data.is_null() && buf.length > 0 {
        let slice = std::slice::from_raw_parts_mut(buf.data, buf.length);
        slice.zeroize();
        drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
        buf.data = std::ptr::null_mut();
        buf.length = 0;
    }
}

/// # Safety
/// `error` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn aura_error_free(error: *mut AuraError) {
    if error.is_null() {
        return;
    }
    let e = &mut *error;
    if !e.message.is_null() {
        drop(CString::from_raw(e.message));
        e.message = std::ptr::null_mut();
    }
}

#[no_mangle]
pub const extern "C" fn aura_error_string(code: AuraErrorCode) -> *const c_char {
    let s: &'static [u8] = match code {
        AuraErrorCode::AuraSuccess => b"Success\0",
        AuraErrorCode::AuraErrorGeneric => b"Generic error\0",
        AuraErrorCode::AuraErrorInvalidInput => b"Invalid input\0",
        AuraErrorCode::AuraErrorKeyGeneration => b"Key generation failed\0",
        AuraErrorCode::AuraErrorDeriveKey => b"Key derivation failed\0",
        AuraErrorCode::AuraErrorHandshake => b"Handshake failed\0",
        AuraErrorCode::AuraErrorEncryption => b"Encryption failed\0",
        AuraErrorCode::AuraErrorDecryption => b"Decryption failed\0",
        AuraErrorCode::AuraErrorDecode => b"Decode failed\0",
        AuraErrorCode::AuraErrorEncode => b"Encode failed\0",
        AuraErrorCode::AuraErrorBufferTooSmall => b"Buffer too small\0",
        AuraErrorCode::AuraErrorObjectDisposed => b"Object disposed\0",
        AuraErrorCode::AuraErrorPrepareLocal => b"Prepare local failed\0",
        AuraErrorCode::AuraErrorOutOfMemory => b"Out of memory\0",
        AuraErrorCode::AuraErrorCryptoFailure => b"Crypto failure\0",
        AuraErrorCode::AuraErrorNullPointer => b"Null pointer\0",
        AuraErrorCode::AuraErrorInvalidState => b"Invalid state\0",
        AuraErrorCode::AuraErrorReplayAttack => b"Replay attack detected\0",
        AuraErrorCode::AuraErrorSessionExpired => b"Session expired\0",
        AuraErrorCode::AuraErrorPqMissing => b"Post-quantum material missing\0",
        AuraErrorCode::AuraErrorGroupProtocol => b"Group protocol error\0",
        AuraErrorCode::AuraErrorGroupMembership => b"Group membership error\0",
        AuraErrorCode::AuraErrorTreeIntegrity => b"Tree integrity error\0",
        AuraErrorCode::AuraErrorWelcome => b"Welcome processing error\0",
        AuraErrorCode::AuraErrorMessageExpired => b"Message expired\0",
        AuraErrorCode::AuraErrorFranking => b"Franking verification failed\0",
        AuraErrorCode::AuraErrorVoipCall => b"VoIP call error\0",
        AuraErrorCode::AuraErrorVoipMedia => b"VoIP media error\0",
        AuraErrorCode::AuraErrorVoipRekey => b"VoIP rekey error\0",
        AuraErrorCode::AuraErrorBusy => b"Handle is already in use by another call\0",
    };
    s.as_ptr().cast::<c_char>()
}

/// # Safety
/// `out_handle` must point to writable `*mut AuraSealedStateCounterTrackerHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_create(
    out_handle: *mut *mut AuraSealedStateCounterTrackerHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSealedStateCounterTrackerHandle(Some(
                SealedStateCounterTracker::new(),
            )))),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `(data, data_length)` must form a valid readable slice. `out_handle` must
/// point to writable `*mut AuraSealedStateCounterTrackerHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_create_from_serialized(
    data: *const u8,
    data_length: usize,
    out_handle: *mut *mut AuraSealedStateCounterTrackerHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if data.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let data = std::slice::from_raw_parts(data, data_length);
        let tracker = match SealedStateCounterTracker::deserialize(data) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSealedStateCounterTrackerHandle(Some(tracker)))),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live tracker handle and `out_state` must point to a
/// writable `AuraBuffer`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_serialize(
    handle: *mut AuraSealedStateCounterTrackerHandle,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_state is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let tracker = match require_counter_tracker_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        write_buffer(out_state, tracker.serialize());
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live tracker handle and `out_counter` must point to a
/// writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_get_max_restored_counter(
    handle: *mut AuraSealedStateCounterTrackerHandle,
    out_counter: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_counter.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_counter is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let tracker = match require_counter_tracker_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        *out_counter = tracker.max_restored_counter();
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live tracker handle and `out_counter` must point to a
/// writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_get_latest_issued_counter(
    handle: *mut AuraSealedStateCounterTrackerHandle,
    out_counter: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_counter.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_counter is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let tracker = match require_counter_tracker_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        *out_counter = tracker.latest_issued_counter();
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle_ptr` must point to a handle from
/// `aura_sealed_state_counter_tracker_create*`, or be null. The handle must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_counter_tracker_destroy(
    handle_ptr: *mut *mut AuraSealedStateCounterTrackerHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// `out_handle` must point to writable `*mut AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_create(
    out_handle: *mut *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_handle is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSealedStateSlotHandle(Some(
                SealedStateSlot::new(),
            )))),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `(data, data_length)` must form a valid readable slice. `out_handle` must
/// point to writable `*mut AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_create_from_serialized(
    data: *const u8,
    data_length: usize,
    out_handle: *mut *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if data.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let data = std::slice::from_raw_parts(data, data_length);
        let slot = match SealedStateSlot::deserialize(data) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSealedStateSlotHandle(Some(slot)))),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live slot handle and `out_state` must point to a writable
/// `AuraBuffer`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_serialize(
    handle: *mut AuraSealedStateSlotHandle,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_state is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let slot = match require_sealed_state_slot_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let bytes = match slot.serialize() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        write_buffer(out_state, bytes);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live slot handle and `out_counter` must point to a
/// writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_get_max_restored_counter(
    handle: *mut AuraSealedStateSlotHandle,
    out_counter: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_counter.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_counter is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let slot = match require_sealed_state_slot_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        *out_counter = slot.max_restored_counter();
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle` must be a live slot handle and `out_counter` must point to a
/// writable `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_get_latest_issued_counter(
    handle: *mut AuraSealedStateSlotHandle,
    out_counter: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_counter.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_counter is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let slot = match require_sealed_state_slot_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        *out_counter = slot.latest_issued_counter();
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// `handle_ptr` must point to a handle from `aura_sealed_state_slot_create*`, or
/// be null. The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_sealed_state_slot_destroy(
    handle_ptr: *mut *mut AuraSealedStateSlotHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// # Safety
/// `(data, length)` must form a valid, writable byte slice.
#[no_mangle]
pub unsafe extern "C" fn aura_secure_wipe(data: *mut u8, length: usize) -> AuraErrorCode {
    ffi_catch_panic!(std::ptr::null_mut(), unsafe {
        if data.is_null() {
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if length == 0 {
            return AuraErrorCode::AuraSuccess;
        }
        if length > MAX_BUFFER_SIZE {
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let slice = std::slice::from_raw_parts_mut(data, length);
        crate::api::AuraProtocol::secure_wipe(slice);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(credential, credential_length)` must form a valid
/// readable slice.  `out_secrets` must point to writable `*mut AuraKeyPackageSecretsHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_generate_key_package(
    identity_handle: *mut AuraIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_key_package: *mut AuraBuffer,
    out_secrets: *mut *mut AuraKeyPackageSecretsHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key_package.is_null() || out_secrets.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if credential_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Credential too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        use crate::protocol::group::key_package;
        match key_package::create_key_package(identity, cred) {
            Ok((kp, x25519_priv, kyber_sec)) => {
                let mut buf = Vec::new();
                if let Err(e) = kp.encode(&mut buf) {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorEncode,
                        &format!("KeyPackage encode: {e}"),
                    );
                    return AuraErrorCode::AuraErrorEncode;
                }
                write_buffer(out_key_package, buf);
                replace_out_handle(
                    out_secrets,
                    Box::into_raw(Box::new(AuraKeyPackageSecretsHandle {
                        x25519_private: x25519_priv,
                        kyber_secret: kyber_sec,
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from
/// `aura_group_generate_key_package`, or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_group_key_package_secrets_destroy(
    handle_ptr: *mut *mut AuraKeyPackageSecretsHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

/// Seals a key package's private secrets under a 32-byte at-rest key so the host
/// can persist them across launches.
///
/// The secrets otherwise live only in RAM and
/// every cross-session Welcome fails). Mirrors `aura_session_serialize_sealed`.
///
/// # Safety
/// See module-level FFI safety contract. `handle` must be a live handle from
/// `aura_group_generate_key_package` or `aura_group_key_package_secrets_deserialize_sealed`.
/// `(key, key_length)` must form a readable 32-byte slice; `out_state` must be writable.
#[no_mangle]
pub unsafe extern "C" fn aura_group_key_package_secrets_serialize_sealed(
    handle: *mut AuraKeyPackageSecretsHandle,
    key: *const u8,
    key_length: usize,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let secrets = &*handle;
        use crate::protocol::group::key_package;
        match key_package::seal_key_package_secrets(
            &secrets.x25519_private,
            &secrets.kyber_secret,
            key_slice,
        ) {
            Ok(bytes) => {
                write_buffer(out_state, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Reverses `aura_group_key_package_secrets_serialize_sealed`, rebuilding a
/// secrets handle from a sealed blob. A wrong key or tampering fails the AEAD tag.
///
/// # Safety
/// See module-level FFI safety contract. `(state_bytes, state_length)` and
/// `(key, key_length)` must form valid readable slices. `out_handle` must point
/// to writable `*mut AuraKeyPackageSecretsHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_key_package_secrets_deserialize_sealed(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    out_handle: *mut *mut AuraKeyPackageSecretsHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null() || key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_length == 0 || state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid sealed state length",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let state = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        use crate::protocol::group::key_package;
        match key_package::unseal_key_package_secrets(state, key_slice) {
            Ok((x25519_private, kyber_secret)) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraKeyPackageSecretsHandle {
                        x25519_private,
                        kyber_secret,
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key_package_bytes, key_package_length)` must form a
/// valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_validate_key_package(
    key_package_bytes: *const u8,
    key_package_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key_package_bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "KeyPackage pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_package_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "KeyPackage too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let kp_slice = std::slice::from_raw_parts(key_package_bytes, key_package_length);
        let kp = match crate::proto::GroupKeyPackage::decode(kp_slice) {
            Ok(kp) => kp,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("KeyPackage decode: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        match crate::protocol::group::key_package::validate_key_package(&kp) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(credential, credential_length)` must form a valid
/// readable slice.  `out_handle` must point to writable `*mut AuraGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_create(
    identity_handle: *mut AuraIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        // Default (non-shielded) e2e chats use the `standard()` policy: same
        // sealed/enhanced posture as shield but a messaging-realistic skipped-key
        // budget, so an offline burst or a few dropped events don't permanently
        // wall the receive chain. `aura_group_create_shielded` keeps `shield()`.
        match GroupSession::create_with_policy_and_time_provider(
            identity,
            cred,
            GroupSecurityPolicy::standard(),
            time_provider,
        ) {
            Ok(session) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_create_shielded(
    identity_handle: *mut AuraIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::create_with_policy_and_time_provider(
            identity,
            cred,
            GroupSecurityPolicy::shield(),
            time_provider,
        ) {
            Ok(session) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_is_shielded(
    handle: *mut AuraGroupSessionHandle,
    out_shielded: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_shielded.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_shielded is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.is_shielded() {
            Ok(shielded) => {
                *out_shielded = u8::from(shielded);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Returns the stable, versioned security tier derived from the group's
/// cryptographically bound policy.
///
/// # Safety
/// See module-level FFI safety contract. `out_tier` must point to writable
/// [`AuraGroupSecurityTier`] storage.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_security_tier(
    handle: *mut AuraGroupSessionHandle,
    out_tier: *mut AuraGroupSecurityTier,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_tier.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_tier is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.security_policy() {
            Ok(policy) => {
                *out_tier = policy.security_tier().into();
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  Each field of `policy` must be populated by the
/// caller.  Invalid policy values (e.g. `max_messages_per_epoch < 10`) return an error.
#[no_mangle]
pub unsafe extern "C" fn aura_group_create_with_policy(
    identity_handle: *mut AuraIdentityHandle,
    credential: *const u8,
    credential_length: usize,
    policy: *const AuraGroupSecurityPolicy,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_handle.is_null() || policy.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };
        let p = &*policy;
        let rust_policy = GroupSecurityPolicy {
            max_messages_per_epoch: p.max_messages_per_epoch,
            max_skipped_keys_per_sender: p.max_skipped_keys_per_sender,
            block_external_join: p.block_external_join != 0,
            enhanced_key_schedule: p.enhanced_key_schedule != 0,
            mandatory_franking: p.mandatory_franking != 0,
        };
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::create_with_policy_and_time_provider(
            identity,
            cred,
            rust_policy,
            time_provider,
        ) {
            Ok(session) => {
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `out_policy` must point to a writable
/// `AuraGroupSecurityPolicy`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_security_policy(
    handle: *mut AuraGroupSessionHandle,
    out_policy: *mut AuraGroupSecurityPolicy,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_policy.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_policy is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.security_policy() {
            Ok(p) => {
                (*out_policy).max_messages_per_epoch = p.max_messages_per_epoch;
                (*out_policy).max_skipped_keys_per_sender = p.max_skipped_keys_per_sender;
                (*out_policy).block_external_join = u8::from(p.block_external_join);
                (*out_policy).enhanced_key_schedule = u8::from(p.enhanced_key_schedule);
                (*out_policy).mandatory_franking = u8::from(p.mandatory_franking);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(welcome_bytes, welcome_length)` must form a valid
/// readable slice.  `out_group_handle` must point to writable `*mut AuraGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_join(
    identity_handle: *mut AuraIdentityHandle,
    welcome_bytes: *const u8,
    welcome_length: usize,
    secrets_handle: *mut AuraKeyPackageSecretsHandle,
    out_group_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if welcome_bytes.is_null() || secrets_handle.is_null() || out_group_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if welcome_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Welcome message too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let welcome_slice = std::slice::from_raw_parts(welcome_bytes, welcome_length);

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let secrets = &*secrets_handle;
        let x25519_private = match secrets.x25519_private.try_clone() {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("x25519 key clone failed: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        let kyber_secret = match secrets.kyber_secret.try_clone() {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("kyber key clone failed: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        match GroupSession::from_welcome_with_time_provider(
            welcome_slice,
            x25519_private,
            kyber_secret,
            &identity.get_identity_ed25519_public(),
            &identity.get_identity_x25519_public(),
            ed25519_secret,
            time_provider,
        ) {
            Ok(session) => {
                replace_out_handle(
                    out_group_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(key_package_bytes, key_package_length)` must form a
/// valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_add_member(
    handle: *mut AuraGroupSessionHandle,
    key_package_bytes: *const u8,
    key_package_length: usize,
    out_commit: *mut AuraBuffer,
    out_welcome: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key_package_bytes.is_null() || out_commit.is_null() || out_welcome.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_package_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "KeyPackage too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let kp_slice = std::slice::from_raw_parts(key_package_bytes, key_package_length);
        let kp = match crate::proto::GroupKeyPackage::decode(kp_slice) {
            Ok(kp) => kp,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("KeyPackage decode: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.add_member(&kp) {
            Ok((commit_bytes, welcome_bytes)) => {
                write_buffer(out_commit, commit_bytes);
                write_buffer(out_welcome, welcome_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_remove_member(
    handle: *mut AuraGroupSessionHandle,
    leaf_index: u32,
    out_commit: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_commit.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.remove_member(leaf_index) {
            Ok(commit_bytes) => {
                write_buffer(out_commit, commit_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_update(
    handle: *mut AuraGroupSessionHandle,
    out_commit: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_commit.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.update() {
            Ok(commit_bytes) => {
                write_buffer(out_commit, commit_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(commit_bytes, commit_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_process_commit(
    handle: *mut AuraGroupSessionHandle,
    commit_bytes: *const u8,
    commit_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if commit_bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if commit_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Commit too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slice = std::slice::from_raw_parts(commit_bytes, commit_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.process_commit(slice) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt(
    handle: *mut AuraGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt(pt) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(ciphertext, ciphertext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_decrypt(
    handle: *mut AuraGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_sender_leaf: *mut u32,
    out_generation: *mut u32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if ciphertext.is_null()
            || out_plaintext.is_null()
            || out_sender_leaf.is_null()
            || out_generation.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if ciphertext_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Ciphertext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.decrypt(ct) {
            Ok(result) => {
                write_buffer(out_plaintext, result.plaintext);
                *out_sender_leaf = result.sender_leaf_index;
                *out_generation = result.generation;
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_id(
    handle: *mut AuraGroupSessionHandle,
    out_group_id: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_group_id.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.group_id() {
            Ok(group_id) => {
                write_buffer(out_group_id, group_id);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_epoch(handle: *mut AuraGroupSessionHandle) -> u64 {
    ffi_catch_panic_value!(0u64, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.epoch().ok())
            .unwrap_or(0)
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_my_leaf_index(handle: *mut AuraGroupSessionHandle) -> u32 {
    ffi_catch_panic_value!(u32::MAX, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.my_leaf_index().ok())
            .unwrap_or(u32::MAX)
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_member_count(handle: *mut AuraGroupSessionHandle) -> u32 {
    ffi_catch_panic_value!(0u32, unsafe {
        group_ref_or_none(handle.cast_const())
            .and_then(|s| s.member_count().ok())
            .unwrap_or(0)
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(key, key_length)` must form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_serialize(
    handle: *mut AuraGroupSessionHandle,
    key: *const u8,
    key_length: usize,
    external_counter: u64,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if external_counter == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "external_counter must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_sealed_state(key_slice, external_counter) {
            Ok(bytes) => {
                write_buffer(out_state, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(state_bytes, state_length)` and `(key, key_length)` must
/// form valid readable slices.  `out_handle` must point to writable `*mut AuraGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_deserialize(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    min_external_counter: u64,
    out_external_counter: *mut u64,
    identity_handle: *mut AuraIdentityHandle,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null()
            || key.is_null()
            || out_handle.is_null()
            || out_external_counter.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if state_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "State blob too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match GroupSession::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        match GroupSession::from_sealed_state_with_time_provider(
            state_slice,
            key_slice,
            ed25519_secret,
            min_external_counter,
            time_provider,
        ) {
            Ok(session) => {
                *out_external_counter = external_counter;
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `tracker_handle` must be a live
/// `AuraSealedStateCounterTrackerHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_serialize_with_tracker(
    handle: *mut AuraGroupSessionHandle,
    key: *const u8,
    key_length: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match tracker.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let bytes = match session.export_sealed_state(key_slice, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_export(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        write_buffer(out_state, bytes);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(state_bytes, state_length)` and
/// `(key, key_length)` must form valid readable slices. `out_handle` must
/// point to writable `*mut AuraGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_deserialize_with_tracker(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    identity_handle: *mut AuraIdentityHandle,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null() || key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if state_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "State blob too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match GroupSession::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let session = match GroupSession::from_sealed_state_with_time_provider(
            state_slice,
            key_slice,
            ed25519_secret,
            tracker.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraGroupSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `slot_handle` must be a live `AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_export_persisted_state(
    handle: *mut AuraGroupSessionHandle,
    key: *const u8,
    key_length: usize,
    slot_handle: *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match slot.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let bytes = match session.export_sealed_state(key_slice, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        match slot.note_successful_export(external_counter, bytes) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `slot_handle` must be a live `AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_restore_persisted_state(
    slot_handle: *mut AuraSealedStateSlotHandle,
    key: *const u8,
    key_length: usize,
    identity_handle: *mut AuraIdentityHandle,
    out_handle: *mut *mut AuraGroupSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if slot.is_empty() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed-state slot is empty",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let state_slice = slot.sealed_state();
        if state_slice.len() > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "State blob too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match GroupSession::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(sk) => sk,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let session = match GroupSession::from_sealed_state_with_time_provider(
            state_slice,
            key_slice,
            ed25519_secret,
            slot.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = slot.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraGroupSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_export_public_state(
    handle: *mut AuraGroupSessionHandle,
    out_public_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_public_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_public_state() {
            Ok(bytes) => {
                write_buffer(out_public_state, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(joiner_identity_ed25519_public, joiner_identity_ed25519_public_length)`,
/// `(joiner_identity_x25519_public, joiner_identity_x25519_public_length)`, and
/// `(joiner_credential, joiner_credential_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_authorize_external_join(
    handle: *mut AuraGroupSessionHandle,
    joiner_identity_ed25519_public: *const u8,
    joiner_identity_ed25519_public_length: usize,
    joiner_identity_x25519_public: *const u8,
    joiner_identity_x25519_public_length: usize,
    joiner_credential: *const u8,
    joiner_credential_length: usize,
    out_authorization: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if joiner_identity_ed25519_public.is_null()
            || joiner_identity_x25519_public.is_null()
            || out_authorization.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if joiner_identity_ed25519_public_length > MAX_BUFFER_SIZE
            || joiner_identity_x25519_public_length > MAX_BUFFER_SIZE
            || joiner_credential_length > MAX_BUFFER_SIZE
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "joiner input exceeds MAX_BUFFER_SIZE",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let joiner_ed = std::slice::from_raw_parts(
            joiner_identity_ed25519_public,
            joiner_identity_ed25519_public_length,
        );
        let joiner_x = std::slice::from_raw_parts(
            joiner_identity_x25519_public,
            joiner_identity_x25519_public_length,
        );
        let joiner_credential = if joiner_credential.is_null() || joiner_credential_length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(joiner_credential, joiner_credential_length)
        };
        match session.authorize_external_join(joiner_ed, joiner_x, joiner_credential) {
            Ok(bytes) => {
                write_buffer(out_authorization, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(public_state, public_state_length)`,
/// `(authorization, authorization_length)`, and
/// `(credential, credential_length)` must form valid readable slices.
/// `out_group_handle` must point to writable `*mut AuraGroupSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_group_join_external(
    identity_handle: *mut AuraIdentityHandle,
    public_state: *const u8,
    public_state_length: usize,
    authorization: *const u8,
    authorization_length: usize,
    credential: *const u8,
    credential_length: usize,
    out_group_handle: *mut *mut AuraGroupSessionHandle,
    out_commit: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if public_state.is_null()
            || authorization.is_null()
            || out_group_handle.is_null()
            || out_commit.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if public_state_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Public state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if credential_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Credential too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(public_state, public_state_length);
        let auth_slice = if authorization.is_null() || authorization_length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(authorization, authorization_length)
        };
        let cred = if credential.is_null() || credential_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(credential, credential_length).to_vec()
        };

        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match GroupSession::from_external_join_with_time_provider(
            state_slice,
            auth_slice,
            identity,
            cred,
            time_provider,
        ) {
            Ok((session, commit_bytes)) => {
                replace_out_handle(
                    out_group_handle,
                    Box::into_raw(Box::new(AuraGroupSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                write_buffer(out_commit, commit_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

struct FfiPskResolver {
    psk_id: Vec<u8>,
    psk: Vec<u8>,
}

impl crate::protocol::group::PskResolver for FfiPskResolver {
    fn resolve(&self, psk_id: &[u8]) -> Option<Vec<u8>> {
        if psk_id == self.psk_id {
            Some(self.psk.clone())
        } else {
            None
        }
    }
}

/// # Safety
/// See module-level FFI safety contract.  `(psk_id, psk_id_length)` and `(psk, psk_length)` must
/// form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_set_psk(
    handle: *mut AuraGroupSessionHandle,
    psk_id: *const u8,
    psk_id_length: usize,
    psk: *const u8,
    psk_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || psk_id.is_null() || psk.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if psk_id_length == 0 || psk_length < PSK_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "PSK id and value are required",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let id_slice = std::slice::from_raw_parts(psk_id, psk_id_length);
        let psk_slice = std::slice::from_raw_parts(psk, psk_length);
        let resolver = Box::new(FfiPskResolver {
            psk_id: id_slice.to_vec(),
            psk: psk_slice.to_vec(),
        });
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(s) => s,
            Err(code) => return code,
        };
        match session.set_psk_resolver(resolver) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_member_leaf_indices(
    handle: *mut AuraGroupSessionHandle,
    out_indices: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_indices.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let indices = match session.member_leaf_indices() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut buf = Vec::with_capacity(indices.len() * size_of::<u32>());
        for idx in &indices {
            buf.extend_from_slice(&idx.to_le_bytes());
        }
        write_buffer(out_indices, buf);
        AuraErrorCode::AuraSuccess
    })
}

/// Return the authenticated KeyPackage stored at an active group leaf.
///
/// # Safety
/// `handle` must be an active group handle and `out_key_package` must be a
/// writable `AuraBuffer`. The caller owns the returned buffer and must release
/// it with [`aura_buffer_release`].
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_member_key_package(
    handle: *mut AuraGroupSessionHandle,
    leaf_index: u32,
    out_key_package: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key_package.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(value) => value,
            Err(code) => return code,
        };
        let encoded = match session.member_key_package(leaf_index) {
            Ok(value) => value,
            Err(error) => return write_protocol_error(out_error, &error),
        };
        write_buffer(out_key_package, encoded);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle from `aura_group_create`,
/// or be null.  The handle must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn aura_group_destroy(handle_ptr: *mut *mut AuraGroupSessionHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

struct FfiStateKeyProvider {
    handle: SecureMemoryHandle,
}

impl crate::interfaces::IStateKeyProvider for FfiStateKeyProvider {
    fn get_state_encryption_key(&self) -> Result<SecureMemoryHandle, ProtocolError> {
        let size = self.handle.size();
        let mut out = SecureMemoryHandle::allocate(size)
            .map_err(|e| ProtocolError::generic(format!("Allocate failed: {e}")))?;
        let bytes = self
            .handle
            .read_bytes(size)
            .map_err(ProtocolError::from_crypto)?;
        out.write(&bytes).map_err(ProtocolError::from_crypto)?;
        Ok(out)
    }
}

/// # Safety
/// See module-level FFI safety contract.  `(key, key_length)` must form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_session_serialize_sealed(
    handle: *mut AuraSessionHandle,
    key: *const u8,
    key_length: usize,
    external_counter: u64,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if external_counter == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "external_counter must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.export_sealed_state(&provider, external_counter) {
            Ok(bytes) => {
                write_buffer(out_state, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(state_bytes, state_length)` and `(key, key_length)` must
/// form valid readable slices.  `out_handle` must point to writable `*mut AuraSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_session_deserialize_sealed(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    min_external_counter: u64,
    out_external_counter: *mut u64,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null()
            || key.is_null()
            || out_external_counter.is_null()
            || out_handle.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        match Session::from_sealed_state(state_slice, &provider, min_external_counter) {
            Ok(session) => {
                *out_external_counter = external_counter;
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(state_bytes, state_length)` and
/// `(key, key_length)` must form valid readable slices. `time_provider_handle`
/// may be NULL to use the system clock.
#[no_mangle]
pub unsafe extern "C" fn aura_session_deserialize_sealed_with_time_provider(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    min_external_counter: u64,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_external_counter: *mut u64,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null()
            || key.is_null()
            || out_external_counter.is_null()
            || out_handle.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        match Session::from_sealed_state_with_time_provider(
            state_slice,
            &provider,
            min_external_counter,
            time_provider,
        ) {
            Ok(session) => {
                *out_external_counter = external_counter;
                replace_out_handle(
                    out_handle,
                    Box::into_raw(Box::new(AuraSessionHandle {
                        inner: Some(session),
                        in_use: AtomicBool::new(false),
                    })),
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `tracker_handle` must be a live
/// `AuraSealedStateCounterTrackerHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_session_serialize_sealed_with_tracker(
    handle: *mut AuraSessionHandle,
    key: *const u8,
    key_length: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    out_state: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_state.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match tracker.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let key_slice = std::slice::from_raw_parts(key, key_length);
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let bytes = match session.export_sealed_state(&provider, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_export(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        write_buffer(out_state, bytes);
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(state_bytes, state_length)` and
/// `(key, key_length)` must form valid readable slices. `out_handle` must
/// point to writable `*mut AuraSessionHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_session_deserialize_sealed_with_tracker(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null() || key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let session = match Session::from_sealed_state(
            state_slice,
            &provider,
            tracker.min_import_counter(),
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(state_bytes, state_length)` and
/// `(key, key_length)` must form valid readable slices. `time_provider_handle`
/// may be NULL to use the system clock.
#[no_mangle]
pub unsafe extern "C" fn aura_session_deserialize_sealed_with_tracker_and_time_provider(
    state_bytes: *const u8,
    state_length: usize,
    key: *const u8,
    key_length: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if state_bytes.is_null() || key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_slice = std::slice::from_raw_parts(state_bytes, state_length);
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let session = match Session::from_sealed_state_with_time_provider(
            state_slice,
            &provider,
            tracker.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `slot_handle` must be a live `AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_session_export_persisted_state(
    handle: *mut AuraSessionHandle,
    key: *const u8,
    key_length: usize,
    slot_handle: *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "key is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match slot.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }
        let provider = FfiStateKeyProvider { handle: smh };
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let bytes = match session.export_sealed_state(&provider, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        match slot.note_successful_export(external_counter, bytes) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `slot_handle` must be a live `AuraSealedStateSlotHandle`.
#[no_mangle]
pub unsafe extern "C" fn aura_session_restore_persisted_state(
    slot_handle: *mut AuraSealedStateSlotHandle,
    key: *const u8,
    key_length: usize,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if slot.is_empty() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed-state slot is empty",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let state_slice = slot.sealed_state();
        if state_slice.len() > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let session =
            match Session::from_sealed_state(state_slice, &provider, slot.min_import_counter()) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };
        if let Err(e) = slot.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract. `(key, key_length)` must form a valid
/// readable slice. `time_provider_handle` may be NULL to use the system clock.
#[no_mangle]
pub unsafe extern "C" fn aura_session_restore_persisted_state_with_time_provider(
    slot_handle: *mut AuraSealedStateSlotHandle,
    key: *const u8,
    key_length: usize,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_handle: *mut *mut AuraSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if key.is_null() || out_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Key must be exactly 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if slot.is_empty() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed-state slot is empty",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let key_slice = std::slice::from_raw_parts(key, key_length);
        let state_slice = slot.sealed_state();
        if state_slice.len() > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let external_counter = match Session::sealed_state_external_counter(state_slice) {
            Ok(c) => c,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let mut smh = match SecureMemoryHandle::allocate(AES_KEY_BYTES) {
            Ok(h) => h,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorOutOfMemory,
                    &format!("Allocate: {e}"),
                );
                return AuraErrorCode::AuraErrorOutOfMemory;
            }
        };
        if let Err(e) = smh.write(key_slice) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorGeneric,
                &format!("Write: {e}"),
            );
            return AuraErrorCode::AuraErrorGeneric;
        }

        let provider = FfiStateKeyProvider { handle: smh };
        let session = match Session::from_sealed_state_with_time_provider(
            state_slice,
            &provider,
            slot.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = slot.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_handle,
            Box::into_raw(Box::new(AuraSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` and
/// `(hint, hint_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_sealed(
    handle: *mut AuraGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    hint: *const u8,
    hint_length: usize,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);

        if hint_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "hint too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let hint_slice = if hint.is_null() || hint_length == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(hint, hint_length)
        };

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_sealed(pt, hint_slice) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_disappearing(
    handle: *mut AuraGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    ttl_seconds: u32,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_disappearing(pt, ttl_seconds) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Encrypts a disappearing group message with a nested sealed payload.
///
/// # Safety
/// See module-level FFI safety contract. `(plaintext, plaintext_length)` and
/// the optional `(hint, hint_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_sealed_disappearing(
    handle: *mut AuraGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    hint: *const u8,
    hint_length: usize,
    ttl_seconds: u32,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if hint_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "hint too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let hint_slice = if hint.is_null() || hint_length == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(hint, hint_length)
        };
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_sealed_disappearing(pt, hint_slice, ttl_seconds) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(plaintext, plaintext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_frankable(
    handle: *mut AuraGroupSessionHandle,
    plaintext: *const u8,
    plaintext_length: usize,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if plaintext.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if plaintext_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Plaintext too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let pt = std::slice::from_raw_parts(plaintext, plaintext_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_frankable(pt) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(new_content, new_content_length)` and
/// `(target_message_id, target_message_id_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_edit(
    handle: *mut AuraGroupSessionHandle,
    new_content: *const u8,
    new_content_length: usize,
    target_message_id: *const u8,
    target_message_id_length: usize,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if new_content.is_null() || target_message_id.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if new_content_length > MAX_ENVELOPE_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Content too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if target_message_id_length != MESSAGE_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "target_message_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let content = std::slice::from_raw_parts(new_content, new_content_length);
        let target_id = std::slice::from_raw_parts(target_message_id, target_message_id_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_edit(content, target_id) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(target_message_id, target_message_id_length)` must form
/// a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_delete(
    handle: *mut AuraGroupSessionHandle,
    target_message_id: *const u8,
    target_message_id_length: usize,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if target_message_id.is_null() || out_ciphertext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if target_message_id_length != MESSAGE_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "target_message_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let target_id = std::slice::from_raw_parts(target_message_id, target_message_id_length);
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_delete(target_id) {
            Ok(ct_bytes) => {
                write_buffer(out_ciphertext, ct_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[repr(C)]
pub struct AuraGroupDecryptResult {
    pub plaintext: AuraBuffer,
    pub sender_leaf_index: u32,
    pub generation: u32,
    pub content_type: u32,
    pub ttl_seconds: u32,
    pub sent_timestamp: u64,
    pub message_id: AuraBuffer,
    pub referenced_message_id: AuraBuffer,
    pub has_sealed_payload: u8,
    pub has_franking_data: u8,
    pub sealed_hint: AuraBuffer,
    pub sealed_encrypted_content: AuraBuffer,
    pub sealed_nonce: AuraBuffer,
    pub sealed_key: AuraBuffer,
    pub franking_tag: AuraBuffer,
    pub franking_key: AuraBuffer,
    pub franking_content: AuraBuffer,
    pub franking_sealed_content: AuraBuffer,
}

unsafe fn clear_group_decrypt_result(result: *mut AuraGroupDecryptResult) {
    if result.is_null() {
        return;
    }
    (*result).plaintext.data = std::ptr::null_mut();
    (*result).plaintext.length = 0;
    (*result).sender_leaf_index = 0;
    (*result).generation = 0;
    (*result).content_type = 0;
    (*result).ttl_seconds = 0;
    (*result).sent_timestamp = 0;
    (*result).message_id.data = std::ptr::null_mut();
    (*result).message_id.length = 0;
    (*result).referenced_message_id.data = std::ptr::null_mut();
    (*result).referenced_message_id.length = 0;
    (*result).has_sealed_payload = 0;
    (*result).has_franking_data = 0;
    (*result).sealed_hint.data = std::ptr::null_mut();
    (*result).sealed_hint.length = 0;
    (*result).sealed_encrypted_content.data = std::ptr::null_mut();
    (*result).sealed_encrypted_content.length = 0;
    (*result).sealed_nonce.data = std::ptr::null_mut();
    (*result).sealed_nonce.length = 0;
    (*result).sealed_key.data = std::ptr::null_mut();
    (*result).sealed_key.length = 0;
    (*result).franking_tag.data = std::ptr::null_mut();
    (*result).franking_tag.length = 0;
    (*result).franking_key.data = std::ptr::null_mut();
    (*result).franking_key.length = 0;
    (*result).franking_content.data = std::ptr::null_mut();
    (*result).franking_content.length = 0;
    (*result).franking_sealed_content.data = std::ptr::null_mut();
    (*result).franking_sealed_content.length = 0;
}

unsafe fn write_group_decrypt_result(
    out_result: *mut AuraGroupDecryptResult,
    mut result: GroupDecryptResult,
) {
    write_buffer(
        std::ptr::addr_of_mut!((*out_result).plaintext),
        std::mem::take(&mut result.plaintext),
    );
    (*out_result).sender_leaf_index = result.sender_leaf_index;
    (*out_result).generation = result.generation;
    (*out_result).content_type = result.content_type.to_u32();
    (*out_result).ttl_seconds = result.ttl_seconds;
    (*out_result).sent_timestamp = result.sent_timestamp;
    write_buffer(
        std::ptr::addr_of_mut!((*out_result).message_id),
        std::mem::take(&mut result.message_id),
    );
    write_buffer(
        std::ptr::addr_of_mut!((*out_result).referenced_message_id),
        std::mem::take(&mut result.referenced_message_id),
    );
    (*out_result).has_sealed_payload = u8::from(result.sealed_payload.is_some());
    (*out_result).has_franking_data = u8::from(result.franking_data.is_some());
    if let Some(mut sealed) = result.sealed_payload {
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).sealed_hint),
            std::mem::take(&mut sealed.hint),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).sealed_encrypted_content),
            std::mem::take(&mut sealed.encrypted_content),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).sealed_nonce),
            std::mem::take(&mut sealed.nonce),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).sealed_key),
            std::mem::take(&mut sealed.seal_key),
        );
    }
    if let Some(mut franking) = result.franking_data {
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).franking_tag),
            std::mem::take(&mut franking.franking_tag),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).franking_key),
            std::mem::take(&mut franking.franking_key),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).franking_content),
            std::mem::take(&mut franking.content),
        );
        write_buffer(
            std::ptr::addr_of_mut!((*out_result).franking_sealed_content),
            std::mem::take(&mut franking.sealed_content),
        );
    }
}

unsafe fn group_decrypt_ex_impl(
    handle: *mut AuraGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_result: *mut AuraGroupDecryptResult,
    out_error: *mut AuraError,
    open_sealed: bool,
) -> AuraErrorCode {
    if ciphertext.is_null() || out_result.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "A required pointer is null",
        );
        return AuraErrorCode::AuraErrorNullPointer;
    }
    clear_group_decrypt_result(out_result);
    if ciphertext_length > MAX_GROUP_MESSAGE_SIZE {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorInvalidInput,
            "Ciphertext too large",
        );
        return AuraErrorCode::AuraErrorInvalidInput;
    }

    let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);
    let (_guard, session) = match require_group_mut(handle, out_error) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let decrypted = if open_sealed {
        session.decrypt_open_sealed(ct)
    } else {
        session.decrypt(ct)
    };
    match decrypted {
        Ok(result) => {
            write_group_decrypt_result(out_result, result);
            AuraErrorCode::AuraSuccess
        }
        Err(error) => write_protocol_error(out_error, &error),
    }
}

/// # Safety
/// `result` must be null or point to a value previously written by this FFI layer.
#[no_mangle]
pub unsafe extern "C" fn aura_group_decrypt_result_free(result: *mut AuraGroupDecryptResult) {
    if result.is_null() {
        return;
    }
    aura_buffer_release(std::ptr::addr_of_mut!((*result).plaintext));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).message_id));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).referenced_message_id));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).sealed_hint));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).sealed_encrypted_content));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).sealed_nonce));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).sealed_key));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).franking_tag));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).franking_key));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).franking_content));
    aura_buffer_release(std::ptr::addr_of_mut!((*result).franking_sealed_content));
    clear_group_decrypt_result(result);
}

/// # Safety
/// See module-level FFI safety contract.  `(ciphertext, ciphertext_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_decrypt_ex(
    handle: *mut AuraGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_result: *mut AuraGroupDecryptResult,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        group_decrypt_ex_impl(
            handle,
            ciphertext,
            ciphertext_length,
            out_result,
            out_error,
            false,
        )
    })
}

/// Decrypts a group message and opens any nested sealed payload before it
/// crosses the FFI boundary.
///
/// The result keeps the authenticated sealed content
/// type, but `plaintext` contains the actual inner payload and no seal key is
/// exported to the host.
///
/// # Safety
/// See module-level FFI safety contract. `(ciphertext, ciphertext_length)` must
/// form a valid readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_decrypt_open_sealed_ex(
    handle: *mut AuraGroupSessionHandle,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_result: *mut AuraGroupDecryptResult,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        group_decrypt_ex_impl(
            handle,
            ciphertext,
            ciphertext_length,
            out_result,
            out_error,
            true,
        )
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(group_id, group_id_length)` must form a valid
/// readable slice.
#[no_mangle]
pub unsafe extern "C" fn aura_group_compute_message_id(
    group_id: *const u8,
    group_id_length: usize,
    epoch: u64,
    sender_leaf_index: u32,
    generation: u32,
    out_message_id: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if group_id.is_null() || out_message_id.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if group_id_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "group_id_length exceeds MAX_BUFFER_SIZE",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let gid = std::slice::from_raw_parts(group_id, group_id_length);
        let id =
            crate::protocol::group::compute_message_id(gid, epoch, sender_leaf_index, generation);
        write_buffer(out_message_id, id);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_set_member_role(
    handle: *mut AuraGroupSessionHandle,
    leaf_index: u32,
    role: i32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.set_member_role(leaf_index, role) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_get_member_role(
    handle: *mut AuraGroupSessionHandle,
    leaf_index: u32,
    out_role: *mut i32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_role.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_role is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.get_member_role(leaf_index) {
            Ok(role) => {
                *out_role = role;
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_reaction(
    handle: *mut AuraGroupSessionHandle,
    message_id: *const u8,
    message_id_length: usize,
    emoji: *const u8,
    emoji_length: usize,
    remove: u8,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if message_id.is_null() || emoji.is_null() || out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if message_id_length != MESSAGE_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "message_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let mid = std::slice::from_raw_parts(message_id, message_id_length);
        let emoji_bytes = std::slice::from_raw_parts(emoji, emoji_length);
        let Ok(emoji_str) = std::str::from_utf8(emoji_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "emoji is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_reaction(mid, emoji_str, remove != 0) {
            Ok(ct) => {
                write_buffer(out_buffer, ct);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_read_receipt(
    handle: *mut AuraGroupSessionHandle,
    message_ids_flat: *const u8,
    message_id_count: usize,
    timestamp: u64,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if message_id_count > 0 && message_ids_flat.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "message_ids_flat is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if message_id_count > MAX_READ_RECEIPT_IDS_FFI {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "message_id_count exceeds upper bound",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let flat = if message_id_count > 0 {
            let total_bytes = match message_id_count.checked_mul(MESSAGE_ID_BYTES) {
                Some(n) => n,
                None => {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "message_id_count * MESSAGE_ID_BYTES overflow",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                }
            };
            std::slice::from_raw_parts(message_ids_flat, total_bytes)
        } else {
            &[]
        };
        let ids: Vec<Vec<u8>> = flat
            .chunks_exact(MESSAGE_ID_BYTES)
            .map(<[u8]>::to_vec)
            .collect();
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_read_receipt(&ids, timestamp) {
            Ok(ct) => {
                write_buffer(out_buffer, ct);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_encrypt_typing(
    handle: *mut AuraGroupSessionHandle,
    is_typing: u8,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.encrypt_typing(is_typing != 0) {
            Ok(ct) => {
                write_buffer(out_buffer, ct);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(hint, hint_length)`, `(encrypted_content, encrypted_content_length)`,
/// `(nonce, nonce_length)`, and `(seal_key, seal_key_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_reveal_sealed(
    hint: *const u8,
    hint_length: usize,
    encrypted_content: *const u8,
    encrypted_content_length: usize,
    nonce: *const u8,
    nonce_length: usize,
    seal_key: *const u8,
    seal_key_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if encrypted_content.is_null()
            || nonce.is_null()
            || seal_key.is_null()
            || out_plaintext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if nonce_length != AES_GCM_NONCE_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Nonce must be 12 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if seal_key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Seal key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if encrypted_content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Encrypted content too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        if hint_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "hint too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let _ = if hint.is_null() || hint_length == 0 {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(hint, hint_length)
        };
        let ec = std::slice::from_raw_parts(encrypted_content, encrypted_content_length);
        let n = std::slice::from_raw_parts(nonce, nonce_length);
        let sk = std::slice::from_raw_parts(seal_key, seal_key_length);

        use crate::protocol::group::{GroupSession, SealedPayload};
        let payload = SealedPayload {
            hint: vec![],
            encrypted_content: ec.to_vec(),
            nonce: n.to_vec(),
            seal_key: sk.to_vec(),
        };
        match GroupSession::reveal_sealed(&payload) {
            Ok(pt) => {
                write_buffer(out_plaintext, pt);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `(franking_tag, franking_tag_length)`,
/// `(franking_key, franking_key_length)`, `(content, content_length)`, and
/// `(sealed_content, sealed_content_length)` must form valid readable slices.
#[no_mangle]
pub unsafe extern "C" fn aura_group_verify_franking(
    franking_tag: *const u8,
    franking_tag_length: usize,
    franking_key: *const u8,
    franking_key_length: usize,
    content: *const u8,
    content_length: usize,
    sealed_content: *const u8,
    sealed_content_length: usize,
    out_valid: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if franking_tag.is_null()
            || franking_key.is_null()
            || content.is_null()
            || out_valid.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if franking_tag_length != HMAC_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Franking tag must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if franking_key_length != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Franking key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Content too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if sealed_content_length > MAX_GROUP_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Sealed content too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        use crate::protocol::group::{FrankingData, GroupSession};
        let sc = if sealed_content.is_null() || sealed_content_length == 0 {
            vec![]
        } else {
            std::slice::from_raw_parts(sealed_content, sealed_content_length).to_vec()
        };
        let data = FrankingData {
            franking_tag: std::slice::from_raw_parts(franking_tag, franking_tag_length).to_vec(),
            franking_key: std::slice::from_raw_parts(franking_key, franking_key_length).to_vec(),
            content: std::slice::from_raw_parts(content, content_length).to_vec(),
            sealed_content: sc,
        };
        match GroupSession::verify_franking(&data) {
            Ok(valid) => {
                *out_valid = u8::from(valid);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_group_get_pending_reinit(
    handle: *mut AuraGroupSessionHandle,
    out_new_group_id: *mut AuraBuffer,
    out_new_version: *mut u32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_new_group_id.is_null() || out_new_version.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.pending_reinit() {
            Ok(Some(info)) => {
                write_buffer(out_new_group_id, info.new_group_id);
                *out_new_version = info.new_version;
            }
            Ok(None) => {
                write_buffer(out_new_group_id, vec![]);
                *out_new_version = 0;
            }
            Err(e) => return write_protocol_error(out_error, &e),
        }
        AuraErrorCode::AuraSuccess
    })
}

/// Acquires the handle's busy-flag; the returned [`BusyGuard`] releases it on
/// drop, preventing concurrent access from multiple FFI calls.
unsafe fn require_voip_ref<'a>(
    handle: *const AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> Result<(BusyGuard<'a>, &'a crate::protocol::voip::VoipSession), AuraErrorCode> {
    if handle.is_null() {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "null VoIP session handle",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    // Safety: we only read the `in_use` field; we need a *const → *const cast
    // which is sound because `AtomicBool` access is through atomic ops.
    let guard = try_acquire_busy(&(*handle).in_use).map_err(|()| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorBusy,
            "VoIP session handle is already in use by another call",
        );
        AuraErrorCode::AuraErrorBusy
    })?;
    let inner = (*handle).inner.as_ref().ok_or_else(|| {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorObjectDisposed,
            "VoIP session disposed",
        );
        AuraErrorCode::AuraErrorObjectDisposed
    })?;
    Ok((guard, inner))
}

unsafe fn read_optional_voip_screen_share_meta(
    width: u32,
    height: u32,
    frame_rate: u32,
    codec_hint: *const u8,
    codec_hint_len: usize,
    out_error: *mut AuraError,
) -> Result<Option<ScreenShareMetadata>, AuraErrorCode> {
    let has_dimensions = width != 0 || height != 0 || frame_rate != 0;
    let has_hint = !codec_hint.is_null() && codec_hint_len != 0;
    if !has_dimensions && !has_hint {
        return Ok(None);
    }
    if codec_hint.is_null() && codec_hint_len != 0 {
        write_error(
            out_error,
            AuraErrorCode::AuraErrorNullPointer,
            "screen share codec_hint pointer is null",
        );
        return Err(AuraErrorCode::AuraErrorNullPointer);
    }
    let codec_hint = if has_hint {
        let bytes = std::slice::from_raw_parts(codec_hint, codec_hint_len);
        match std::str::from_utf8(bytes) {
            Ok(s) => Some(s.to_owned()),
            Err(_) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "invalid UTF-8 in screen share codec_hint",
                );
                return Err(AuraErrorCode::AuraErrorInvalidInput);
            }
        }
    } else {
        None
    };
    let meta = ScreenShareMetadata {
        width,
        height,
        frame_rate,
        codec_hint,
    };
    match crate::protocol::voip::validate_screen_share_metadata(&meta) {
        Ok(()) => Ok(Some(meta)),
        Err(e) => {
            let code = write_protocol_error(out_error, &e);
            Err(code)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_accept_call(
    identity_handle: *const AuraIdentityHandle,
    call_init_bytes: *const u8,
    call_init_len: usize,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    out_accept_bytes: *mut AuraBuffer,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_accept_bytes.is_null() || out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if call_init_bytes.is_null() || call_init_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null CallInit bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if call_init_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "CallInit too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let init_bytes = std::slice::from_raw_parts(call_init_bytes, call_init_len);
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);

        let call_init = match crate::proto::CallInit::decode(init_bytes) {
            Ok(v) => v,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("CallInit decode: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let ed_public = identity.get_identity_ed25519_public();
        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        if call_init.version != crate::core::constants::VOIP_PROTOCOL_VERSION {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "unsupported VoIP protocol version",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(e) = crate::protocol::voip::validate_call_media_type(call_init.media_type) {
            return write_protocol_error(out_error, &e);
        }
        if let Some(ref meta) = call_init.screen_share {
            if let Err(e) = crate::protocol::voip::validate_screen_share_metadata(meta) {
                return write_protocol_error(out_error, &e);
            }
        }

        let auth_context = crate::protocol::voip::call_key_exchange::CallInitAuthContext {
            version: call_init.version,
            media_type: call_init.media_type,
            ratchet_interval_frames: call_init.ratchet_interval_frames,
            pq_rekey_interval_secs: call_init.pq_rekey_interval_secs,
            shield_mode: call_init.shield_mode,
        };

        let accept_output =
            match crate::protocol::voip::call_key_exchange::callee_accept_with_context_and_screen_share(
                &ed_secret,
                &ed_public,
                &kyber_secret,
                kyber_pub,
                &call_init.call_id,
                &call_init.ephemeral_x25519_public,
                &call_init.kyber_ciphertext,
                &call_init.identity_ed25519_public,
                &call_init.signature,
                &call_init.key_confirmation_mac,
                &auth_context,
                call_init.screen_share.as_ref(),
                None,
            ) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };

        let proto = crate::proto::CallAccept {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            callee_device_id: Vec::new(),
            call_id: call_init.call_id.clone(),
            ephemeral_x25519_public: accept_output.ephemeral_x25519_public,
            kyber_ciphertext: accept_output.kyber_ciphertext,
            identity_ed25519_public: accept_output.identity_ed25519_public,
            signature: accept_output.signature,
            key_confirmation_mac: accept_output.key_confirmation_mac,
            screen_share: None,
        };
        let mut buf = Vec::new();
        if let Err(e) = proto.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("CallAccept encode: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }
        write_buffer(out_accept_bytes, buf);

        let session = match crate::protocol::voip::VoipSession::from_key_material_with_time_provider_and_screen_share(
            call_init.call_id,
            crate::protocol::voip::CallRole::Callee,
            accept_output.key_material,
            call_init.ratchet_interval_frames,
            call_init.pq_rekey_interval_secs,
            call_init.shield_mode,
            time_provider,
            call_init.screen_share,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_accept_call_with_options(
    identity_handle: *const AuraIdentityHandle,
    call_init_bytes: *const u8,
    call_init_len: usize,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    screen_share_width: u32,
    screen_share_height: u32,
    screen_share_frame_rate: u32,
    screen_share_codec_hint: *const u8,
    screen_share_codec_hint_len: usize,
    out_accept_bytes: *mut AuraBuffer,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_accept_bytes.is_null() || out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let accept_screen_share = match read_optional_voip_screen_share_meta(
            screen_share_width,
            screen_share_height,
            screen_share_frame_rate,
            screen_share_codec_hint,
            screen_share_codec_hint_len,
            out_error,
        ) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if call_init_bytes.is_null() || call_init_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null CallInit bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if call_init_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "CallInit too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let init_bytes = std::slice::from_raw_parts(call_init_bytes, call_init_len);
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);

        let call_init = match crate::proto::CallInit::decode(init_bytes) {
            Ok(v) => v,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("CallInit decode: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        if call_init.version != crate::core::constants::VOIP_PROTOCOL_VERSION {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "unsupported VoIP protocol version",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(e) = crate::protocol::voip::validate_call_media_type(call_init.media_type) {
            return write_protocol_error(out_error, &e);
        }
        if let Some(ref meta) = call_init.screen_share {
            if let Err(e) = crate::protocol::voip::validate_screen_share_metadata(meta) {
                return write_protocol_error(out_error, &e);
            }
        }

        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let ed_public = identity.get_identity_ed25519_public();
        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let auth_context = crate::protocol::voip::call_key_exchange::CallInitAuthContext {
            version: call_init.version,
            media_type: call_init.media_type,
            ratchet_interval_frames: call_init.ratchet_interval_frames,
            pq_rekey_interval_secs: call_init.pq_rekey_interval_secs,
            shield_mode: call_init.shield_mode,
        };

        let accept_output =
            match crate::protocol::voip::call_key_exchange::callee_accept_with_context_and_screen_share(
                &ed_secret,
                &ed_public,
                &kyber_secret,
                kyber_pub,
                &call_init.call_id,
                &call_init.ephemeral_x25519_public,
                &call_init.kyber_ciphertext,
                &call_init.identity_ed25519_public,
                &call_init.signature,
                &call_init.key_confirmation_mac,
                &auth_context,
                call_init.screen_share.as_ref(),
                accept_screen_share.as_ref(),
            ) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };

        let proto = crate::proto::CallAccept {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            callee_device_id: Vec::new(),
            call_id: call_init.call_id.clone(),
            ephemeral_x25519_public: accept_output.ephemeral_x25519_public,
            kyber_ciphertext: accept_output.kyber_ciphertext,
            identity_ed25519_public: accept_output.identity_ed25519_public,
            signature: accept_output.signature,
            key_confirmation_mac: accept_output.key_confirmation_mac,
            screen_share: accept_screen_share.clone(),
        };
        let mut buf = Vec::new();
        if let Err(e) = proto.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("CallAccept encode: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }
        write_buffer(out_accept_bytes, buf);

        let session_meta = call_init
            .screen_share
            .clone()
            .or_else(|| accept_screen_share.clone());
        let session = match crate::protocol::voip::VoipSession::from_key_material_with_time_provider_and_screen_share(
            call_init.call_id,
            crate::protocol::voip::CallRole::Callee,
            accept_output.key_material,
            call_init.ratchet_interval_frames,
            call_init.pq_rekey_interval_secs,
            call_init.shield_mode,
            time_provider,
            session_meta,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_encrypt_frame(
    handle: *const AuraVoipSessionHandle,
    payload_type: u8,
    ssrc: u32,
    timestamp: u32,
    sequence_number: u16,
    payload: *const u8,
    payload_len: usize,
    out_frame: *mut AuraEncryptedFrame,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        unsafe {
            clear_encrypted_frame(out_frame);
        }
        if out_frame.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_frame is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if payload.is_null() || payload_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null payload",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let data = std::slice::from_raw_parts(payload, payload_len);
        let header = crate::protocol::voip::frame::FrameHeader {
            payload_type,
            ssrc,
            timestamp,
            sequence_number,
        };

        let enc = match session.encrypt_frame(&header, data) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        write_buffer(&raw mut (*out_frame).call_id, enc.call_id);
        (*out_frame).ssrc = enc.ssrc;
        (*out_frame).frame_counter = enc.frame_counter;
        (*out_frame).ratchet_generation = enc.ratchet_generation;
        write_buffer(
            &raw mut (*out_frame).encrypted_payload,
            enc.encrypted_payload,
        );
        write_buffer(&raw mut (*out_frame).nonce, enc.nonce);
        write_buffer(&raw mut (*out_frame).encrypted_header, enc.encrypted_header);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_decrypt_frame(
    handle: *const AuraVoipSessionHandle,
    call_id: *const u8,
    call_id_len: usize,
    ssrc: u32,
    frame_counter: u64,
    ratchet_generation: u32,
    encrypted_payload: *const u8,
    encrypted_payload_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    encrypted_header: *const u8,
    encrypted_header_len: usize,
    out_frame: *mut AuraDecryptedFrame,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        unsafe {
            clear_decrypted_frame(out_frame);
        }
        if out_frame.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_frame is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };

        let cid = if call_id.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(call_id, call_id_len)
        };
        let enc_payload = if encrypted_payload.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(encrypted_payload, encrypted_payload_len)
        };
        let enc_nonce = if nonce.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(nonce, nonce_len)
        };
        let enc_header = if encrypted_header.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(encrypted_header, encrypted_header_len)
        };
        if cid.len() > CALL_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "call_id too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if enc_payload.len() > MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "encrypted payload too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if enc_header.len() > MAX_VOIP_ENCRYPTED_HEADER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "encrypted header too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if enc_nonce.len() > AES_GCM_NONCE_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "nonce too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let encrypted = crate::protocol::voip::EncryptedFrame {
            call_id: cid.to_vec(),
            ssrc,
            frame_counter,
            ratchet_generation,
            encrypted_payload: enc_payload.to_vec(),
            nonce: enc_nonce.to_vec(),
            encrypted_header: enc_header.to_vec(),
        };

        let dec = match session.decrypt_frame(&encrypted) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        write_buffer(&raw mut (*out_frame).payload, dec.payload);
        (*out_frame).payload_type = dec.header.payload_type;
        (*out_frame).ssrc = dec.header.ssrc;
        (*out_frame).timestamp = dec.header.timestamp;
        (*out_frame).sequence_number = dec.header.sequence_number;
        (*out_frame).frame_counter = dec.frame_counter;
        (*out_frame).ratchet_generation = dec.ratchet_generation;
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_id(
    handle: *const AuraVoipSessionHandle,
    out_buf: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        write_buffer(out_buf, session.call_id());
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_ssrc(
    handle: *const AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> u32 {
    ffi_catch_panic_value!(0, {
        let Ok((_guard, session)) = require_voip_ref(handle, out_error) else {
            return 0;
        };
        session.ssrc()
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_is_shield_mode(
    handle: *const AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> u8 {
    ffi_catch_panic_value!(0, {
        let Ok((_guard, session)) = require_voip_ref(handle, out_error) else {
            return 0;
        };
        u8::from(session.is_shield_mode())
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_end_call(
    handle: *const AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.end_call() {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_generate_call_end_hmac(
    handle: *const AuraVoipSessionHandle,
    device_id: *const u8,
    device_id_len: usize,
    timestamp: u64,
    out_hmac: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let did = if device_id.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(device_id, device_id_len)
        };
        match session.generate_call_end_hmac(did, timestamp) {
            Ok(h) => {
                write_buffer(out_hmac, h);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_verify_call_end_hmac(
    handle: *const AuraVoipSessionHandle,
    device_id: *const u8,
    device_id_len: usize,
    timestamp: u64,
    hmac_value: *const u8,
    hmac_value_len: usize,
    out_valid: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let did = if device_id.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(device_id, device_id_len)
        };
        let hmac_bytes = if hmac_value.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(hmac_value, hmac_value_len)
        };
        match session.verify_call_end_hmac(did, timestamp, hmac_bytes) {
            Ok(is_valid) => {
                if !out_valid.is_null() {
                    *out_valid = u8::from(is_valid);
                }
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_build_call_end(
    handle: *const AuraVoipSessionHandle,
    device_id: *const u8,
    device_id_len: usize,
    timestamp: u64,
    out_buf: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let did = if device_id.is_null() {
            &[] as &[u8]
        } else {
            std::slice::from_raw_parts(device_id, device_id_len)
        };
        match session.build_call_end(did, timestamp) {
            Ok(bytes) => {
                write_buffer(out_buf, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_process_call_end(
    handle: *const AuraVoipSessionHandle,
    call_end_bytes: *const u8,
    call_end_len: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if call_end_bytes.is_null() || call_end_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null CallEnd bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let call_end = std::slice::from_raw_parts(call_end_bytes, call_end_len);
        match session.process_call_end(call_end) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_encrypt_call_control(
    handle: *const AuraVoipSessionHandle,
    control_type: u8,
    dtmf_digit: u8,
    out_frame: *mut AuraEncryptedFrame,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        unsafe {
            clear_encrypted_frame(out_frame);
        }
        if out_frame.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_frame is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let control = match control_type {
            1 => crate::protocol::voip::CallControlType::Mute,
            2 => crate::protocol::voip::CallControlType::Unmute,
            3 => crate::protocol::voip::CallControlType::Hold,
            4 => crate::protocol::voip::CallControlType::Unhold,
            5 => crate::protocol::voip::CallControlType::Dtmf(dtmf_digit),
            _ => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "unknown control type",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            }
        };
        let enc = match session.encrypt_call_control(control) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        write_buffer(&raw mut (*out_frame).call_id, enc.call_id);
        (*out_frame).ssrc = enc.ssrc;
        (*out_frame).frame_counter = enc.frame_counter;
        (*out_frame).ratchet_generation = enc.ratchet_generation;
        write_buffer(
            &raw mut (*out_frame).encrypted_payload,
            enc.encrypted_payload,
        );
        write_buffer(&raw mut (*out_frame).nonce, enc.nonce);
        write_buffer(&raw mut (*out_frame).encrypted_header, enc.encrypted_header);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_export_sealed_state(
    handle: *const AuraVoipSessionHandle,
    state_key: *const u8,
    state_key_len: usize,
    external_counter: u64,
    out_buf: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        match session.export_sealed_state(key, external_counter) {
            Ok(data) => {
                write_buffer(out_buf, data);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_export_sealed_state_with_tracker(
    handle: *const AuraVoipSessionHandle,
    state_key: *const u8,
    state_key_len: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    out_buf: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_buf.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buf is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match tracker.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let data = match session.export_sealed_state(key, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_export(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        write_buffer(out_buf, data);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_export_persisted_state(
    handle: *const AuraVoipSessionHandle,
    state_key: *const u8,
    state_key_len: usize,
    slot_handle: *mut AuraSealedStateSlotHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let external_counter = match slot.next_export_counter() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let data = match session.export_sealed_state(key, external_counter) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        match slot.note_successful_export(external_counter, data) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

pub struct AuraVoipCallInitiatorHandle {
    pub init_output: Option<crate::protocol::voip::CallInitOutput>,
    pub call_id: Vec<u8>,
    pub media_type: i32,
    pub shield_mode: bool,
    pub ratchet_interval_frames: u32,
    pub pq_rekey_interval_secs: u32,
    pub screen_share_meta: Option<ScreenShareMetadata>,
    pub time_provider: Arc<dyn ITimeProvider>,
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_init(
    identity_handle: *const AuraIdentityHandle,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    shield_mode: u8,
    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
    out_init_bytes: *mut AuraBuffer,
    out_initiator: *mut *mut AuraVoipCallInitiatorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_init_bytes.is_null() || out_initiator.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);

        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let ed_public = identity.get_identity_ed25519_public();
        let media_type = CallMediaType::CallMediaAudio as i32;

        let auth_context = crate::protocol::voip::call_key_exchange::CallInitAuthContext {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            media_type,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode: shield_mode != 0,
        };

        let init_output = match crate::protocol::voip::call_key_exchange::caller_init_with_context(
            &ed_secret,
            &ed_public,
            kyber_pub,
            &auth_context,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let is_shield = shield_mode != 0;
        let proto = crate::proto::CallInit {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            caller_device_id: Vec::new(),
            call_id: init_output.call_id.clone(),
            ephemeral_x25519_public: init_output.ephemeral_x25519_public.clone(),
            kyber_ciphertext: init_output.kyber_ciphertext.clone(),
            identity_ed25519_public: init_output.identity_ed25519_public.clone(),
            signature: init_output.signature.clone(),
            key_confirmation_mac: init_output.key_confirmation_mac.clone(),
            media_type,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode: is_shield,
            screen_share: None,
        };
        let mut buf = Vec::new();
        if let Err(e) = proto.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("CallInit encode: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }
        write_buffer(out_init_bytes, buf);

        let call_id = init_output.call_id.clone();
        let initiator = Box::new(AuraVoipCallInitiatorHandle {
            init_output: Some(init_output),
            call_id,
            media_type,
            shield_mode: is_shield,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            screen_share_meta: None,
            time_provider,
        });
        replace_out_handle(out_initiator, Box::into_raw(initiator));

        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_init_with_options(
    identity_handle: *const AuraIdentityHandle,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    media_type: i32,
    shield_mode: u8,
    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
    screen_share_width: u32,
    screen_share_height: u32,
    screen_share_frame_rate: u32,
    screen_share_codec_hint: *const u8,
    screen_share_codec_hint_len: usize,
    out_init_bytes: *mut AuraBuffer,
    out_initiator: *mut *mut AuraVoipCallInitiatorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_init_bytes.is_null() || out_initiator.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(e) = crate::protocol::voip::validate_call_media_type(media_type) {
            return write_protocol_error(out_error, &e);
        }
        let screen_share_meta = match read_optional_voip_screen_share_meta(
            screen_share_width,
            screen_share_height,
            screen_share_frame_rate,
            screen_share_codec_hint,
            screen_share_codec_hint_len,
            out_error,
        ) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let time_provider = match clone_identity_time_provider(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);

        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let ed_public = identity.get_identity_ed25519_public();

        let auth_context = crate::protocol::voip::call_key_exchange::CallInitAuthContext {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            media_type,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode: shield_mode != 0,
        };

        let init_output = match crate::protocol::voip::call_key_exchange::caller_init_with_context_and_screen_share(
            &ed_secret,
            &ed_public,
            kyber_pub,
            &auth_context,
            screen_share_meta.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let is_shield = shield_mode != 0;
        let proto = crate::proto::CallInit {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            caller_device_id: Vec::new(),
            call_id: init_output.call_id.clone(),
            ephemeral_x25519_public: init_output.ephemeral_x25519_public.clone(),
            kyber_ciphertext: init_output.kyber_ciphertext.clone(),
            identity_ed25519_public: init_output.identity_ed25519_public.clone(),
            signature: init_output.signature.clone(),
            key_confirmation_mac: init_output.key_confirmation_mac.clone(),
            media_type,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            shield_mode: is_shield,
            screen_share: screen_share_meta.clone(),
        };
        let mut buf = Vec::new();
        if let Err(e) = proto.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("CallInit encode: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }
        write_buffer(out_init_bytes, buf);

        let call_id = init_output.call_id.clone();
        let initiator = Box::new(AuraVoipCallInitiatorHandle {
            init_output: Some(init_output),
            call_id,
            media_type,
            shield_mode: is_shield,
            ratchet_interval_frames,
            pq_rekey_interval_secs,
            screen_share_meta,
            time_provider,
        });
        replace_out_handle(out_initiator, Box::into_raw(initiator));

        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_init_start(
    identity_handle: *const AuraIdentityHandle,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    shield_mode: u8,
    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
    out_init_bytes: *mut AuraBuffer,
    out_initiator: *mut *mut AuraVoipCallInitiatorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    aura_voip_call_init(
        identity_handle,
        peer_kyber_public,
        peer_kyber_public_len,
        shield_mode,
        ratchet_interval_frames,
        pq_rekey_interval_secs,
        out_init_bytes,
        out_initiator,
        out_error,
    )
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_init_start_with_options(
    identity_handle: *const AuraIdentityHandle,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    media_type: i32,
    shield_mode: u8,
    ratchet_interval_frames: u32,
    pq_rekey_interval_secs: u32,
    screen_share_width: u32,
    screen_share_height: u32,
    screen_share_frame_rate: u32,
    screen_share_codec_hint: *const u8,
    screen_share_codec_hint_len: usize,
    out_init_bytes: *mut AuraBuffer,
    out_initiator: *mut *mut AuraVoipCallInitiatorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    aura_voip_call_init_with_options(
        identity_handle,
        peer_kyber_public,
        peer_kyber_public_len,
        media_type,
        shield_mode,
        ratchet_interval_frames,
        pq_rekey_interval_secs,
        screen_share_width,
        screen_share_height,
        screen_share_frame_rate,
        screen_share_codec_hint,
        screen_share_codec_hint_len,
        out_init_bytes,
        out_initiator,
        out_error,
    )
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_init_complete(
    initiator_handle: *mut AuraVoipCallInitiatorHandle,
    identity_handle: *const AuraIdentityHandle,
    accept_bytes: *const u8,
    accept_len: usize,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if initiator_handle.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "null initiator handle",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if accept_bytes.is_null() || accept_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null CallAccept bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if accept_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "CallAccept too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let accept_data = std::slice::from_raw_parts(accept_bytes, accept_len);
        let accept = match crate::proto::CallAccept::decode(accept_data) {
            Ok(v) => v,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("CallAccept decode: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };

        if accept.version != crate::core::constants::VOIP_PROTOCOL_VERSION {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "unsupported VoIP protocol version",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Some(ref meta) = accept.screen_share {
            if let Err(e) = crate::protocol::voip::validate_screen_share_metadata(meta) {
                return write_protocol_error(out_error, &e);
            }
        }

        let initiator = &mut *initiator_handle;
        let Some(init_output) = initiator.init_output.take() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "initiator already consumed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        let auth_context = crate::protocol::voip::call_key_exchange::CallInitAuthContext {
            version: crate::core::constants::VOIP_PROTOCOL_VERSION,
            media_type: initiator.media_type,
            ratchet_interval_frames: initiator.ratchet_interval_frames,
            pq_rekey_interval_secs: initiator.pq_rekey_interval_secs,
            shield_mode: initiator.shield_mode,
        };
        let key_material =
            match crate::protocol::voip::call_key_exchange::caller_finish_with_context_and_screen_share(
                &init_output,
                &kyber_secret,
                &initiator.call_id,
                &accept.ephemeral_x25519_public,
                &accept.kyber_ciphertext,
                &accept.identity_ed25519_public,
                &accept.signature,
                &accept.key_confirmation_mac,
                &auth_context,
                accept.screen_share.as_ref(),
            ) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };

        let screen_share_meta = accept
            .screen_share
            .or_else(|| initiator.screen_share_meta.clone());
        let session = match crate::protocol::voip::VoipSession::from_key_material_with_time_provider_and_screen_share(
            initiator.call_id.clone(),
            crate::protocol::voip::CallRole::Caller,
            key_material,
            initiator.ratchet_interval_frames,
            initiator.pq_rekey_interval_secs,
            initiator.shield_mode,
            initiator.time_provider.clone(),
            screen_share_meta,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_call_initiator_destroy(
    handle_ptr: *mut *mut AuraVoipCallInitiatorHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_initiate_rekey(
    handle: *const AuraVoipSessionHandle,
    identity_handle: *const AuraIdentityHandle,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    out_rekey_bytes: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);

        match session.initiate_rekey(&ed_secret, kyber_pub) {
            Ok(bytes) => {
                write_buffer(out_rekey_bytes, bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_process_rekey(
    handle: *const AuraVoipSessionHandle,
    identity_handle: *const AuraIdentityHandle,
    peer_ed25519_public: *const u8,
    peer_ed25519_public_len: usize,
    rekey_bytes: *const u8,
    rekey_len: usize,
    peer_kyber_public: *const u8,
    peer_kyber_public_len: usize,
    out_ack_bytes: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if rekey_bytes.is_null() || rekey_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null rekey bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if rekey_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "CallRekey too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if peer_kyber_public.is_null() || peer_kyber_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer kyber public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let rekey_data = std::slice::from_raw_parts(rekey_bytes, rekey_len);
        let kyber_pub = std::slice::from_raw_parts(peer_kyber_public, peer_kyber_public_len);
        let ed_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        if peer_ed25519_public.is_null() || peer_ed25519_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer ed25519 public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let peer_ed_pub = std::slice::from_raw_parts(peer_ed25519_public, peer_ed25519_public_len);
        match session.process_rekey(
            rekey_data,
            peer_ed_pub,
            &kyber_secret,
            kyber_pub,
            &ed_secret,
        ) {
            Ok(ack_bytes) => {
                write_buffer(out_ack_bytes, ack_bytes);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_process_rekey_ack(
    handle: *const AuraVoipSessionHandle,
    identity_handle: *const AuraIdentityHandle,
    peer_ed25519_public: *const u8,
    peer_ed25519_public_len: usize,
    ack_bytes: *const u8,
    ack_len: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if ack_bytes.is_null() || ack_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null rekey ack bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if ack_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "CallRekeyAck too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let ack_data = std::slice::from_raw_parts(ack_bytes, ack_len);
        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        if peer_ed25519_public.is_null() || peer_ed25519_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer ed25519 public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let peer_ed_pub = std::slice::from_raw_parts(peer_ed25519_public, peer_ed25519_public_len);
        match session.process_rekey_ack(ack_data, peer_ed_pub, &kyber_secret) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_import_sealed_state(
    data: *const u8,
    data_len: usize,
    state_key: *const u8,
    state_key_len: usize,
    min_external_counter: u64,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if data.is_null() || data_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null sealed state data",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if data_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let state_data = std::slice::from_raw_parts(data, data_len);
        let key = std::slice::from_raw_parts(state_key, state_key_len);

        let session = match crate::protocol::voip::VoipSession::from_sealed_state(
            state_data,
            key,
            min_external_counter,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_import_sealed_state_with_time_provider(
    data: *const u8,
    data_len: usize,
    state_key: *const u8,
    state_key_len: usize,
    min_external_counter: u64,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if data.is_null() || data_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null sealed state data",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if data_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_data = std::slice::from_raw_parts(data, data_len);
        let key = std::slice::from_raw_parts(state_key, state_key_len);

        let session = match crate::protocol::voip::VoipSession::from_sealed_state_with_time_provider(
            state_data,
            key,
            min_external_counter,
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_import_sealed_state_with_tracker(
    data: *const u8,
    data_len: usize,
    state_key: *const u8,
    state_key_len: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if data.is_null() || data_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null sealed state data",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if data_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_data = std::slice::from_raw_parts(data, data_len);
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let external_counter =
            match crate::protocol::voip::VoipSession::sealed_state_external_counter(state_data) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };

        let session = match crate::protocol::voip::VoipSession::from_sealed_state(
            state_data,
            key,
            tracker.min_import_counter(),
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_import_sealed_state_with_tracker_and_time_provider(
    data: *const u8,
    data_len: usize,
    state_key: *const u8,
    state_key_len: usize,
    tracker_handle: *mut AuraSealedStateCounterTrackerHandle,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if data.is_null() || data_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null sealed state data",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if data_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let tracker = match require_counter_tracker_mut(tracker_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_data = std::slice::from_raw_parts(data, data_len);
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let external_counter =
            match crate::protocol::voip::VoipSession::sealed_state_external_counter(state_data) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };

        let session = match crate::protocol::voip::VoipSession::from_sealed_state_with_time_provider(
            state_data,
            key,
            tracker.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = tracker.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_restore_persisted_state(
    slot_handle: *mut AuraSealedStateSlotHandle,
    state_key: *const u8,
    state_key_len: usize,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if slot.is_empty() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed-state slot is empty",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let state_data = slot.sealed_state();
        if state_data.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let external_counter =
            match crate::protocol::voip::VoipSession::sealed_state_external_counter(state_data) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };
        let session = match crate::protocol::voip::VoipSession::from_sealed_state(
            state_data,
            key,
            slot.min_import_counter(),
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = slot.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_restore_persisted_state_with_time_provider(
    slot_handle: *mut AuraSealedStateSlotHandle,
    state_key: *const u8,
    state_key_len: usize,
    time_provider_handle: *const AuraTimeProviderHandle,
    out_session: *mut *mut AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if out_session.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if state_key.is_null() || state_key_len != AES_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "state key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let slot = match require_sealed_state_slot_mut(slot_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if slot.is_empty() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed-state slot is empty",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let time_provider = match clone_time_provider_or_default(time_provider_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let state_data = slot.sealed_state();
        if state_data.len() > MAX_VOIP_SIGNAL_MESSAGE_SIZE + MAX_VOIP_ENCRYPTED_PAYLOAD_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "sealed state too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let key = std::slice::from_raw_parts(state_key, state_key_len);
        let external_counter =
            match crate::protocol::voip::VoipSession::sealed_state_external_counter(state_data) {
                Ok(v) => v,
                Err(e) => return write_protocol_error(out_error, &e),
            };
        let session = match crate::protocol::voip::VoipSession::from_sealed_state_with_time_provider(
            state_data,
            key,
            slot.min_import_counter(),
            time_provider,
        ) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        if let Err(e) = slot.note_successful_restore(external_counter) {
            return write_protocol_error(out_error, &e);
        }
        replace_out_handle(
            out_session,
            Box::into_raw(Box::new(AuraVoipSessionHandle {
                inner: Some(session),
                in_use: AtomicBool::new(false),
            })),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_sealed_state_external_counter(
    data: *const u8,
    data_len: usize,
    out_external_counter: *mut u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        if data.is_null() || data_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null sealed state data",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let state_data = std::slice::from_raw_parts(data, data_len);
        match crate::protocol::voip::VoipSession::sealed_state_external_counter(state_data) {
            Ok(counter) => {
                if !out_external_counter.is_null() {
                    *out_external_counter = counter;
                }
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_session_destroy(handle_ptr: *mut *mut AuraVoipSessionHandle) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

#[repr(C)]
pub struct AuraCallStatistics {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub frames_dropped: u64,
    pub rekey_count: u32,
    pub ratchet_generation: u32,
    pub call_duration_secs: u64,
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_set_screen_share_meta(
    handle: *const AuraVoipSessionHandle,
    width: u32,
    height: u32,
    frame_rate: u32,
    codec_hint: *const u8,
    codec_hint_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let hint = if codec_hint.is_null() || codec_hint_length == 0 {
            None
        } else {
            let bytes = std::slice::from_raw_parts(codec_hint, codec_hint_length);
            if let Ok(s) = std::str::from_utf8(bytes) {
                Some(s)
            } else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "invalid UTF-8 in codec_hint",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            }
        };
        match session.set_screen_share_meta(width, height, frame_rate, hint) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_get_screen_share_meta(
    handle: *const AuraVoipSessionHandle,
    out_width: *mut u32,
    out_height: *mut u32,
    out_frame_rate: *mut u32,
    out_codec_hint: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.get_screen_share_meta() {
            Ok(Some((w, h, fr, hint))) => {
                if !out_width.is_null() {
                    *out_width = w;
                }
                if !out_height.is_null() {
                    *out_height = h;
                }
                if !out_frame_rate.is_null() {
                    *out_frame_rate = fr;
                }
                if !out_codec_hint.is_null() {
                    let hint_bytes = hint.unwrap_or_default().into_bytes();
                    write_buffer(out_codec_hint, hint_bytes);
                }
                AuraErrorCode::AuraSuccess
            }
            Ok(None) => {
                if !out_width.is_null() {
                    *out_width = 0;
                }
                if !out_height.is_null() {
                    *out_height = 0;
                }
                if !out_frame_rate.is_null() {
                    *out_frame_rate = 0;
                }
                if !out_codec_hint.is_null() {
                    write_buffer(out_codec_hint, vec![]);
                }
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_clear_screen_share_meta(
    handle: *const AuraVoipSessionHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.clear_screen_share_meta() {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_get_call_statistics(
    handle: *const AuraVoipSessionHandle,
    out_stats: *mut AuraCallStatistics,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.get_call_statistics() {
            Ok(stats) => {
                if !out_stats.is_null() {
                    *out_stats = AuraCallStatistics {
                        frames_sent: stats.frames_sent,
                        frames_received: stats.frames_received,
                        frames_dropped: stats.frames_dropped,
                        rekey_count: stats.rekey_count,
                        ratchet_generation: stats.ratchet_generation,
                        call_duration_secs: stats.call_duration_secs,
                    };
                }
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_set_recording_consent(
    handle: *const AuraVoipSessionHandle,
    consent: i32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.set_recording_consent(consent) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_get_local_recording_consent(
    handle: *const AuraVoipSessionHandle,
) -> i32 {
    ffi_catch_panic_value!(-1, {
        if handle.is_null() {
            return -1;
        }
        let Ok(_guard) = try_acquire_busy(&(*handle).in_use) else {
            return -1;
        };
        let Some(ref session) = (*handle).inner else {
            return -1;
        };
        session.get_local_recording_consent().unwrap_or(-1)
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_set_remote_recording_consent(
    handle: *const AuraVoipSessionHandle,
    consent: i32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.set_remote_recording_consent(consent) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_get_remote_recording_consent(
    handle: *const AuraVoipSessionHandle,
) -> i32 {
    ffi_catch_panic_value!(-1, {
        if handle.is_null() {
            return -1;
        }
        let Ok(_guard) = try_acquire_busy(&(*handle).in_use) else {
            return -1;
        };
        let Some(ref session) = (*handle).inner else {
            return -1;
        };
        session.get_remote_recording_consent().unwrap_or(-1)
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_both_consented_to_recording(
    handle: *const AuraVoipSessionHandle,
) -> bool {
    ffi_catch_panic_value!(false, {
        if handle.is_null() {
            return false;
        }
        let Ok(_guard) = try_acquire_busy(&(*handle).in_use) else {
            return false;
        };
        let Some(ref session) = (*handle).inner else {
            return false;
        };
        session.both_consented_to_recording().unwrap_or(false)
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_build_recording_consent_message(
    handle: *const AuraVoipSessionHandle,
    identity_handle: *const AuraIdentityHandle,
    consent: i32,
    timestamp_unix: u64,
    out_message: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ed25519_secret = match identity.get_identity_ed25519_private_key_copy() {
            Ok(secret) => secret,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        match session.build_recording_consent_message(consent, timestamp_unix, &ed25519_secret) {
            Ok(message) => {
                write_buffer(out_message, message);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_voip_process_recording_consent_message(
    handle: *const AuraVoipSessionHandle,
    peer_ed25519_public: *const u8,
    peer_ed25519_public_len: usize,
    message_bytes: *const u8,
    message_len: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        let (_guard, session) = match require_voip_ref(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if peer_ed25519_public.is_null() || peer_ed25519_public_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null peer ed25519 public key",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if message_bytes.is_null() || message_len == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "null recording consent message bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if message_len > MAX_VOIP_SIGNAL_MESSAGE_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "RecordingConsentMessage too large",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let peer_public = std::slice::from_raw_parts(peer_ed25519_public, peer_ed25519_public_len);
        let message = std::slice::from_raw_parts(message_bytes, message_len);
        match session.process_recording_consent_message(message, peer_public) {
            Ok(_) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

// ─── Session identity / ID getters ─────────────────────────────────────────

#[repr(C)]
pub struct AuraSessionPeerIdentity {
    pub ed25519_public: [u8; ED25519_PUBLIC_KEY_BYTES],
    pub x25519_public: [u8; X25519_PUBLIC_KEY_BYTES],
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_id(
    handle: *mut AuraSessionHandle,
    out_session_id: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_session_id.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_session_id is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        write_buffer(out_session_id, session.get_session_id());
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_identity_binding_hash(
    handle: *mut AuraSessionHandle,
    out_binding_hash: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_binding_hash.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_binding_hash is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        write_buffer(out_binding_hash, session.get_identity_binding_hash());
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_peer_identity(
    handle: *mut AuraSessionHandle,
    out_identity: *mut AuraSessionPeerIdentity,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_identity.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_identity is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let peer = session.get_peer_identity();
        if peer.ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || peer.x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidState,
                "Peer identity keys have unexpected length",
            );
            return AuraErrorCode::AuraErrorInvalidState;
        }
        let mut result = AuraSessionPeerIdentity {
            ed25519_public: [0u8; ED25519_PUBLIC_KEY_BYTES],
            x25519_public: [0u8; X25519_PUBLIC_KEY_BYTES],
        };
        result.ed25519_public.copy_from_slice(&peer.ed25519_public);
        result.x25519_public.copy_from_slice(&peer.x25519_public);
        *out_identity = result;
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_local_identity(
    handle: *mut AuraSessionHandle,
    out_identity: *mut AuraSessionPeerIdentity,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_identity.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_identity is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let local = session.get_local_identity();
        if local.ed25519_public.len() != ED25519_PUBLIC_KEY_BYTES
            || local.x25519_public.len() != X25519_PUBLIC_KEY_BYTES
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidState,
                "Local identity keys have unexpected length",
            );
            return AuraErrorCode::AuraErrorInvalidState;
        }
        let mut result = AuraSessionPeerIdentity {
            ed25519_public: [0u8; ED25519_PUBLIC_KEY_BYTES],
            x25519_public: [0u8; X25519_PUBLIC_KEY_BYTES],
        };
        result.ed25519_public.copy_from_slice(&local.ed25519_public);
        result.x25519_public.copy_from_slice(&local.x25519_public);
        *out_identity = result;
        AuraErrorCode::AuraSuccess
    })
}

// ─── OTK replenishment ─────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn aura_prekey_bundle_replenish(
    identity_handle: *mut AuraIdentityHandle,
    count: u32,
    out_keys: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_keys.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_keys is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if count == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "count must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let (_identity_guard, identity) = match require_identity_mut(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let pairs = match identity.replenish_one_time_pre_keys(count) {
            Ok(p) => p,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let proto_opks: Vec<OneTimePreKey> = pairs
            .into_iter()
            .map(|(id, pk)| OneTimePreKey {
                one_time_pre_key_id: id,
                public_key: pk,
            })
            .collect();
        let partial_bundle = PreKeyBundle {
            version: PROTOCOL_VERSION,
            one_time_pre_keys: proto_opks,
            ..Default::default()
        };
        let mut buf = Vec::new();
        if let Err(e) = partial_bundle.encode(&mut buf) {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorEncode,
                &format!("Failed to encode replenished OTKs: {e}"),
            );
            return AuraErrorCode::AuraErrorEncode;
        }
        write_buffer(out_keys, buf);
        AuraErrorCode::AuraSuccess
    })
}

// ─── EnvelopeMetadata parsing ──────────────────────────────────────────────

#[repr(C)]
pub struct AuraEnvelopeMetadata {
    pub envelope_type: AuraEnvelopeType,
    pub envelope_id: u32,
    pub message_index: u64,
    pub correlation_id: *mut c_char,
    pub correlation_id_length: usize,
}

#[no_mangle]
pub unsafe extern "C" fn aura_envelope_metadata_parse(
    metadata_bytes: *const u8,
    metadata_length: usize,
    out_meta: *mut AuraEnvelopeMetadata,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if metadata_bytes.is_null() || out_meta.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if metadata_length > MAX_BUFFER_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "metadata_length exceeds MAX_BUFFER_SIZE",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        // Free any FFI-owned correlation_id from a prior call to prevent leaks
        // when callers reuse the same AuraEnvelopeMetadata.
        if !(*out_meta).correlation_id.is_null() {
            drop(CString::from_raw((*out_meta).correlation_id));
            (*out_meta).correlation_id = std::ptr::null_mut();
            (*out_meta).correlation_id_length = 0;
        }
        let slice = std::slice::from_raw_parts(metadata_bytes, metadata_length);
        let proto = match crate::proto::EnvelopeMetadata::decode(slice) {
            Ok(m) => m,
            Err(e) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorDecode,
                    &format!("Failed to decode EnvelopeMetadata: {e}"),
                );
                return AuraErrorCode::AuraErrorDecode;
            }
        };
        let envelope_type = match proto.envelope_type {
            1 => AuraEnvelopeType::AuraEnvelopeResponse,
            2 => AuraEnvelopeType::AuraEnvelopeNotification,
            3 => AuraEnvelopeType::AuraEnvelopeHeartbeat,
            4 => AuraEnvelopeType::AuraEnvelopeErrorResponse,
            _ => AuraEnvelopeType::AuraEnvelopeRequest,
        };
        let (correlation_id_ptr, correlation_id_length) = match proto.correlation_id.as_ref() {
            None => (std::ptr::null_mut(), 0),
            Some(cid) => match CString::new(cid.as_str()) {
                Ok(cstr) => {
                    let len = cstr.as_bytes().len();
                    (cstr.into_raw(), len)
                }
                Err(_) => {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "correlation_id contains interior NUL byte",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                }
            },
        };
        *out_meta = AuraEnvelopeMetadata {
            envelope_type,
            envelope_id: proto.envelope_id,
            message_index: proto.message_index,
            correlation_id: correlation_id_ptr,
            correlation_id_length,
        };
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_envelope_metadata_free(meta: *mut AuraEnvelopeMetadata) {
    if meta.is_null() {
        return;
    }
    if !unsafe { (*meta).correlation_id }.is_null() {
        unsafe {
            drop(CString::from_raw((*meta).correlation_id));
            (*meta).correlation_id = std::ptr::null_mut();
            (*meta).correlation_id_length = 0;
        }
    }
}

// ─── C event callbacks — 1-to-1 session ────────────────────────────────────

pub type AuraOnHandshakeCompleted = Option<
    unsafe extern "C" fn(session_id: *const u8, session_id_len: usize, user_data: *mut c_void),
>;

pub type AuraOnRatchetRotated = Option<unsafe extern "C" fn(epoch: u64, user_data: *mut c_void)>;

pub type AuraOnSessionError = Option<
    unsafe extern "C" fn(code: AuraErrorCode, message: *const c_char, user_data: *mut c_void),
>;

pub type AuraOnNonceExhaustionWarning =
    Option<unsafe extern "C" fn(remaining: u64, max_capacity: u64, user_data: *mut c_void)>;

pub type AuraOnRatchetStallingWarning =
    Option<unsafe extern "C" fn(messages_since_ratchet: u64, user_data: *mut c_void)>;

#[repr(C)]
pub struct AuraSessionEventCallbacks {
    pub on_handshake_completed: AuraOnHandshakeCompleted,
    pub on_ratchet_rotated: AuraOnRatchetRotated,
    pub on_error: AuraOnSessionError,
    pub on_nonce_exhaustion_warning: AuraOnNonceExhaustionWarning,
    pub on_ratchet_stalling_warning: AuraOnRatchetStallingWarning,
    pub user_data: *mut c_void,
}

struct CFfiSessionEventHandler {
    callbacks: AuraSessionEventCallbacks,
}

// SAFETY: `AuraSessionEventCallbacks` contains a `*mut c_void` (`user_data`)
// and C function pointers.  The FFI contract — documented in
// `include/aura_client_api.h` alongside
// `aura_session_set_event_handler` — requires callers to supply callbacks
// and `user_data` that are themselves thread-safe.  The protocol may invoke
// these callbacks from any thread that drives ratchet/session state (not
// necessarily the thread that called `aura_session_set_event_handler`), so
// Swift/Objective-C/C# callers MUST ensure their `user_data` object is
// `Sendable`/thread-safe (e.g. wrap non-thread-safe state in a lock, or
// marshal to the UI thread inside the callback).
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for CFfiSessionEventHandler {}
unsafe impl Sync for CFfiSessionEventHandler {}

impl IProtocolEventHandler for CFfiSessionEventHandler {
    fn on_handshake_completed(&self, session_id: &[u8]) {
        if let Some(cb) = self.callbacks.on_handshake_completed {
            invoke_c_callback!(cb(
                session_id.as_ptr(),
                session_id.len(),
                self.callbacks.user_data,
            ));
        }
    }

    fn on_ratchet_rotated(&self, epoch: u64) {
        if let Some(cb) = self.callbacks.on_ratchet_rotated {
            invoke_c_callback!(cb(epoch, self.callbacks.user_data));
        }
    }

    fn on_error(&self, error: &ProtocolError) {
        if let Some(cb) = self.callbacks.on_error {
            let code = error_code_from_protocol(error);
            let msg = CString::new(error.to_string()).unwrap_or_default();
            invoke_c_callback!(cb(code, msg.as_ptr(), self.callbacks.user_data));
        }
    }

    fn on_nonce_exhaustion_warning(&self, remaining: u64, max_capacity: u64) {
        if let Some(cb) = self.callbacks.on_nonce_exhaustion_warning {
            invoke_c_callback!(cb(remaining, max_capacity, self.callbacks.user_data));
        }
    }

    fn on_ratchet_stalling_warning(&self, messages_since_ratchet: u64) {
        if let Some(cb) = self.callbacks.on_ratchet_stalling_warning {
            invoke_c_callback!(cb(messages_since_ratchet, self.callbacks.user_data));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_set_event_handler(
    handle: *mut AuraSessionHandle,
    callbacks: *const AuraSessionEventCallbacks,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "callbacks is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiSessionEventHandler { callbacks: cbs });
        session.set_event_handler(handler);
        AuraErrorCode::AuraSuccess
    })
}

// ─── C event callbacks — group session ─────────────────────────────────────

pub type AuraOnMemberAdded = Option<
    unsafe extern "C" fn(
        leaf_index: u32,
        identity_ed25519: *const u8,
        identity_ed25519_len: usize,
        user_data: *mut c_void,
    ),
>;

pub type AuraOnMemberRemoved =
    Option<unsafe extern "C" fn(leaf_index: u32, user_data: *mut c_void)>;

pub type AuraOnEpochAdvanced =
    Option<unsafe extern "C" fn(new_epoch: u64, member_count: u32, user_data: *mut c_void)>;

pub type AuraOnSenderKeyExhaustionWarning =
    Option<unsafe extern "C" fn(remaining: u32, max_capacity: u32, user_data: *mut c_void)>;

pub type AuraOnReInitProposed = Option<
    unsafe extern "C" fn(
        new_group_id: *const u8,
        new_group_id_len: usize,
        new_version: u32,
        user_data: *mut c_void,
    ),
>;

#[repr(C)]
pub struct AuraGroupEventCallbacks {
    pub on_member_added: AuraOnMemberAdded,
    pub on_member_removed: AuraOnMemberRemoved,
    pub on_epoch_advanced: AuraOnEpochAdvanced,
    pub on_sender_key_exhaustion_warning: AuraOnSenderKeyExhaustionWarning,
    pub on_reinit_proposed: AuraOnReInitProposed,
    pub user_data: *mut c_void,
}

struct CFfiGroupEventHandler {
    callbacks: AuraGroupEventCallbacks,
}

// SAFETY: See comment on `CFfiSessionEventHandler` — the caller is
// responsible for supplying thread-safe callbacks and `user_data`.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for CFfiGroupEventHandler {}
unsafe impl Sync for CFfiGroupEventHandler {}

impl IGroupEventHandler for CFfiGroupEventHandler {
    fn on_member_added(&self, leaf_index: u32, identity_ed25519: &[u8]) {
        if let Some(cb) = self.callbacks.on_member_added {
            invoke_c_callback!(cb(
                leaf_index,
                identity_ed25519.as_ptr(),
                identity_ed25519.len(),
                self.callbacks.user_data,
            ));
        }
    }

    fn on_member_removed(&self, leaf_index: u32) {
        if let Some(cb) = self.callbacks.on_member_removed {
            invoke_c_callback!(cb(leaf_index, self.callbacks.user_data));
        }
    }

    fn on_epoch_advanced(&self, new_epoch: u64, member_count: u32) {
        if let Some(cb) = self.callbacks.on_epoch_advanced {
            invoke_c_callback!(cb(new_epoch, member_count, self.callbacks.user_data));
        }
    }

    fn on_sender_key_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
        if let Some(cb) = self.callbacks.on_sender_key_exhaustion_warning {
            invoke_c_callback!(cb(remaining, max_capacity, self.callbacks.user_data));
        }
    }

    fn on_reinit_proposed(&self, new_group_id: &[u8], new_version: u32) {
        if let Some(cb) = self.callbacks.on_reinit_proposed {
            invoke_c_callback!(cb(
                new_group_id.as_ptr(),
                new_group_id.len(),
                new_version,
                self.callbacks.user_data,
            ));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_group_set_event_handler(
    handle: *mut AuraGroupSessionHandle,
    callbacks: *const AuraGroupEventCallbacks,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "callbacks is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_group_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiGroupEventHandler { callbacks: cbs });
        session.set_event_handler(handler);
        AuraErrorCode::AuraSuccess
    })
}

// ─── C event callbacks — identity ──────────────────────────────────────────

pub type AuraOnOtkExhaustionWarning =
    Option<unsafe extern "C" fn(remaining: u32, max_capacity: u32, user_data: *mut c_void)>;

#[repr(C)]
pub struct AuraIdentityEventCallbacks {
    pub on_otk_exhaustion_warning: AuraOnOtkExhaustionWarning,
    pub user_data: *mut c_void,
}

struct CFfiIdentityEventHandler {
    callbacks: AuraIdentityEventCallbacks,
}

// SAFETY: See comment on `CFfiSessionEventHandler` — the caller is
// responsible for supplying thread-safe callbacks and `user_data`.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for CFfiIdentityEventHandler {}
unsafe impl Sync for CFfiIdentityEventHandler {}

impl IIdentityEventHandler for CFfiIdentityEventHandler {
    fn on_otk_exhaustion_warning(&self, remaining: u32, max_capacity: u32) {
        if let Some(cb) = self.callbacks.on_otk_exhaustion_warning {
            invoke_c_callback!(cb(remaining, max_capacity, self.callbacks.user_data));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn aura_identity_set_event_handler(
    handle: *mut AuraIdentityHandle,
    callbacks: *const AuraIdentityEventCallbacks,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if callbacks.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "callbacks is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_identity_guard, identity) = match require_identity_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let cbs = std::ptr::read(callbacks);
        let handler = Arc::new(CFfiIdentityEventHandler { callbacks: cbs });
        identity.set_event_handler(handler);
        AuraErrorCode::AuraSuccess
    })
}

// ── Attachment v2: Thumbnail ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_encrypt_thumbnail(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    thumbnail_mime_type: *const u8,
    thumbnail_mime_type_length: usize,
    thumbnail_plaintext: *const u8,
    thumbnail_plaintext_length: usize,
    out_nonce: *mut AuraBuffer,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || thumbnail_mime_type.is_null()
            || thumbnail_plaintext.is_null()
            || out_nonce.is_null()
            || out_ciphertext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if file_key_length != ATTACHMENT_FILE_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "file_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "attachment_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if thumbnail_plaintext_length == 0
            || thumbnail_plaintext_length > MAX_ATTACHMENT_THUMBNAIL_SIZE
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Thumbnail size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let fk = std::slice::from_raw_parts(file_key, file_key_length);
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_bytes =
            std::slice::from_raw_parts(thumbnail_mime_type, thumbnail_mime_type_length);
        let Ok(mime) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid UTF-8 mime_type",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let plaintext = std::slice::from_raw_parts(thumbnail_plaintext, thumbnail_plaintext_length);

        match crate::protocol::attachment::encrypt_thumbnail(fk, aid, mime, plaintext) {
            Ok((nonce, ct)) => {
                write_buffer(out_nonce, nonce);
                write_buffer(out_ciphertext, ct);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_decrypt_thumbnail(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    thumbnail_mime_type: *const u8,
    thumbnail_mime_type_length: usize,
    nonce: *const u8,
    nonce_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || thumbnail_mime_type.is_null()
            || nonce.is_null()
            || ciphertext.is_null()
            || out_plaintext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if file_key_length != ATTACHMENT_FILE_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "file_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "attachment_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if nonce_length != AES_GCM_NONCE_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "nonce must be 12 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let fk = std::slice::from_raw_parts(file_key, file_key_length);
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_bytes =
            std::slice::from_raw_parts(thumbnail_mime_type, thumbnail_mime_type_length);
        let Ok(mime) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid UTF-8 mime_type",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let nonce_slice = std::slice::from_raw_parts(nonce, nonce_length);
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);

        match crate::protocol::attachment::decrypt_thumbnail(fk, aid, mime, nonce_slice, ct) {
            Ok(pt) => {
                write_buffer(out_plaintext, pt);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

// ── Attachment v2: TTL ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_validate_ttl(
    ttl_seconds: u64,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, {
        match crate::protocol::attachment::validate_ttl(ttl_seconds) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => unsafe { write_protocol_error(out_error, &e) },
        }
    })
}

#[no_mangle]
pub const extern "C" fn aura_attachment_is_expired(
    created_at_unix: u64,
    ttl_seconds: u64,
    now_unix: u64,
) -> bool {
    crate::protocol::attachment::is_attachment_expired(created_at_unix, ttl_seconds, now_unix)
}

// ── Attachment v2: Progress ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_progress_create(
    attachment_id: *const u8,
    attachment_id_length: usize,
    chunk_count: u32,
    out_progress: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if attachment_id.is_null() || out_progress.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "attachment_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        match crate::protocol::attachment::create_chunk_progress(aid, chunk_count) {
            Ok(progress) => {
                let mut buf = Vec::new();
                if let Err(e) = progress.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("ChunkProgress encode: {e}")),
                    );
                }
                write_buffer(out_progress, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_progress_mark_completed(
    progress_bytes: *const u8,
    progress_length: usize,
    chunk_index: u32,
    bytes_transferred: u64,
    now_unix: u64,
    out_updated_progress: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if progress_bytes.is_null() || out_updated_progress.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let pbytes = std::slice::from_raw_parts(progress_bytes, progress_length);
        let mut progress = match ChunkProgress::decode(pbytes) {
            Ok(v) => v,
            Err(e) => {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode(format!("ChunkProgress decode: {e}")),
                );
            }
        };

        if let Err(e) = crate::protocol::attachment::mark_chunk_completed(
            &mut progress,
            chunk_index,
            bytes_transferred,
            now_unix,
        ) {
            return write_protocol_error(out_error, &e);
        }

        let mut buf = Vec::new();
        if let Err(e) = progress.encode(&mut buf) {
            return write_protocol_error(
                out_error,
                &ProtocolError::encode(format!("ChunkProgress encode: {e}")),
            );
        }
        write_buffer(out_updated_progress, buf);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_progress_get_remaining(
    progress_bytes: *const u8,
    progress_length: usize,
    out_remaining: *mut AuraBuffer,
    out_remaining_count: *mut u32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if progress_bytes.is_null() || out_remaining.is_null() || out_remaining_count.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }

        let pbytes = std::slice::from_raw_parts(progress_bytes, progress_length);
        let progress = match ChunkProgress::decode(pbytes) {
            Ok(v) => v,
            Err(e) => {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode(format!("ChunkProgress decode: {e}")),
                );
            }
        };

        let remaining = match crate::protocol::attachment::get_remaining_chunks(&progress) {
            Ok(v) => v,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        *out_remaining_count = u32::try_from(remaining.len()).unwrap_or(0);
        let bytes: Vec<u8> = remaining.iter().flat_map(|i| i.to_le_bytes()).collect();
        write_buffer(out_remaining, bytes);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_progress_is_complete(
    progress_bytes: *const u8,
    progress_length: usize,
) -> bool {
    ffi_catch_panic_value!(false, {
        if progress_bytes.is_null() || progress_length == 0 {
            return false;
        }
        let pbytes = unsafe { std::slice::from_raw_parts(progress_bytes, progress_length) };
        let Ok(progress) = ChunkProgress::decode(pbytes) else {
            return false;
        };
        crate::protocol::attachment::is_transfer_complete(&progress)
    })
}

// ── Attachment v2: Collage ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_generate_collage_id(
    out_collage_id: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_collage_id.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_collage_id is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        write_buffer(
            out_collage_id,
            crate::protocol::attachment::generate_collage_id(),
        );
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_collage_create(
    manifest_array: *const *const u8,
    manifest_lengths: *const usize,
    manifest_count: usize,
    out_collage: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if manifest_array.is_null() || manifest_lengths.is_null() || out_collage.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if manifest_count == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "manifest_count must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if manifest_count > MAX_COLLAGE_ATTACHMENTS {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "manifest_count exceeds maximum",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let ptrs = std::slice::from_raw_parts(manifest_array, manifest_count);
        let lens = std::slice::from_raw_parts(manifest_lengths, manifest_count);

        let mut manifests = Vec::with_capacity(manifest_count);
        for i in 0..manifest_count {
            if ptrs[i].is_null() {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorNullPointer,
                    "manifest pointer is null",
                );
                return AuraErrorCode::AuraErrorNullPointer;
            }
            if let Err(code) =
                ensure_ffi_len_at_most(out_error, lens[i], MAX_ATTACHMENT_MANIFEST_SIZE, "manifest")
            {
                return code;
            }
            let bytes = std::slice::from_raw_parts(ptrs[i], lens[i]);
            let m = match AttachmentManifest::decode(bytes) {
                Ok(v) => v,
                Err(e) => {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::decode(format!("Manifest decode: {e}")),
                    );
                }
            };
            manifests.push(m);
        }

        match crate::protocol::attachment::create_collage_manifest(&manifests) {
            Ok(collage) => {
                let mut buf = Vec::new();
                if let Err(e) = collage.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("CollageManifest encode: {e}")),
                    );
                }
                write_buffer(out_collage, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_collage_validate(
    collage_bytes: *const u8,
    collage_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if collage_bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "collage_bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if collage_length == 0 || collage_length > MAX_COLLAGE_MANIFEST_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Collage size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let bytes = std::slice::from_raw_parts(collage_bytes, collage_length);
        let collage = match CollageManifest::decode(bytes) {
            Ok(v) => v,
            Err(e) => {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode(format!("CollageManifest decode: {e}")),
                );
            }
        };
        match crate::protocol::attachment::validate_collage_manifest(&collage) {
            Ok(_) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

// ── Attachment v2: Streaming ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_encryptor_create(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const u8,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    out_handle: *mut *mut AuraStreamingEncryptorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || mime_type.is_null()
            || out_handle.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            file_key_length,
            ATTACHMENT_FILE_KEY_BYTES,
            "file_key",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            attachment_id_length,
            ATTACHMENT_ID_BYTES,
            "attachment_id",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, mime_type_length, 255, "mime_type") {
            return code;
        }

        let fk = std::slice::from_raw_parts(file_key, file_key_length).to_vec();
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length).to_vec();
        let mime_bytes = std::slice::from_raw_parts(mime_type, mime_type_length);
        let Ok(mime_str) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid UTF-8 mime_type",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let mime = mime_str.to_string();

        match StreamingEncryptor::new(fk, aid, mime, total_size, chunk_size, chunk_count) {
            Ok(enc) => {
                let handle = Box::new(AuraStreamingEncryptorHandle {
                    inner: Some(enc),
                    in_use: AtomicBool::new(false),
                });
                replace_out_handle(out_handle, Box::into_raw(handle));
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_encryptor_write(
    handle: *mut AuraStreamingEncryptorHandle,
    data: *const u8,
    data_length: usize,
    out_chunks: *mut AuraBuffer,
    out_chunk_count: *mut u32,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || data.is_null() || out_chunks.is_null() || out_chunk_count.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let _guard = match try_acquire_busy(&(*handle).in_use) {
            Ok(g) => g,
            Err(()) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorBusy,
                    "streaming encryptor handle is already in use by another call",
                );
                return AuraErrorCode::AuraErrorBusy;
            }
        };

        let Some(enc) = (*handle).inner.as_mut() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "Encryptor disposed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };
        if let Err(code) = ensure_ffi_len_at_most(out_error, data_length, MAX_BUFFER_SIZE, "data") {
            return code;
        }

        let input = std::slice::from_raw_parts(data, data_length);
        match enc.write(input) {
            Ok(chunks) => {
                *out_chunk_count = u32::try_from(chunks.len()).unwrap_or(0);
                let serialized = serialize_encrypted_chunks(&chunks);
                write_buffer(out_chunks, serialized);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_encryptor_finish(
    handle: *mut AuraStreamingEncryptorHandle,
    out_chunk: *mut AuraBuffer,
    out_has_chunk: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || out_chunk.is_null() || out_has_chunk.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let _guard = match try_acquire_busy(&(*handle).in_use) {
            Ok(g) => g,
            Err(()) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorBusy,
                    "streaming encryptor handle is already in use by another call",
                );
                return AuraErrorCode::AuraErrorBusy;
            }
        };

        let Some(enc) = (*handle).inner.take() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "Encryptor disposed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        match enc.finish() {
            Ok(Some(chunk)) => {
                *out_has_chunk = 1;
                let serialized = serialize_encrypted_chunks(&[chunk]);
                write_buffer(out_chunk, serialized);
                AuraErrorCode::AuraSuccess
            }
            Ok(None) => {
                *out_has_chunk = 0;
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle
/// from `aura_attachment_streaming_encryptor_create`, or be null.  After this
/// call the stored handle pointer is set to null so subsequent calls from the
/// same site are no-ops (prevents double-free).
#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_encryptor_destroy(
    handle_ptr: *mut *mut AuraStreamingEncryptorHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

fn serialize_encrypted_chunks(chunks: &[crate::protocol::attachment::EncryptedChunk]) -> Vec<u8> {
    let mut buf = Vec::new();
    for c in chunks {
        buf.extend_from_slice(&c.chunk_index.to_le_bytes());
        buf.extend_from_slice(&u32::try_from(c.nonce.len()).unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(&c.nonce);
        buf.extend_from_slice(&u32::try_from(c.ciphertext.len()).unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(&c.ciphertext);
    }
    buf
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_decryptor_create(
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const u8,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    out_handle: *mut *mut AuraStreamingDecryptorHandle,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if file_key.is_null()
            || attachment_id.is_null()
            || mime_type.is_null()
            || out_handle.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            file_key_length,
            ATTACHMENT_FILE_KEY_BYTES,
            "file_key",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            attachment_id_length,
            ATTACHMENT_ID_BYTES,
            "attachment_id",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, mime_type_length, 255, "mime_type") {
            return code;
        }

        let fk = std::slice::from_raw_parts(file_key, file_key_length).to_vec();
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length).to_vec();
        let mime_bytes = std::slice::from_raw_parts(mime_type, mime_type_length);
        let Ok(mime_str) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid UTF-8 mime_type",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let mime = mime_str.to_string();

        match StreamingDecryptor::new(fk, aid, mime, total_size, chunk_size, chunk_count) {
            Ok(dec) => {
                let handle = Box::new(AuraStreamingDecryptorHandle {
                    inner: Some(dec),
                    in_use: AtomicBool::new(false),
                });
                replace_out_handle(out_handle, Box::into_raw(handle));
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_decryptor_write(
    handle: *mut AuraStreamingDecryptorHandle,
    chunk_index: u32,
    nonce: *const u8,
    nonce_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
    out_plaintext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null() || nonce.is_null() || ciphertext.is_null() || out_plaintext.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let _guard = match try_acquire_busy(&(*handle).in_use) {
            Ok(g) => g,
            Err(()) => {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorBusy,
                    "streaming decryptor handle is already in use by another call",
                );
                return AuraErrorCode::AuraErrorBusy;
            }
        };

        let Some(dec) = (*handle).inner.as_mut() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "Decryptor disposed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };
        if let Err(code) =
            ensure_ffi_len_exact(out_error, nonce_length, AES_GCM_NONCE_BYTES, "nonce")
        {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            ciphertext_length,
            MAX_ATTACHMENT_CHUNK_SIZE + 16,
            "ciphertext",
        ) {
            return code;
        }

        let nonce_slice = std::slice::from_raw_parts(nonce, nonce_length);
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length);

        match dec.decrypt_next(chunk_index, nonce_slice, ct) {
            Ok(pt) => {
                write_buffer(out_plaintext, pt);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_decryptor_is_complete(
    handle: *mut AuraStreamingDecryptorHandle,
) -> bool {
    ffi_catch_panic_value!(false, {
        if handle.is_null() {
            return false;
        }
        let Ok(_guard) = try_acquire_busy(unsafe { &(*handle).in_use }) else {
            return false;
        };
        let dec = unsafe { &*handle };
        dec.inner
            .as_ref()
            .is_some_and(StreamingDecryptor::is_complete)
    })
}

/// # Safety
/// See module-level FFI safety contract.  `handle_ptr` must point to a handle
/// from `aura_attachment_streaming_decryptor_create`, or be null.  After this
/// call the stored handle pointer is set to null so subsequent calls from the
/// same site are no-ops (prevents double-free).
#[no_mangle]
pub unsafe extern "C" fn aura_attachment_streaming_decryptor_destroy(
    handle_ptr: *mut *mut AuraStreamingDecryptorHandle,
) {
    ffi_catch_panic_value!((), unsafe {
        if handle_ptr.is_null() {
            return;
        }
        let handle = std::ptr::replace(handle_ptr, std::ptr::null_mut());
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    });
}

// ── Attachment v2: Manifest v2 ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_manifest_create_v2(
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const u8,
    mime_type_length: usize,
    total_size: u64,
    chunk_size: u32,
    chunk_count: u32,
    file_sha256: *const u8,
    file_sha256_length: usize,
    encrypted_file_key: *const u8,
    encrypted_file_key_length: usize,
    collage_index: i64,
    thumbnail_ciphertext: *const u8,
    thumbnail_ciphertext_length: usize,
    thumbnail_nonce: *const u8,
    thumbnail_nonce_length: usize,
    thumbnail_mime_type: *const u8,
    thumbnail_mime_type_length: usize,
    thumbnail_original_size: u32,
    ttl_seconds: u64,
    created_at_unix: u64,
    out_manifest: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if attachment_id.is_null()
            || mime_type.is_null()
            || file_sha256.is_null()
            || encrypted_file_key.is_null()
            || out_manifest.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES
            || file_sha256_length != ATTACHMENT_HASH_BYTES
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "ID and SHA-256 must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if encrypted_file_key_length == 0
            || encrypted_file_key_length > MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "encrypted_file_key size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, mime_type_length, 255, "mime_type") {
            return code;
        }

        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_bytes = std::slice::from_raw_parts(mime_type, mime_type_length);
        let Ok(mime_s) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "Invalid UTF-8 mime_type",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let mime_str = mime_s.to_string();
        let sha = std::slice::from_raw_parts(file_sha256, file_sha256_length);
        let efk = std::slice::from_raw_parts(encrypted_file_key, encrypted_file_key_length);

        let has_thumbnail = thumbnail_ciphertext_length > 0
            || thumbnail_nonce_length > 0
            || thumbnail_mime_type_length > 0
            || thumbnail_original_size > 0;
        if has_thumbnail
            && (thumbnail_ciphertext.is_null()
                || thumbnail_nonce.is_null()
                || thumbnail_mime_type.is_null())
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "Thumbnail pointers must be non-null when thumbnail fields are present",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if has_thumbnail {
            if let Err(code) = ensure_ffi_len_at_most(
                out_error,
                thumbnail_ciphertext_length,
                MAX_ATTACHMENT_THUMBNAIL_SIZE,
                "thumbnail_ciphertext",
            ) {
                return code;
            }
            if let Err(code) = ensure_ffi_len_exact(
                out_error,
                thumbnail_nonce_length,
                AES_GCM_NONCE_BYTES,
                "thumbnail_nonce",
            ) {
                return code;
            }
            if let Err(code) = ensure_ffi_len_at_most(
                out_error,
                thumbnail_mime_type_length,
                255,
                "thumbnail_mime_type",
            ) {
                return code;
            }
        }

        let has_ttl = ttl_seconds > 0;

        let manifest = AttachmentManifest {
            version: ATTACHMENT_PROTOCOL_VERSION,
            attachment_id: aid.to_vec(),
            mime_type: mime_str,
            total_size,
            chunk_size,
            chunk_count,
            file_sha256: sha.to_vec(),
            encrypted_file_key: efk.to_vec(),
            encryption_scheme: "AES-256-GCM-SIV".to_string(),
            collage_index: if collage_index >= 0 {
                Some(u32::try_from(collage_index).unwrap_or(0))
            } else {
                None
            },
            encrypted_thumbnail: if has_thumbnail {
                Some(
                    std::slice::from_raw_parts(thumbnail_ciphertext, thumbnail_ciphertext_length)
                        .to_vec(),
                )
            } else {
                None
            },
            thumbnail_nonce: if has_thumbnail && !thumbnail_nonce.is_null() {
                Some(std::slice::from_raw_parts(thumbnail_nonce, thumbnail_nonce_length).to_vec())
            } else {
                None
            },
            thumbnail_mime_type: if has_thumbnail && !thumbnail_mime_type.is_null() {
                let tb =
                    std::slice::from_raw_parts(thumbnail_mime_type, thumbnail_mime_type_length);
                let Ok(ts) = std::str::from_utf8(tb) else {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "thumbnail_mime_type is not valid UTF-8",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                };
                Some(ts.to_string())
            } else {
                None
            },
            thumbnail_size: if has_thumbnail {
                Some(thumbnail_original_size)
            } else {
                None
            },
            ttl_seconds: if has_ttl { Some(ttl_seconds) } else { None },
            created_at_unix: if has_ttl { Some(created_at_unix) } else { None },
            original_filename: None,
            media_width: None,
            media_height: None,
            duration_ms: None,
            alt_text: None,
            content_policy: None,
            voice_meta: None,
        };

        if let Err(e) = crate::protocol::attachment::validate_manifest(&manifest) {
            return write_protocol_error(out_error, &e);
        }

        let mut buf = Vec::new();
        if let Err(e) = manifest.encode(&mut buf) {
            return write_protocol_error(
                out_error,
                &ProtocolError::encode(format!("AttachmentManifest encode: {e}")),
            );
        }
        write_buffer(out_manifest, buf);
        AuraErrorCode::AuraSuccess
    })
}

// ── Attachment v2: File Key Helper ──

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_encrypt_file_key(
    handle: *mut AuraSessionHandle,
    file_key: *const u8,
    file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    out_encrypted_file_key: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null()
            || file_key.is_null()
            || attachment_id.is_null()
            || out_encrypted_file_key.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if file_key_length != ATTACHMENT_FILE_KEY_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "file_key must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "attachment_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let Some(session) = (*handle).inner.as_ref() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "Session disposed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        let fk = std::slice::from_raw_parts(file_key, file_key_length);
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);

        match crate::protocol::attachment::encrypt_file_key_for_session(session, fk, aid) {
            Ok(encrypted) => {
                write_buffer(out_encrypted_file_key, encrypted);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_decrypt_file_key(
    handle: *mut AuraSessionHandle,
    encrypted_file_key: *const u8,
    encrypted_file_key_length: usize,
    attachment_id: *const u8,
    attachment_id_length: usize,
    out_file_key: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if handle.is_null()
            || encrypted_file_key.is_null()
            || attachment_id.is_null()
            || out_file_key.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if attachment_id_length != ATTACHMENT_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "attachment_id must be 32 bytes",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if encrypted_file_key_length > MAX_ATTACHMENT_ENCRYPTED_FILE_KEY_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "encrypted_file_key size is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }

        let Some(session) = (*handle).inner.as_ref() else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorObjectDisposed,
                "Session disposed",
            );
            return AuraErrorCode::AuraErrorObjectDisposed;
        };

        let efk = std::slice::from_raw_parts(encrypted_file_key, encrypted_file_key_length);
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);

        match crate::protocol::attachment::decrypt_file_key_from_session(session, efk, aid) {
            Ok(key) => {
                write_buffer(out_file_key, key);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_validate_magic_bytes(
    header: *const u8,
    header_length: usize,
    mime_type: *const u8,
    mime_type_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if header.is_null() || mime_type.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, mime_type_length, 255, "mime_type") {
            return code;
        }
        let header_slice = std::slice::from_raw_parts(header, header_length);
        let mime_bytes = std::slice::from_raw_parts(mime_type, mime_type_length);
        let Ok(mime_str) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "mime_type is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        match crate::protocol::attachment::validate_magic_bytes(header_slice, mime_str) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_detect_mime(
    header: *const u8,
    header_length: usize,
    out_mime: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if header.is_null() || out_mime.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) =
            ensure_ffi_len_at_most(out_error, header_length, MAX_BUFFER_SIZE, "header")
        {
            return code;
        }
        let header_slice = std::slice::from_raw_parts(header, header_length);
        let buf = crate::protocol::attachment::detect_mime_from_magic(header_slice)
            .map_or_else(Vec::new, |mime| mime.as_bytes().to_vec());
        write_buffer(out_mime, buf);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_validate_filename(
    name: *const u8,
    name_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if name.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "name is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            name_length,
            MAX_ATTACHMENT_FILENAME_BYTES,
            "name",
        ) {
            return code;
        }
        let name_bytes = std::slice::from_raw_parts(name, name_length);
        let Ok(name_str) = std::str::from_utf8(name_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "name is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        match crate::protocol::attachment::validate_filename(name_str) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_sanitize_filename(
    name: *const u8,
    name_length: usize,
    out_sanitized: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if name.is_null() || out_sanitized.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, name_length, MAX_BUFFER_SIZE, "name") {
            return code;
        }
        let name_bytes = std::slice::from_raw_parts(name, name_length);
        let Ok(name_str) = std::str::from_utf8(name_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "name is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let sanitized = crate::protocol::attachment::sanitize_filename(name_str);
        write_buffer(out_sanitized, sanitized.into_bytes());
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_collage_create_with_metadata(
    manifest_array: *const *const u8,
    manifest_lengths: *const usize,
    manifest_count: usize,
    name: *const u8,
    name_length: usize,
    description: *const u8,
    description_length: usize,
    layout: i32,
    out_collage: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if manifest_array.is_null() || manifest_lengths.is_null() || out_collage.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if manifest_count == 0 {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "manifest_count must be > 0",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if manifest_count > MAX_COLLAGE_ATTACHMENTS {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "manifest_count exceeds maximum",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            name_length,
            max_utf8_bytes(MAX_COLLAGE_NAME_CHARS),
            "name",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            description_length,
            max_utf8_bytes(MAX_COLLAGE_DESCRIPTION_CHARS),
            "description",
        ) {
            return code;
        }

        let ptrs = std::slice::from_raw_parts(manifest_array, manifest_count);
        let lens = std::slice::from_raw_parts(manifest_lengths, manifest_count);

        let mut manifests = Vec::with_capacity(manifest_count);
        for i in 0..manifest_count {
            if ptrs[i].is_null() {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorNullPointer,
                    "manifest pointer is null",
                );
                return AuraErrorCode::AuraErrorNullPointer;
            }
            if let Err(code) =
                ensure_ffi_len_at_most(out_error, lens[i], MAX_ATTACHMENT_MANIFEST_SIZE, "manifest")
            {
                return code;
            }
            let bytes = std::slice::from_raw_parts(ptrs[i], lens[i]);
            let Ok(m) = AttachmentManifest::decode(bytes) else {
                return write_protocol_error(
                    out_error,
                    &ProtocolError::decode("Manifest decode failed".to_string()),
                );
            };
            manifests.push(m);
        }

        let name_opt = if !name.is_null() && name_length > 0 {
            let nb = std::slice::from_raw_parts(name, name_length);
            let Ok(s) = std::str::from_utf8(nb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "name is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(s)
        } else {
            None
        };
        let desc_opt = if !description.is_null() && description_length > 0 {
            let db = std::slice::from_raw_parts(description, description_length);
            let Ok(s) = std::str::from_utf8(db) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "description is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(s)
        } else {
            None
        };
        let layout_opt = if layout >= 0 { Some(layout) } else { None };

        match crate::protocol::attachment::create_collage_manifest_with_metadata(
            &manifests, name_opt, desc_opt, layout_opt,
        ) {
            Ok(collage) => {
                let mut buf = Vec::new();
                if let Err(e) = collage.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("CollageManifest encode: {e}")),
                    );
                }
                write_buffer(out_collage, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_inline_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) =
            ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "InlineAttachment")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = InlineAttachment::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("InlineAttachment decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_inline_attachment(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_inline_create(
    attachment_id: *const u8,
    attachment_id_length: usize,
    mime_type: *const u8,
    mime_type_length: usize,
    data: *const u8,
    data_length: usize,
    original_filename: *const u8,
    original_filename_length: usize,
    has_content_policy: u8,
    view_once: u8,
    no_forward: u8,
    no_save: u8,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if attachment_id.is_null() || mime_type.is_null() || data.is_null() || out_buffer.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            attachment_id_length,
            ATTACHMENT_ID_BYTES,
            "attachment_id",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, mime_type_length, 255, "mime_type") {
            return code;
        }
        if data_length == 0 || data_length > MAX_INLINE_ATTACHMENT_DATA_SIZE {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "data length is out of range",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            original_filename_length,
            MAX_ATTACHMENT_FILENAME_BYTES,
            "filename",
        ) {
            return code;
        }
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let mime_bytes = std::slice::from_raw_parts(mime_type, mime_type_length);
        let Ok(mime_str) = std::str::from_utf8(mime_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "mime_type is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let data_slice = std::slice::from_raw_parts(data, data_length);
        let filename = if !original_filename.is_null() && original_filename_length > 0 {
            let fb = std::slice::from_raw_parts(original_filename, original_filename_length);
            let Ok(fs) = std::str::from_utf8(fb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "filename is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(fs.to_string())
        } else {
            None
        };
        let policy = if has_content_policy != 0 {
            Some(ContentPolicy {
                view_once: view_once != 0,
                no_forward: no_forward != 0,
                no_save: no_save != 0,
            })
        } else {
            None
        };
        match crate::protocol::attachment::create_inline_attachment(
            aid.to_vec(),
            mime_str.to_string(),
            data_slice.to_vec(),
            filename,
            policy,
        ) {
            Ok(inline) => {
                let mut buf = Vec::new();
                if let Err(e) = inline.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("InlineAttachment encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_reference_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) =
            ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "AttachmentReference")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = AttachmentReference::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("AttachmentReference decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_attachment_reference(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_reference_create(
    attachment_id: *const u8,
    attachment_id_length: usize,
    reference_type: i32,
    source_message_id: *const u8,
    source_message_id_length: usize,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if attachment_id.is_null() || out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_exact(
            out_error,
            attachment_id_length,
            ATTACHMENT_ID_BYTES,
            "attachment_id",
        ) {
            return code;
        }
        if !source_message_id.is_null() || source_message_id_length > 0 {
            if source_message_id.is_null() {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorNullPointer,
                    "source_message_id is null",
                );
                return AuraErrorCode::AuraErrorNullPointer;
            }
            if let Err(code) = ensure_ffi_len_exact(
                out_error,
                source_message_id_length,
                MESSAGE_ID_BYTES,
                "source_message_id",
            ) {
                return code;
            }
        }
        let aid = std::slice::from_raw_parts(attachment_id, attachment_id_length);
        let smid = if !source_message_id.is_null() && source_message_id_length > 0 {
            Some(std::slice::from_raw_parts(source_message_id, source_message_id_length).to_vec())
        } else {
            None
        };
        match crate::protocol::attachment::create_attachment_reference(
            aid.to_vec(),
            reference_type,
            smid,
        ) {
            Ok(reference) => {
                let mut buf = Vec::new();
                if let Err(e) = reference.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("AttachmentReference encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_voice_meta_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) =
            ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "VoiceMessageMeta")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = VoiceMessageMeta::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("VoiceMessageMeta decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_voice_message_meta(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_voice_meta_create(
    waveform_samples: *const f32,
    waveform_count: usize,
    transcript: *const u8,
    transcript_length: usize,
    playback_speed_hint: f32,
    has_playback_speed: u8,
    is_listened: u8,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if waveform_count > MAX_VOICE_WAVEFORM_SAMPLES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "waveform_count exceeds maximum",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            transcript_length,
            max_utf8_bytes(MAX_VOICE_TRANSCRIPT_CHARS),
            "transcript",
        ) {
            return code;
        }
        let waveform = if !waveform_samples.is_null() && waveform_count > 0 {
            std::slice::from_raw_parts(waveform_samples, waveform_count).to_vec()
        } else {
            Vec::new()
        };
        let transcript_opt = if !transcript.is_null() && transcript_length > 0 {
            let tb = std::slice::from_raw_parts(transcript, transcript_length);
            let Ok(ts) = std::str::from_utf8(tb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "transcript is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ts.to_string())
        } else {
            None
        };
        let speed = if has_playback_speed != 0 {
            Some(playback_speed_hint)
        } else {
            None
        };
        match crate::protocol::attachment::create_voice_message_meta(
            waveform,
            transcript_opt,
            speed,
            is_listened != 0,
        ) {
            Ok(voice) => {
                let mut buf = Vec::new();
                if let Err(e) = voice.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("VoiceMessageMeta encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_location_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) =
            ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "LocationAttachment")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = LocationAttachment::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("LocationAttachment decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_location_attachment(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_location_create(
    latitude: f64,
    longitude: f64,
    accuracy_meters: f64,
    has_accuracy: u8,
    label: *const u8,
    label_length: usize,
    timestamp_unix: u64,
    has_timestamp: u8,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            label_length,
            max_utf8_bytes(MAX_LOCATION_LABEL_CHARS),
            "label",
        ) {
            return code;
        }
        let accuracy = if has_accuracy != 0 {
            Some(accuracy_meters)
        } else {
            None
        };
        let label_opt = if !label.is_null() && label_length > 0 {
            let lb = std::slice::from_raw_parts(label, label_length);
            let Ok(ls) = std::str::from_utf8(lb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "label is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ls.to_string())
        } else {
            None
        };
        let ts = if has_timestamp != 0 {
            Some(timestamp_unix)
        } else {
            None
        };
        match crate::protocol::attachment::create_location_attachment(
            latitude, longitude, accuracy, label_opt, ts,
        ) {
            Ok(loc) => {
                let mut buf = Vec::new();
                if let Err(e) = loc.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("LocationAttachment encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_contact_card_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "ContactCard")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = ContactCard::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("ContactCard decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_contact_card(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_contact_card_create(
    display_name: *const u8,
    display_name_length: usize,
    phone: *const u8,
    phone_length: usize,
    email: *const u8,
    email_length: usize,
    avatar_data: *const u8,
    avatar_data_length: usize,
    organization: *const u8,
    organization_length: usize,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if display_name.is_null() || out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            display_name_length,
            max_utf8_bytes(MAX_CONTACT_DISPLAY_NAME_CHARS),
            "display_name",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            phone_length,
            max_utf8_bytes(MAX_CONTACT_PHONE_CHARS),
            "phone",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            email_length,
            max_utf8_bytes(MAX_CONTACT_EMAIL_CHARS),
            "email",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            avatar_data_length,
            MAX_CONTACT_AVATAR_DATA_SIZE,
            "avatar_data",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            organization_length,
            max_utf8_bytes(MAX_CONTACT_ORGANIZATION_CHARS),
            "organization",
        ) {
            return code;
        }
        let dn_bytes = std::slice::from_raw_parts(display_name, display_name_length);
        let Ok(dn_str) = std::str::from_utf8(dn_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "display_name is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let phone_opt = if !phone.is_null() && phone_length > 0 {
            let pb = std::slice::from_raw_parts(phone, phone_length);
            let Ok(ps) = std::str::from_utf8(pb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "phone is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ps.to_string())
        } else {
            None
        };
        let email_opt = if !email.is_null() && email_length > 0 {
            let eb = std::slice::from_raw_parts(email, email_length);
            let Ok(es) = std::str::from_utf8(eb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "email is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(es.to_string())
        } else {
            None
        };
        let avatar_opt = if !avatar_data.is_null() && avatar_data_length > 0 {
            Some(std::slice::from_raw_parts(avatar_data, avatar_data_length).to_vec())
        } else {
            None
        };
        let org_opt = if !organization.is_null() && organization_length > 0 {
            let ob = std::slice::from_raw_parts(organization, organization_length);
            let Ok(os) = std::str::from_utf8(ob) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "organization is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(os.to_string())
        } else {
            None
        };
        match crate::protocol::attachment::create_contact_card(
            dn_str.to_string(),
            phone_opt,
            email_opt,
            avatar_opt,
            org_opt,
        ) {
            Ok(card) => {
                let mut buf = Vec::new();
                if let Err(e) = card.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("ContactCard encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_link_preview_validate(
    bytes: *const u8,
    length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if bytes.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "bytes is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(out_error, length, MAX_BUFFER_SIZE, "LinkPreview")
        {
            return code;
        }
        let slice = std::slice::from_raw_parts(bytes, length);
        let Ok(obj) = LinkPreview::decode(slice) else {
            return write_protocol_error(
                out_error,
                &ProtocolError::decode("LinkPreview decode failed".to_string()),
            );
        };
        match crate::protocol::attachment::validate_link_preview(&obj) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_attachment_link_preview_create(
    url: *const u8,
    url_length: usize,
    title: *const u8,
    title_length: usize,
    description: *const u8,
    description_length: usize,
    preview_image: *const u8,
    preview_image_length: usize,
    preview_image_mime: *const u8,
    preview_image_mime_length: usize,
    domain: *const u8,
    domain_length: usize,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if url.is_null() || out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            url_length,
            max_utf8_bytes(MAX_LINK_PREVIEW_URL_CHARS),
            "url",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            title_length,
            max_utf8_bytes(MAX_LINK_PREVIEW_TITLE_CHARS),
            "title",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            description_length,
            max_utf8_bytes(MAX_LINK_PREVIEW_DESCRIPTION_CHARS),
            "description",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            preview_image_length,
            MAX_LINK_PREVIEW_IMAGE_SIZE,
            "preview_image",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            preview_image_mime_length,
            255,
            "preview_image_mime",
        ) {
            return code;
        }
        if let Err(code) = ensure_ffi_len_at_most(
            out_error,
            domain_length,
            max_utf8_bytes(MAX_LINK_PREVIEW_DOMAIN_CHARS),
            "domain",
        ) {
            return code;
        }
        let url_bytes = std::slice::from_raw_parts(url, url_length);
        let Ok(url_str) = std::str::from_utf8(url_bytes) else {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "url is not valid UTF-8",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        };
        let title_opt = if !title.is_null() && title_length > 0 {
            let tb = std::slice::from_raw_parts(title, title_length);
            let Ok(ts) = std::str::from_utf8(tb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "title is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ts.to_string())
        } else {
            None
        };
        let desc_opt = if !description.is_null() && description_length > 0 {
            let db = std::slice::from_raw_parts(description, description_length);
            let Ok(ds) = std::str::from_utf8(db) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "description is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ds.to_string())
        } else {
            None
        };
        let image_opt = if !preview_image.is_null() && preview_image_length > 0 {
            Some(std::slice::from_raw_parts(preview_image, preview_image_length).to_vec())
        } else {
            None
        };
        let image_mime_opt = if !preview_image_mime.is_null() && preview_image_mime_length > 0 {
            let mb = std::slice::from_raw_parts(preview_image_mime, preview_image_mime_length);
            let Ok(ms) = std::str::from_utf8(mb) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "preview_image_mime is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ms.to_string())
        } else {
            None
        };
        let domain_opt = if !domain.is_null() && domain_length > 0 {
            let db = std::slice::from_raw_parts(domain, domain_length);
            let Ok(ds) = std::str::from_utf8(db) else {
                write_error(
                    out_error,
                    AuraErrorCode::AuraErrorInvalidInput,
                    "domain is not valid UTF-8",
                );
                return AuraErrorCode::AuraErrorInvalidInput;
            };
            Some(ds.to_string())
        } else {
            None
        };
        match crate::protocol::attachment::create_link_preview(
            url_str.to_string(),
            title_opt,
            desc_opt,
            image_opt,
            image_mime_opt,
            domain_opt,
        ) {
            Ok(preview) => {
                let mut buf = Vec::new();
                if let Err(e) = preview.encode(&mut buf) {
                    return write_protocol_error(
                        out_error,
                        &ProtocolError::encode(format!("LinkPreview encode: {e}")),
                    );
                }
                write_buffer(out_buffer, buf);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_metadata(
    handle: *mut AuraSessionHandle,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let meta = match session.get_metadata() {
            Ok(m) => m,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let resp = SessionMetadataResponse {
            session_id: meta.session_id,
            is_initiator: meta.is_initiator,
            send_ratchet_epoch: meta.send_ratchet_epoch,
            recv_ratchet_epoch: meta.recv_ratchet_epoch,
            send_message_index: meta.send_message_index,
            recv_message_index: meta.recv_message_index,
            nonce_remaining: meta.nonce_remaining,
            skipped_keys_count: u32::try_from(meta.skipped_keys_count).unwrap_or(u32::MAX),
            cached_metadata_keys_count: u32::try_from(meta.cached_metadata_keys_count)
                .unwrap_or(u32::MAX),
            state_counter: meta.state_counter,
            total_messages_sent: meta.total_messages_sent,
            total_messages_received: meta.total_messages_received,
            device_id: meta.device_id.unwrap_or_default(),
            session_ttl_seconds: meta.session_ttl_seconds,
            last_activity_unix: meta.last_activity_unix,
        };
        let mut buf = Vec::new();
        if let Err(e) = resp.encode(&mut buf) {
            return write_protocol_error(
                out_error,
                &ProtocolError::encode(format!("SessionMetadataResponse encode: {e}")),
            );
        }
        write_buffer(out_buffer, buf);
        AuraErrorCode::AuraSuccess
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_is_expired(handle: *mut AuraSessionHandle) -> bool {
    ffi_catch_panic_value!(false, {
        if handle.is_null() {
            return false;
        }
        let Some(session) = (unsafe { (*handle).inner.as_ref() }) else {
            return false;
        };
        session.is_expired().unwrap_or(false)
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_set_device_id(
    handle: *mut AuraSessionHandle,
    device_id: *const u8,
    device_id_length: usize,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if device_id.is_null() || device_id_length != DEVICE_ID_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "device_id must be non-null and exactly DEVICE_ID_BYTES",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let id_slice = std::slice::from_raw_parts(device_id, device_id_length);
        match session.set_device_id(id_slice) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_get_device_id(
    handle: *mut AuraSessionHandle,
    out_buffer: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_buffer.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "out_buffer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        match session.get_device_id() {
            Ok(Some(id)) => {
                write_buffer(out_buffer, id);
                AuraErrorCode::AuraSuccess
            }
            Ok(None) => {
                write_buffer(out_buffer, Vec::new());
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn aura_session_set_ttl(
    handle: *mut AuraSessionHandle,
    ttl_seconds: u64,
    has_ttl: bool,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        let (_guard, session) = match require_session_mut(handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let ttl = if has_ttl { Some(ttl_seconds) } else { None };
        match session.set_session_ttl(ttl) {
            Ok(()) => AuraErrorCode::AuraSuccess,
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

// ============================================================================
// Channel encryption FFI (Phase 3)
//
// Stateless FFI wrappers around `crate::protocol::channel`. No session handle
// is exposed — channel keys are managed externally by the calling layer (iOS
// ChannelKeyStore). Wire envelope assembly is done outside this module.
// ============================================================================

const CHANNEL_KEY_BYTES: usize = crate::core::constants::AES_KEY_BYTES;
const CHANNEL_KEY_ID_BYTES_FFI: usize = crate::protocol::channel::CHANNEL_KEY_ID_BYTES;
const CHANNEL_ID_BYTES_FFI: usize = crate::protocol::channel::CHANNEL_ID_BYTES;
const CHANNEL_X25519_BYTES: usize = crate::core::constants::X25519_PUBLIC_KEY_BYTES;
const CHANNEL_X25519_PRIV_BYTES: usize = crate::core::constants::X25519_PRIVATE_KEY_BYTES;
const CHANNEL_KYBER_PUBLIC_BYTES: usize = crate::core::constants::KYBER_PUBLIC_KEY_BYTES;
const CHANNEL_NONCE_BYTES: usize = crate::core::constants::AES_GCM_NONCE_BYTES;
const CHANNEL_ED25519_PUB_BYTES: usize = crate::core::constants::ED25519_PUBLIC_KEY_BYTES;
const CHANNEL_ED25519_SECRET_BYTES_FFI: usize =
    crate::protocol::channel::CHANNEL_ED25519_SECRET_BYTES;
const CHANNEL_ED25519_SIG_BYTES: usize = crate::core::constants::ED25519_SIGNATURE_BYTES;

/// Generate a fresh channel key + UUID v4 identifier.
///
/// # Safety
/// `out_key_id` must point to a writable 16-byte buffer.
/// `out_key` must point to a writable 32-byte buffer.
/// See module-level FFI safety contract.
#[no_mangle]
pub unsafe extern "C" fn aura_channel_generate_key(
    out_key_id: *mut u8,
    out_key: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if out_key_id.is_null() || out_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required output pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        match crate::protocol::channel::generate_channel_key() {
            Ok(material) => {
                std::ptr::copy_nonoverlapping(
                    material.key_id.as_ptr(),
                    out_key_id,
                    CHANNEL_KEY_ID_BYTES_FFI,
                );
                std::ptr::copy_nonoverlapping(material.key.as_ptr(), out_key, CHANNEL_KEY_BYTES);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Wrap a 32-byte channel key for one subscriber device using their X25519 and
/// ML-KEM-768 public keys.
///
/// # Safety
/// `channel_key` must point to a 32-byte readable slice.
/// `device_x25519_public` must point to a 32-byte readable slice.
/// `device_kyber_public` must point to a 1184-byte readable slice.
/// `out_blob` must point to a writable [`AuraBuffer`].
#[no_mangle]
pub unsafe extern "C" fn aura_channel_wrap_key_for_device(
    channel_key: *const u8,
    device_x25519_public: *const u8,
    device_kyber_public: *const u8,
    out_blob: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if channel_key.is_null()
            || device_x25519_public.is_null()
            || device_kyber_public.is_null()
            || out_blob.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let mut key_buf = [0u8; CHANNEL_KEY_BYTES];
        std::ptr::copy_nonoverlapping(channel_key, key_buf.as_mut_ptr(), CHANNEL_KEY_BYTES);
        let mut device_pub = [0u8; CHANNEL_X25519_BYTES];
        std::ptr::copy_nonoverlapping(
            device_x25519_public,
            device_pub.as_mut_ptr(),
            CHANNEL_X25519_BYTES,
        );
        let mut device_kyber_pub = [0u8; CHANNEL_KYBER_PUBLIC_BYTES];
        std::ptr::copy_nonoverlapping(
            device_kyber_public,
            device_kyber_pub.as_mut_ptr(),
            CHANNEL_KYBER_PUBLIC_BYTES,
        );

        match crate::protocol::channel::wrap_key_for_device(
            &key_buf,
            &device_pub,
            &device_kyber_pub,
        ) {
            Ok(blob) => {
                write_buffer(out_blob, blob);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Unwrap a channel key blob using the device identity's X25519 and ML-KEM-768
/// secret keys.
///
/// # Safety
/// `(blob, blob_length)` must form a valid readable slice.
/// `identity_handle` must point to a live identity handle.
/// `out_channel_key` must point to a writable 32-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn aura_channel_unwrap_key_blob(
    blob: *const u8,
    blob_length: usize,
    identity_handle: *const AuraIdentityHandle,
    out_channel_key: *mut u8,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if blob.is_null() || identity_handle.is_null() || out_channel_key.is_null() {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let blob_slice = std::slice::from_raw_parts(blob, blob_length);
        let (_identity_guard, identity) = match require_identity_ref(identity_handle, out_error) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let device_secret_vec = match identity.get_identity_x25519_private_key_copy() {
            Ok(secret) => secret,
            Err(e) => return write_protocol_error(out_error, &e),
        };
        let device_secret: [u8; CHANNEL_X25519_PRIV_BYTES] =
            match device_secret_vec.as_slice().try_into() {
                Ok(secret) => secret,
                Err(_) => {
                    write_error(
                        out_error,
                        AuraErrorCode::AuraErrorInvalidInput,
                        "Identity X25519 secret has invalid length",
                    );
                    return AuraErrorCode::AuraErrorInvalidInput;
                }
            };
        let kyber_secret = match identity.clone_kyber_secret_key() {
            Ok(secret) => secret,
            Err(e) => return write_protocol_error(out_error, &e),
        };

        match crate::protocol::channel::unwrap_key_blob(blob_slice, &device_secret, &kyber_secret) {
            Ok(unwrapped) => {
                std::ptr::copy_nonoverlapping(
                    unwrapped.as_ptr(),
                    out_channel_key,
                    CHANNEL_KEY_BYTES,
                );
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Encrypt a channel message. Outputs the nonce, signature, and ciphertext as
/// separate buffers; the caller assembles the wire envelope.
///
/// # Safety
/// All `*const u8` parameters must point to readable slices of the documented
/// length. `out_nonce` (12 bytes) and `out_signature` (64 bytes) must be
/// writable. `out_ciphertext` must point to a writable [`AuraBuffer`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn aura_channel_encrypt_message(
    plaintext: *const u8,
    plaintext_length: usize,
    channel_key: *const u8,
    channel_id: *const u8,
    channel_key_id: *const u8,
    generation: u64,
    sender_ed25519_secret: *const u8,
    out_nonce: *mut u8,
    out_signature: *mut u8,
    out_ciphertext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if (plaintext.is_null() && plaintext_length != 0)
            || channel_key.is_null()
            || channel_id.is_null()
            || channel_key_id.is_null()
            || sender_ed25519_secret.is_null()
            || out_nonce.is_null()
            || out_signature.is_null()
            || out_ciphertext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        let pt = if plaintext_length == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(plaintext, plaintext_length)
        };
        let mut key_buf = [0u8; CHANNEL_KEY_BYTES];
        std::ptr::copy_nonoverlapping(channel_key, key_buf.as_mut_ptr(), CHANNEL_KEY_BYTES);
        let mut chan_id = [0u8; CHANNEL_ID_BYTES_FFI];
        std::ptr::copy_nonoverlapping(channel_id, chan_id.as_mut_ptr(), CHANNEL_ID_BYTES_FFI);
        let mut chan_key_id = [0u8; CHANNEL_KEY_ID_BYTES_FFI];
        std::ptr::copy_nonoverlapping(
            channel_key_id,
            chan_key_id.as_mut_ptr(),
            CHANNEL_KEY_ID_BYTES_FFI,
        );
        let mut signing_secret = [0u8; CHANNEL_ED25519_SECRET_BYTES_FFI];
        std::ptr::copy_nonoverlapping(
            sender_ed25519_secret,
            signing_secret.as_mut_ptr(),
            CHANNEL_ED25519_SECRET_BYTES_FFI,
        );

        match crate::protocol::channel::encrypt_message(
            pt,
            &key_buf,
            &chan_id,
            &chan_key_id,
            generation,
            &signing_secret,
        ) {
            Ok(fields) => {
                std::ptr::copy_nonoverlapping(
                    fields.nonce.as_ptr(),
                    out_nonce,
                    CHANNEL_NONCE_BYTES,
                );
                std::ptr::copy_nonoverlapping(
                    fields.sender_signature.as_ptr(),
                    out_signature,
                    CHANNEL_ED25519_SIG_BYTES,
                );
                write_buffer(out_ciphertext, fields.ciphertext);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}

/// Decrypt a channel message. Verifies Ed25519 signature, then AES-GCM-SIV.
///
/// # Safety
/// All `*const u8` parameters must point to readable slices of the documented
/// length. `out_plaintext` must point to a writable [`AuraBuffer`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn aura_channel_decrypt_message(
    ciphertext: *const u8,
    ciphertext_length: usize,
    nonce: *const u8,
    signature: *const u8,
    channel_key_id: *const u8,
    generation: u64,
    channel_key: *const u8,
    channel_id: *const u8,
    sender_ed25519_public: *const u8,
    out_plaintext: *mut AuraBuffer,
    out_error: *mut AuraError,
) -> AuraErrorCode {
    ffi_catch_panic!(out_error, unsafe {
        if ciphertext.is_null()
            || nonce.is_null()
            || signature.is_null()
            || channel_key_id.is_null()
            || channel_key.is_null()
            || channel_id.is_null()
            || sender_ed25519_public.is_null()
            || out_plaintext.is_null()
        {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorNullPointer,
                "A required pointer is null",
            );
            return AuraErrorCode::AuraErrorNullPointer;
        }
        if ciphertext_length > MAX_ENVELOPE_MESSAGE_SIZE + AES_GCM_TAG_BYTES {
            write_error(
                out_error,
                AuraErrorCode::AuraErrorInvalidInput,
                "ciphertext length exceeds maximum",
            );
            return AuraErrorCode::AuraErrorInvalidInput;
        }
        let ct = std::slice::from_raw_parts(ciphertext, ciphertext_length).to_vec();
        let mut nonce_buf = [0u8; CHANNEL_NONCE_BYTES];
        std::ptr::copy_nonoverlapping(nonce, nonce_buf.as_mut_ptr(), CHANNEL_NONCE_BYTES);
        let mut sig_buf = [0u8; CHANNEL_ED25519_SIG_BYTES];
        std::ptr::copy_nonoverlapping(signature, sig_buf.as_mut_ptr(), CHANNEL_ED25519_SIG_BYTES);
        let mut chan_key_id = [0u8; CHANNEL_KEY_ID_BYTES_FFI];
        std::ptr::copy_nonoverlapping(
            channel_key_id,
            chan_key_id.as_mut_ptr(),
            CHANNEL_KEY_ID_BYTES_FFI,
        );
        let mut key_buf = [0u8; CHANNEL_KEY_BYTES];
        std::ptr::copy_nonoverlapping(channel_key, key_buf.as_mut_ptr(), CHANNEL_KEY_BYTES);
        let mut chan_id = [0u8; CHANNEL_ID_BYTES_FFI];
        std::ptr::copy_nonoverlapping(channel_id, chan_id.as_mut_ptr(), CHANNEL_ID_BYTES_FFI);
        let mut sender_pub = [0u8; CHANNEL_ED25519_PUB_BYTES];
        std::ptr::copy_nonoverlapping(
            sender_ed25519_public,
            sender_pub.as_mut_ptr(),
            CHANNEL_ED25519_PUB_BYTES,
        );

        let fields = crate::protocol::channel::ChannelEncryptedFields {
            channel_key_id: chan_key_id,
            generation,
            nonce: nonce_buf,
            ciphertext: ct,
            sender_signature: sig_buf,
        };

        match crate::protocol::channel::decrypt_message(&fields, &key_buf, &chan_id, &sender_pub) {
            Ok(decoded) => {
                write_buffer(out_plaintext, decoded.plaintext);
                AuraErrorCode::AuraSuccess
            }
            Err(e) => write_protocol_error(out_error, &e),
        }
    })
}
