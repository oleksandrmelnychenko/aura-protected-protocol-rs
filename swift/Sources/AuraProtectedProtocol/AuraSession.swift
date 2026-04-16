// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

private extension Data {
    var eppHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

public struct AuraSessionIdentity: Sendable {
    public let ed25519PublicKey: Data
    public let x25519PublicKey: Data

    public func matches(
        ed25519PublicKey expectedEd25519: Data,
        x25519PublicKey expectedX25519: Data
    ) -> Bool {
        ed25519PublicKey == expectedEd25519 && x25519PublicKey == expectedX25519
    }

    public var ed25519FingerprintHex: String {
        ed25519PublicKey.eppHexString
    }

    public var x25519FingerprintHex: String {
        x25519PublicKey.eppHexString
    }
}

public struct AuraEnvelopeMetadata: Sendable {
    public let envelopeType: UInt32
    public let envelopeId: UInt32
    public let messageIndex: UInt64
    public let correlationId: String?
}

public struct AuraSessionVerificationSnapshot: Sendable {
    public let sessionId: Data
    public let identityBindingHash: Data
    public let localIdentity: AuraSessionIdentity
    public let peerIdentity: AuraSessionIdentity
}

/// Represents a 1:1 encrypted session in the Aura Protected Protocol.
///
/// A session is created through a handshake between two identities and provides
/// symmetric encryption/decryption of messages with forward secrecy via the
/// Double Ratchet algorithm. Sessions can be serialized for persistent storage
/// and later restored.
public final class AuraSession {

    /// The opaque handle to the native session object.
    internal var handle: UnsafeMutableRawPointer?

    /// Creates an `AuraSession` from a native handle.
    ///
    /// - Parameter handle: The opaque pointer to the native session.
    internal init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_session_destroy(&handle)
        }
    }

    /// Encrypts plaintext into an encrypted envelope.
    ///
    /// The envelope type, ID, and correlation ID are authenticated and encrypted
    /// inside the outer envelope metadata.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - envelopeType: The type of envelope (default: `AURA_ENVELOPE_REQUEST`).
    ///   - envelopeId: An optional envelope identifier (default: 0).
    ///   - correlationId: An optional correlation string for request/response matching (default: empty).
    /// - Returns: The encrypted envelope as `Data`.
    /// - Throws: `AuraError.objectDisposed` if the session has been destroyed,
    ///   or another `AuraError` if encryption fails.
    public func encrypt(
        plaintext: Data,
        envelopeType: UInt32 = 0, // AURA_ENVELOPE_REQUEST
        envelopeId: UInt32 = 0,
        correlationId: String = ""
    ) throws -> Data {
        guard handle != nil else {
            throw AuraError.objectDisposed
        }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { plaintextBytes in
            correlationId.withCString { correlationPtr in
                native_epp_session_encrypt(
                    handle,
                    plaintextBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count,
                    envelopeType,
                    envelopeId,
                    correlationPtr,
                    correlationId.utf8.count,
                    &outBuffer,
                    &outError
                )
            }
        }
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    /// Decrypts an encrypted envelope and returns the plaintext.
    ///
    /// - Parameter encryptedEnvelope: The encrypted envelope data to decrypt.
    /// - Returns: The decrypted plaintext as `Data`.
    /// - Throws: `AuraError.objectDisposed` if the session has been destroyed,
    ///   or another `AuraError` if decryption fails (e.g., replay attack, expired session).
    public func decrypt(encryptedEnvelope: Data) throws -> Data {
        guard handle != nil else {
            throw AuraError.objectDisposed
        }
        var outPlaintext = NativeAuraBuffer(data: nil, length: 0)
        var outMetadata = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = encryptedEnvelope.withUnsafeBytes { envelopeBytes in
            native_epp_session_decrypt(
                handle,
                envelopeBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                encryptedEnvelope.count,
                &outPlaintext,
                &outMetadata,
                &outError
            )
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            if outMetadata.data != nil { native_epp_buffer_release(&outMetadata) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public func decryptWithMetadata(
        encryptedEnvelope: Data
    ) throws -> (plaintext: Data, metadata: AuraEnvelopeMetadata) {
        guard handle != nil else {
            throw AuraError.objectDisposed
        }
        var outPlaintext = NativeAuraBuffer(data: nil, length: 0)
        var outMetadata = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = encryptedEnvelope.withUnsafeBytes { envelopeBytes in
            native_epp_session_decrypt(
                handle,
                envelopeBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                encryptedEnvelope.count,
                &outPlaintext,
                &outMetadata,
                &outError
            )
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            if outMetadata.data != nil { native_epp_buffer_release(&outMetadata) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let plaintext = dataFromBuffer(outPlaintext),
              let metadataBytes = dataFromBuffer(outMetadata) else {
            throw AuraError.bufferTooSmall
        }
        var nativeMeta = NativeAuraEnvelopeMetadata(
            envelope_type: 0,
            envelope_id: 0,
            message_index: 0,
            correlation_id: nil,
            correlation_id_length: 0
        )
        var parseError = NativeAuraError(code: 0, message: nil)
        let parseResult = metadataBytes.withUnsafeBytes { bytes in
            native_epp_envelope_metadata_parse(
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                metadataBytes.count,
                &nativeMeta,
                &parseError
            )
        }
        defer {
            native_epp_envelope_metadata_free(&nativeMeta)
            native_epp_error_free(&parseError)
        }
        guard parseResult == AURA_SUCCESS else {
            throw AuraError.from(code: parseResult, nativeError: parseError)
        }
        let correlationId = nativeMeta.correlation_id.map { String(cString: $0) }
        return (
            plaintext,
            AuraEnvelopeMetadata(
                envelopeType: nativeMeta.envelope_type,
                envelopeId: nativeMeta.envelope_id,
                messageIndex: nativeMeta.message_index,
                correlationId: correlationId
            )
        )
    }

    /// Serializes the session state, encrypted under the given key, for persistent storage.
    ///
    /// The external counter is a monotonic value that the caller must persist alongside
    /// the sealed state to prevent rollback attacks during deserialization.
    ///
    /// - Parameters:
    ///   - key: The encryption key used to seal the state.
    ///   - externalCounter: A monotonically increasing counter value.
    /// - Returns: The sealed session state as `Data`.
    /// - Throws: `AuraError.objectDisposed` if the session has been destroyed,
    ///   or another `AuraError` if serialization fails.
    public func serialize(key: Data, externalCounter: UInt64) throws -> Data {
        guard handle != nil else {
            throw AuraError.objectDisposed
        }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_serialize_sealed(
                handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                externalCounter,
                &outBuffer,
                &outError
            )
        }
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    /// Serializes the session state using a managed anti-rollback tracker.
    ///
    /// Persist the returned sealed state together with `tracker.serialize()`
    /// for the same storage slot.
    public func serialize(key: Data, tracker: AuraSealedStateCounterTracker) throws -> Data {
        guard handle != nil else { throw AuraError.objectDisposed }
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_serialize_sealed_with_tracker(
                handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                tracker.handle,
                &outBuffer,
                &outError
            )
        }
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    /// Exports the session state into a managed persisted slot.
    ///
    /// Persist `slot.serialize()` as one record after a successful export.
    public func exportPersistedState(key: Data, slot: AuraSealedStateSlot) throws {
        guard handle != nil else { throw AuraError.objectDisposed }
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        var outError = NativeAuraError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_export_persisted_state(
                handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                slot.handle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
    }

    /// Deserializes a previously sealed session state.
    ///
    /// The `minExternalCounter` parameter prevents rollback attacks by rejecting
    /// sealed states whose counter is below this value.
    ///
    /// - Parameters:
    ///   - sealedState: The sealed session state data.
    ///   - key: The encryption key used to unseal the state.
    ///   - minExternalCounter: The minimum acceptable external counter value.
    /// - Returns: A tuple containing the restored `AuraSession` and its external counter.
    /// - Throws: `AuraError` if deserialization or authentication fails.
    public static func deserialize(
        sealedState: Data,
        key: Data,
        minExternalCounter: UInt64
    ) throws -> (session: AuraSession, externalCounter: UInt64) {
        var outHandle: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_session_deserialize_sealed(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    minExternalCounter,
                    &outCounter,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return (AuraSession(handle: handle), outCounter)
    }

    public static func deserialize(
        sealedState: Data,
        key: Data,
        minExternalCounter: UInt64,
        timeProvider: AuraTimeProvider
    ) throws -> (session: AuraSession, externalCounter: UInt64) {
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_session_deserialize_sealed_with_time_provider(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    minExternalCounter,
                    timeProvider.handle,
                    &outCounter,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return (AuraSession(handle: handle), outCounter)
    }

    /// Deserializes a previously sealed session state using a managed tracker.
    ///
    /// The tracker supplies the restore watermark and is advanced only after a
    /// successful restore.
    public static func deserialize(
        sealedState: Data,
        key: Data,
        tracker: AuraSealedStateCounterTracker
    ) throws -> AuraSession {
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_session_deserialize_sealed_with_tracker(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    tracker.handle,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSession(handle: handle)
    }

    public static func deserialize(
        sealedState: Data,
        key: Data,
        tracker: AuraSealedStateCounterTracker,
        timeProvider: AuraTimeProvider
    ) throws -> AuraSession {
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_session_deserialize_sealed_with_tracker_and_time_provider(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    tracker.handle,
                    timeProvider.handle,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSession(handle: handle)
    }

    /// Restores a session from a managed persisted slot.
    ///
    /// After a successful restore, re-serialize and persist the slot so its
    /// restore watermark is advanced in the same record.
    public static func restorePersistedState(
        slot: AuraSealedStateSlot,
        key: Data
    ) throws -> AuraSession {
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_restore_persisted_state(
                slot.handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSession(handle: handle)
    }

    public static func restorePersistedState(
        slot: AuraSealedStateSlot,
        key: Data,
        timeProvider: AuraTimeProvider
    ) throws -> AuraSession {
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_session_restore_persisted_state_with_time_provider(
                slot.handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                key.count,
                timeProvider.handle,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSession(handle: handle)
    }

    public func sessionId() throws -> Data {
        guard handle != nil else { throw AuraError.objectDisposed }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_session_get_id(handle, &outBuffer, &outError)
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public func identityBindingHash() throws -> Data {
        guard handle != nil else { throw AuraError.objectDisposed }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_session_get_identity_binding_hash(handle, &outBuffer, &outError)
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public func peerIdentity() throws -> AuraSessionIdentity {
        guard handle != nil else { throw AuraError.objectDisposed }
        var native = NativeAuraSessionPeerIdentity(
            ed25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            x25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_session_get_peer_identity(handle, &native, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSessionIdentity(
            ed25519PublicKey: withUnsafeBytes(of: native.ed25519_public) { Data($0) },
            x25519PublicKey: withUnsafeBytes(of: native.x25519_public) { Data($0) }
        )
    }

    public func localIdentity() throws -> AuraSessionIdentity {
        guard handle != nil else { throw AuraError.objectDisposed }
        var native = NativeAuraSessionPeerIdentity(
            ed25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            x25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_session_get_local_identity(handle, &native, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraSessionIdentity(
            ed25519PublicKey: withUnsafeBytes(of: native.ed25519_public) { Data($0) },
            x25519PublicKey: withUnsafeBytes(of: native.x25519_public) { Data($0) }
        )
    }

    public func verifyPeerIdentity(
        ed25519PublicKey expectedEd25519: Data,
        x25519PublicKey expectedX25519: Data
    ) throws -> Bool {
        try peerIdentity().matches(
            ed25519PublicKey: expectedEd25519,
            x25519PublicKey: expectedX25519
        )
    }

    public func requirePeerIdentity(
        ed25519PublicKey expectedEd25519: Data,
        x25519PublicKey expectedX25519: Data
    ) throws {
        guard try verifyPeerIdentity(
            ed25519PublicKey: expectedEd25519,
            x25519PublicKey: expectedX25519
        ) else {
            throw AuraError.handshake("Peer identity verification failed")
        }
    }

    public func verificationSnapshot() throws -> AuraSessionVerificationSnapshot {
        AuraSessionVerificationSnapshot(
            sessionId: try sessionId(),
            identityBindingHash: try identityBindingHash(),
            localIdentity: try localIdentity(),
            peerIdentity: try peerIdentity()
        )
    }

    /// Returns the number of nonce values remaining before the session must be rekeyed.
    ///
    /// When this value reaches zero, no more messages can be encrypted and the session
    /// must be re-established via a new handshake.
    ///
    /// - Returns: The number of remaining nonce values.
    /// - Throws: `AuraError.objectDisposed` if the session has been destroyed,
    ///   or another `AuraError` if the query fails.
    public func nonceRemaining() throws -> UInt64 {
        guard handle != nil else {
            throw AuraError.objectDisposed
        }
        var remaining: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_session_nonce_remaining(handle, &remaining, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return remaining
    }
}
