// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

private extension Data {
    var eppHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

public struct EppSessionIdentity: Sendable {
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

public struct EppEnvelopeMetadata: Sendable {
    public let envelopeType: UInt32
    public let envelopeId: UInt32
    public let messageIndex: UInt64
    public let correlationId: String?
}

public struct EppSessionVerificationSnapshot: Sendable {
    public let sessionId: Data
    public let identityBindingHash: Data
    public let localIdentity: EppSessionIdentity
    public let peerIdentity: EppSessionIdentity
}

/// Represents a 1:1 encrypted session in the Ecliptix Protected Protocol.
///
/// A session is created through a handshake between two identities and provides
/// symmetric encryption/decryption of messages with forward secrecy via the
/// Double Ratchet algorithm. Sessions can be serialized for persistent storage
/// and later restored.
public final class EppSession {

    /// The opaque handle to the native session object.
    internal var handle: UnsafeMutableRawPointer?

    /// Creates an `EppSession` from a native handle.
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
    ///   - envelopeType: The type of envelope (default: `EPP_ENVELOPE_REQUEST`).
    ///   - envelopeId: An optional envelope identifier (default: 0).
    ///   - correlationId: An optional correlation string for request/response matching (default: empty).
    /// - Returns: The encrypted envelope as `Data`.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if encryption fails.
    public func encrypt(
        plaintext: Data,
        envelopeType: UInt32 = 0, // EPP_ENVELOPE_REQUEST
        envelopeId: UInt32 = 0,
        correlationId: String = ""
    ) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Decrypts an encrypted envelope and returns the plaintext.
    ///
    /// - Parameter encryptedEnvelope: The encrypted envelope data to decrypt.
    /// - Returns: The decrypted plaintext as `Data`.
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if decryption fails (e.g., replay attack, expired session).
    public func decrypt(encryptedEnvelope: Data) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outPlaintext = NativeEppBuffer(data: nil, length: 0)
        var outMetadata = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    public func decryptWithMetadata(
        encryptedEnvelope: Data
    ) throws -> (plaintext: Data, metadata: EppEnvelopeMetadata) {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outPlaintext = NativeEppBuffer(data: nil, length: 0)
        var outMetadata = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let plaintext = dataFromBuffer(outPlaintext),
              let metadataBytes = dataFromBuffer(outMetadata) else {
            throw EppError.bufferTooSmall
        }
        var nativeMeta = NativeEppEnvelopeMetadata(
            envelope_type: 0,
            envelope_id: 0,
            message_index: 0,
            correlation_id: nil,
            correlation_id_length: 0
        )
        var parseError = NativeEppError(code: 0, message: nil)
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
        guard parseResult == EPP_SUCCESS else {
            throw EppError.from(code: parseResult, nativeError: parseError)
        }
        let correlationId = nativeMeta.correlation_id.map { String(cString: $0) }
        return (
            plaintext,
            EppEnvelopeMetadata(
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
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if serialization fails.
    public func serialize(key: Data, externalCounter: UInt64) throws -> Data {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
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
    /// - Returns: A tuple containing the restored `EppSession` and its external counter.
    /// - Throws: `EppError` if deserialization or authentication fails.
    public static func deserialize(
        sealedState: Data,
        key: Data,
        minExternalCounter: UInt64
    ) throws -> (session: EppSession, externalCounter: UInt64) {
        var outHandle: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return (EppSession(handle: handle), outCounter)
    }

    public func sessionId() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_get_id(handle, &outBuffer, &outError)
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    public func identityBindingHash() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_get_identity_binding_hash(handle, &outBuffer, &outError)
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outBuffer) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    public func peerIdentity() throws -> EppSessionIdentity {
        guard handle != nil else { throw EppError.objectDisposed }
        var native = NativeEppSessionPeerIdentity(
            ed25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            x25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_get_peer_identity(handle, &native, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppSessionIdentity(
            ed25519PublicKey: withUnsafeBytes(of: native.ed25519_public) { Data($0) },
            x25519PublicKey: withUnsafeBytes(of: native.x25519_public) { Data($0) }
        )
    }

    public func localIdentity() throws -> EppSessionIdentity {
        guard handle != nil else { throw EppError.objectDisposed }
        var native = NativeEppSessionPeerIdentity(
            ed25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            x25519_public: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        )
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_get_local_identity(handle, &native, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppSessionIdentity(
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
            throw EppError.handshake("Peer identity verification failed")
        }
    }

    public func verificationSnapshot() throws -> EppSessionVerificationSnapshot {
        EppSessionVerificationSnapshot(
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
    /// - Throws: `EppError.objectDisposed` if the session has been destroyed,
    ///   or another `EppError` if the query fails.
    public func nonceRemaining() throws -> UInt64 {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var remaining: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_session_nonce_remaining(handle, &remaining, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return remaining
    }
}
