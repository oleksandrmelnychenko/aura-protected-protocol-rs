// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

// MARK: - Session Configuration

/// Configuration for a 1:1 session, controlling ratchet chain limits.
public struct EppSessionConfig {

    /// The maximum number of messages allowed per ratchet chain before rekeying is required.
    public let maxMessagesPerChain: UInt32

    /// Creates a session configuration.
    ///
    /// - Parameter maxMessagesPerChain: Maximum messages per chain (default: 1000).
    public init(maxMessagesPerChain: UInt32 = 1000) {
        self.maxMessagesPerChain = maxMessagesPerChain
    }

    /// Converts to the native C representation.
    internal var native: NativeEppSessionConfig {
        NativeEppSessionConfig(max_messages_per_chain: maxMessagesPerChain)
    }
}

// MARK: - Handshake Initiator

/// The initiating side of a two-step handshake that establishes a 1:1 encrypted session.
///
/// Usage:
/// 1. Call `start(identity:peerPrekeyBundle:config:)` to produce an initiator and handshake-init payload.
/// 2. Send the handshake-init payload to the responder.
/// 3. Receive the handshake-ack payload from the responder.
/// 4. Call `finish(handshakeAck:)` to obtain the `EppSession`.
public final class EppHandshakeInitiator {

    private var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_handshake_initiator_destroy(&handle)
        }
    }

    /// Begins a handshake as the initiator.
    ///
    /// - Parameters:
    ///   - identity: The local identity performing the handshake.
    ///   - peerPrekeyBundle: The peer's pre-key bundle obtained out-of-band.
    ///   - config: Session configuration (default: 1000 messages per chain).
    /// - Returns: A tuple containing the initiator object and the handshake-init payload to send to the peer.
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if the handshake start fails.
    public static func start(
        identity: EppIdentity,
        peerPrekeyBundle: Data,
        config: EppSessionConfig = EppSessionConfig()
    ) throws -> (initiator: EppHandshakeInitiator, handshakeInit: Data) {
        guard identity.handle != nil else {
            throw EppError.objectDisposed
        }
        var outHandle: UnsafeMutableRawPointer?
        var outHandshakeInit = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        var nativeConfig = config.native
        let result = peerPrekeyBundle.withUnsafeBytes { bundleBytes in
            native_epp_handshake_initiator_start(
                identity.handle,
                bundleBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                peerPrekeyBundle.count,
                &nativeConfig,
                &outHandle,
                &outHandshakeInit,
                &outError
            )
        }
        defer {
            if outHandshakeInit.data != nil { native_epp_buffer_release(&outHandshakeInit) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let initData = dataFromBuffer(outHandshakeInit) else {
            throw EppError.bufferTooSmall
        }
        return (EppHandshakeInitiator(handle: handle), initData)
    }

    /// Completes the handshake by processing the responder's acknowledgement.
    ///
    /// After this call succeeds, the initiator is consumed and the returned session
    /// is ready for encrypting and decrypting messages.
    ///
    /// Call `peerIdentity()` and optionally `identityBindingHash()` on the
    /// returned session before trusting it, if your application pins or verifies
    /// peers out of band.
    ///
    /// - Parameter handshakeAck: The handshake-ack payload received from the responder.
    /// - Returns: The established `EppSession`.
    /// - Throws: `EppError.objectDisposed` if the initiator has been destroyed,
    ///   or another `EppError` if the handshake finish fails.
    public func finish(handshakeAck: Data) throws -> EppSession {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = handshakeAck.withUnsafeBytes { ackBytes in
            native_epp_handshake_initiator_finish(
                handle,
                ackBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                handshakeAck.count,
                &outSession,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let sessionHandle = outSession else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppSession(handle: sessionHandle)
    }

    /// Completes the handshake and immediately verifies the peer identity.
    ///
    /// This is the safest one-shot flow when your application already knows
    /// the expected peer identity out of band.
    public func finishVerifyingPeer(
        handshakeAck: Data,
        expectedPeerIdentity: EppSessionIdentity
    ) throws -> EppSession {
        let session = try finish(handshakeAck: handshakeAck)
        try session.requirePeerIdentity(
            ed25519PublicKey: expectedPeerIdentity.ed25519PublicKey,
            x25519PublicKey: expectedPeerIdentity.x25519PublicKey
        )
        return session
    }

    /// Completes the handshake and immediately verifies the peer identity.
    public func finishVerifyingPeer(
        handshakeAck: Data,
        expectedPeerEd25519PublicKey: Data,
        expectedPeerX25519PublicKey: Data
    ) throws -> EppSession {
        let session = try finish(handshakeAck: handshakeAck)
        try session.requirePeerIdentity(
            ed25519PublicKey: expectedPeerEd25519PublicKey,
            x25519PublicKey: expectedPeerX25519PublicKey
        )
        return session
    }
}

// MARK: - Handshake Responder

/// The responding side of a two-step handshake that establishes a 1:1 encrypted session.
///
/// Usage:
/// 1. Receive the handshake-init payload from the initiator.
/// 2. Call `start(identity:localPrekeyBundle:handshakeInit:config:)` to produce a responder and handshake-ack payload.
/// 3. Send the handshake-ack payload back to the initiator.
/// 4. Call `finish()` to obtain the `EppSession`.
public final class EppHandshakeResponder {

    private var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_handshake_responder_destroy(&handle)
        }
    }

    /// Begins a handshake as the responder.
    ///
    /// - Parameters:
    ///   - identity: The local identity performing the handshake.
    ///   - localPrekeyBundle: The local pre-key bundle that was shared with the initiator.
    ///   - handshakeInit: The handshake-init payload received from the initiator.
    ///   - config: Session configuration (default: 1000 messages per chain).
    /// - Returns: A tuple containing the responder object and the handshake-ack payload to send back.
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if the handshake start fails.
    public static func start(
        identity: EppIdentity,
        localPrekeyBundle: Data,
        handshakeInit: Data,
        config: EppSessionConfig = EppSessionConfig()
    ) throws -> (responder: EppHandshakeResponder, handshakeAck: Data) {
        guard identity.handle != nil else {
            throw EppError.objectDisposed
        }
        var outHandle: UnsafeMutableRawPointer?
        var outHandshakeAck = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        var nativeConfig = config.native
        let result = localPrekeyBundle.withUnsafeBytes { bundleBytes in
            handshakeInit.withUnsafeBytes { initBytes in
                native_epp_handshake_responder_start(
                    identity.handle,
                    bundleBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    localPrekeyBundle.count,
                    initBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    handshakeInit.count,
                    &nativeConfig,
                    &outHandle,
                    &outHandshakeAck,
                    &outError
                )
            }
        }
        defer {
            if outHandshakeAck.data != nil { native_epp_buffer_release(&outHandshakeAck) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let ackData = dataFromBuffer(outHandshakeAck) else {
            throw EppError.bufferTooSmall
        }
        return (EppHandshakeResponder(handle: handle), ackData)
    }

    /// Completes the handshake on the responder side.
    ///
    /// After this call succeeds, the responder is consumed and the returned session
    /// is ready for encrypting and decrypting messages.
    ///
    /// Call `peerIdentity()` and optionally `identityBindingHash()` on the
    /// returned session before trusting it, if your application pins or verifies
    /// peers out of band.
    ///
    /// - Returns: The established `EppSession`.
    /// - Throws: `EppError.objectDisposed` if the responder has been destroyed,
    ///   or another `EppError` if the handshake finish fails.
    public func finish() throws -> EppSession {
        guard handle != nil else {
            throw EppError.objectDisposed
        }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_handshake_responder_finish(
            handle,
            &outSession,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let sessionHandle = outSession else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppSession(handle: sessionHandle)
    }

    /// Completes the handshake and immediately verifies the peer identity.
    ///
    /// This is the safest one-shot flow when your application already knows
    /// the expected peer identity out of band.
    public func finishVerifyingPeer(
        expectedPeerIdentity: EppSessionIdentity
    ) throws -> EppSession {
        let session = try finish()
        try session.requirePeerIdentity(
            ed25519PublicKey: expectedPeerIdentity.ed25519PublicKey,
            x25519PublicKey: expectedPeerIdentity.x25519PublicKey
        )
        return session
    }

    /// Completes the handshake and immediately verifies the peer identity.
    public func finishVerifyingPeer(
        expectedPeerEd25519PublicKey: Data,
        expectedPeerX25519PublicKey: Data
    ) throws -> EppSession {
        let session = try finish()
        try session.requirePeerIdentity(
            ed25519PublicKey: expectedPeerEd25519PublicKey,
            x25519PublicKey: expectedPeerX25519PublicKey
        )
        return session
    }
}

// MARK: - EcliptixProtectedProtocol Namespace

/// Top-level namespace for Ecliptix Protected Protocol library operations.
///
/// Provides global initialization/shutdown, version info, key derivation,
/// and secure memory wiping.
public enum EcliptixProtectedProtocol {

    /// Initializes the EPP library. Must be called before any other EPP operations.
    ///
    /// - Throws: `EppError` if initialization fails.
    public static func initialize() throws {
        let result = native_epp_init()
        guard result == EPP_SUCCESS else {
            throw EppError.from(
                code: result,
                nativeError: NativeEppError(code: result, message: nil)
            )
        }
    }

    /// Calls the native shutdown hook.
    ///
    /// The current native implementation is a no-op and does not release
    /// meaningful global resources. It is kept only for API symmetry.
    public static func shutdown() {
        native_epp_shutdown()
    }

    /// The version string of the native EPP library.
    public static var version: String {
        guard let ptr = native_epp_version() else { return "unknown" }
        return String(cString: ptr)
    }

    /// Derives an application key from an opaque session key and user context.
    ///
    /// This is typically used to derive storage encryption keys from session material
    /// combined with application-specific context.
    ///
    /// - Parameters:
    ///   - opaqueSessionKey: The session key material.
    ///   - userContext: Application-specific context bytes.
    /// - Parameter outputLength: Requested key length in bytes. Must be 1...64.
    /// - Returns: A derived key of exactly `outputLength` bytes.
    /// - Throws: `EppError` if key derivation fails.
    public static func deriveRootKey(
        opaqueSessionKey: Data,
        userContext: Data,
        outputLength: Int = 64
    ) throws -> Data {
        guard (1...64).contains(outputLength) else {
            throw EppError.invalidInput("outputLength must be in 1...64")
        }
        let rootKeyLength = outputLength
        var outKey = Data(count: rootKeyLength)
        var outError = NativeEppError(code: 0, message: nil)
        let result = opaqueSessionKey.withUnsafeBytes { sessionKeyBytes in
            userContext.withUnsafeBytes { contextBytes in
                outKey.withUnsafeMutableBytes { keyBytes in
                    native_epp_derive_root_key(
                        sessionKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        opaqueSessionKey.count,
                        contextBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        userContext.count,
                        keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        rootKeyLength,
                        &outError
                    )
                }
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return outKey
    }

    /// Securely wipes the contents of a `Data` value by overwriting it with zeros.
    ///
    /// This uses a platform-specific secure wipe that prevents the compiler from
    /// optimizing away the zeroing operation.
    ///
    /// - Parameter data: The data to wipe. After this call, all bytes will be zero.
    public static func secureWipe(_ data: inout Data) {
        let length = data.count
        data.withUnsafeMutableBytes { bytes in
            if let ptr = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                _ = native_epp_secure_wipe(ptr, length)
            }
        }
    }
}
