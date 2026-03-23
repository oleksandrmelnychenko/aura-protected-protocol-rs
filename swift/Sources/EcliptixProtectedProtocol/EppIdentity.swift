// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

private extension Data {
    var eppHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

/// Represents a cryptographic identity in the Ecliptix Protected Protocol.
///
/// An identity encapsulates X25519, Ed25519, and Kyber key pairs used for
/// key exchange, signing, and post-quantum key encapsulation. Identities can
/// be created randomly or deterministically from a seed.
public final class EppIdentity {

    /// The opaque handle to the native identity object.
    internal var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_identity_destroy(&handle)
        }
    }

    /// Creates a new random identity with freshly generated key material.
    ///
    /// - Returns: A new `EppIdentity` instance.
    /// - Throws: `EppError` if key generation fails.
    public static func create() throws -> EppIdentity {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_identity_create(&outHandle, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppIdentity(handle: handle)
    }

    /// Creates a deterministic identity from a seed.
    ///
    /// The same seed will always produce the same identity key material,
    /// which is useful for recovery and testing.
    ///
    /// - Parameter seed: The seed bytes used to derive the identity.
    /// - Returns: A new `EppIdentity` instance derived from the seed.
    /// - Throws: `EppError` if identity creation fails.
    public static func create(fromSeed seed: Data) throws -> EppIdentity {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = seed.withUnsafeBytes { seedBytes in
            native_epp_identity_create_from_seed(
                seedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                seed.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppIdentity(handle: handle)
    }

    /// Creates a deterministic identity from a seed and a membership identifier.
    ///
    /// The membership ID provides additional context for key derivation, allowing
    /// the same seed to produce different identities for different group memberships.
    ///
    /// - Parameters:
    ///   - seed: The seed bytes used to derive the identity.
    ///   - membershipId: A string identifier for the membership context.
    /// - Returns: A new `EppIdentity` instance.
    /// - Throws: `EppError` if identity creation fails.
    public static func create(fromSeed seed: Data, membershipId: String) throws -> EppIdentity {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = seed.withUnsafeBytes { seedBytes in
            membershipId.withCString { membershipPtr in
                native_epp_identity_create_with_context(
                    seedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    seed.count,
                    membershipPtr,
                    membershipId.utf8.count,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppIdentity(handle: handle)
    }

    /// The X25519 public key (32 bytes) used for Diffie-Hellman key exchange.
    ///
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if the key cannot be retrieved.
    public var x25519PublicKey: Data {
        get throws {
            guard handle != nil else { throw EppError.objectDisposed }
            var key = Data(count: 32)
            var outError = NativeEppError(code: 0, message: nil)
            let result = key.withUnsafeMutableBytes { keyBytes in
                native_epp_identity_get_x25519_public(
                    handle,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    32,
                    &outError
                )
            }
            defer { native_epp_error_free(&outError) }
            guard result == EPP_SUCCESS else {
                throw EppError.from(code: result, nativeError: outError)
            }
            return key
        }
    }

    /// The Ed25519 public key (32 bytes) used for digital signatures.
    ///
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if the key cannot be retrieved.
    public var ed25519PublicKey: Data {
        get throws {
            guard handle != nil else { throw EppError.objectDisposed }
            var key = Data(count: 32)
            var outError = NativeEppError(code: 0, message: nil)
            let result = key.withUnsafeMutableBytes { keyBytes in
                native_epp_identity_get_ed25519_public(
                    handle,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    32,
                    &outError
                )
            }
            defer { native_epp_error_free(&outError) }
            guard result == EPP_SUCCESS else {
                throw EppError.from(code: result, nativeError: outError)
            }
            return key
        }
    }

    /// The Kyber public key (1184 bytes) used for post-quantum key encapsulation.
    ///
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if the key cannot be retrieved.
    public var kyberPublicKey: Data {
        get throws {
            guard handle != nil else { throw EppError.objectDisposed }
            var key = Data(count: 1184)
            var outError = NativeEppError(code: 0, message: nil)
            let result = key.withUnsafeMutableBytes { keyBytes in
                native_epp_identity_get_kyber_public(
                    handle,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    1184,
                    &outError
                )
            }
            defer { native_epp_error_free(&outError) }
            guard result == EPP_SUCCESS else {
                throw EppError.from(code: result, nativeError: outError)
            }
            return key
        }
    }

    public func sessionIdentity() throws -> EppSessionIdentity {
        EppSessionIdentity(
            ed25519PublicKey: try ed25519PublicKey,
            x25519PublicKey: try x25519PublicKey
        )
    }

    public func ed25519FingerprintHex() throws -> String {
        try ed25519PublicKey.eppHexString
    }

    public func x25519FingerprintHex() throws -> String {
        try x25519PublicKey.eppHexString
    }

    /// Creates a pre-key bundle from this identity for use in handshake protocols.
    ///
    /// The pre-key bundle contains the public keys needed by a peer to initiate
    /// a handshake with this identity.
    ///
    /// - Returns: The serialized pre-key bundle as `Data`.
    /// - Throws: `EppError.objectDisposed` if the identity has been destroyed,
    ///   or another `EppError` if bundle creation fails.
    public func createPrekeyBundle() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_prekey_bundle_create(handle, &outBuffer, &outError)
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

    public func replenishOneTimePrekeys(count: UInt32) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_prekey_bundle_replenish(handle, count, &outBuffer, &outError)
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
}
