// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Represents all possible errors returned by the Ecliptix Protected Protocol library.
///
/// Each case corresponds to a specific error code from the native FFI layer.
/// Use `errorDescription` for a human-readable description of the error.
public enum EppError: Error, LocalizedError {
    case generic(String)
    case invalidInput(String)
    case keyGeneration(String)
    case deriveKey(String)
    case handshake(String)
    case encryption(String)
    case decryption(String)
    case decode(String)
    case encode(String)
    case bufferTooSmall
    case objectDisposed
    case prepareLocal(String)
    case outOfMemory
    case cryptoFailure(String)
    case nullPointer
    case invalidState(String)
    case replayAttack
    case sessionExpired
    case postQuantumMissing
    case groupProtocol(String)
    case groupMembership(String)
    case treeIntegrity(String)
    case welcome(String)
    case messageExpired
    case franking(String)
    case voipCall(String)
    case voipMedia(String)
    case voipRekey(String)
    case busy(String)
    case unknown(UInt32)

    /// Creates an `EppError` from a native error code and error struct.
    ///
    /// - Parameters:
    ///   - code: The native FFI error code.
    ///   - nativeError: The native error struct containing an optional error message.
    /// - Returns: The corresponding `EppError` case.
    internal static func from(code: UInt32, nativeError: NativeEppError) -> EppError {
        let message: String
        if let msg = nativeError.message {
            message = String(cString: msg)
        } else if let ptr = native_epp_error_string(code) {
            message = String(cString: ptr)
        } else {
            message = "Unknown error"
        }
        switch code {
        case EPP_ERROR_GENERIC: return .generic(message)
        case EPP_ERROR_INVALID_INPUT: return .invalidInput(message)
        case EPP_ERROR_KEY_GENERATION: return .keyGeneration(message)
        case EPP_ERROR_DERIVE_KEY: return .deriveKey(message)
        case EPP_ERROR_HANDSHAKE: return .handshake(message)
        case EPP_ERROR_ENCRYPTION: return .encryption(message)
        case EPP_ERROR_DECRYPTION: return .decryption(message)
        case EPP_ERROR_DECODE: return .decode(message)
        case EPP_ERROR_ENCODE: return .encode(message)
        case EPP_ERROR_BUFFER_TOO_SMALL: return .bufferTooSmall
        case EPP_ERROR_OBJECT_DISPOSED: return .objectDisposed
        case EPP_ERROR_PREPARE_LOCAL: return .prepareLocal(message)
        case EPP_ERROR_OUT_OF_MEMORY: return .outOfMemory
        case EPP_ERROR_CRYPTO_FAILURE: return .cryptoFailure(message)
        case EPP_ERROR_NULL_POINTER: return .nullPointer
        case EPP_ERROR_INVALID_STATE: return .invalidState(message)
        case EPP_ERROR_REPLAY_ATTACK: return .replayAttack
        case EPP_ERROR_SESSION_EXPIRED: return .sessionExpired
        case EPP_ERROR_PQ_MISSING: return .postQuantumMissing
        case EPP_ERROR_GROUP_PROTOCOL: return .groupProtocol(message)
        case EPP_ERROR_GROUP_MEMBERSHIP: return .groupMembership(message)
        case EPP_ERROR_TREE_INTEGRITY: return .treeIntegrity(message)
        case EPP_ERROR_WELCOME: return .welcome(message)
        case EPP_ERROR_MESSAGE_EXPIRED: return .messageExpired
        case EPP_ERROR_FRANKING: return .franking(message)
        case EPP_ERROR_VOIP_CALL: return .voipCall(message)
        case EPP_ERROR_VOIP_MEDIA: return .voipMedia(message)
        case EPP_ERROR_VOIP_REKEY: return .voipRekey(message)
        case EPP_ERROR_BUSY: return .busy(message)
        default: return .unknown(code)
        }
    }

    public var errorDescription: String? {
        switch self {
        case .generic(let msg): return "EPP error: \(msg)"
        case .invalidInput(let msg): return "Invalid input: \(msg)"
        case .keyGeneration(let msg): return "Key generation failed: \(msg)"
        case .deriveKey(let msg): return "Key derivation failed: \(msg)"
        case .handshake(let msg): return "Handshake failed: \(msg)"
        case .encryption(let msg): return "Encryption failed: \(msg)"
        case .decryption(let msg): return "Decryption failed: \(msg)"
        case .decode(let msg): return "Decode failed: \(msg)"
        case .encode(let msg): return "Encode failed: \(msg)"
        case .bufferTooSmall: return "Buffer too small"
        case .objectDisposed: return "Object has been disposed"
        case .prepareLocal(let msg): return "Prepare local failed: \(msg)"
        case .outOfMemory: return "Out of memory"
        case .cryptoFailure(let msg): return "Crypto failure: \(msg)"
        case .nullPointer: return "Null pointer"
        case .invalidState(let msg): return "Invalid state: \(msg)"
        case .replayAttack: return "Replay attack detected"
        case .sessionExpired: return "Session expired"
        case .postQuantumMissing: return "Post-quantum not available"
        case .groupProtocol(let msg): return "Group protocol: \(msg)"
        case .groupMembership(let msg): return "Group membership: \(msg)"
        case .treeIntegrity(let msg): return "Tree integrity: \(msg)"
        case .welcome(let msg): return "Welcome: \(msg)"
        case .messageExpired: return "Message expired"
        case .franking(let msg): return "Franking: \(msg)"
        case .voipCall(let msg): return "VoIP call: \(msg)"
        case .voipMedia(let msg): return "VoIP media: \(msg)"
        case .voipRekey(let msg): return "VoIP rekey: \(msg)"
        case .busy(let msg): return "Handle busy: \(msg)"
        case .unknown(let code): return "Unknown EPP error (code: \(code))"
        }
    }
}
