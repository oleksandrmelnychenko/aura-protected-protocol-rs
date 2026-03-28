// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Single-record sealed-state persistence slot.
///
/// A slot bundles the latest sealed blob together with tracker state in one
/// serializable object. Persist the serialized slot as a single record.
///
/// Important: this improves crash consistency, but it does not by itself stop a
/// full-record rollback by an attacker who can replace the entire serialized
/// slot with an older slot. For that, the application still needs trusted
/// monotonic storage outside the slot.
public final class EppSealedStateSlot {
    internal var handle: UnsafeMutableRawPointer?

    public init() throws {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_sealed_state_slot_create(&outHandle, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        self.handle = handle
    }

    public init(serialized: Data) throws {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = serialized.withUnsafeBytes { bytes in
            native_epp_sealed_state_slot_create_from_serialized(
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                serialized.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_sealed_state_slot_destroy(&handle)
        }
    }

    public func serialize() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_sealed_state_slot_serialize(handle, &outBuffer, &outError)
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

    public func maxRestoredCounter() throws -> UInt64 {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_sealed_state_slot_get_max_restored_counter(
            handle,
            &outCounter,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return outCounter
    }

    public func latestIssuedCounter() throws -> UInt64 {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_sealed_state_slot_get_latest_issued_counter(
            handle,
            &outCounter,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return outCounter
    }
}
