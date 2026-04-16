// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Managed anti-rollback tracker for one sealed-state storage slot.
///
/// Persist the serialized tracker next to the sealed blob for the same slot and
/// prefer the tracker-based sealed-state APIs over manual counter management.
public final class AuraSealedStateCounterTracker {
    internal var handle: UnsafeMutableRawPointer?

    public init() throws {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_sealed_state_counter_tracker_create(&outHandle, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        self.handle = handle
    }

    public init(serialized: Data) throws {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = serialized.withUnsafeBytes { bytes in
            native_epp_sealed_state_counter_tracker_create_from_serialized(
                bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                serialized.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_sealed_state_counter_tracker_destroy(&handle)
        }
    }

    public func serialize() throws -> Data {
        guard handle != nil else { throw AuraError.objectDisposed }
        var outBuffer = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_sealed_state_counter_tracker_serialize(handle, &outBuffer, &outError)
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

    public func maxRestoredCounter() throws -> UInt64 {
        guard handle != nil else { throw AuraError.objectDisposed }
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_sealed_state_counter_tracker_get_max_restored_counter(
            handle,
            &outCounter,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return outCounter
    }

    public func latestIssuedCounter() throws -> UInt64 {
        guard handle != nil else { throw AuraError.objectDisposed }
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = native_epp_sealed_state_counter_tracker_get_latest_issued_counter(
            handle,
            &outCounter,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return outCounter
    }
}
