// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Mutable manual clock for deterministic tests and trusted-time integrations.
///
/// Identity-bound protocol flows can inherit this clock via
/// `EppIdentity.setTimeProvider(_:)`. Session and VoIP sealed-state restore
/// APIs also expose overloads that accept an explicit provider.
public final class EppTimeProvider {
    internal var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_time_provider_destroy(&handle)
        }
    }

    public static func manual(initialNowUnix: UInt64) throws -> EppTimeProvider {
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_time_provider_manual_create(
            initialNowUnix,
            &outHandle,
            &outError
        )
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppTimeProvider(handle: handle)
    }

    public func setNowUnix(_ nowUnix: UInt64) throws {
        guard handle != nil else { throw EppError.objectDisposed }
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_time_provider_manual_set_now_unix(handle, nowUnix, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
    }
}
