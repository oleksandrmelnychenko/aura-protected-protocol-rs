// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

/// Cryptographic utility functions for the Aura Protected Protocol.
///
/// Provides envelope validation and Shamir's Secret Sharing operations.
public enum AuraCrypto {

    /// Validates the structure of an encrypted envelope without decrypting it.
    ///
    /// This checks the envelope header, version, and structural integrity
    /// without requiring any key material.
    ///
    /// - Parameter data: The envelope data to validate.
    /// - Throws: `AuraError` if the envelope is malformed or structurally invalid.
    public static func validateEnvelope(_ data: Data) throws {
        var outError = NativeAuraError(code: 0, message: nil)
        let result = data.withUnsafeBytes { dataBytes in
            native_epp_envelope_validate(
                dataBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                data.count,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
    }

    /// Splits a secret into shares using Shamir's Secret Sharing.
    ///
    /// Any `threshold` shares out of the `shareCount` total can reconstruct the
    /// original secret. The `authKey` is used to authenticate the shares and
    /// must be provided again during reconstruction.
    ///
    /// - Parameters:
    ///   - secret: The secret data to split.
    ///   - threshold: The minimum number of shares required to reconstruct the secret.
    ///   - shareCount: The total number of shares to generate.
    ///   - authKey: An authentication key for share integrity verification.
    /// - Returns: An array of `shareCount` share data objects.
    /// - Throws: `AuraError` if splitting fails (e.g., invalid threshold/shareCount).
    public static func shamirSplit(
        secret: Data,
        threshold: UInt8,
        shareCount: UInt8,
        authKey: Data
    ) throws -> [Data] {
        var outShares = NativeAuraBuffer(data: nil, length: 0)
        var outShareLength: Int = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = secret.withUnsafeBytes { secretBytes in
            authKey.withUnsafeBytes { authKeyBytes in
                native_epp_shamir_split(
                    secretBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    secret.count,
                    threshold,
                    shareCount,
                    authKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    authKey.count,
                    &outShares,
                    &outShareLength,
                    &outError
                )
            }
        }
        defer {
            if outShares.data != nil { native_epp_buffer_release(&outShares) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let ptr = outShares.data, outShareLength > 0 else {
            throw AuraError.bufferTooSmall
        }
        let totalCount = Int(shareCount)
        var shares = [Data]()
        shares.reserveCapacity(totalCount)
        for i in 0..<totalCount {
            let offset = i * outShareLength
            let shareData = Data(bytes: ptr.advanced(by: offset), count: outShareLength)
            shares.append(shareData)
        }
        return shares
    }

    /// Reconstructs a secret from Shamir shares.
    ///
    /// At least `threshold` shares (the same threshold used during splitting) must be
    /// provided. The `authKey` must match the one used during splitting.
    ///
    /// - Parameters:
    ///   - shares: An array of share data objects (at least `threshold` shares required).
    ///   - authKey: The authentication key used during splitting.
    ///   - threshold: The minimum number of shares required (must match the split threshold).
    /// - Returns: The reconstructed secret data.
    /// - Throws: `AuraError` if reconstruction fails (e.g., insufficient shares, wrong auth key).
    public static func shamirReconstruct(
        shares: [Data],
        authKey: Data,
        threshold: Int
    ) throws -> Data {
        guard !shares.isEmpty else {
            throw AuraError.invalidInput("No shares provided")
        }
        let shareLength = shares[0].count
        let shareCount = shares.count
        var flatShares = Data(capacity: shareCount * shareLength)
        for share in shares {
            flatShares.append(share)
        }
        var outSecret = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = flatShares.withUnsafeBytes { sharesBytes in
            authKey.withUnsafeBytes { authKeyBytes in
                native_epp_shamir_reconstruct(
                    sharesBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    flatShares.count,
                    shareLength,
                    shareCount,
                    authKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    authKey.count,
                    &outSecret,
                    &outError
                )
            }
        }
        defer {
            if outSecret.data != nil { native_epp_buffer_release(&outSecret) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outSecret) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }
}
