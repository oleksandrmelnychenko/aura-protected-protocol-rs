// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

import Foundation

// MARK: - Group Security Policy

/// Security policy controlling group session behavior.
///
/// The policy defines limits on messages per epoch, skipped keys, and whether
/// features like external join, enhanced key schedule, and mandatory franking
/// are enabled.
public struct EppGroupSecurityPolicy: Sendable {

    /// Maximum number of messages allowed per epoch before a commit is required.
    public var maxMessagesPerEpoch: UInt32

    /// Maximum number of skipped message keys retained per sender for out-of-order delivery.
    public var maxSkippedKeysPerSender: UInt32

    /// Whether external joins (without a welcome message) are blocked.
    public var blockExternalJoin: Bool

    /// Whether the enhanced key schedule (with additional key derivation steps) is enabled.
    public var enhancedKeySchedule: Bool

    /// Whether franking (message accountability) is mandatory for all messages.
    public var mandatoryFranking: Bool

    /// Creates a group security policy with the specified parameters.
    ///
    /// - Parameters:
    ///   - maxMessagesPerEpoch: Maximum messages per epoch (default: 1000).
    ///   - maxSkippedKeysPerSender: Maximum skipped keys per sender (default: 32).
    ///   - blockExternalJoin: Block external joins (default: false).
    ///   - enhancedKeySchedule: Enable enhanced key schedule (default: false).
    ///   - mandatoryFranking: Require franking on all messages (default: false).
    public init(
        maxMessagesPerEpoch: UInt32 = 1000,
        maxSkippedKeysPerSender: UInt32 = 32,
        blockExternalJoin: Bool = false,
        enhancedKeySchedule: Bool = false,
        mandatoryFranking: Bool = false
    ) {
        self.maxMessagesPerEpoch = maxMessagesPerEpoch
        self.maxSkippedKeysPerSender = maxSkippedKeysPerSender
        self.blockExternalJoin = blockExternalJoin
        self.enhancedKeySchedule = enhancedKeySchedule
        self.mandatoryFranking = mandatoryFranking
    }

    /// A "shield" preset with enhanced security: external join blocked,
    /// enhanced key schedule enabled, and mandatory franking.
    public static let shield = EppGroupSecurityPolicy(
        maxMessagesPerEpoch: 1000,
        maxSkippedKeysPerSender: 4,
        blockExternalJoin: true,
        enhancedKeySchedule: true,
        mandatoryFranking: true
    )

    /// Converts to the native C representation.
    internal var native: NativeEppGroupSecurityPolicy {
        NativeEppGroupSecurityPolicy(
            max_messages_per_epoch: maxMessagesPerEpoch,
            max_skipped_keys_per_sender: maxSkippedKeysPerSender,
            block_external_join: blockExternalJoin ? 1 : 0,
            enhanced_key_schedule: enhancedKeySchedule ? 1 : 0,
            mandatory_franking: mandatoryFranking ? 1 : 0
        )
    }

    /// Creates an `EppGroupSecurityPolicy` from its native C representation.
    internal static func from(native: NativeEppGroupSecurityPolicy) -> EppGroupSecurityPolicy {
        EppGroupSecurityPolicy(
            maxMessagesPerEpoch: native.max_messages_per_epoch,
            maxSkippedKeysPerSender: native.max_skipped_keys_per_sender,
            blockExternalJoin: native.block_external_join != 0,
            enhancedKeySchedule: native.enhanced_key_schedule != 0,
            mandatoryFranking: native.mandatory_franking != 0
        )
    }
}

// MARK: - Group Decrypt Result

/// The full result of decrypting a group message, including all metadata.
///
/// This is returned by `EppGroupSession.decryptEx(_:)` and provides access to
/// fields like message ID, content type, TTL, timestamps, and franking/sealed flags.
public struct EppGroupDecryptResult {

    /// The decrypted plaintext content.
    public let plaintext: Data

    /// The leaf index of the sender within the group tree.
    public let senderLeafIndex: UInt32

    /// The generation counter (message number within the sender's chain).
    public let generation: UInt32

    /// The content type identifier for the message.
    public let contentType: UInt32

    /// The time-to-live in seconds for disappearing messages (0 if not a disappearing message).
    public let ttlSeconds: UInt32

    /// The timestamp (Unix epoch, seconds) when the message was sent.
    public let sentTimestamp: UInt64

    /// The unique message identifier.
    public let messageId: Data

    /// The message ID referenced by this message (for edits/deletes), or `nil` if not referencing another message.
    public let referencedMessageId: Data?

    /// Whether this message contains a sealed (encrypted hint) payload.
    public let hasSealedPayload: Bool

    /// Whether this message contains franking data for accountability verification.
    public let hasFrankingData: Bool

    public let sealedHint: Data?
    public let sealedEncryptedContent: Data?
    public let sealedNonce: Data?
    public let sealedKey: Data?
    public let frankingTag: Data?
    public let frankingKey: Data?
    public let frankingContent: Data?
    public let frankingSealedContent: Data?
}

// MARK: - Key Package Secrets

/// Wraps the opaque secrets handle produced when generating a key package.
///
/// These secrets are consumed when joining a group via a welcome message.
/// The secrets are automatically destroyed when this object is deallocated.
public final class EppKeyPackageSecrets {

    /// The opaque handle to the native key package secrets.
    internal var handle: UnsafeMutableRawPointer?

    internal init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_group_key_package_secrets_destroy(&handle)
        }
    }
}

// MARK: - Group Session

/// A group encrypted session supporting MLS-style group messaging.
///
/// Group sessions support multi-party encryption with forward secrecy, post-compromise
/// security, membership changes (add/remove/update), and advanced message types
/// including sealed, disappearing, frankable, edit, and delete messages.
public final class EppGroupSession {

    /// The opaque handle to the native group session object.
    internal var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_group_destroy(&handle)
        }
    }

    // MARK: - Creation

    /// Creates a new group session with the hardened shielded security policy.
    ///
    /// The caller becomes the first (and only) member of the group.
    ///
    /// - Parameters:
    ///   - identity: The local identity creating the group.
    ///   - credential: The credential bytes to associate with this member.
    /// - Returns: A new `EppGroupSession`.
    /// - Throws: `EppError` if group creation fails.
    public static func create(identity: EppIdentity, credential: Data) throws -> EppGroupSession {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = credential.withUnsafeBytes { credBytes in
            native_epp_group_create(
                identity.handle,
                credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                credential.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppGroupSession(handle: handle)
    }

    /// Creates a new group session with the "shielded" security policy preset.
    ///
    /// The shielded policy blocks external joins, enables enhanced key schedule,
    /// and makes franking mandatory.
    ///
    /// - Parameters:
    ///   - identity: The local identity creating the group.
    ///   - credential: The credential bytes to associate with this member.
    /// - Returns: A new shielded `EppGroupSession`.
    /// - Throws: `EppError` if group creation fails.
    public static func createShielded(identity: EppIdentity, credential: Data) throws -> EppGroupSession {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = credential.withUnsafeBytes { credBytes in
            native_epp_group_create_shielded(
                identity.handle,
                credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                credential.count,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppGroupSession(handle: handle)
    }

    /// Creates a new group session with a custom security policy.
    ///
    /// - Parameters:
    ///   - identity: The local identity creating the group.
    ///   - credential: The credential bytes to associate with this member.
    ///   - policy: The custom security policy for the group.
    /// - Returns: A new `EppGroupSession` with the specified policy.
    /// - Throws: `EppError` if group creation fails.
    public static func create(
        identity: EppIdentity,
        credential: Data,
        policy: EppGroupSecurityPolicy
    ) throws -> EppGroupSession {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        var nativePolicy = policy.native
        let result = credential.withUnsafeBytes { credBytes in
            native_epp_group_create_with_policy(
                identity.handle,
                credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                credential.count,
                &nativePolicy,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppGroupSession(handle: handle)
    }

    // MARK: - Key Packages

    /// Generates a key package and corresponding secrets for joining a group.
    ///
    /// The key package should be uploaded to a server so that existing group members
    /// can add this identity. The secrets must be retained and passed to `join(identity:welcome:secrets:)`
    /// when processing the resulting welcome message.
    ///
    /// - Parameters:
    ///   - identity: The identity generating the key package.
    ///   - credential: The credential bytes for this member.
    /// - Returns: A tuple containing the serialized key package and its secrets.
    /// - Throws: `EppError` if key package generation fails.
    public static func generateKeyPackage(
        identity: EppIdentity,
        credential: Data
    ) throws -> (keyPackage: Data, secrets: EppKeyPackageSecrets) {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outKeyPackage = NativeEppBuffer(data: nil, length: 0)
        var outSecrets: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = credential.withUnsafeBytes { credBytes in
            native_epp_group_generate_key_package(
                identity.handle,
                credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                credential.count,
                &outKeyPackage,
                &outSecrets,
                &outError
            )
        }
        defer {
            if outKeyPackage.data != nil { native_epp_buffer_release(&outKeyPackage) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS, let secretsHandle = outSecrets else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let kpData = dataFromBuffer(outKeyPackage) else {
            throw EppError.bufferTooSmall
        }
        return (kpData, EppKeyPackageSecrets(handle: secretsHandle))
    }

    // MARK: - Joining

    /// Joins an existing group using a welcome message and previously generated key package secrets.
    ///
    /// - Parameters:
    ///   - identity: The local identity joining the group.
    ///   - welcome: The welcome message received from an existing group member.
    ///   - secrets: The key package secrets from `generateKeyPackage(identity:credential:)`.
    /// - Returns: The `EppGroupSession` for the joined group.
    /// - Throws: `EppError` if joining fails (e.g., invalid welcome, mismatched secrets).
    public static func join(
        identity: EppIdentity,
        welcome: Data,
        secrets: EppKeyPackageSecrets
    ) throws -> EppGroupSession {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        guard secrets.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
        let result = welcome.withUnsafeBytes { welcomeBytes in
            native_epp_group_join(
                identity.handle,
                welcomeBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                welcome.count,
                secrets.handle,
                &outHandle,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppGroupSession(handle: handle)
    }

    /// Joins a group externally using the group's public state plus an
    /// authorization artifact issued by an existing member.
    ///
    /// This produces a commit that must be distributed to all existing members for them
    /// to recognize the new member.
    ///
    /// - Parameters:
    ///   - identity: The local identity joining the group.
    ///   - publicState: The group's exported public state.
    ///   - credential: The credential bytes for this member.
    /// - Returns: A tuple containing the joined `EppGroupSession` and the commit to distribute.
    /// - Throws: `EppError` if external join fails (e.g., blocked by policy).
    public static func joinExternal(
        identity: EppIdentity,
        publicState: Data,
        authorization: Data,
        credential: Data
    ) throws -> (session: EppGroupSession, commit: Data) {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outCommit = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = publicState.withUnsafeBytes { stateBytes in
            authorization.withUnsafeBytes { authBytes in
                credential.withUnsafeBytes { credBytes in
                    native_epp_group_join_external(
                        identity.handle,
                        stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        publicState.count,
                        authBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        authorization.count,
                        credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        credential.count,
                        &outHandle,
                        &outCommit,
                        &outError
                    )
                }
            }
        }
        defer {
            if outCommit.data != nil { native_epp_buffer_release(&outCommit) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let commitData = dataFromBuffer(outCommit) else {
            throw EppError.bufferTooSmall
        }
        return (EppGroupSession(handle: handle), commitData)
    }

    public func authorizeExternalJoin(
        joinerIdentity: EppIdentity,
        credential: Data
    ) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        guard joinerIdentity.handle != nil else { throw EppError.objectDisposed }
        let joinerEd = try joinerIdentity.ed25519PublicKey
        let joinerX = try joinerIdentity.x25519PublicKey
        var outAuthorization = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = joinerEd.withUnsafeBytes { edBytes in
            joinerX.withUnsafeBytes { xBytes in
                credential.withUnsafeBytes { credBytes in
                    native_epp_group_authorize_external_join(
                        handle,
                        edBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        joinerEd.count,
                        xBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        joinerX.count,
                        credBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        credential.count,
                        &outAuthorization,
                        &outError
                    )
                }
            }
        }
        defer {
            if outAuthorization.data != nil { native_epp_buffer_release(&outAuthorization) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outAuthorization) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    // MARK: - Membership

    /// Adds a new member to the group using their key package.
    ///
    /// Returns both a commit (to distribute to existing members) and a welcome message
    /// (to send to the new member).
    ///
    /// - Parameter keyPackage: The new member's key package.
    /// - Returns: A tuple containing the commit and welcome message.
    /// - Throws: `EppError` if adding the member fails.
    public func addMember(keyPackage: Data) throws -> (commit: Data, welcome: Data) {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCommit = NativeEppBuffer(data: nil, length: 0)
        var outWelcome = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = keyPackage.withUnsafeBytes { kpBytes in
            native_epp_group_add_member(
                handle,
                kpBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                keyPackage.count,
                &outCommit,
                &outWelcome,
                &outError
            )
        }
        defer {
            if outCommit.data != nil { native_epp_buffer_release(&outCommit) }
            if outWelcome.data != nil { native_epp_buffer_release(&outWelcome) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let commitData = dataFromBuffer(outCommit) else {
            throw EppError.bufferTooSmall
        }
        guard let welcomeData = dataFromBuffer(outWelcome) else {
            throw EppError.bufferTooSmall
        }
        return (commitData, welcomeData)
    }

    /// Removes a member from the group by their leaf index.
    ///
    /// Returns a commit that must be distributed to all remaining members.
    ///
    /// - Parameter leafIndex: The leaf index of the member to remove.
    /// - Returns: The commit message to distribute.
    /// - Throws: `EppError` if removal fails (e.g., invalid leaf index).
    public func removeMember(leafIndex: UInt32) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCommit = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_remove_member(
            handle,
            leafIndex,
            &outCommit,
            &outError
        )
        defer {
            if outCommit.data != nil { native_epp_buffer_release(&outCommit) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let commitData = dataFromBuffer(outCommit) else {
            throw EppError.bufferTooSmall
        }
        return commitData
    }

    /// Performs a self-update, rotating this member's key material.
    ///
    /// Returns a commit that must be distributed to all members to advance the epoch.
    ///
    /// - Returns: The commit message to distribute.
    /// - Throws: `EppError` if the update fails.
    public func update() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCommit = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_update(handle, &outCommit, &outError)
        defer {
            if outCommit.data != nil { native_epp_buffer_release(&outCommit) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let commitData = dataFromBuffer(outCommit) else {
            throw EppError.bufferTooSmall
        }
        return commitData
    }

    /// Processes a commit message received from another group member.
    ///
    /// This advances the group state to the next epoch and applies any membership
    /// changes contained in the commit.
    ///
    /// - Parameter commitBytes: The serialized commit message.
    /// - Throws: `EppError` if commit processing fails (e.g., invalid commit, tree integrity violation).
    public func processCommit(_ commitBytes: Data) throws {
        guard handle != nil else { throw EppError.objectDisposed }
        var outError = NativeEppError(code: 0, message: nil)
        let result = commitBytes.withUnsafeBytes { commitBuf in
            native_epp_group_process_commit(
                handle,
                commitBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                commitBytes.count,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
    }

    // MARK: - Messaging

    /// Encrypts plaintext for all group members.
    ///
    /// - Parameter plaintext: The data to encrypt.
    /// - Returns: The encrypted ciphertext.
    /// - Throws: `EppError` if encryption fails.
    public func encrypt(_ plaintext: Data) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { ptBytes in
            native_epp_group_encrypt(
                handle,
                ptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                plaintext.count,
                &outCiphertext,
                &outError
            )
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Decrypts a group message, returning the plaintext and basic sender information.
    ///
    /// - Parameter ciphertext: The encrypted message to decrypt.
    /// - Returns: A tuple containing the plaintext, sender leaf index, and generation counter.
    /// - Throws: `EppError` if decryption fails.
    public func decrypt(_ ciphertext: Data) throws -> (plaintext: Data, senderLeafIndex: UInt32, generation: UInt32) {
        guard handle != nil else { throw EppError.objectDisposed }
        var outPlaintext = NativeEppBuffer(data: nil, length: 0)
        var outSenderLeaf: UInt32 = 0
        var outGeneration: UInt32 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = ciphertext.withUnsafeBytes { ctBytes in
            native_epp_group_decrypt(
                handle,
                ctBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ciphertext.count,
                &outPlaintext,
                &outSenderLeaf,
                &outGeneration,
                &outError
            )
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw EppError.bufferTooSmall
        }
        return (data, outSenderLeaf, outGeneration)
    }

    /// Decrypts a group message with full metadata, including message IDs, content type,
    /// TTL, timestamp, and franking/sealed flags.
    ///
    /// - Parameter ciphertext: The encrypted message to decrypt.
    /// - Returns: An `EppGroupDecryptResult` with all available metadata.
    /// - Throws: `EppError` if decryption fails.
    public func decryptEx(_ ciphertext: Data) throws -> EppGroupDecryptResult {
        guard handle != nil else { throw EppError.objectDisposed }
        var nativeResult = NativeEppGroupDecryptResult(
            plaintext: NativeEppBuffer(data: nil, length: 0),
            sender_leaf_index: 0,
            generation: 0,
            content_type: 0,
            ttl_seconds: 0,
            sent_timestamp: 0,
            message_id: NativeEppBuffer(data: nil, length: 0),
            referenced_message_id: NativeEppBuffer(data: nil, length: 0),
            has_sealed_payload: 0,
            has_franking_data: 0,
            sealed_hint: NativeEppBuffer(data: nil, length: 0),
            sealed_encrypted_content: NativeEppBuffer(data: nil, length: 0),
            sealed_nonce: NativeEppBuffer(data: nil, length: 0),
            sealed_key: NativeEppBuffer(data: nil, length: 0),
            franking_tag: NativeEppBuffer(data: nil, length: 0),
            franking_key: NativeEppBuffer(data: nil, length: 0),
            franking_content: NativeEppBuffer(data: nil, length: 0),
            franking_sealed_content: NativeEppBuffer(data: nil, length: 0)
        )
        var outError = NativeEppError(code: 0, message: nil)
        let result = ciphertext.withUnsafeBytes { ctBytes in
            native_epp_group_decrypt_ex(
                handle,
                ctBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ciphertext.count,
                &nativeResult,
                &outError
            )
        }
        defer {
            native_epp_group_decrypt_result_free(&nativeResult)
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let plaintext = dataFromBuffer(nativeResult.plaintext) else {
            throw EppError.bufferTooSmall
        }
        guard let messageId = dataFromBuffer(nativeResult.message_id) else {
            throw EppError.bufferTooSmall
        }
        let referencedMessageId = dataFromBuffer(nativeResult.referenced_message_id)
        let sealedHint = dataFromBuffer(nativeResult.sealed_hint)
        let sealedEncryptedContent = dataFromBuffer(nativeResult.sealed_encrypted_content)
        let sealedNonce = dataFromBuffer(nativeResult.sealed_nonce)
        let sealedKey = dataFromBuffer(nativeResult.sealed_key)
        let frankingTag = dataFromBuffer(nativeResult.franking_tag)
        let frankingKey = dataFromBuffer(nativeResult.franking_key)
        let frankingContent = dataFromBuffer(nativeResult.franking_content)
        let frankingSealedContent = dataFromBuffer(nativeResult.franking_sealed_content)
        return EppGroupDecryptResult(
            plaintext: plaintext,
            senderLeafIndex: nativeResult.sender_leaf_index,
            generation: nativeResult.generation,
            contentType: nativeResult.content_type,
            ttlSeconds: nativeResult.ttl_seconds,
            sentTimestamp: nativeResult.sent_timestamp,
            messageId: messageId,
            referencedMessageId: referencedMessageId,
            hasSealedPayload: nativeResult.has_sealed_payload != 0,
            hasFrankingData: nativeResult.has_franking_data != 0,
            sealedHint: sealedHint,
            sealedEncryptedContent: sealedEncryptedContent,
            sealedNonce: sealedNonce,
            sealedKey: sealedKey,
            frankingTag: frankingTag,
            frankingKey: frankingKey,
            frankingContent: frankingContent,
            frankingSealedContent: frankingSealedContent
        )
    }

    // MARK: - Special Message Types

    /// Encrypts a sealed (hint-encrypted) message.
    ///
    /// Sealed messages have their content encrypted with an additional layer that
    /// can only be revealed by a party possessing the hint key.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - hint: The hint data used for the seal layer.
    /// - Returns: The sealed encrypted ciphertext.
    /// - Throws: `EppError` if encryption fails.
    public func encryptSealed(_ plaintext: Data, hint: Data) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { ptBytes in
            hint.withUnsafeBytes { hintBytes in
                native_epp_group_encrypt_sealed(
                    handle,
                    ptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    plaintext.count,
                    hintBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    hint.count,
                    &outCiphertext,
                    &outError
                )
            }
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Encrypts a disappearing message with a time-to-live.
    ///
    /// The TTL is authenticated metadata indicating how long the message should
    /// be retained before the recipient deletes it.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - ttlSeconds: The time-to-live in seconds after which the message should be deleted.
    /// - Returns: The encrypted ciphertext with TTL metadata.
    /// - Throws: `EppError` if encryption fails.
    public func encryptDisappearing(_ plaintext: Data, ttlSeconds: UInt32) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { ptBytes in
            native_epp_group_encrypt_disappearing(
                handle,
                ptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                plaintext.count,
                ttlSeconds,
                &outCiphertext,
                &outError
            )
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Encrypts a frankable message that includes an accountability tag.
    ///
    /// Franking allows a recipient to prove to a third party that a specific sender
    /// sent a specific message, without revealing the encryption keys.
    ///
    /// - Parameter plaintext: The data to encrypt.
    /// - Returns: The encrypted ciphertext with franking data.
    /// - Throws: `EppError` if encryption fails.
    public func encryptFrankable(_ plaintext: Data) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = plaintext.withUnsafeBytes { ptBytes in
            native_epp_group_encrypt_frankable(
                handle,
                ptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                plaintext.count,
                &outCiphertext,
                &outError
            )
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Encrypts an edit message that replaces the content of a previously sent message.
    ///
    /// - Parameters:
    ///   - newContent: The replacement content.
    ///   - targetMessageId: The message ID of the original message being edited.
    /// - Returns: The encrypted edit ciphertext.
    /// - Throws: `EppError` if encryption fails.
    public func encryptEdit(newContent: Data, targetMessageId: Data) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = newContent.withUnsafeBytes { contentBytes in
            targetMessageId.withUnsafeBytes { midBytes in
                native_epp_group_encrypt_edit(
                    handle,
                    contentBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    newContent.count,
                    midBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    targetMessageId.count,
                    &outCiphertext,
                    &outError
                )
            }
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Encrypts a delete message that requests deletion of a previously sent message.
    ///
    /// - Parameter targetMessageId: The message ID of the message to delete.
    /// - Returns: The encrypted delete ciphertext.
    /// - Throws: `EppError` if encryption fails.
    public func encryptDelete(targetMessageId: Data) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outCiphertext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = targetMessageId.withUnsafeBytes { midBytes in
            native_epp_group_encrypt_delete(
                handle,
                midBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                targetMessageId.count,
                &outCiphertext,
                &outError
            )
        }
        defer {
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outCiphertext) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    // MARK: - Crypto Verification (Static)

    /// Computes a deterministic message ID from group parameters and message coordinates.
    ///
    /// This can be used to verify or predict message IDs without decrypting the message.
    ///
    /// - Parameters:
    ///   - groupId: The group identifier.
    ///   - epoch: The epoch number.
    ///   - senderLeafIndex: The sender's leaf index.
    ///   - generation: The generation counter.
    /// - Returns: The computed message ID.
    /// - Throws: `EppError` if computation fails.
    public static func computeMessageId(
        groupId: Data,
        epoch: UInt64,
        senderLeafIndex: UInt32,
        generation: UInt32
    ) throws -> Data {
        var outMessageId = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = groupId.withUnsafeBytes { gidBytes in
            native_epp_group_compute_message_id(
                gidBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                groupId.count,
                epoch,
                senderLeafIndex,
                generation,
                &outMessageId,
                &outError
            )
        }
        defer {
            if outMessageId.data != nil { native_epp_buffer_release(&outMessageId) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let data = dataFromBuffer(outMessageId) else {
            throw EppError.bufferTooSmall
        }
        return data
    }

    /// Reveals the plaintext of a sealed message using the seal key and nonce.
    ///
    /// - Parameters:
    ///   - hint: The hint data from the sealed message.
    ///   - encryptedContent: The sealed encrypted content.
    ///   - nonce: The nonce used in the seal encryption.
    ///   - sealKey: The key used to encrypt the sealed content.
    /// - Returns: The revealed plaintext.
    /// - Throws: `EppError` if reveal fails (e.g., wrong key, corrupted data).
    public static func revealSealed(
        hint: Data,
        encryptedContent: Data,
        nonce: Data,
        sealKey: Data
    ) throws -> Data {
        var outPlaintext = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = hint.withUnsafeBytes { hintBytes in
            encryptedContent.withUnsafeBytes { contentBytes in
                nonce.withUnsafeBytes { nonceBytes in
                    sealKey.withUnsafeBytes { keyBytes in
                        native_epp_group_reveal_sealed(
                            hintBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            hint.count,
                            contentBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            encryptedContent.count,
                            nonceBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            nonce.count,
                            keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            sealKey.count,
                            &outPlaintext,
                            &outError
                        )
                    }
                }
            }
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
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

    /// Verifies a franking tag against the original content and sealed content.
    ///
    /// - Parameters:
    ///   - frankingTag: The franking tag to verify.
    ///   - frankingKey: The franking key.
    ///   - content: The original plaintext content.
    ///   - sealedContent: The sealed (encrypted) content.
    /// - Returns: `true` if the franking tag is valid, `false` otherwise.
    /// - Throws: `EppError` if verification encounters an error.
    public static func verifyFranking(
        frankingTag: Data,
        frankingKey: Data,
        content: Data,
        sealedContent: Data
    ) throws -> Bool {
        var outValid: UInt8 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = frankingTag.withUnsafeBytes { tagBytes in
            frankingKey.withUnsafeBytes { keyBytes in
                content.withUnsafeBytes { contentBytes in
                    sealedContent.withUnsafeBytes { sealedBytes in
                        native_epp_group_verify_franking(
                            tagBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            frankingTag.count,
                            keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            frankingKey.count,
                            contentBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            content.count,
                            sealedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            sealedContent.count,
                            &outValid,
                            &outError
                        )
                    }
                }
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return outValid != 0
    }

    // MARK: - State Queries

    /// The unique identifier of this group.
    ///
    /// - Throws: `EppError` if the group ID cannot be retrieved.
    public var groupId: Data {
        get throws {
            guard handle != nil else { throw EppError.objectDisposed }
            var outBuffer = NativeEppBuffer(data: nil, length: 0)
            var outError = NativeEppError(code: 0, message: nil)
            let result = native_epp_group_get_id(handle, &outBuffer, &outError)
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

    /// The current epoch number of the group.
    ///
    /// The epoch advances with each commit.
    public var epoch: UInt64 {
        return native_epp_group_get_epoch(handle)
    }

    /// This member's leaf index within the group tree.
    public var myLeafIndex: UInt32 {
        return native_epp_group_get_my_leaf_index(handle)
    }

    /// The number of members currently in the group.
    public var memberCount: UInt32 {
        return native_epp_group_get_member_count(handle)
    }

    /// Returns the leaf indices of all current group members.
    ///
    /// The returned array contains `UInt32` leaf indices that can be used to
    /// identify specific members (e.g., for removal).
    ///
    /// - Returns: An array of member leaf indices.
    /// - Throws: `EppError` if the query fails.
    public func memberLeafIndices() throws -> [UInt32] {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_get_member_leaf_indices(handle, &outBuffer, &outError)
        defer {
            if outBuffer.data != nil { native_epp_buffer_release(&outBuffer) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let ptr = outBuffer.data else {
            throw EppError.bufferTooSmall
        }
        let count = outBuffer.length / MemoryLayout<UInt32>.size
        var indices = [UInt32]()
        indices.reserveCapacity(count)
        let typedPtr = UnsafeRawPointer(ptr).bindMemory(to: UInt32.self, capacity: count)
        for i in 0..<count {
            indices.append(typedPtr[i])
        }
        return indices
    }

    /// Whether this group session uses the shielded security policy.
    ///
    /// - Throws: `EppError` if the query fails.
    public var isShielded: Bool {
        get throws {
            guard handle != nil else { throw EppError.objectDisposed }
            var outShielded: UInt8 = 0
            var outError = NativeEppError(code: 0, message: nil)
            let result = native_epp_group_is_shielded(handle, &outShielded, &outError)
            defer { native_epp_error_free(&outError) }
            guard result == EPP_SUCCESS else {
                throw EppError.from(code: result, nativeError: outError)
            }
            return outShielded != 0
        }
    }

    /// Returns the current security policy of the group session.
    ///
    /// - Returns: The `EppGroupSecurityPolicy` in effect.
    /// - Throws: `EppError` if the query fails.
    public func securityPolicy() throws -> EppGroupSecurityPolicy {
        guard handle != nil else { throw EppError.objectDisposed }
        var nativePolicy = NativeEppGroupSecurityPolicy(
            max_messages_per_epoch: 0,
            max_skipped_keys_per_sender: 0,
            block_external_join: 0,
            enhanced_key_schedule: 0,
            mandatory_franking: 0
        )
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_get_security_policy(handle, &nativePolicy, &outError)
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppGroupSecurityPolicy.from(native: nativePolicy)
    }

    // MARK: - PSK

    /// Sets a pre-shared key (PSK) on the group session.
    ///
    /// PSKs provide an additional layer of authentication and can be used
    /// to bind the group to an external secret.
    ///
    /// - Parameters:
    ///   - pskId: The identifier for the PSK.
    ///   - psk: The pre-shared key bytes.
    /// - Throws: `EppError` if setting the PSK fails.
    public func setPsk(pskId: Data, psk: Data) throws {
        guard handle != nil else { throw EppError.objectDisposed }
        var outError = NativeEppError(code: 0, message: nil)
        let result = pskId.withUnsafeBytes { pskIdBytes in
            psk.withUnsafeBytes { pskBytes in
                native_epp_group_set_psk(
                    handle,
                    pskIdBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    pskId.count,
                    pskBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    psk.count,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
    }

    // MARK: - Reinit

    /// Checks whether a reinit is pending for this group session.
    ///
    /// A reinit occurs when the group needs to transition to a new group ID or
    /// protocol version. If a reinit is pending, the caller should create a new
    /// group session with the returned parameters.
    ///
    /// - Returns: A tuple containing the new group ID and protocol version if a reinit is pending,
    ///   or `nil` if no reinit is pending.
    /// - Throws: `EppError` if the query fails.
    public func pendingReinit() throws -> (newGroupId: Data, newVersion: UInt32)? {
        guard handle != nil else { throw EppError.objectDisposed }
        var outGroupId = NativeEppBuffer(data: nil, length: 0)
        var outVersion: UInt32 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_get_pending_reinit(
            handle,
            &outGroupId,
            &outVersion,
            &outError
        )
        defer {
            if outGroupId.data != nil { native_epp_buffer_release(&outGroupId) }
            native_epp_error_free(&outError)
        }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let groupIdData = dataFromBuffer(outGroupId) else {
            return nil
        }
        return (groupIdData, outVersion)
    }

    // MARK: - Serialization

    /// Serializes the group session state, encrypted under the given key, for persistent storage.
    ///
    /// The external counter is a monotonic value that the caller must persist alongside
    /// the sealed state to prevent rollback attacks during deserialization.
    ///
    /// - Parameters:
    ///   - key: The encryption key used to seal the state.
    ///   - externalCounter: A monotonically increasing counter value.
    /// - Returns: The sealed group session state.
    /// - Throws: `EppError` if serialization fails.
    public func serialize(key: Data, externalCounter: UInt64) throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = key.withUnsafeBytes { keyBytes in
            native_epp_group_serialize(
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

    /// Deserializes a previously sealed group session state.
    ///
    /// The `minExternalCounter` parameter prevents rollback attacks by rejecting
    /// sealed states whose counter is below this value.
    ///
    /// - Parameters:
    ///   - sealedState: The sealed group session state data.
    ///   - key: The encryption key used to unseal the state.
    ///   - minExternalCounter: The minimum acceptable external counter value.
    ///   - identity: The identity associated with this group membership.
    /// - Returns: A tuple containing the restored `EppGroupSession` and its external counter.
    /// - Throws: `EppError` if deserialization or authentication fails.
    public static func deserialize(
        sealedState: Data,
        key: Data,
        minExternalCounter: UInt64,
        identity: EppIdentity
    ) throws -> (session: EppGroupSession, externalCounter: UInt64) {
        guard identity.handle != nil else { throw EppError.objectDisposed }
        var outHandle: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            key.withUnsafeBytes { keyBytes in
                native_epp_group_deserialize(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    key.count,
                    minExternalCounter,
                    &outCounter,
                    identity.handle,
                    &outHandle,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return (EppGroupSession(handle: handle), outCounter)
    }

    /// Exports the public state of the group for external join operations.
    ///
    /// The exported state can be shared with parties that want to join the group
    /// without receiving a welcome message.
    ///
    /// - Returns: The serialized public group state.
    /// - Throws: `EppError` if export fails.
    public func exportPublicState() throws -> Data {
        guard handle != nil else { throw EppError.objectDisposed }
        var outBuffer = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
        let result = native_epp_group_export_public_state(handle, &outBuffer, &outError)
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
