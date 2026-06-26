import Foundation

public struct AuraContentPolicyConfig: Sendable {
    public let viewOnce: Bool
    public let noForward: Bool
    public let noSave: Bool

    public init(viewOnce: Bool = false, noForward: Bool = false, noSave: Bool = false) {
        self.viewOnce = viewOnce
        self.noForward = noForward
        self.noSave = noSave
    }
}

public enum AuraCollageLayout: Int32, Sendable {
    case grid = 0
    case carousel = 1
    case list = 2
    case stack = 3
}

public enum AuraReferenceType: Int32, Sendable {
    case reply = 0
    case quote = 1
    case forward = 2
}

public enum AuraAttachment {

    private static func withManifestPointerBuffers<R>(
        manifests: [Data],
        _ body: (UnsafeBufferPointer<UnsafePointer<UInt8>?>, UnsafeBufferPointer<Int>) throws -> R
    ) rethrows -> R {
        var rawPtrs: [UnsafePointer<UInt8>?] = Array(repeating: nil, count: manifests.count)
        let rawLens: [Int] = manifests.map(\.count)

        func borrow(_ index: Int) throws -> R {
            if index == manifests.count {
                return try rawPtrs.withUnsafeBufferPointer { ptrBuf in
                    try rawLens.withUnsafeBufferPointer { lenBuf in
                        try body(ptrBuf, lenBuf)
                    }
                }
            }

            return try manifests[index].withUnsafeBytes { ptr in
                rawPtrs[index] = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return try borrow(index + 1)
            }
        }

        return try borrow(0)
    }

    public static func generateId() throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_attachment_generate_id(&buf, &err)
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func generateFileKey() throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_attachment_generate_file_key(&buf, &err)
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func encryptChunk(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        plaintext: Data
    ) throws -> (nonce: Data, ciphertext: Data) {
        var outNonce = NativeAuraBuffer(data: nil, length: 0)
        var outCiphertext = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeType.withCString { mimePtr in
                    plaintext.withUnsafeBytes { ptPtr in
                        native_epp_attachment_encrypt_chunk(
                            fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            fkPtr.count,
                            aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            aidPtr.count,
                            mimePtr,
                            mimeType.utf8.count,
                            totalSize,
                            chunkSize,
                            chunkIndex,
                            chunkCount,
                            ptPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            ptPtr.count,
                            &outNonce,
                            &outCiphertext,
                            &err
                        )
                    }
                }
            }
        }
        defer {
            if outNonce.data != nil { native_epp_buffer_release(&outNonce) }
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let nonceData = dataFromBuffer(outNonce),
              let ctData = dataFromBuffer(outCiphertext) else {
            throw AuraError.bufferTooSmall
        }
        return (nonce: nonceData, ciphertext: ctData)
    }

    public static func decryptChunk(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        nonce: Data,
        ciphertext: Data
    ) throws -> Data {
        var outPlaintext = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeType.withCString { mimePtr in
                    nonce.withUnsafeBytes { noncePtr in
                        ciphertext.withUnsafeBytes { ctPtr in
                            native_epp_attachment_decrypt_chunk(
                                fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                fkPtr.count,
                                aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                aidPtr.count,
                                mimePtr,
                                mimeType.utf8.count,
                                totalSize,
                                chunkSize,
                                chunkIndex,
                                chunkCount,
                                noncePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                noncePtr.count,
                                ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                ctPtr.count,
                                &outPlaintext,
                                &err
                            )
                        }
                    }
                }
            }
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func createManifest(
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkCount: UInt32,
        fileSha256: Data,
        encryptedFileKey: Data
    ) throws -> Data {
        var outManifest = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = attachmentId.withUnsafeBytes { aidPtr in
            mimeType.withCString { mimePtr in
                fileSha256.withUnsafeBytes { shaPtr in
                    encryptedFileKey.withUnsafeBytes { efkPtr in
                        native_epp_attachment_manifest_create(
                            aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            aidPtr.count,
                            mimePtr,
                            mimeType.utf8.count,
                            totalSize,
                            chunkSize,
                            chunkCount,
                            shaPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            shaPtr.count,
                            efkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            efkPtr.count,
                            &outManifest,
                            &err
                        )
                    }
                }
            }
        }
        defer {
            if outManifest.data != nil { native_epp_buffer_release(&outManifest) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outManifest) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateManifest(_ manifestBytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = manifestBytes.withUnsafeBytes { ptr in
            native_epp_attachment_manifest_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func validateChunk(
        manifestBytes: Data,
        chunkIndex: UInt32,
        nonce: Data,
        ciphertext: Data
    ) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = manifestBytes.withUnsafeBytes { mPtr in
            nonce.withUnsafeBytes { noncePtr in
                ciphertext.withUnsafeBytes { ctPtr in
                    native_epp_attachment_chunk_validate(
                        mPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        mPtr.count,
                        chunkIndex,
                        noncePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        noncePtr.count,
                        ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        ctPtr.count,
                        &err
                    )
                }
            }
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func encryptThumbnail(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        plaintext: Data
    ) throws -> (nonce: Data, ciphertext: Data) {
        var outNonce = NativeAuraBuffer(data: nil, length: 0)
        var outCiphertext = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeData.withUnsafeBytes { mimePtr in
                    plaintext.withUnsafeBytes { ptPtr in
                        native_epp_attachment_encrypt_thumbnail(
                            fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            fkPtr.count,
                            aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            aidPtr.count,
                            mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            mimePtr.count,
                            ptPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            ptPtr.count,
                            &outNonce,
                            &outCiphertext,
                            &err
                        )
                    }
                }
            }
        }
        defer {
            if outNonce.data != nil { native_epp_buffer_release(&outNonce) }
            if outCiphertext.data != nil { native_epp_buffer_release(&outCiphertext) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let nonceData = dataFromBuffer(outNonce),
              let ctData = dataFromBuffer(outCiphertext) else {
            throw AuraError.bufferTooSmall
        }
        return (nonce: nonceData, ciphertext: ctData)
    }

    public static func decryptThumbnail(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        nonce: Data,
        ciphertext: Data
    ) throws -> Data {
        var outPlaintext = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeData.withUnsafeBytes { mimePtr in
                    nonce.withUnsafeBytes { noncePtr in
                        ciphertext.withUnsafeBytes { ctPtr in
                            native_epp_attachment_decrypt_thumbnail(
                                fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                fkPtr.count,
                                aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                aidPtr.count,
                                mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                mimePtr.count,
                                noncePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                noncePtr.count,
                                ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                ctPtr.count,
                                &outPlaintext,
                                &err
                            )
                        }
                    }
                }
            }
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateTtl(_ seconds: UInt64) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_attachment_validate_ttl(seconds, &err)
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func isExpired(createdAt: UInt64, ttl: UInt64, now: UInt64) -> Bool {
        native_epp_attachment_is_expired(createdAt, ttl, now)
    }

    public static func createProgress(
        attachmentId: Data,
        chunkCount: UInt32
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = attachmentId.withUnsafeBytes { aidPtr in
            native_epp_attachment_progress_create(
                aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                aidPtr.count,
                chunkCount,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func progressMarkCompleted(
        progressBytes: Data,
        chunkIndex: UInt32,
        bytesTransferred: UInt64,
        nowUnix: UInt64
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = progressBytes.withUnsafeBytes { pPtr in
            native_epp_attachment_progress_mark_completed(
                pPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                pPtr.count,
                chunkIndex,
                bytesTransferred,
                nowUnix,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func progressGetRemaining(
        progressBytes: Data
    ) throws -> (remaining: Data, count: UInt32) {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var remainingCount: UInt32 = 0
        var err = NativeAuraError(code: 0, message: nil)
        let code = progressBytes.withUnsafeBytes { pPtr in
            native_epp_attachment_progress_get_remaining(
                pPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                pPtr.count,
                &buf,
                &remainingCount,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        let data = dataFromBuffer(buf) ?? Data()
        return (remaining: data, count: remainingCount)
    }

    public static func progressIsComplete(_ progressBytes: Data) -> Bool {
        progressBytes.withUnsafeBytes { pPtr in
            native_epp_attachment_progress_is_complete(
                pPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                pPtr.count
            )
        }
    }

    public static func generateCollageId() throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_attachment_generate_collage_id(&buf, &err)
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func createCollage(manifests: [Data]) throws -> Data {
        var outCollage = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let manifestCount = manifests.count
        guard manifestCount > 0 else {
            throw AuraError.invalidInput("At least one manifest is required")
        }

        let code = Self.withManifestPointerBuffers(manifests: manifests) { ptrBuf, lenBuf in
            native_epp_attachment_collage_create(
                ptrBuf.baseAddress!,
                lenBuf.baseAddress!,
                manifestCount,
                &outCollage,
                &err
            )
        }
        defer {
            if outCollage.data != nil { native_epp_buffer_release(&outCollage) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outCollage) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateCollage(_ collageBytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = collageBytes.withUnsafeBytes { ptr in
            native_epp_attachment_collage_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func validateMagicBytes(header: Data, mimeType: String) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let code = header.withUnsafeBytes { hPtr in
            mimeData.withUnsafeBytes { mPtr in
                native_epp_attachment_validate_magic_bytes(
                    hPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    hPtr.count,
                    mPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    mPtr.count,
                    &err
                )
            }
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func detectMime(header: Data) throws -> String? {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = header.withUnsafeBytes { hPtr in
            native_epp_attachment_detect_mime(
                hPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                hPtr.count,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    public static func validateFilename(_ name: String) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let nameData = Data(name.utf8)
        let code = nameData.withUnsafeBytes { nPtr in
            native_epp_attachment_validate_filename(
                nPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                nPtr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func sanitizeFilename(_ name: String) throws -> String {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let nameData = Data(name.utf8)
        let code = nameData.withUnsafeBytes { nPtr in
            native_epp_attachment_sanitize_filename(
                nPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                nPtr.count,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf),
              let result = String(data: data, encoding: .utf8) else {
            throw AuraError.bufferTooSmall
        }
        return result
    }

    public static func createManifestV2(
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkCount: UInt32,
        fileSha256: Data,
        encryptedFileKey: Data,
        collageIndex: Int64 = -1,
        thumbnailCiphertext: Data? = nil,
        thumbnailNonce: Data? = nil,
        thumbnailMimeType: String? = nil,
        thumbnailOriginalSize: UInt32 = 0,
        ttlSeconds: UInt64 = 0,
        createdAtUnix: UInt64 = 0
    ) throws -> Data {
        var outManifest = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)

        let mimeData = Data(mimeType.utf8)
        let thumbMimeData = thumbnailMimeType.map { Data($0.utf8) } ?? Data()
        let thumbCt = thumbnailCiphertext ?? Data()
        let thumbNonce = thumbnailNonce ?? Data()

        let code = attachmentId.withUnsafeBytes { aidPtr in
            mimeData.withUnsafeBytes { mimePtr in
                fileSha256.withUnsafeBytes { shaPtr in
                    encryptedFileKey.withUnsafeBytes { efkPtr in
                        thumbCt.withUnsafeBytes { tctPtr in
                            thumbNonce.withUnsafeBytes { tnPtr in
                                thumbMimeData.withUnsafeBytes { tmPtr in
                                    native_epp_attachment_manifest_create_v2(
                                        aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        aidPtr.count,
                                        mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        mimePtr.count,
                                        totalSize,
                                        chunkSize,
                                        chunkCount,
                                        shaPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        shaPtr.count,
                                        efkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                        efkPtr.count,
                                        collageIndex,
                                        thumbnailCiphertext != nil ? tctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                        tctPtr.count,
                                        thumbnailNonce != nil ? tnPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                        tnPtr.count,
                                        thumbnailMimeType != nil ? tmPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                        tmPtr.count,
                                        thumbnailOriginalSize,
                                        ttlSeconds,
                                        createdAtUnix,
                                        &outManifest,
                                        &err
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        defer {
            if outManifest.data != nil { native_epp_buffer_release(&outManifest) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outManifest) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func encryptFileKey(
        sessionHandle: UnsafeMutableRawPointer,
        fileKey: Data,
        attachmentId: Data
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                native_epp_attachment_encrypt_file_key(
                    sessionHandle,
                    fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    fkPtr.count,
                    aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    aidPtr.count,
                    &buf,
                    &err
                )
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func decryptFileKey(
        sessionHandle: UnsafeMutableRawPointer,
        encryptedFileKey: Data,
        attachmentId: Data
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = encryptedFileKey.withUnsafeBytes { efkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                native_epp_attachment_decrypt_file_key(
                    sessionHandle,
                    efkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    efkPtr.count,
                    aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    aidPtr.count,
                    &buf,
                    &err
                )
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func createCollageWithMetadata(
        manifests: [Data],
        name: String? = nil,
        description: String? = nil,
        layout: AuraCollageLayout? = nil
    ) throws -> Data {
        var outCollage = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let manifestCount = manifests.count
        let nameData = name.map { Data($0.utf8) } ?? Data()
        let descData = description.map { Data($0.utf8) } ?? Data()
        let layoutValue = layout?.rawValue ?? -1
        guard manifestCount > 0 else {
            throw AuraError.invalidInput("At least one manifest is required")
        }

        let code = Self.withManifestPointerBuffers(manifests: manifests) { ptrBuf, lenBuf in
            nameData.withUnsafeBytes { nPtr in
                descData.withUnsafeBytes { dPtr in
                    native_epp_attachment_collage_create_with_metadata(
                        ptrBuf.baseAddress!,
                        lenBuf.baseAddress!,
                        manifestCount,
                        name != nil ? nPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                        nameData.count,
                        description != nil ? dPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                        descData.count,
                        layoutValue,
                        &outCollage,
                        &err
                    )
                }
            }
        }
        defer {
            if outCollage.data != nil { native_epp_buffer_release(&outCollage) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outCollage) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func createInlineAttachment(
        attachmentId: Data,
        mimeType: String,
        data inlineData: Data,
        filename: String? = nil,
        contentPolicy: AuraContentPolicyConfig? = nil
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let filenameData = filename.map { Data($0.utf8) } ?? Data()
        let hasPolicy: UInt8 = contentPolicy != nil ? 1 : 0
        let viewOnce: UInt8 = contentPolicy?.viewOnce == true ? 1 : 0
        let noForward: UInt8 = contentPolicy?.noForward == true ? 1 : 0
        let noSave: UInt8 = contentPolicy?.noSave == true ? 1 : 0

        let code = attachmentId.withUnsafeBytes { aidPtr in
            mimeData.withUnsafeBytes { mimePtr in
                inlineData.withUnsafeBytes { dPtr in
                    filenameData.withUnsafeBytes { fnPtr in
                        native_epp_attachment_inline_create(
                            aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            aidPtr.count,
                            mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            mimePtr.count,
                            dPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            dPtr.count,
                            filename != nil ? fnPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                            filenameData.count,
                            hasPolicy,
                            viewOnce,
                            noForward,
                            noSave,
                            &buf,
                            &err
                        )
                    }
                }
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateInlineAttachment(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_inline_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func createAttachmentReference(
        attachmentId: Data,
        referenceType: AuraReferenceType,
        sourceMessageId: Data? = nil
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let smid = sourceMessageId ?? Data()
        let code = attachmentId.withUnsafeBytes { aidPtr in
            smid.withUnsafeBytes { smidPtr in
                native_epp_attachment_reference_create(
                    aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    aidPtr.count,
                    referenceType.rawValue,
                    sourceMessageId != nil ? smidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                    smid.count,
                    &buf,
                    &err
                )
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateAttachmentReference(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_reference_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func createVoiceMessageMeta(
        waveform: [Float],
        transcript: String? = nil,
        playbackSpeed: Float? = nil,
        isListened: Bool = false
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let transcriptData = transcript.map { Data($0.utf8) } ?? Data()
        let hasSpeed: UInt8 = playbackSpeed != nil ? 1 : 0
        let speedVal: Float = playbackSpeed ?? 0.0
        let listened: UInt8 = isListened ? 1 : 0

        let code = waveform.withUnsafeBufferPointer { wPtr in
            transcriptData.withUnsafeBytes { tPtr in
                native_epp_attachment_voice_meta_create(
                    wPtr.baseAddress,
                    wPtr.count,
                    transcript != nil ? tPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                    transcriptData.count,
                    speedVal,
                    hasSpeed,
                    listened,
                    &buf,
                    &err
                )
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateVoiceMessageMeta(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_voice_meta_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func createLocationAttachment(
        latitude: Double,
        longitude: Double,
        accuracy: Double? = nil,
        label: String? = nil,
        timestamp: UInt64? = nil
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let labelData = label.map { Data($0.utf8) } ?? Data()
        let hasAccuracy: UInt8 = accuracy != nil ? 1 : 0
        let accuracyVal: Double = accuracy ?? 0.0
        let hasTimestamp: UInt8 = timestamp != nil ? 1 : 0
        let timestampVal: UInt64 = timestamp ?? 0

        let code = labelData.withUnsafeBytes { lPtr in
            native_epp_attachment_location_create(
                latitude,
                longitude,
                accuracyVal,
                hasAccuracy,
                label != nil ? lPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                labelData.count,
                timestampVal,
                hasTimestamp,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateLocationAttachment(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_location_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func createContactCard(
        displayName: String,
        phone: String? = nil,
        email: String? = nil,
        avatar: Data? = nil,
        organization: String? = nil
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let dnData = Data(displayName.utf8)
        let phoneData = phone.map { Data($0.utf8) } ?? Data()
        let emailData = email.map { Data($0.utf8) } ?? Data()
        let avatarData = avatar ?? Data()
        let orgData = organization.map { Data($0.utf8) } ?? Data()

        let code = dnData.withUnsafeBytes { dnPtr in
            phoneData.withUnsafeBytes { phPtr in
                emailData.withUnsafeBytes { emPtr in
                    avatarData.withUnsafeBytes { avPtr in
                        orgData.withUnsafeBytes { orgPtr in
                            native_epp_attachment_contact_card_create(
                                dnPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                dnPtr.count,
                                phone != nil ? phPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                phoneData.count,
                                email != nil ? emPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                emailData.count,
                                avatar != nil ? avPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                avatarData.count,
                                organization != nil ? orgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                orgData.count,
                                &buf,
                                &err
                            )
                        }
                    }
                }
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateContactCard(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_contact_card_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }

    public static func createLinkPreview(
        url: String,
        title: String? = nil,
        description: String? = nil,
        previewImage: Data? = nil,
        previewImageMime: String? = nil,
        domain: String? = nil
    ) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let urlData = Data(url.utf8)
        let titleData = title.map { Data($0.utf8) } ?? Data()
        let descData = description.map { Data($0.utf8) } ?? Data()
        let imageData = previewImage ?? Data()
        let imageMimeData = previewImageMime.map { Data($0.utf8) } ?? Data()
        let domainData = domain.map { Data($0.utf8) } ?? Data()

        let code = urlData.withUnsafeBytes { urlPtr in
            titleData.withUnsafeBytes { tPtr in
                descData.withUnsafeBytes { dPtr in
                    imageData.withUnsafeBytes { imgPtr in
                        imageMimeData.withUnsafeBytes { imPtr in
                            domainData.withUnsafeBytes { domPtr in
                                native_epp_attachment_link_preview_create(
                                    urlPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                    urlPtr.count,
                                    title != nil ? tPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                    titleData.count,
                                    description != nil ? dPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                    descData.count,
                                    previewImage != nil ? imgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                    imageData.count,
                                    previewImageMime != nil ? imPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                    imageMimeData.count,
                                    domain != nil ? domPtr.baseAddress?.assumingMemoryBound(to: UInt8.self) : nil,
                                    domainData.count,
                                    &buf,
                                    &err
                                )
                            }
                        }
                    }
                }
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(buf) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public static func validateLinkPreview(_ bytes: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = bytes.withUnsafeBytes { ptr in
            native_epp_attachment_link_preview_validate(
                ptr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
    }
}

public final class AuraStreamingEncryptor {

    private var handle: UnsafeMutableRawPointer?

    public init(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkCount: UInt32
    ) throws {
        var outHandle: UnsafeMutableRawPointer? = nil
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeData.withUnsafeBytes { mimePtr in
                    native_epp_attachment_streaming_encryptor_create(
                        fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        fkPtr.count,
                        aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        aidPtr.count,
                        mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        mimePtr.count,
                        totalSize,
                        chunkSize,
                        chunkCount,
                        &outHandle,
                        &err
                    )
                }
            }
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        self.handle = outHandle
    }

    deinit {
        if handle != nil {
            native_epp_attachment_streaming_encryptor_destroy(&handle)
        }
    }

    public func write(_ data: Data) throws -> (chunks: Data, chunkCount: UInt32) {
        guard let h = handle else {
            throw AuraError.objectDisposed
        }
        var outChunks = NativeAuraBuffer(data: nil, length: 0)
        var outCount: UInt32 = 0
        var err = NativeAuraError(code: 0, message: nil)
        let code = data.withUnsafeBytes { dPtr in
            native_epp_attachment_streaming_encryptor_write(
                h,
                dPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                dPtr.count,
                &outChunks,
                &outCount,
                &err
            )
        }
        defer {
            if outChunks.data != nil { native_epp_buffer_release(&outChunks) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        let chunksData = dataFromBuffer(outChunks) ?? Data()
        return (chunks: chunksData, chunkCount: outCount)
    }

    public func finish() throws -> Data? {
        guard let h = handle else {
            throw AuraError.objectDisposed
        }
        handle = nil
        var outChunk = NativeAuraBuffer(data: nil, length: 0)
        var hasChunk: UInt8 = 0
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_attachment_streaming_encryptor_finish(
            h,
            &outChunk,
            &hasChunk,
            &err
        )
        defer {
            if outChunk.data != nil { native_epp_buffer_release(&outChunk) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        if hasChunk != 0 {
            return dataFromBuffer(outChunk)
        }
        return nil
    }
}

public final class AuraStreamingDecryptor {

    private var handle: UnsafeMutableRawPointer?

    public init(
        fileKey: Data,
        attachmentId: Data,
        mimeType: String,
        totalSize: UInt64,
        chunkSize: UInt32,
        chunkCount: UInt32
    ) throws {
        var outHandle: UnsafeMutableRawPointer? = nil
        var err = NativeAuraError(code: 0, message: nil)
        let mimeData = Data(mimeType.utf8)
        let code = fileKey.withUnsafeBytes { fkPtr in
            attachmentId.withUnsafeBytes { aidPtr in
                mimeData.withUnsafeBytes { mimePtr in
                    native_epp_attachment_streaming_decryptor_create(
                        fkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        fkPtr.count,
                        aidPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        aidPtr.count,
                        mimePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        mimePtr.count,
                        totalSize,
                        chunkSize,
                        chunkCount,
                        &outHandle,
                        &err
                    )
                }
            }
        }
        defer { native_epp_error_free(&err) }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        self.handle = outHandle
    }

    deinit {
        if handle != nil {
            native_epp_attachment_streaming_decryptor_destroy(&handle)
        }
    }

    public func decryptNext(
        chunkIndex: UInt32,
        nonce: Data,
        ciphertext: Data
    ) throws -> Data {
        guard let h = handle else {
            throw AuraError.objectDisposed
        }
        var outPlaintext = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = nonce.withUnsafeBytes { noncePtr in
            ciphertext.withUnsafeBytes { ctPtr in
                native_epp_attachment_streaming_decryptor_write(
                    h,
                    chunkIndex,
                    noncePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    noncePtr.count,
                    ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    ctPtr.count,
                    &outPlaintext,
                    &err
                )
            }
        }
        defer {
            if outPlaintext.data != nil { native_epp_buffer_release(&outPlaintext) }
            native_epp_error_free(&err)
        }
        guard code == AURA_SUCCESS else {
            throw AuraError.from(code: code, nativeError: err)
        }
        guard let data = dataFromBuffer(outPlaintext) else {
            throw AuraError.bufferTooSmall
        }
        return data
    }

    public var isComplete: Bool {
        guard let h = handle else {
            return false
        }
        return native_epp_attachment_streaming_decryptor_is_complete(h)
    }
}
