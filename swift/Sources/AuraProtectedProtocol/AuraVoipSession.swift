import Foundation

public enum AuraCallControlType {
    case mute
    case unmute
    case hold
    case unhold
    case dtmf(UInt8)
}

public struct AuraEncryptedVoipFrame {
    public let callId: Data
    public let ssrc: UInt32
    public let frameCounter: UInt64
    public let ratchetGeneration: UInt32
    public let encryptedPayload: Data
    public let nonce: Data
    public let encryptedHeader: Data
}

public struct AuraDecryptedVoipFrame {
    public let payload: Data
    public let payloadType: UInt8
    public let ssrc: UInt32
    public let timestamp: UInt32
    public let sequenceNumber: UInt16
    public let frameCounter: UInt64
    public let ratchetGeneration: UInt32
}

private func voipDataFromBuffer(_ buffer: NativeAuraBuffer) throws -> Data {
    if buffer.length == 0 {
        return Data()
    }
    guard let ptr = buffer.data else {
        throw AuraError.bufferTooSmall
    }
    return Data(bytes: ptr, count: buffer.length)
}

public struct AuraVoipScreenShareMeta {
    public let width: UInt32
    public let height: UInt32
    public let frameRate: UInt32
    public let codecHint: String?
}

public struct AuraVoipCallStatistics {
    public let framesSent: UInt64
    public let framesReceived: UInt64
    public let framesDropped: UInt64
    public let rekeyCount: UInt32
    public let ratchetGeneration: UInt32
    public let callDurationSeconds: UInt64
}

public final class AuraVoipCallInitiator {
    private var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_voip_call_initiator_destroy(&handle)
        }
    }

    public static func start(
        identity: AuraIdentity,
        peerKyberPublic: Data,
        shieldMode: Bool = false,
        ratchetIntervalFrames: UInt32 = 512,
        pqRekeyIntervalSeconds: UInt32 = 60
    ) throws -> (initiator: AuraVoipCallInitiator, callInit: Data) {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var outHandle: UnsafeMutableRawPointer?
        var outInit = NativeAuraBuffer(data: nil, length: 0)
        var outError = NativeAuraError(code: 0, message: nil)
        let result = peerKyberPublic.withUnsafeBytes { keyBytes in
            native_epp_voip_call_init_start(
                identity.handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                peerKyberPublic.count,
                shieldMode ? 1 : 0,
                ratchetIntervalFrames,
                pqRekeyIntervalSeconds,
                &outInit,
                &outHandle,
                &outError
            )
        }
        defer {
            if outInit.data != nil { native_epp_buffer_release(&outInit) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS, let handle = outHandle else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let callInit = dataFromBuffer(outInit) else {
            throw AuraError.bufferTooSmall
        }
        return (AuraVoipCallInitiator(handle: handle), callInit)
    }

    public func finish(identity: AuraIdentity, callAccept: Data) throws -> AuraVoipSession {
        guard handle != nil else { throw AuraError.objectDisposed }
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = callAccept.withUnsafeBytes { acceptBytes in
            native_epp_voip_call_init_complete(
                handle,
                identity.handle,
                acceptBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                callAccept.count,
                &outSession,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraVoipSession(handle: sessionHandle)
    }
}

public final class AuraVoipSession: @unchecked Sendable {
    private var handle: UnsafeMutableRawPointer?

    internal init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if handle != nil {
            native_epp_voip_session_destroy(&handle)
        }
    }

    public func encryptFrame(
        payloadType: UInt8,
        ssrc: UInt32,
        timestamp: UInt32,
        sequenceNumber: UInt16,
        payload: Data
    ) throws -> AuraEncryptedVoipFrame {
        var nativeFrame = NativeAuraEncryptedFrame(
            call_id: NativeAuraBuffer(data: nil, length: 0),
            ssrc: 0,
            frame_counter: 0,
            ratchet_generation: 0,
            encrypted_payload: NativeAuraBuffer(data: nil, length: 0),
            nonce: NativeAuraBuffer(data: nil, length: 0),
            encrypted_header: NativeAuraBuffer(data: nil, length: 0)
        )
        var err = NativeAuraError(code: 0, message: nil)

        let code = payload.withUnsafeBytes { ptr in
            native_epp_voip_encrypt_frame(
                handle,
                payloadType, ssrc, timestamp, sequenceNumber,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                payload.count,
                &nativeFrame, &err
            )
        }
        defer {
            if nativeFrame.call_id.data != nil { native_epp_buffer_release(&nativeFrame.call_id) }
            if nativeFrame.encrypted_payload.data != nil { native_epp_buffer_release(&nativeFrame.encrypted_payload) }
            if nativeFrame.nonce.data != nil { native_epp_buffer_release(&nativeFrame.nonce) }
            if nativeFrame.encrypted_header.data != nil { native_epp_buffer_release(&nativeFrame.encrypted_header) }
        }
        try checkResult(code, &err)

        let result = AuraEncryptedVoipFrame(
            callId: try voipDataFromBuffer(nativeFrame.call_id),
            ssrc: nativeFrame.ssrc,
            frameCounter: nativeFrame.frame_counter,
            ratchetGeneration: nativeFrame.ratchet_generation,
            encryptedPayload: try voipDataFromBuffer(nativeFrame.encrypted_payload),
            nonce: try voipDataFromBuffer(nativeFrame.nonce),
            encryptedHeader: try voipDataFromBuffer(nativeFrame.encrypted_header)
        )
        return result
    }

    public func decryptFrame(_ frame: AuraEncryptedVoipFrame) throws -> AuraDecryptedVoipFrame {
        var nativeFrame = NativeAuraDecryptedFrame(
            payload: NativeAuraBuffer(data: nil, length: 0),
            payload_type: 0, ssrc: 0, timestamp: 0,
            sequence_number: 0, frame_counter: 0, ratchet_generation: 0
        )
        var err = NativeAuraError(code: 0, message: nil)

        let code = frame.callId.withUnsafeBytes { cidPtr in
            frame.encryptedPayload.withUnsafeBytes { payPtr in
                frame.nonce.withUnsafeBytes { noncePtr in
                    frame.encryptedHeader.withUnsafeBytes { hdrPtr in
                        native_epp_voip_decrypt_frame(
                            handle,
                            cidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), frame.callId.count,
                            frame.ssrc, frame.frameCounter, frame.ratchetGeneration,
                            payPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), frame.encryptedPayload.count,
                            noncePtr.baseAddress?.assumingMemoryBound(to: UInt8.self), frame.nonce.count,
                            hdrPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), frame.encryptedHeader.count,
                            &nativeFrame, &err
                        )
                    }
                }
            }
        }
        defer {
            if nativeFrame.payload.data != nil { native_epp_buffer_release(&nativeFrame.payload) }
        }
        try checkResult(code, &err)

        return AuraDecryptedVoipFrame(
            payload: try voipDataFromBuffer(nativeFrame.payload),
            payloadType: nativeFrame.payload_type,
            ssrc: nativeFrame.ssrc,
            timestamp: nativeFrame.timestamp,
            sequenceNumber: nativeFrame.sequence_number,
            frameCounter: nativeFrame.frame_counter,
            ratchetGeneration: nativeFrame.ratchet_generation
        )
    }

    public var callId: Data {
        get throws {
            var buf = NativeAuraBuffer(data: nil, length: 0)
            var err = NativeAuraError(code: 0, message: nil)
            let code = native_epp_voip_call_id(handle, &buf, &err)
            defer {
                if buf.data != nil { native_epp_buffer_release(&buf) }
            }
            try checkResult(code, &err)
            guard let ptr = buf.data else { return Data() }
            return Data(bytes: ptr, count: buf.length)
        }
    }

    public var ssrc: UInt32 {
        var err = NativeAuraError(code: 0, message: nil)
        return native_epp_voip_ssrc(handle, &err)
    }

    public var isShieldMode: Bool {
        var err = NativeAuraError(code: 0, message: nil)
        return native_epp_voip_is_shield_mode(handle, &err) != 0
    }

    public func endCall() throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_end_call(handle, &err)
        try checkResult(code, &err)
    }

    public func generateCallEndHmac(deviceId: Data, timestamp: UInt64) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = deviceId.withUnsafeBytes { ptr in
            native_epp_voip_generate_call_end_hmac(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                deviceId.count,
                timestamp,
                &buf, &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func verifyCallEndHmac(deviceId: Data, timestamp: UInt64, hmacValue: Data) throws -> Bool {
        var outValid: UInt8 = 0
        var err = NativeAuraError(code: 0, message: nil)
        let code = deviceId.withUnsafeBytes { devicePtr in
            hmacValue.withUnsafeBytes { hmacPtr in
                native_epp_voip_verify_call_end_hmac(
                    handle,
                    devicePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    deviceId.count,
                    timestamp,
                    hmacPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    hmacValue.count,
                    &outValid,
                    &err
                )
            }
        }
        try checkResult(code, &err)
        return outValid != 0
    }

    public func buildCallEnd(deviceId: Data, timestamp: UInt64) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = deviceId.withUnsafeBytes { ptr in
            native_epp_voip_build_call_end(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                deviceId.count,
                timestamp,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func processCallEnd(_ callEnd: Data) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = callEnd.withUnsafeBytes { ptr in
            native_epp_voip_process_call_end(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                callEnd.count,
                &err
            )
        }
        try checkResult(code, &err)
    }

    public func encryptCallControl(_ control: AuraCallControlType) throws -> AuraEncryptedVoipFrame {
        var nativeFrame = NativeAuraEncryptedFrame(
            call_id: NativeAuraBuffer(data: nil, length: 0),
            ssrc: 0, frame_counter: 0, ratchet_generation: 0,
            encrypted_payload: NativeAuraBuffer(data: nil, length: 0),
            nonce: NativeAuraBuffer(data: nil, length: 0),
            encrypted_header: NativeAuraBuffer(data: nil, length: 0)
        )
        var err = NativeAuraError(code: 0, message: nil)

        let (controlType, dtmfDigit): (UInt8, UInt8) = {
            switch control {
            case .mute: return (1, 0)
            case .unmute: return (2, 0)
            case .hold: return (3, 0)
            case .unhold: return (4, 0)
            case .dtmf(let d): return (5, d)
            }
        }()

        let code = native_epp_voip_encrypt_call_control(
            handle, controlType, dtmfDigit, &nativeFrame, &err
        )
        defer {
            if nativeFrame.call_id.data != nil { native_epp_buffer_release(&nativeFrame.call_id) }
            if nativeFrame.encrypted_payload.data != nil { native_epp_buffer_release(&nativeFrame.encrypted_payload) }
            if nativeFrame.nonce.data != nil { native_epp_buffer_release(&nativeFrame.nonce) }
            if nativeFrame.encrypted_header.data != nil { native_epp_buffer_release(&nativeFrame.encrypted_header) }
        }
        try checkResult(code, &err)

        return AuraEncryptedVoipFrame(
            callId: try voipDataFromBuffer(nativeFrame.call_id),
            ssrc: nativeFrame.ssrc,
            frameCounter: nativeFrame.frame_counter,
            ratchetGeneration: nativeFrame.ratchet_generation,
            encryptedPayload: try voipDataFromBuffer(nativeFrame.encrypted_payload),
            nonce: try voipDataFromBuffer(nativeFrame.nonce),
            encryptedHeader: try voipDataFromBuffer(nativeFrame.encrypted_header)
        )
    }

    public func setScreenShareMeta(
        width: UInt32,
        height: UInt32,
        frameRate: UInt32,
        codecHint: String? = nil
    ) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = codecHint?.data(using: .utf8)?.withUnsafeBytes { ptr in
            native_epp_voip_set_screen_share_meta(
                handle,
                width,
                height,
                frameRate,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                ptr.count,
                &err
            )
        } ?? native_epp_voip_set_screen_share_meta(
            handle,
            width,
            height,
            frameRate,
            nil,
            0,
            &err
        )
        try checkResult(code, &err)
    }

    public func getScreenShareMeta() throws -> AuraVoipScreenShareMeta? {
        var width: UInt32 = 0
        var height: UInt32 = 0
        var frameRate: UInt32 = 0
        var codecHint = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_get_screen_share_meta(
            handle,
            &width,
            &height,
            &frameRate,
            &codecHint,
            &err
        )
        defer {
            if codecHint.data != nil { native_epp_buffer_release(&codecHint) }
        }
        try checkResult(code, &err)
        if width == 0 && height == 0 && frameRate == 0 && codecHint.length == 0 {
            return nil
        }
        let hint = codecHint.data.map { String(decoding: UnsafeBufferPointer(start: $0, count: codecHint.length), as: UTF8.self) }
        return AuraVoipScreenShareMeta(
            width: width,
            height: height,
            frameRate: frameRate,
            codecHint: hint
        )
    }

    public func clearScreenShareMeta() throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_clear_screen_share_meta(handle, &err)
        try checkResult(code, &err)
    }

    public func getCallStatistics() throws -> AuraVoipCallStatistics {
        var nativeStats = NativeAuraCallStatistics(
            frames_sent: 0,
            frames_received: 0,
            frames_dropped: 0,
            rekey_count: 0,
            ratchet_generation: 0,
            call_duration_secs: 0
        )
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_get_call_statistics(handle, &nativeStats, &err)
        try checkResult(code, &err)
        return AuraVoipCallStatistics(
            framesSent: nativeStats.frames_sent,
            framesReceived: nativeStats.frames_received,
            framesDropped: nativeStats.frames_dropped,
            rekeyCount: nativeStats.rekey_count,
            ratchetGeneration: nativeStats.ratchet_generation,
            callDurationSeconds: nativeStats.call_duration_secs
        )
    }

    public func setRecordingConsent(_ consent: Int32) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_set_recording_consent(handle, consent, &err)
        try checkResult(code, &err)
    }

    public var localRecordingConsent: Int32 {
        native_epp_voip_get_local_recording_consent(handle)
    }

    public var remoteRecordingConsent: Int32 {
        native_epp_voip_get_remote_recording_consent(handle)
    }

    public var bothConsentedToRecording: Bool {
        native_epp_voip_both_consented_to_recording(handle)
    }

    public func buildRecordingConsentMessage(
        identity: AuraIdentity,
        consent: Int32,
        timestampUnix: UInt64
    ) throws -> Data {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var outMessage = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = native_epp_voip_build_recording_consent_message(
            handle,
            identity.handle,
            consent,
            timestampUnix,
            &outMessage,
            &err
        )
        defer {
            if outMessage.data != nil { native_epp_buffer_release(&outMessage) }
        }
        try checkResult(code, &err)
        guard let message = dataFromBuffer(outMessage) else {
            throw AuraError.bufferTooSmall
        }
        return message
    }

    public func processRecordingConsentMessage(
        _ message: Data,
        peerEd25519Public: Data
    ) throws {
        var err = NativeAuraError(code: 0, message: nil)
        let code = peerEd25519Public.withUnsafeBytes { peerBytes in
            message.withUnsafeBytes { messageBytes in
                native_epp_voip_process_recording_consent_message(
                    handle,
                    peerBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerEd25519Public.count,
                    messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    message.count,
                    &err
                )
            }
        }
        try checkResult(code, &err)
    }

    public func exportSealedState(stateKey: Data, externalCounter: UInt64) throws -> Data {
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = stateKey.withUnsafeBytes { ptr in
            native_epp_voip_export_sealed_state(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                stateKey.count,
                externalCounter,
                &buf, &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func exportSealedState(
        stateKey: Data,
        tracker: AuraSealedStateCounterTracker
    ) throws -> Data {
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = stateKey.withUnsafeBytes { ptr in
            native_epp_voip_export_sealed_state_with_tracker(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                stateKey.count,
                tracker.handle,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func exportPersistedState(
        stateKey: Data,
        slot: AuraSealedStateSlot
    ) throws {
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        var err = NativeAuraError(code: 0, message: nil)
        let code = stateKey.withUnsafeBytes { ptr in
            native_epp_voip_export_persisted_state(
                handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                stateKey.count,
                slot.handle,
                &err
            )
        }
        try checkResult(code, &err)
    }

    public func initiateRekey(identity: AuraIdentity, peerKyberPublic: Data) throws -> Data {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = peerKyberPublic.withUnsafeBytes { ptr in
            native_epp_voip_initiate_rekey(
                handle,
                identity.handle,
                ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                peerKyberPublic.count,
                &buf,
                &err
            )
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func processRekey(
        identity: AuraIdentity,
        peerEd25519Public: Data,
        rekeyBytes: Data,
        peerKyberPublic: Data
    ) throws -> Data {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var buf = NativeAuraBuffer(data: nil, length: 0)
        var err = NativeAuraError(code: 0, message: nil)
        let code = peerEd25519Public.withUnsafeBytes { peerEdPtr in
            rekeyBytes.withUnsafeBytes { rekeyPtr in
                peerKyberPublic.withUnsafeBytes { peerKyberPtr in
                    native_epp_voip_process_rekey(
                        handle,
                        identity.handle,
                        peerEdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        peerEd25519Public.count,
                        rekeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        rekeyBytes.count,
                        peerKyberPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        peerKyberPublic.count,
                        &buf,
                        &err
                    )
                }
            }
        }
        defer {
            if buf.data != nil { native_epp_buffer_release(&buf) }
        }
        try checkResult(code, &err)
        guard let ptr = buf.data else { return Data() }
        return Data(bytes: ptr, count: buf.length)
    }

    public func processRekeyAck(
        identity: AuraIdentity,
        peerEd25519Public: Data,
        ackBytes: Data
    ) throws {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var err = NativeAuraError(code: 0, message: nil)
        let code = peerEd25519Public.withUnsafeBytes { peerEdPtr in
            ackBytes.withUnsafeBytes { ackPtr in
                native_epp_voip_process_rekey_ack(
                    handle,
                    identity.handle,
                    peerEdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerEd25519Public.count,
                    ackPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ackBytes.count,
                    &err
                )
            }
        }
        try checkResult(code, &err)
    }

    public static func acceptCall(
        identity: AuraIdentity,
        callInit: Data,
        peerKyberPublic: Data
    ) throws -> (session: AuraVoipSession, callAccept: Data) {
        guard identity.handle != nil else { throw AuraError.objectDisposed }

        var outAccept = NativeAuraBuffer(data: nil, length: 0)
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = callInit.withUnsafeBytes { callInitPtr in
            peerKyberPublic.withUnsafeBytes { peerKyberPtr in
                native_epp_voip_accept_call(
                    identity.handle,
                    callInitPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    callInit.count,
                    peerKyberPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    peerKyberPublic.count,
                    &outAccept,
                    &outSession,
                    &outError
                )
            }
        }
        defer {
            if outAccept.data != nil { native_epp_buffer_release(&outAccept) }
            native_epp_error_free(&outError)
        }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        guard let acceptData = dataFromBuffer(outAccept) else {
            throw AuraError.bufferTooSmall
        }
        return (AuraVoipSession(handle: sessionHandle), acceptData)
    }

    public static func importSealedState(
        _ sealedState: Data,
        stateKey: Data,
        minExternalCounter: UInt64
    ) throws -> (session: AuraVoipSession, externalCounter: UInt64) {
        var outSession: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)

        let counterResult = sealedState.withUnsafeBytes { stateBytes in
            native_epp_voip_sealed_state_external_counter(
                stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sealedState.count,
                &outCounter,
                &outError
            )
        }
        guard counterResult == AURA_SUCCESS else {
            defer { native_epp_error_free(&outError) }
            throw AuraError.from(code: counterResult, nativeError: outError)
        }
        native_epp_error_free(&outError)
        outError = NativeAuraError(code: 0, message: nil)

        let result = sealedState.withUnsafeBytes { stateBytes in
            stateKey.withUnsafeBytes { keyBytes in
                native_epp_voip_import_sealed_state(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    stateKey.count,
                    minExternalCounter,
                    &outSession,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return (AuraVoipSession(handle: sessionHandle), outCounter)
    }

    public static func importSealedState(
        _ sealedState: Data,
        stateKey: Data,
        minExternalCounter: UInt64,
        timeProvider: AuraTimeProvider
    ) throws -> (session: AuraVoipSession, externalCounter: UInt64) {
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outSession: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)

        let counterResult = sealedState.withUnsafeBytes { stateBytes in
            native_epp_voip_sealed_state_external_counter(
                stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sealedState.count,
                &outCounter,
                &outError
            )
        }
        guard counterResult == AURA_SUCCESS else {
            defer { native_epp_error_free(&outError) }
            throw AuraError.from(code: counterResult, nativeError: outError)
        }
        native_epp_error_free(&outError)
        outError = NativeAuraError(code: 0, message: nil)

        let result = sealedState.withUnsafeBytes { stateBytes in
            stateKey.withUnsafeBytes { keyBytes in
                native_epp_voip_import_sealed_state_with_time_provider(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    stateKey.count,
                    minExternalCounter,
                    timeProvider.handle,
                    &outSession,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return (AuraVoipSession(handle: sessionHandle), outCounter)
    }

    public static func importSealedState(
        _ sealedState: Data,
        stateKey: Data,
        tracker: AuraSealedStateCounterTracker
    ) throws -> AuraVoipSession {
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            stateKey.withUnsafeBytes { keyBytes in
                native_epp_voip_import_sealed_state_with_tracker(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    stateKey.count,
                    tracker.handle,
                    &outSession,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraVoipSession(handle: sessionHandle)
    }

    public static func importSealedState(
        _ sealedState: Data,
        stateKey: Data,
        tracker: AuraSealedStateCounterTracker,
        timeProvider: AuraTimeProvider
    ) throws -> AuraVoipSession {
        guard tracker.handle != nil else { throw AuraError.objectDisposed }
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            stateKey.withUnsafeBytes { keyBytes in
                native_epp_voip_import_sealed_state_with_tracker_and_time_provider(
                    stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    sealedState.count,
                    keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    stateKey.count,
                    tracker.handle,
                    timeProvider.handle,
                    &outSession,
                    &outError
                )
            }
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraVoipSession(handle: sessionHandle)
    }

    public static func restorePersistedState(
        slot: AuraSealedStateSlot,
        stateKey: Data
    ) throws -> AuraVoipSession {
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = stateKey.withUnsafeBytes { keyBytes in
            native_epp_voip_restore_persisted_state(
                slot.handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                stateKey.count,
                &outSession,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraVoipSession(handle: sessionHandle)
    }

    public static func restorePersistedState(
        slot: AuraSealedStateSlot,
        stateKey: Data,
        timeProvider: AuraTimeProvider
    ) throws -> AuraVoipSession {
        guard slot.handle != nil else { throw AuraError.objectDisposed }
        guard timeProvider.handle != nil else { throw AuraError.objectDisposed }
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeAuraError(code: 0, message: nil)
        let result = stateKey.withUnsafeBytes { keyBytes in
            native_epp_voip_restore_persisted_state_with_time_provider(
                slot.handle,
                keyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                stateKey.count,
                timeProvider.handle,
                &outSession,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS, let sessionHandle = outSession else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return AuraVoipSession(handle: sessionHandle)
    }

    public static func sealedStateExternalCounter(_ sealedState: Data) throws -> UInt64 {
        var outCounter: UInt64 = 0
        var outError = NativeAuraError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            native_epp_voip_sealed_state_external_counter(
                stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sealedState.count,
                &outCounter,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == AURA_SUCCESS else {
            throw AuraError.from(code: result, nativeError: outError)
        }
        return outCounter
    }
}
