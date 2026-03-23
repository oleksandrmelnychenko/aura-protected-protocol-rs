import Foundation

public enum EppCallControlType {
    case mute
    case unmute
    case hold
    case unhold
    case dtmf(UInt8)
}

public struct EppEncryptedVoipFrame {
    public let callId: Data
    public let ssrc: UInt32
    public let frameCounter: UInt64
    public let ratchetGeneration: UInt32
    public let encryptedPayload: Data
    public let nonce: Data
    public let encryptedHeader: Data
}

public struct EppDecryptedVoipFrame {
    public let payload: Data
    public let payloadType: UInt8
    public let ssrc: UInt32
    public let timestamp: UInt32
    public let sequenceNumber: UInt16
    public let frameCounter: UInt64
    public let ratchetGeneration: UInt32
}

public final class EppVoipCallInitiator {
    private var handle: UnsafeMutableRawPointer?

    private init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if let h = handle {
            native_epp_voip_call_initiator_destroy(h)
        }
    }

    public static func start(
        identity: EppIdentity,
        peerKyberPublic: Data,
        shieldMode: Bool = false,
        ratchetIntervalFrames: UInt32 = 512,
        pqRekeyIntervalSeconds: UInt32 = 60
    ) throws -> (initiator: EppVoipCallInitiator, callInit: Data) {
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var outHandle: UnsafeMutableRawPointer?
        var outInit = NativeEppBuffer(data: nil, length: 0)
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS, let handle = outHandle else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let callInit = dataFromBuffer(outInit) else {
            throw EppError.bufferTooSmall
        }
        return (EppVoipCallInitiator(handle: handle), callInit)
    }

    public func finish(identity: EppIdentity, callAccept: Data) throws -> EppVoipSession {
        guard handle != nil else { throw EppError.objectDisposed }
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var outSession: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS, let sessionHandle = outSession else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return EppVoipSession(handle: sessionHandle)
    }
}

public final class EppVoipSession: @unchecked Sendable {
    private var handle: UnsafeMutableRawPointer?

    internal init(handle: UnsafeMutableRawPointer) {
        self.handle = handle
    }

    deinit {
        if let h = handle {
            native_epp_voip_session_destroy(h)
        }
    }

    public func encryptFrame(
        payloadType: UInt8,
        ssrc: UInt32,
        timestamp: UInt32,
        sequenceNumber: UInt16,
        payload: Data
    ) throws -> EppEncryptedVoipFrame {
        var nativeFrame = NativeEppEncryptedFrame(
            call_id: NativeEppBuffer(data: nil, length: 0),
            ssrc: 0,
            frame_counter: 0,
            ratchet_generation: 0,
            encrypted_payload: NativeEppBuffer(data: nil, length: 0),
            nonce: NativeEppBuffer(data: nil, length: 0),
            encrypted_header: NativeEppBuffer(data: nil, length: 0)
        )
        var err = NativeEppError(code: 0, message: nil)

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

        let result = EppEncryptedVoipFrame(
            callId: Data(bytes: nativeFrame.call_id.data!, count: nativeFrame.call_id.length),
            ssrc: nativeFrame.ssrc,
            frameCounter: nativeFrame.frame_counter,
            ratchetGeneration: nativeFrame.ratchet_generation,
            encryptedPayload: Data(bytes: nativeFrame.encrypted_payload.data!, count: nativeFrame.encrypted_payload.length),
            nonce: Data(bytes: nativeFrame.nonce.data!, count: nativeFrame.nonce.length),
            encryptedHeader: Data(bytes: nativeFrame.encrypted_header.data!, count: nativeFrame.encrypted_header.length)
        )
        return result
    }

    public func decryptFrame(_ frame: EppEncryptedVoipFrame) throws -> EppDecryptedVoipFrame {
        var nativeFrame = NativeEppDecryptedFrame(
            payload: NativeEppBuffer(data: nil, length: 0),
            payload_type: 0, ssrc: 0, timestamp: 0,
            sequence_number: 0, frame_counter: 0, ratchet_generation: 0
        )
        var err = NativeEppError(code: 0, message: nil)

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

        return EppDecryptedVoipFrame(
            payload: Data(bytes: nativeFrame.payload.data!, count: nativeFrame.payload.length),
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
            var buf = NativeEppBuffer(data: nil, length: 0)
            var err = NativeEppError(code: 0, message: nil)
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
        var err = NativeEppError(code: 0, message: nil)
        return native_epp_voip_ssrc(handle, &err)
    }

    public var isShieldMode: Bool {
        var err = NativeEppError(code: 0, message: nil)
        return native_epp_voip_is_shield_mode(handle, &err) != 0
    }

    public func endCall() throws {
        var err = NativeEppError(code: 0, message: nil)
        let code = native_epp_voip_end_call(handle, &err)
        try checkResult(code, &err)
    }

    public func generateCallEndHmac(deviceId: Data, timestamp: UInt64) throws -> Data {
        var buf = NativeEppBuffer(data: nil, length: 0)
        var err = NativeEppError(code: 0, message: nil)
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
        var err = NativeEppError(code: 0, message: nil)
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
        var buf = NativeEppBuffer(data: nil, length: 0)
        var err = NativeEppError(code: 0, message: nil)
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
        var err = NativeEppError(code: 0, message: nil)
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

    public func encryptCallControl(_ control: EppCallControlType) throws -> EppEncryptedVoipFrame {
        var nativeFrame = NativeEppEncryptedFrame(
            call_id: NativeEppBuffer(data: nil, length: 0),
            ssrc: 0, frame_counter: 0, ratchet_generation: 0,
            encrypted_payload: NativeEppBuffer(data: nil, length: 0),
            nonce: NativeEppBuffer(data: nil, length: 0),
            encrypted_header: NativeEppBuffer(data: nil, length: 0)
        )
        var err = NativeEppError(code: 0, message: nil)

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

        return EppEncryptedVoipFrame(
            callId: Data(bytes: nativeFrame.call_id.data!, count: nativeFrame.call_id.length),
            ssrc: nativeFrame.ssrc,
            frameCounter: nativeFrame.frame_counter,
            ratchetGeneration: nativeFrame.ratchet_generation,
            encryptedPayload: Data(bytes: nativeFrame.encrypted_payload.data!, count: nativeFrame.encrypted_payload.length),
            nonce: Data(bytes: nativeFrame.nonce.data!, count: nativeFrame.nonce.length),
            encryptedHeader: Data(bytes: nativeFrame.encrypted_header.data!, count: nativeFrame.encrypted_header.length)
        )
    }

    public func exportSealedState(stateKey: Data, externalCounter: UInt64) throws -> Data {
        var buf = NativeEppBuffer(data: nil, length: 0)
        var err = NativeEppError(code: 0, message: nil)
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

    public func initiateRekey(identity: EppIdentity, peerKyberPublic: Data) throws -> Data {
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var buf = NativeEppBuffer(data: nil, length: 0)
        var err = NativeEppError(code: 0, message: nil)
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
        identity: EppIdentity,
        peerEd25519Public: Data,
        rekeyBytes: Data,
        peerKyberPublic: Data
    ) throws -> Data {
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var buf = NativeEppBuffer(data: nil, length: 0)
        var err = NativeEppError(code: 0, message: nil)
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
        identity: EppIdentity,
        peerEd25519Public: Data,
        ackBytes: Data
    ) throws {
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var err = NativeEppError(code: 0, message: nil)
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
        identity: EppIdentity,
        callInit: Data,
        peerKyberPublic: Data
    ) throws -> (session: EppVoipSession, callAccept: Data) {
        guard identity.handle != nil else { throw EppError.objectDisposed }

        var outAccept = NativeEppBuffer(data: nil, length: 0)
        var outSession: UnsafeMutableRawPointer?
        var outError = NativeEppError(code: 0, message: nil)
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
        guard result == EPP_SUCCESS, let sessionHandle = outSession else {
            throw EppError.from(code: result, nativeError: outError)
        }
        guard let acceptData = dataFromBuffer(outAccept) else {
            throw EppError.bufferTooSmall
        }
        return (EppVoipSession(handle: sessionHandle), acceptData)
    }

    public static func importSealedState(
        _ sealedState: Data,
        stateKey: Data,
        minExternalCounter: UInt64
    ) throws -> (session: EppVoipSession, externalCounter: UInt64) {
        var outSession: UnsafeMutableRawPointer?
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)

        let counterResult = sealedState.withUnsafeBytes { stateBytes in
            native_epp_voip_sealed_state_external_counter(
                stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sealedState.count,
                &outCounter,
                &outError
            )
        }
        guard counterResult == EPP_SUCCESS else {
            defer { native_epp_error_free(&outError) }
            throw EppError.from(code: counterResult, nativeError: outError)
        }
        native_epp_error_free(&outError)
        outError = NativeEppError(code: 0, message: nil)

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
        guard result == EPP_SUCCESS, let sessionHandle = outSession else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return (EppVoipSession(handle: sessionHandle), outCounter)
    }

    public static func sealedStateExternalCounter(_ sealedState: Data) throws -> UInt64 {
        var outCounter: UInt64 = 0
        var outError = NativeEppError(code: 0, message: nil)
        let result = sealedState.withUnsafeBytes { stateBytes in
            native_epp_voip_sealed_state_external_counter(
                stateBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                sealedState.count,
                &outCounter,
                &outError
            )
        }
        defer { native_epp_error_free(&outError) }
        guard result == EPP_SUCCESS else {
            throw EppError.from(code: result, nativeError: outError)
        }
        return outCounter
    }
}
