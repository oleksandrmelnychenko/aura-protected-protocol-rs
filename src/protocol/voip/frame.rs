use crate::core::constants::*;
use crate::core::errors::ProtocolError;

pub struct FrameHeader {
    pub payload_type: u8,
    pub ssrc: u32,
    pub timestamp: u32,
    pub sequence_number: u16,
}

impl FrameHeader {
    pub const SERIALIZED_SIZE: usize = 11;

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.push(self.payload_type);
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(ProtocolError::voip_media("frame header too short"));
        }
        let payload_type = data[0];
        let ssrc = u32::from_be_bytes(
            data[1..5]
                .try_into()
                .map_err(|_| ProtocolError::voip_media("ssrc parse failed"))?,
        );
        let timestamp = u32::from_be_bytes(
            data[5..9]
                .try_into()
                .map_err(|_| ProtocolError::voip_media("timestamp parse failed"))?,
        );
        let sequence_number = u16::from_be_bytes(
            data[9..11]
                .try_into()
                .map_err(|_| ProtocolError::voip_media("sequence number parse failed"))?,
        );
        Ok(Self {
            payload_type,
            ssrc,
            timestamp,
            sequence_number,
        })
    }
}

pub fn build_frame_aad(
    call_id: &[u8],
    ssrc: u32,
    frame_counter: u64,
    ratchet_generation: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(call_id.len() + SSRC_BYTES + 8 + 4);
    aad.extend_from_slice(call_id);
    aad.extend_from_slice(&ssrc.to_be_bytes());
    aad.extend_from_slice(&frame_counter.to_be_bytes());
    aad.extend_from_slice(&ratchet_generation.to_be_bytes());
    aad
}
