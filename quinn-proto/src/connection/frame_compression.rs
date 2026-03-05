use crate::{TransportError, VarInt, coding::Codec};

const SCHC_PAYLOAD_MARKER: [u8; 4] = *b"SCHC";
const SCHC_PAYLOAD_VERSION: u8 = 1;
const SCHC_ENVELOPE_BASE_LEN: usize = 4 + 1 + 1 + 4;
const SCHC_TRIM_ZERO_SUFFIX_LEN: usize = SCHC_ENVELOPE_BASE_LEN + 2;
const SCHC_MARKER_RANGE: std::ops::Range<usize> = 0..4;
const SCHC_VERSION_INDEX: usize = 4;
const SCHC_RULE_INDEX: usize = 5;
const SCHC_PROFILE_SIGNATURE_RANGE: std::ops::Range<usize> = 6..10;
const SCHC_BODY_RANGE: std::ops::RangeFrom<usize> = 10..;
const SCHC_TRIM_ORIGINAL_LEN_RANGE: std::ops::Range<usize> = 10..12;
const SCHC_TRIM_BODY_RANGE: std::ops::RangeFrom<usize> = 12..;
const QUIC_DATAGRAM_WITH_LEN_TYPE: u8 = 0x31;

fn read_u16_be(input: &[u8]) -> u16 {
    let mut bytes = [0; 2];
    bytes.copy_from_slice(input);
    u16::from_be_bytes(bytes)
}

fn read_u32_be(input: &[u8]) -> u32 {
    let mut bytes = [0; 4];
    bytes.copy_from_slice(input);
    u32::from_be_bytes(bytes)
}

fn decode_quic_varint(input: &[u8]) -> Option<(u64, usize)> {
    let mut cursor = input;
    let start = cursor.len();
    let value = VarInt::decode(&mut cursor).ok()?;
    Some((value.into_inner(), start - cursor.len()))
}

fn encode_quic_varint(value: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    VarInt::from_u64(value).ok()?.encode(&mut out);
    Some(out)
}

fn trimmed_zero_suffix_len(payload: &[u8]) -> usize {
    payload
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last_non_zero| last_non_zero + 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SchcFrameRule {
    EscapeRaw = 0,
    TrimZeroSuffix = 1,
    DatagramZeroTail = 2,
}

impl SchcFrameRule {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EscapeRaw),
            1 => Some(Self::TrimZeroSuffix),
            2 => Some(Self::DatagramZeroTail),
            _ => None,
        }
    }
}

pub(crate) trait FrameCompressionCodec {
    fn compress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError>;
    fn decompress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopFrameCompressionCodec;

impl FrameCompressionCodec for NoopFrameCompressionCodec {
    fn compress(&self, _: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }

    fn decompress(&self, _: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SchcFrameCompressionCodec {
    profile_id: VarInt,
    profile_revision: VarInt,
    max_decompressed_payload: usize,
}

impl SchcFrameCompressionCodec {
    pub(crate) fn new(
        profile_id: VarInt,
        profile_revision: VarInt,
        max_decompressed_payload: usize,
    ) -> Self {
        Self {
            profile_id,
            profile_revision,
            max_decompressed_payload,
        }
    }

    fn profile_signature(&self) -> [u8; 4] {
        let profile = self.profile_id.into_inner();
        let revision = self.profile_revision.into_inner();
        let mixed =
            profile.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ revision.rotate_left(17) ^ (profile >> 7);
        let signature = (mixed as u32) ^ ((mixed >> 32) as u32);
        signature.to_be_bytes()
    }

    fn is_schc_envelope(payload: &[u8]) -> bool {
        payload.len() >= SCHC_ENVELOPE_BASE_LEN
            && payload[SCHC_MARKER_RANGE] == SCHC_PAYLOAD_MARKER
            && payload[SCHC_VERSION_INDEX] == SCHC_PAYLOAD_VERSION
    }

    fn encode_envelope(&self, rule: SchcFrameRule, metadata: &[u8], body: &[u8]) -> Vec<u8> {
        let mut compressed =
            Vec::with_capacity(SCHC_ENVELOPE_BASE_LEN + metadata.len() + body.len());
        compressed.extend_from_slice(&SCHC_PAYLOAD_MARKER);
        compressed.push(SCHC_PAYLOAD_VERSION);
        compressed.push(rule as u8);
        compressed.extend_from_slice(&self.profile_signature());
        compressed.extend_from_slice(metadata);
        compressed.extend_from_slice(body);
        compressed
    }

    fn try_compress_trim_zero_suffix(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let original_len = u16::try_from(payload.len()).ok()?;
        let trimmed_len = trimmed_zero_suffix_len(payload);
        if trimmed_len == payload.len() {
            return None;
        }

        Some(self.encode_envelope(
            SchcFrameRule::TrimZeroSuffix,
            &original_len.to_be_bytes(),
            &payload[..trimmed_len],
        ))
    }

    fn try_compress_datagram_zero_tail(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.first().copied() != Some(QUIC_DATAGRAM_WITH_LEN_TYPE) {
            return None;
        }

        let (declared_len, varint_len) = decode_quic_varint(payload.get(1..)?)?;
        let declared_len = usize::try_from(declared_len).ok()?;
        let data_start = 1 + varint_len;
        if payload.len() < data_start {
            return None;
        }
        let data = payload.get(data_start..)?;
        if data.len() != declared_len {
            return None;
        }
        let datagram_len_u16 = u16::try_from(declared_len).ok()?;

        let trimmed_len = trimmed_zero_suffix_len(data);
        if trimmed_len == data.len() {
            return None;
        }

        Some(self.encode_envelope(
            SchcFrameRule::DatagramZeroTail,
            &datagram_len_u16.to_be_bytes(),
            &data[..trimmed_len],
        ))
    }

    fn validate_and_decode_profile_signature(&self, payload: &[u8]) -> Result<(), TransportError> {
        let encoded = read_u32_be(&payload[SCHC_PROFILE_SIGNATURE_RANGE]);
        let expected = u32::from_be_bytes(self.profile_signature());
        if encoded != expected {
            return Err(TransportError::FRAME_ENCODING_ERROR(
                "SCHC profile signature mismatch",
            ));
        }
        Ok(())
    }

    fn ensure_within_limit(&self, decompressed_len: usize) -> Result<(), TransportError> {
        if decompressed_len > self.max_decompressed_payload {
            return Err(TransportError::FRAME_ENCODING_ERROR(
                "SCHC payload exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn decompress_datagram_zero_tail(&self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        if payload.len() < SCHC_TRIM_ZERO_SUFFIX_LEN {
            return Err(TransportError::FRAME_ENCODING_ERROR(
                "malformed SCHC datagram payload",
            ));
        }

        let original_datagram_len =
            usize::from(read_u16_be(&payload[SCHC_TRIM_ORIGINAL_LEN_RANGE]));
        let trimmed_data = &payload[SCHC_TRIM_BODY_RANGE];
        if trimmed_data.len() > original_datagram_len {
            return Err(TransportError::FRAME_ENCODING_ERROR(
                "malformed SCHC datagram payload envelope",
            ));
        }

        let mut data = Vec::with_capacity(original_datagram_len);
        data.extend_from_slice(trimmed_data);
        data.resize(original_datagram_len, 0);

        let datagram_len = encode_quic_varint(original_datagram_len as u64).ok_or(
            TransportError::FRAME_ENCODING_ERROR("invalid SCHC datagram length"),
        )?;
        let mut decompressed = Vec::with_capacity(1 + datagram_len.len() + data.len());
        decompressed.push(QUIC_DATAGRAM_WITH_LEN_TYPE);
        decompressed.extend_from_slice(&datagram_len);
        decompressed.extend_from_slice(&data);
        Ok(decompressed)
    }
}

impl FrameCompressionCodec for SchcFrameCompressionCodec {
    fn compress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        let mut best: Option<Vec<u8>> = None;

        let candidates = [
            self.try_compress_datagram_zero_tail(payload),
            self.try_compress_trim_zero_suffix(payload),
        ];
        for candidate in candidates {
            if let Some(candidate) = candidate {
                if candidate.len() >= payload.len() {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|current_best| candidate.len() < current_best.len())
                {
                    best = Some(candidate);
                }
            }
        }

        if best.is_none() && Self::is_schc_envelope(payload) {
            return Ok(Some(self.encode_envelope(
                SchcFrameRule::EscapeRaw,
                &[],
                payload,
            )));
        }

        Ok(best)
    }

    fn decompress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        if !Self::is_schc_envelope(payload) {
            return Ok(None);
        }

        self.validate_and_decode_profile_signature(payload)?;

        let rule = SchcFrameRule::from_u8(payload[SCHC_RULE_INDEX]).ok_or(
            TransportError::FRAME_ENCODING_ERROR("unknown SCHC frame rule"),
        )?;
        let decompressed = match rule {
            SchcFrameRule::EscapeRaw => payload[SCHC_BODY_RANGE].to_vec(),
            SchcFrameRule::TrimZeroSuffix => {
                if payload.len() < SCHC_TRIM_ZERO_SUFFIX_LEN {
                    return Err(TransportError::FRAME_ENCODING_ERROR(
                        "malformed SCHC payload envelope",
                    ));
                }

                let decompressed_len =
                    usize::from(read_u16_be(&payload[SCHC_TRIM_ORIGINAL_LEN_RANGE]));
                let body = &payload[SCHC_TRIM_BODY_RANGE];
                if body.len() > decompressed_len {
                    return Err(TransportError::FRAME_ENCODING_ERROR(
                        "malformed SCHC payload envelope",
                    ));
                }

                let mut decompressed = Vec::with_capacity(decompressed_len);
                decompressed.extend_from_slice(body);
                decompressed.resize(decompressed_len, 0);
                decompressed
            }
            SchcFrameRule::DatagramZeroTail => self.decompress_datagram_zero_tail(payload)?,
        };

        self.ensure_within_limit(decompressed.len())?;
        Ok(Some(decompressed))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum FrameCompressionState {
    Disabled(NoopFrameCompressionCodec),
    Schc(SchcFrameCompressionCodec),
}

impl Default for FrameCompressionState {
    fn default() -> Self {
        Self::Disabled(NoopFrameCompressionCodec)
    }
}

impl FrameCompressionState {
    pub(crate) fn use_schc(
        &mut self,
        profile_id: VarInt,
        profile_revision: VarInt,
        max_decompressed_payload: usize,
    ) {
        *self = Self::Schc(SchcFrameCompressionCodec::new(
            profile_id,
            profile_revision,
            max_decompressed_payload,
        ));
    }

    pub(crate) fn disable(&mut self) {
        *self = Self::Disabled(NoopFrameCompressionCodec);
    }

    pub(crate) fn is_schc_enabled(&self) -> bool {
        matches!(self, Self::Schc(_))
    }

    pub(crate) fn compress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        match self {
            Self::Disabled(codec) => codec.compress(payload),
            Self::Schc(codec) => codec.compress(payload),
        }
    }

    pub(crate) fn decompress(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        match self {
            Self::Disabled(codec) => codec.decompress(payload),
            Self::Schc(codec) => codec.decompress(payload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameCompressionCodec, SchcFrameCompressionCodec};
    use crate::{VarInt, coding::Codec};

    #[test]
    fn schc_roundtrip() {
        let codec = SchcFrameCompressionCodec::new(VarInt(7), VarInt(1), 2048);
        let payload = [
            1u8, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let compressed = codec.compress(&payload).unwrap().unwrap();
        let decompressed = codec.decompress(&compressed).unwrap().unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn schc_profile_mismatch_errors() {
        let codec = SchcFrameCompressionCodec::new(VarInt(7), VarInt(1), 2048);
        let other = SchcFrameCompressionCodec::new(VarInt(8), VarInt(1), 2048);
        let payload = [1u8, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let compressed = codec.compress(&payload).unwrap().unwrap();
        other.decompress(&compressed).unwrap_err();
    }

    #[test]
    fn schc_datagram_zero_tail_roundtrip() {
        let codec = SchcFrameCompressionCodec::new(VarInt(9), VarInt(1), 4096);

        let mut payload = Vec::new();
        payload.push(0x31);
        crate::VarInt::from_u64(256).unwrap().encode(&mut payload);
        payload.push(0xAA);
        payload.resize(payload.len() + 255, 0);

        let compressed = codec.compress(&payload).unwrap().unwrap();
        assert!(compressed.len() < payload.len());
        let decompressed = codec.decompress(&compressed).unwrap().unwrap();
        assert_eq!(decompressed, payload);
    }

    #[test]
    fn schc_malformed_envelope_errors() {
        let codec = SchcFrameCompressionCodec::new(VarInt(7), VarInt(1), 2048);
        let malformed = b"SCHC\x01\xFF\x00\x00\x00\x00".to_vec();
        codec.decompress(&malformed).unwrap_err();
    }
}
