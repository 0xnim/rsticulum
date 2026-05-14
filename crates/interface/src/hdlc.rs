//! HDLC framing protocol — byte-compatible with Python RNS `SerialInterface.py`
//!
//! HDLC-like framing used by RNode hardware over serial. Each frame is wrapped
//! with FLAG bytes (0x7E), and special bytes are escaped using 0x7D with XOR 0x20.

/// Frame delimiter / flag byte
pub const FLAG: u8 = 0x7E;
/// Escape byte
pub const ESC: u8 = 0x7D;
/// XOR mask applied to escaped bytes
pub const ESC_MASK: u8 = 0x20;

/// Stateless HDLC frame encoder.
pub struct HdlcFrame;

impl HdlcFrame {
    /// Escapes the given data bytes for HDLC framing.
    ///   ESC (0x7D) → ESC (ESC ^ ESC_MASK) = 0x7D 0x5D
    ///   FLAG (0x7E) → ESC (FLAG ^ ESC_MASK) = 0x7D 0x5E
    fn escape(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + data.len() / 4);
        for &b in data {
            match b {
                ESC => {
                    out.push(ESC);
                    out.push(ESC ^ ESC_MASK); // 0x5D
                }
                FLAG => {
                    out.push(ESC);
                    out.push(FLAG ^ ESC_MASK); // 0x5E
                }
                _ => out.push(b),
            }
        }
        out
    }

    /// Encode an HDLC frame: FLAG + escaped(data) + FLAG
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(data.len() + data.len() / 4 + 2);
        frame.push(FLAG);
        frame.extend(HdlcFrame::escape(data));
        frame.push(FLAG);
        frame
    }
}

/// State-machine HDLC frame decoder.
///
/// Feed bytes one at a time via `feed()`. Returns `Some(Vec<u8>)` when a
/// complete frame has been decoded, or `None` if more data is needed.
#[derive(Debug, Clone)]
pub struct HdlcDecoder {
    /// Whether we are currently inside a frame (past the opening FLAG)
    in_frame: bool,
    /// Whether the previous byte was ESC (escape mode)
    escape: bool,
    /// Accumulated data buffer for the current frame
    data_buffer: Vec<u8>,
}

impl HdlcDecoder {
    /// Create a new HDLC decoder in the initial state.
    pub fn new() -> Self {
        HdlcDecoder {
            in_frame: false,
            escape: false,
            data_buffer: Vec::new(),
        }
    }

    /// Reset the decoder to initial state, discarding any partial frame.
    pub fn reset(&mut self) {
        self.in_frame = false;
        self.escape = false;
        self.data_buffer.clear();
    }

    /// Feed a single byte to the decoder. Returns `Some(Vec<u8>)` when a
    /// complete frame has been decoded, or `None` if more data is needed.
    pub fn feed(&mut self, byte: u8) -> Option<Vec<u8>> {
        if !self.in_frame {
            // Wait for opening FLAG
            if byte == FLAG {
                self.in_frame = true;
                self.escape = false;
                self.data_buffer.clear();
            }
            return None;
        }

        if self.escape {
            // Previous byte was ESC — unescape this byte
            self.escape = false;
            // XOR with ESC_MASK: FLAG^MASK = 0x5E, ESC^MASK = 0x5D, etc.
            let unescaped = byte ^ ESC_MASK;
            self.data_buffer.push(unescaped);
            return None;
        }

        if byte == ESC {
            self.escape = true;
            return None;
        }

        if byte == FLAG {
            // Closing FLAG — finalize frame, but stay in-frame:
            // the closing FLAG doubles as the opening FLAG of the next
            // frame (standard HDLC back-to-back behavior).
            let result = std::mem::take(&mut self.data_buffer);
            self.data_buffer.clear();
            // in_frame stays true: this FLAG is also the next frame's opening FLAG
            self.in_frame = true;
            return Some(result);
        }

        // Normal data byte
        self.data_buffer.push(byte);
        None
    }
}

impl Default for HdlcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode/decode roundtrip ──────────────────────────────────────────

    #[test]
    fn roundtrip_empty() {
        let encoded = HdlcFrame::encode(&[]);
        // Expected: FLAG, FLAG
        assert_eq!(encoded, vec![FLAG, FLAG]);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_small_payload() {
        let data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    #[test]
    fn roundtrip_large_payload() {
        let data: Vec<u8> = (0..255u8).collect();
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    // ── escape sequences ─────────────────────────────────────────────────

    #[test]
    fn escape_flag_in_payload() {
        // FLAG (0x7E) should become ESC+(FLAG^MASK) = 0x7D 0x5E
        let data = vec![0x41, FLAG, 0x42];
        let encoded = HdlcFrame::encode(&data);

        assert_eq!(encoded, vec![FLAG, 0x41, ESC, FLAG ^ ESC_MASK, 0x42, FLAG]);
        assert_eq!(encoded[2], ESC); // 0x7D — first byte of escape pair
        assert_eq!(encoded[3], 0x5E); // 0x7E ^ 0x20 = 0x5E — second byte

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    #[test]
    fn escape_esc_in_payload() {
        // ESC (0x7D) should become ESC+(ESC^MASK) = 0x7D 0x5D
        let data = vec![0x41, ESC, 0x42];
        let encoded = HdlcFrame::encode(&data);

        assert_eq!(encoded, vec![FLAG, 0x41, ESC, ESC ^ ESC_MASK, 0x42, FLAG]);
        assert_eq!(encoded[2], ESC); // 0x7D — first byte of escape pair
        assert_eq!(encoded[3], 0x5D); // 0x7D ^ 0x20 = 0x5D — second byte

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    #[test]
    fn all_escape_bytes_payload() {
        // Payload of ONLY bytes that need escaping
        let data = vec![FLAG, ESC, FLAG, ESC];
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    // ── partial feed / multiple feed calls ───────────────────────────────

    #[test]
    fn partial_frame_across_feeds() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();

        for (i, &b) in encoded.iter().enumerate() {
            let is_last = i == encoded.len() - 1;
            let result = decoder.feed(b);
            if is_last {
                assert!(result.is_some(), "should return frame on last byte {}", i);
                results.push(result.unwrap());
            } else {
                assert!(result.is_none(), "should not return frame at byte {}", i);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    // ── multiple consecutive frames ──────────────────────────────────────

    #[test]
    fn multiple_consecutive_frames() {
        let data1 = vec![0x01, 0x02, 0x03];
        let data2 = vec![0xAA, 0xBB, 0xCC];

        let mut combined = Vec::new();
        combined.push(FLAG);
        combined.extend(HdlcFrame::escape(&data1));
        // Shared FLAG — closes frame1, opens frame2
        combined.push(FLAG);
        combined.extend(HdlcFrame::escape(&data2));
        combined.push(FLAG);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &combined {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], data1);
        assert_eq!(results[1], data2);
    }

    // ── decoder reset ────────────────────────────────────────────────────

    #[test]
    fn decoder_reset_during_partial_frame() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();

        // Feed only first half of frame
        for &b in &encoded[..3] {
            assert!(decoder.feed(b).is_none());
        }

        // Reset — ensure state is cleared
        decoder.reset();
        assert!(!decoder.in_frame);
        assert!(!decoder.escape);
        assert!(decoder.data_buffer.is_empty());

        // Now feed a complete frame — should work
        let mut results = Vec::new();
        for &b in &HdlcFrame::encode(&data) {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    // ── edge cases ───────────────────────────────────────────────────────

    #[test]
    fn leading_garbage_before_flag() {
        // Bytes before opening FLAG should be ignored
        let data = vec![0x01, 0x02, 0x03];
        let encoded = HdlcFrame::encode(&data);

        let mut stream = vec![0xFF, 0xFE, 0xFD]; // garbage
        stream.extend(encoded);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &stream {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    #[test]
    fn single_byte_frame() {
        let data = vec![0x42];
        let encoded = HdlcFrame::encode(&data);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], data);
    }

    #[test]
    fn back_to_back_flag_sharing() {
        // When frames are back-to-back, the closing FLAG of one is the
        // opening FLAG of the next. This is standard HDLC behavior.
        let data1 = vec![0x01, 0x02];
        let data2 = vec![0x03, 0x04];

        let mut stream = Vec::new();
        stream.push(FLAG);
        stream.extend(HdlcFrame::escape(&data1));
        // Shared FLAG — closes frame 1 and opens frame 2
        stream.push(FLAG);
        stream.extend(HdlcFrame::escape(&data2));
        stream.push(FLAG);

        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &stream {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], data1);
        assert_eq!(results[1], data2);
    }

    #[test]
    fn empty_frame_flagged() {
        // Empty frame between two FLAGs
        let stream = vec![FLAG, FLAG];
        let mut decoder = HdlcDecoder::new();
        let mut results = Vec::new();
        for &b in &stream {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], Vec::<u8>::new());
    }
}
