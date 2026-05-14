//! KISS framing protocol — byte-compatible with Python RNS `KISSInterface.py`
//!
//! KISS (Keep It Simple, Stupid) is a protocol for communicating with TNCs.
//! Each frame is wrapped with FEND bytes, and special bytes are escaped.

/// Frame End delimiter
pub const FEND: u8 = 0xC0;
/// Frame Escape
pub const FESC: u8 = 0xDB;
/// Transposed Frame End (escaped FEND)
pub const TFEND: u8 = 0xDC;
/// Transposed Frame Escape (escaped FESC)
pub const TFESC: u8 = 0xDD;

/// KISS command — data frame
pub const CMD_DATA: u8 = 0x00;
/// KISS command — set TX delay (value in 10ms units)
pub const CMD_TXDELAY: u8 = 0x01;
/// KISS command — set persistence
pub const CMD_P: u8 = 0x02;
/// KISS command — set slot time (value in 10ms units)
pub const CMD_SLOTTIME: u8 = 0x03;
/// KISS command — set TX tail (value in 10ms units)
pub const CMD_TXTAIL: u8 = 0x04;
/// KISS command — set full duplex
pub const CMD_FULLDUPLEX: u8 = 0x05;
/// KISS command — set hardware
pub const CMD_SETHARDWARE: u8 = 0x06;
/// KISS command — TNC is ready
pub const CMD_READY: u8 = 0x0F;
/// KISS command — unknown command response
pub const CMD_UNKNOWN: u8 = 0xFE;
/// KISS command — return code
pub const CMD_RETURN: u8 = 0xFF;

/// A decoded KISS frame, consisting of a command byte and payload data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KissFrameResult {
    /// The KISS command byte
    pub command: u8,
    /// The decoded payload data
    pub data: Vec<u8>,
}

/// Stateless KISS frame encoder.
pub struct KissFrame;

impl KissFrame {
    /// Escapes the given data bytes for KISS framing.
    ///   FESC (0xDB) → FESC TFESC (0xDB 0xDD)
    ///   FEND (0xC0) → FESC TFEND (0xDB 0xDC)
    fn escape(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + data.len() / 4);
        for &b in data {
            match b {
                FESC => {
                    out.push(FESC);
                    out.push(TFESC);
                }
                FEND => {
                    out.push(FESC);
                    out.push(TFEND);
                }
                _ => out.push(b),
            }
        }
        out
    }

    /// Encode a KISS data frame: FEND + CMD_DATA + escaped(data) + FEND
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(data.len() + data.len() / 4 + 3);
        frame.push(FEND);
        frame.push(CMD_DATA);
        frame.extend(KissFrame::escape(data));
        frame.push(FEND);
        frame
    }

    /// Encode a KISS command frame with arbitrary payload data.
    /// Format: FEND + cmd + escaped(data) + FEND
    pub fn encode_cmd(cmd: u8, data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(data.len() + data.len() / 4 + 3);
        frame.push(FEND);
        frame.push(cmd);
        frame.extend(KissFrame::escape(data));
        frame.push(FEND);
        frame
    }

    /// Encode a KISS command frame with a single-byte value payload.
    /// Used for TXDELAY, P, SLOTTIME, TXTAIL configuration commands.
    /// Format: FEND + cmd + escaped([value]) + FEND
    pub fn encode_cmd_value(cmd: u8, value: u8) -> Vec<u8> {
        KissFrame::encode_cmd(cmd, &[value])
    }
}

/// State-machine KISS frame decoder.
///
/// Feed bytes one at a time via `feed()`. Returns `Some(KissFrameResult)`
/// when a complete frame has been decoded.
#[derive(Debug, Clone)]
pub struct KissDecoder {
    /// Whether we are currently inside a frame (past the opening FEND)
    in_frame: bool,
    /// Whether the previous byte was FESC (escape mode)
    escape: bool,
    /// Accumulated data buffer for the current frame
    data_buffer: Vec<u8>,
    /// The command byte for the current frame (None = not yet received)
    command: Option<u8>,
}

impl KissDecoder {
    /// Create a new KISS decoder in the initial state.
    pub fn new() -> Self {
        KissDecoder {
            in_frame: false,
            escape: false,
            data_buffer: Vec::new(),
            command: None,
        }
    }

    /// Reset the decoder to initial state, discarding any partial frame.
    pub fn reset(&mut self) {
        self.in_frame = false;
        self.escape = false;
        self.data_buffer.clear();
        self.command = None;
    }

    /// Feed a single byte to the decoder. Returns `Some(KissFrameResult)` when
    /// a complete frame has been decoded, or `None` if more data is needed.
    pub fn feed(&mut self, byte: u8) -> Option<KissFrameResult> {
        if !self.in_frame {
            // Wait for opening FEND
            if byte == FEND {
                self.in_frame = true;
                self.escape = false;
                self.data_buffer.clear();
                self.command = None;
            }
            return None;
        }

        if self.escape {
            // Previous byte was FESC — handle escaped byte
            self.escape = false;
            match byte {
                TFESC => self.data_buffer.push(FESC),
                TFEND => self.data_buffer.push(FEND),
                _ => {
                    // Malformed: unknown escape sequence; keep byte as-is
                    // (Python RNS silently accepts this)
                    self.data_buffer.push(byte);
                }
            }
            return None;
        }

        if byte == FESC {
            self.escape = true;
            return None;
        }

        if byte == FEND {
            // Closing FEND — finalize frame
            self.in_frame = false;
            let result = KissFrameResult {
                command: self.command.unwrap_or(CMD_DATA),
                data: std::mem::take(&mut self.data_buffer),
            };
            self.data_buffer.clear();
            self.command = None;
            return Some(result);
        }

        // Normal data byte — first non-command byte IS the command
        if self.command.is_none() {
            self.command = Some(byte);
        } else {
            self.data_buffer.push(byte);
        }

        None
    }
}

impl Default for KissDecoder {
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
        let encoded = KissFrame::encode(&[]);
        // Expected: FEND, CMD_DATA, FEND
        assert_eq!(encoded, vec![FEND, CMD_DATA, FEND]);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_DATA);
        assert_eq!(results[0].data, Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_small_payload() {
        let data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_DATA);
        assert_eq!(results[0].data, data);
    }

    #[test]
    fn roundtrip_large_payload() {
        let data: Vec<u8> = (0..255u8).collect();
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_DATA);
        assert_eq!(results[0].data, data);
    }

    // ── escape sequences ─────────────────────────────────────────────────

    #[test]
    fn escape_fesc_in_payload() {
        // Payload containing FESC (0xDB) should be escaped as FESC+TFESC
        let data = vec![0x41, FESC, 0x42];
        let encoded = KissFrame::encode(&data);

        // Expected: FEND, CMD_DATA, 0x41, FESC, TFESC, 0x42, FEND
        assert_eq!(encoded, vec![FEND, CMD_DATA, 0x41, FESC, TFESC, 0x42, FEND]);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }

    #[test]
    fn escape_fend_in_payload() {
        // Payload containing FEND (0xC0) should be escaped as FESC+TFEND
        let data = vec![0x41, FEND, 0x42];
        let encoded = KissFrame::encode(&data);

        assert_eq!(encoded, vec![FEND, CMD_DATA, 0x41, FESC, TFEND, 0x42, FEND]);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }

    #[test]
    fn all_escape_bytes_payload() {
        // Payload of ONLY escape-requiring bytes
        let data = vec![FEND, FESC, FEND, FESC];
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }

    // ── partial feed / multiple feed calls ───────────────────────────────

    #[test]
    fn partial_frame_across_feeds() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();

        // Feed one byte at a time, verify no premature result
        for (i, &b) in encoded.iter().enumerate() {
            let is_last = i == encoded.len() - 1;
            let result = decoder.feed(b);
            if is_last {
                assert!(result.is_some(), "should return frame on last byte");
                results.push(result.unwrap());
            } else {
                assert!(result.is_none(), "should not return frame at byte {}", i);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_DATA);
        assert_eq!(results[0].data, data);
    }

    // ── multiple consecutive frames ──────────────────────────────────────

    #[test]
    fn multiple_consecutive_frames() {
        let data1 = vec![0x01, 0x02, 0x03];
        let data2 = vec![0xAA, 0xBB, 0xCC];

        let mut combined = KissFrame::encode(&data1);
        combined.extend(KissFrame::encode(&data2));

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &combined {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].data, data1);
        assert_eq!(results[1].data, data2);
    }

    // ── decoder reset ────────────────────────────────────────────────────

    #[test]
    fn decoder_reset_during_partial_frame() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();

        // Feed only first half of frame
        for &b in &encoded[..3] {
            assert!(decoder.feed(b).is_none());
        }

        // Reset
        decoder.reset();
        assert!(!decoder.in_frame);
        assert!(!decoder.escape);
        assert!(decoder.data_buffer.is_empty());
        assert!(decoder.command.is_none());

        // Now feed a complete frame — should work
        let mut results = Vec::new();
        for &b in &KissFrame::encode(&data) {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }

    // ── command frames ───────────────────────────────────────────────────

    #[test]
    fn encode_cmd_txdelay() {
        let encoded = KissFrame::encode_cmd_value(CMD_TXDELAY, 50);
        assert_eq!(encoded, vec![FEND, CMD_TXDELAY, 50, FEND]);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_TXDELAY);
        assert_eq!(results[0].data, vec![50]);
    }

    #[test]
    fn encode_cmd_with_data() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = KissFrame::encode_cmd(CMD_RETURN, &data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, CMD_RETURN);
        assert_eq!(results[0].data, data);
    }

    #[test]
    fn encode_cmd_values_all() {
        let cmds = [CMD_TXDELAY, CMD_P, CMD_SLOTTIME, CMD_TXTAIL];
        for &cmd in &cmds {
            let encoded = KissFrame::encode_cmd_value(cmd, 0x42);
            assert_eq!(&encoded[0..2], &[FEND, cmd]);

            let mut decoder = KissDecoder::new();
            let mut results = Vec::new();
            for &b in &encoded {
                if let Some(r) = decoder.feed(b) {
                    results.push(r);
                }
            }
            assert_eq!(results[0].command, cmd);
            assert_eq!(results[0].data, vec![0x42]);
        }
    }

    // ── edge cases ───────────────────────────────────────────────────────

    #[test]
    fn leading_garbage_before_fend() {
        // Bytes before opening FEND should be ignored
        let data = vec![0x01, 0x02, 0x03];
        let encoded = KissFrame::encode(&data);

        let mut stream = vec![0xFF, 0xFE, 0xFD]; // garbage
        stream.extend(encoded);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &stream {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }

    #[test]
    fn single_byte_frame() {
        let data = vec![0x42];
        let encoded = KissFrame::encode(&data);

        let mut decoder = KissDecoder::new();
        let mut results = Vec::new();
        for &b in &encoded {
            if let Some(r) = decoder.feed(b) {
                results.push(r);
            }
        }
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].data, data);
    }
}
