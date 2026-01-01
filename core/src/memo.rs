//! Memo encoding and decoding for encrypted messaging.
//!
//! This module implements a protocol for encoding messages in Zcash transaction memos.
//! Memos are 512 bytes and encrypted along with shielded notes, providing end-to-end
//! encrypted messaging.
//!
//! # Memo Format
//!
//! ```text
//! [0]      version (0x01)
//! [1]      type (0x00=text, 0x01=ack, 0x02=fragment)
//! [2-5]    timestamp (u32, unix epoch, big-endian)
//! [6-9]    nonce (u32, for dedup/ordering, big-endian)
//! [10-13]  fragment info (if type=0x02): total_fragments(u16) + index(u16), big-endian
//! [14-511] payload (UTF-8 text, null-padded)
//! ```
//!
//! # Message Fragmentation
//!
//! Messages longer than 498 bytes (512 - 14 byte header) are split across multiple
//! memos with type=0x02 (fragment). Fragments share the same timestamp and nonce
//! to enable reassembly.

use serde::{Deserialize, Serialize};

/// Maximum size of a Zcash transaction memo in bytes.
pub const MEMO_SIZE: usize = 512;

/// Size of the memo header in bytes.
pub const HEADER_SIZE: usize = 14;

/// Maximum size of the payload (memo size - header size).
pub const MAX_PAYLOAD_SIZE: usize = MEMO_SIZE - HEADER_SIZE;

/// Protocol version for memo format.
pub const MEMO_VERSION: u8 = 0x01;

/// Memo type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MemoType {
    /// Plain text message.
    Text = 0x00,
    /// Acknowledgment/receipt.
    Ack = 0x01,
    /// Message fragment (for messages > MAX_PAYLOAD_SIZE).
    Fragment = 0x02,
}

impl MemoType {
    /// Parse a memo type from a byte.
    pub fn from_u8(value: u8) -> Result<Self, MemoError> {
        match value {
            0x00 => Ok(Self::Text),
            0x01 => Ok(Self::Ack),
            0x02 => Ok(Self::Fragment),
            _ => Err(MemoError::InvalidType(value)),
        }
    }
}

/// Fragment information for multi-part messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentInfo {
    /// Total number of fragments.
    pub total_fragments: u16,
    /// Zero-based index of this fragment.
    pub index: u16,
}

/// A decoded message from a memo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Protocol version.
    pub version: u8,
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: MemoType,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u32,
    /// Nonce for deduplication and ordering.
    pub nonce: u32,
    /// Fragment information (only for Fragment type).
    pub fragment_info: Option<FragmentInfo>,
    /// Message content (UTF-8 text).
    pub content: String,
}

/// Errors that can occur during memo operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoError {
    /// Invalid memo version.
    InvalidVersion(u8),
    /// Invalid memo type.
    InvalidType(u8),
    /// Memo is too short.
    TooShort(usize),
    /// Invalid UTF-8 in payload.
    InvalidUtf8,
    /// Message is too long for a single memo.
    MessageTooLong(usize),
    /// Invalid fragment info.
    InvalidFragmentInfo(String),
}

impl core::fmt::Display for MemoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "Invalid memo version: 0x{:02x}", v),
            Self::InvalidType(t) => write!(f, "Invalid memo type: 0x{:02x}", t),
            Self::TooShort(len) => write!(
                f,
                "Memo too short: {} bytes (expected at least {})",
                len, HEADER_SIZE
            ),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in memo payload"),
            Self::MessageTooLong(len) => write!(
                f,
                "Message too long: {} bytes (max {} per fragment)",
                len, MAX_PAYLOAD_SIZE
            ),
            Self::InvalidFragmentInfo(msg) => write!(f, "Invalid fragment info: {}", msg),
        }
    }
}

impl core::error::Error for MemoError {}

/// Encode a text message into a memo.
///
/// If the message fits in a single memo (≤498 bytes), creates a Text memo.
/// Otherwise, returns an error - use `encode_message_fragments` for long messages.
///
/// # Arguments
///
/// * `text` - The message text (UTF-8)
/// * `timestamp` - Unix timestamp (seconds since epoch)
/// * `nonce` - Random nonce for deduplication
///
/// # Returns
///
/// A 512-byte memo with the encoded message.
pub fn encode_message_memo(text: &str, timestamp: u32, nonce: u32) -> Result<Vec<u8>, MemoError> {
    let text_bytes = text.as_bytes();

    if text_bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(MemoError::MessageTooLong(text_bytes.len()));
    }

    let mut memo = vec![0u8; MEMO_SIZE];

    // Write header
    memo[0] = MEMO_VERSION;
    memo[1] = MemoType::Text as u8;
    memo[2..6].copy_from_slice(&timestamp.to_be_bytes());
    memo[6..10].copy_from_slice(&nonce.to_be_bytes());
    // Fragment info (bytes 10-13) left as zeros for non-fragment messages

    // Write payload
    memo[HEADER_SIZE..HEADER_SIZE + text_bytes.len()].copy_from_slice(text_bytes);
    // Remaining bytes already zeroed (null-padded)

    Ok(memo)
}

/// Encode a long message into multiple memo fragments.
///
/// Splits the message across multiple memos, each with type=Fragment.
/// All fragments share the same timestamp and nonce for reassembly.
///
/// # Arguments
///
/// * `text` - The message text (UTF-8)
/// * `timestamp` - Unix timestamp (seconds since epoch)
/// * `nonce` - Random nonce for deduplication
///
/// # Returns
///
/// A vector of 512-byte memos, each containing a fragment.
pub fn encode_message_fragments(
    text: &str,
    timestamp: u32,
    nonce: u32,
) -> Result<Vec<Vec<u8>>, MemoError> {
    let text_bytes = text.as_bytes();

    // Calculate number of fragments needed
    let total_fragments = text_bytes.len().div_ceil(MAX_PAYLOAD_SIZE);

    if total_fragments > u16::MAX as usize {
        return Err(MemoError::MessageTooLong(text_bytes.len()));
    }

    let mut fragments = Vec::new();

    for (index, chunk) in text_bytes.chunks(MAX_PAYLOAD_SIZE).enumerate() {
        let mut memo = vec![0u8; MEMO_SIZE];

        // Write header
        memo[0] = MEMO_VERSION;
        memo[1] = MemoType::Fragment as u8;
        memo[2..6].copy_from_slice(&timestamp.to_be_bytes());
        memo[6..10].copy_from_slice(&nonce.to_be_bytes());

        // Write fragment info
        memo[10..12].copy_from_slice(&(total_fragments as u16).to_be_bytes());
        memo[12..14].copy_from_slice(&(index as u16).to_be_bytes());

        // Write payload
        memo[HEADER_SIZE..HEADER_SIZE + chunk.len()].copy_from_slice(chunk);

        fragments.push(memo);
    }

    Ok(fragments)
}

/// Decode a message from a memo.
///
/// Parses the memo header and extracts the message content.
/// For fragment messages, returns the fragment - use `reassemble_fragments`
/// to combine multiple fragments.
///
/// # Arguments
///
/// * `memo` - A 512-byte memo
///
/// # Returns
///
/// The decoded message.
pub fn decode_message_memo(memo: &[u8]) -> Result<Message, MemoError> {
    if memo.len() < HEADER_SIZE {
        return Err(MemoError::TooShort(memo.len()));
    }

    // Parse header
    let version = memo[0];
    if version != MEMO_VERSION {
        return Err(MemoError::InvalidVersion(version));
    }

    let msg_type = MemoType::from_u8(memo[1])?;

    let timestamp = u32::from_be_bytes([memo[2], memo[3], memo[4], memo[5]]);
    let nonce = u32::from_be_bytes([memo[6], memo[7], memo[8], memo[9]]);

    // Parse fragment info (if applicable)
    let fragment_info = if msg_type == MemoType::Fragment {
        let total_fragments = u16::from_be_bytes([memo[10], memo[11]]);
        let index = u16::from_be_bytes([memo[12], memo[13]]);

        if total_fragments == 0 {
            return Err(MemoError::InvalidFragmentInfo(
                "Total fragments cannot be zero".to_string(),
            ));
        }

        if index >= total_fragments {
            return Err(MemoError::InvalidFragmentInfo(format!(
                "Fragment index {} >= total fragments {}",
                index, total_fragments
            )));
        }

        Some(FragmentInfo {
            total_fragments,
            index,
        })
    } else {
        None
    };

    // Parse payload
    let payload = &memo[HEADER_SIZE..];

    // Find the end of the string (first null byte or end of memo)
    let end = payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(payload.len());

    let content = core::str::from_utf8(&payload[..end])
        .map_err(|_| MemoError::InvalidUtf8)?
        .to_string();

    Ok(Message {
        version,
        msg_type,
        timestamp,
        nonce,
        fragment_info,
        content,
    })
}

/// Reassemble fragments into a complete message.
///
/// Takes multiple fragment messages with the same timestamp and nonce,
/// sorts them by index, and combines their content.
///
/// # Arguments
///
/// * `fragments` - Vector of fragment messages (order doesn't matter)
///
/// # Returns
///
/// The reassembled message text.
pub fn reassemble_fragments(fragments: &[Message]) -> Result<String, MemoError> {
    if fragments.is_empty() {
        return Ok(String::new());
    }

    // Verify all fragments have the same timestamp and nonce
    let timestamp = fragments[0].timestamp;
    let nonce = fragments[0].nonce;

    for fragment in fragments {
        if fragment.msg_type != MemoType::Fragment {
            return Err(MemoError::InvalidFragmentInfo(
                "Non-fragment message in fragment list".to_string(),
            ));
        }

        if fragment.timestamp != timestamp || fragment.nonce != nonce {
            return Err(MemoError::InvalidFragmentInfo(
                "Fragments have different timestamp or nonce".to_string(),
            ));
        }
    }

    // Sort fragments by index
    let mut sorted_fragments = fragments.to_vec();
    sorted_fragments.sort_by_key(|f| f.fragment_info.as_ref().map(|fi| fi.index).unwrap_or(0));

    // Verify we have all fragments
    if let Some(first_info) = sorted_fragments[0].fragment_info {
        if sorted_fragments.len() != first_info.total_fragments as usize {
            return Err(MemoError::InvalidFragmentInfo(format!(
                "Missing fragments: have {}, expected {}",
                sorted_fragments.len(),
                first_info.total_fragments
            )));
        }

        // Verify indices are sequential
        for (i, fragment) in sorted_fragments.iter().enumerate() {
            if let Some(info) = &fragment.fragment_info
                && info.index as usize != i
            {
                return Err(MemoError::InvalidFragmentInfo(format!(
                    "Non-sequential fragment index: expected {}, got {}",
                    i, info.index
                )));
            }
        }
    }

    // Combine content
    let mut combined = String::new();
    for fragment in &sorted_fragments {
        combined.push_str(&fragment.content);
    }

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_short_message() {
        let text = "Hello, Zcash!";
        let timestamp = 1672531200; // 2023-01-01 00:00:00 UTC
        let nonce = 12345;

        let memo = encode_message_memo(text, timestamp, nonce).unwrap();
        assert_eq!(memo.len(), MEMO_SIZE);

        let message = decode_message_memo(&memo).unwrap();
        assert_eq!(message.version, MEMO_VERSION);
        assert_eq!(message.msg_type, MemoType::Text);
        assert_eq!(message.timestamp, timestamp);
        assert_eq!(message.nonce, nonce);
        assert_eq!(message.content, text);
        assert!(message.fragment_info.is_none());
    }

    #[test]
    fn test_encode_decode_max_payload() {
        let text = "a".repeat(MAX_PAYLOAD_SIZE);
        let timestamp = 1672531200;
        let nonce = 12345;

        let memo = encode_message_memo(&text, timestamp, nonce).unwrap();
        let message = decode_message_memo(&memo).unwrap();

        assert_eq!(message.content, text);
    }

    #[test]
    fn test_encode_message_too_long() {
        let text = "a".repeat(MAX_PAYLOAD_SIZE + 1);
        let timestamp = 1672531200;
        let nonce = 12345;

        let result = encode_message_memo(&text, timestamp, nonce);
        assert!(matches!(result, Err(MemoError::MessageTooLong(_))));
    }

    #[test]
    fn test_encode_decode_fragments() {
        let text = "a".repeat(MAX_PAYLOAD_SIZE * 2 + 100);
        let timestamp = 1672531200;
        let nonce = 12345;

        let fragments = encode_message_fragments(&text, timestamp, nonce).unwrap();
        assert_eq!(fragments.len(), 3); // Should create 3 fragments

        // Decode all fragments
        let mut messages = Vec::new();
        for fragment in &fragments {
            let message = decode_message_memo(fragment).unwrap();
            assert_eq!(message.msg_type, MemoType::Fragment);
            assert_eq!(message.timestamp, timestamp);
            assert_eq!(message.nonce, nonce);
            messages.push(message);
        }

        // Reassemble
        let reassembled = reassemble_fragments(&messages).unwrap();
        assert_eq!(reassembled, text);
    }

    #[test]
    fn test_reassemble_fragments_out_of_order() {
        let text = "Hello, this is a long message that needs fragmentation!";
        let text_long = text.repeat(20);
        let timestamp = 1672531200;
        let nonce = 12345;

        let fragments = encode_message_fragments(&text_long, timestamp, nonce).unwrap();

        // Decode and shuffle
        let mut messages: Vec<_> = fragments
            .iter()
            .map(|f| decode_message_memo(f).unwrap())
            .collect();

        // Reverse order to test sorting
        messages.reverse();

        let reassembled = reassemble_fragments(&messages).unwrap();
        assert_eq!(reassembled, text_long);
    }

    #[test]
    fn test_decode_invalid_version() {
        let mut memo = vec![0u8; MEMO_SIZE];
        memo[0] = 0xFF; // Invalid version

        let result = decode_message_memo(&memo);
        assert!(matches!(result, Err(MemoError::InvalidVersion(0xFF))));
    }

    #[test]
    fn test_decode_invalid_type() {
        let mut memo = vec![0u8; MEMO_SIZE];
        memo[0] = MEMO_VERSION;
        memo[1] = 0xFF; // Invalid type

        let result = decode_message_memo(&memo);
        assert!(matches!(result, Err(MemoError::InvalidType(0xFF))));
    }

    #[test]
    fn test_decode_memo_too_short() {
        let memo = vec![0u8; 10]; // Too short

        let result = decode_message_memo(&memo);
        assert!(matches!(result, Err(MemoError::TooShort(10))));
    }

    #[test]
    fn test_null_padding() {
        let text = "Short";
        let timestamp = 1672531200;
        let nonce = 12345;

        let memo = encode_message_memo(text, timestamp, nonce).unwrap();

        // Verify null padding
        let payload_start = HEADER_SIZE + text.len();
        assert!(memo[payload_start..].iter().all(|&b| b == 0));

        let message = decode_message_memo(&memo).unwrap();
        assert_eq!(message.content, text);
    }

    #[test]
    fn test_fragment_info_validation() {
        let mut memo = vec![0u8; MEMO_SIZE];
        memo[0] = MEMO_VERSION;
        memo[1] = MemoType::Fragment as u8;
        memo[2..6].copy_from_slice(&1672531200u32.to_be_bytes());
        memo[6..10].copy_from_slice(&12345u32.to_be_bytes());

        // total_fragments = 0 (invalid)
        memo[10..12].copy_from_slice(&0u16.to_be_bytes());
        memo[12..14].copy_from_slice(&0u16.to_be_bytes());

        let result = decode_message_memo(&memo);
        assert!(matches!(result, Err(MemoError::InvalidFragmentInfo(_))));

        // index >= total_fragments (invalid)
        memo[10..12].copy_from_slice(&2u16.to_be_bytes()); // total = 2
        memo[12..14].copy_from_slice(&2u16.to_be_bytes()); // index = 2

        let result = decode_message_memo(&memo);
        assert!(matches!(result, Err(MemoError::InvalidFragmentInfo(_))));
    }

    #[test]
    fn test_reassemble_missing_fragments() {
        let text = "a".repeat(MAX_PAYLOAD_SIZE * 3);
        let timestamp = 1672531200;
        let nonce = 12345;

        let fragments = encode_message_fragments(&text, timestamp, nonce).unwrap();
        let mut messages: Vec<_> = fragments
            .iter()
            .map(|f| decode_message_memo(f).unwrap())
            .collect();

        // Remove one fragment
        messages.remove(1);

        let result = reassemble_fragments(&messages);
        assert!(matches!(result, Err(MemoError::InvalidFragmentInfo(_))));
    }

    #[test]
    fn test_unicode_message() {
        let text = "Hello 世界! 🌍 Zcash";
        let timestamp = 1672531200;
        let nonce = 12345;

        let memo = encode_message_memo(text, timestamp, nonce).unwrap();
        let message = decode_message_memo(&memo).unwrap();

        assert_eq!(message.content, text);
    }
}
