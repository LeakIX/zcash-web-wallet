//! # QR Code Generator
//!
//! A minimal, educational QR code generator implementing **ISO/IEC 18004:2015**.
//!
//! This implementation is designed to be readable and reviewable, serving as both
//! a functional library and a learning resource for understanding QR codes.
//!
//! ## Specification Reference
//!
//! This implementation follows **ISO/IEC 18004:2015** (QR Code bar code symbology
//! specification). Key sections referenced:
//!
//! - Section 6: Symbol structure (finder patterns, timing, alignment)
//! - Section 7: Data encoding (modes, character count indicators)
//! - Section 8: Error correction (Reed-Solomon codes over GF(2^8))
//! - Section 9: Codeword placement (zigzag pattern)
//! - Section 10: Data masking (8 mask patterns, penalty scoring)
//! - Annex C: Format and version information encoding
//!
//! ## Library Organization
//!
//! ```text
//! lib.rs
//! +-- Public API
//! |   +-- QrCode::encode()     Entry point: data -> QR code
//! |   +-- QrCode::to_svg()     Render as SVG
//! |   +-- QrCode::to_ascii()   Render as terminal ASCII art
//! |
//! +-- Data Encoding (Section 7)
//! |   +-- find_min_version()   Select smallest QR version for data
//! |   +-- encode_data()        Convert data to codewords
//! |   +-- BitBuffer            Accumulate bits before byte conversion
//! |
//! +-- Error Correction (Section 8)
//! |   +-- add_error_correction()      Compute and interleave EC codewords
//! |   +-- reed_solomon_generator()    Build generator polynomial
//! |   +-- reed_solomon_encode()       Polynomial division in GF(2^8)
//! |   +-- GF256                       Galois Field arithmetic (log/exp tables)
//! |
//! +-- Matrix Construction (Section 6, 9)
//! |   +-- place_function_patterns()   Finder, timing, alignment patterns
//! |   +-- place_data_bits()           Zigzag data placement
//! |
//! +-- Masking (Section 10)
//! |   +-- apply_best_mask()           Try all masks, pick lowest penalty
//! |   +-- calculate_penalty()         Score pattern quality
//! |
//! +-- Format Info (Annex C)
//!     +-- place_format_info()         BCH(15,5) encoded EC level + mask
//!     +-- place_version_info()        BCH(18,6) encoded version (v7+)
//! ```
//!
//! ## QR Code Structure
//!
//! A QR code is a 2D matrix of black/white modules. Size = 4*version + 17.
//!
//! ```text
//!     Version 1 (21x21)              Version 2+ adds alignment patterns
//!     +-------+---+-------+          +-------+---+-------+
//!     |#######|   |#######|          |#######|   |#######|
//!     |# ### #|   |# ### #|          |# ### #|   |# ### #|
//!     |# ### #|   |# ### #|          |# ### #|   |# ### #|
//!     |# ### #|   |# ### #|          |# ### #|   |# ### #|
//!     |#######|   |#######|          |#######|   |#######|
//!     +-------+---+-------+          +-------+---+--+--+-+
//!     |  T    |   |       |          |  T    |   |##|  |
//!     |  I    |   |       |          |  I    |   |##|  |
//!     |  M    | D | DATA  |          |  M    | D +--+  |
//!     |  I    | A |       |          |  I    | A |     |
//!     |  N    | T |       |          |  N    | T |     |
//!     |  G    | A |       |          |  G    | A |     |
//!     +-------+---+-------+          +-------+---+-----+
//!     |#######|   |       |          |#######|   |     |
//!     |# ### #|   |       |          |# ### #|   |     |
//!     |#######|   |       |          |#######|   |     |
//!     +-------+---+-------+          +-------+---+-----+
//!
//!     Legend:
//!     ####### = Finder pattern (7x7, at 3 corners)
//!     TIMING  = Alternating black/white (row 6, col 6)
//!     ##      = Alignment pattern (5x5, version 2+)
//!     DATA    = Encoded data + error correction
//! ```
//!
//! ## Encoding Pipeline
//!
//! ### Step 1: Data Encoding (Section 7)
//!
//! Data is encoded as a bitstream:
//! ```text
//! [Mode Indicator (4 bits)] [Character Count] [Data Bits] [Terminator] [Padding]
//!
//! Mode indicators:
//!   0001 = Numeric (0-9)           - 3.33 bits/char
//!   0010 = Alphanumeric (0-9,A-Z)  - 5.5 bits/char
//!   0100 = Byte (any 8-bit)        - 8 bits/char
//!   1000 = Kanji                   - 13 bits/char
//!
//! Character count field width depends on version:
//!   Byte mode: 8 bits (v1-9), 16 bits (v10-40)
//! ```
//!
//! ### Step 2: Error Correction (Section 8)
//!
//! Uses Reed-Solomon codes over GF(2^8) with primitive polynomial x^8+x^4+x^3+x^2+1.
//!
//! ```text
//! Data codewords:  [D0] [D1] [D2] ... [Dn]
//! EC codewords:    [E0] [E1] [E2] ... [Em]
//!
//! Generator polynomial: g(x) = (x-a^0)(x-a^1)...(x-a^(m-1))
//! EC = Data(x) * x^m mod g(x)
//!
//! For multiple blocks, data and EC codewords are interleaved.
//! ```
//!
//! ### Step 3: Matrix Placement (Section 9)
//!
//! Codewords are placed in a zigzag pattern, bottom-right to top-left:
//!
//! ```text
//!     <- Reading direction
//!
//!     |  |  |  |  |  |  |
//!     |  |  |  |  |  |  |
//!     |8 |7 |6 |5 |4 |3 |2 |1 |  <- Bit positions in 2-column strip
//!     |  |  |  |  |  |  |  |  |
//!     v  ^  v  ^  v  ^  v  ^     <- Alternating up/down
//! ```
//!
//! ### Step 4: Masking (Section 10)
//!
//! 8 mask patterns XOR'd with data to avoid problematic visual patterns:
//!
//! ```text
//! Mask 0: (row + col) % 2 == 0        Mask 4: (row/2 + col/3) % 2 == 0
//! Mask 1: row % 2 == 0                Mask 5: (row*col)%2 + (row*col)%3 == 0
//! Mask 2: col % 3 == 0                Mask 6: ((row*col)%2 + (row*col)%3) % 2 == 0
//! Mask 3: (row + col) % 3 == 0        Mask 7: ((row+col)%2 + (row*col)%3) % 2 == 0
//! ```
//!
//! Penalty scoring selects the mask with fewest:
//! - Long runs of same color
//! - 2x2 blocks of same color
//! - Finder-like patterns (1:1:3:1:1)
//! - Color imbalance (too dark/light)
//!
//! ### Step 5: Format Information (Annex C)
//!
//! 15-bit format info = [EC Level (2 bits)][Mask (3 bits)][BCH EC (10 bits)]
//! XOR'd with 0b101010000010010 to ensure non-zero.
//! Placed around finder patterns for redundancy.
//!
//! ## GF(2^8) Primer
//!
//! Galois Field with 256 elements, used for Reed-Solomon error correction.
//!
//! - **Elements**: Polynomials over GF(2) mod irreducible polynomial
//! - **Irreducible polynomial**: x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
//! - **Primitive element**: alpha = x (i.e., 0x02)
//! - **Addition**: XOR (no carry, mod 2 coefficients)
//! - **Multiplication**: Polynomial multiplication mod 0x11D
//!
//! We use log/antilog tables for efficient multiplication:
//! ```text
//! a * b = exp(log(a) + log(b) mod 255)
//! ```
//!
//! ## Example Usage
//!
//! ```
//! use qr::{QrCode, ErrorCorrectionLevel};
//!
//! let qr = QrCode::encode("Hello", ErrorCorrectionLevel::M).unwrap();
//! let svg = qr.to_svg(10);  // 10 pixels per module
//! ```

/// QR Code error correction levels.
///
/// Higher levels can recover more damage but require more space.
/// The percentages indicate how much of the code can be damaged
/// while still being readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCorrectionLevel {
    /// Low: ~7% error recovery. Best for clean environments.
    L = 0,
    /// Medium: ~15% error recovery. Good balance.
    M = 1,
    /// Quartile: ~25% error recovery.
    Q = 2,
    /// High: ~30% error recovery. Best for harsh environments.
    H = 3,
}

impl ErrorCorrectionLevel {
    /// Get the format info indicator bits for this EC level.
    ///
    /// Per ISO 18004:2015 Table C.1, the 2-bit indicators are:
    /// - L = 01 (not 00!)
    /// - M = 00 (not 01!)
    /// - Q = 11
    /// - H = 10
    ///
    /// Note: This encoding differs from the natural enum ordering.
    fn format_info_bits(self) -> u32 {
        match self {
            ErrorCorrectionLevel::L => 0b01,
            ErrorCorrectionLevel::M => 0b00,
            ErrorCorrectionLevel::Q => 0b11,
            ErrorCorrectionLevel::H => 0b10,
        }
    }
}

/// QR Code encoding modes.
///
/// Different modes have different efficiency for different character sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Numeric: digits 0-9. Most efficient: 3.33 bits/char
    Numeric = 0b0001,
    /// Alphanumeric: 0-9, A-Z, space, $%*+-./: 5.5 bits/char
    Alphanumeric = 0b0010,
    /// Byte: any 8-bit data. 8 bits/char
    Byte = 0b0100,
}

/// A QR code represented as a 2D matrix of modules.
#[derive(Clone, Debug)]
pub struct QrCode {
    /// The module matrix. true = black, false = white.
    modules: Vec<Vec<bool>>,
    /// Tracks which modules are "function patterns" (finder, timing, etc.)
    /// These cannot be masked.
    is_function: Vec<Vec<bool>>,
    /// QR version (1-40). Determines size: (version * 4 + 17) modules per side.
    version: u8,
    /// Error correction level used.
    error_correction: ErrorCorrectionLevel,
    /// Mask pattern applied (0-7).
    mask: u8,
}

impl QrCode {
    /// Generate a QR code from text input.
    ///
    /// Uses byte mode encoding which supports any UTF-8 string.
    /// Automatically selects the smallest version that fits the data.
    pub fn encode(data: &str, ecl: ErrorCorrectionLevel) -> Result<Self, String> {
        let bytes = data.as_bytes();

        // Step 1: Determine the minimum version needed
        let version = Self::find_min_version(bytes.len(), ecl)?;
        let size = version as usize * 4 + 17;

        // Step 2: Encode data into codewords
        let data_codewords = Self::encode_data(bytes, version, ecl)?;

        // Step 3: Add error correction
        let all_codewords = Self::add_error_correction(&data_codewords, version, ecl);

        // Step 4: Create the matrix and place function patterns
        let mut qr = Self {
            modules: vec![vec![false; size]; size],
            is_function: vec![vec![false; size]; size],
            version,
            error_correction: ecl,
            mask: 0,
        };

        qr.place_function_patterns();

        // Step 5: Place data bits
        qr.place_data_bits(&all_codewords);

        // Step 6: Apply best mask
        qr.apply_best_mask();

        // Step 7: Add format information
        qr.place_format_info();

        if version >= 7 {
            qr.place_version_info();
        }

        Ok(qr)
    }

    /// Find minimum QR version that can hold the data.
    ///
    /// Each version has a specific data capacity depending on error correction.
    fn find_min_version(data_len: usize, ecl: ErrorCorrectionLevel) -> Result<u8, String> {
        // Data capacity table for byte mode (version 1-40)
        // Format: [L, M, Q, H] capacities for each version
        let capacities: [(usize, usize, usize, usize); 40] = [
            (17, 14, 11, 7),          // Version 1
            (32, 26, 20, 14),         // Version 2
            (53, 42, 32, 24),         // Version 3
            (78, 62, 46, 34),         // Version 4
            (106, 84, 60, 44),        // Version 5
            (134, 106, 74, 58),       // Version 6
            (154, 122, 86, 64),       // Version 7
            (192, 152, 108, 84),      // Version 8
            (230, 180, 130, 98),      // Version 9
            (271, 213, 151, 119),     // Version 10
            (321, 251, 177, 137),     // Version 11
            (367, 287, 203, 155),     // Version 12
            (425, 331, 241, 177),     // Version 13
            (458, 362, 258, 194),     // Version 14
            (520, 412, 292, 220),     // Version 15
            (586, 450, 322, 250),     // Version 16
            (644, 504, 364, 280),     // Version 17
            (718, 560, 394, 310),     // Version 18
            (792, 624, 442, 338),     // Version 19
            (858, 666, 482, 382),     // Version 20
            (929, 711, 509, 403),     // Version 21
            (1003, 779, 565, 439),    // Version 22
            (1091, 857, 611, 461),    // Version 23
            (1171, 911, 661, 511),    // Version 24
            (1273, 997, 715, 535),    // Version 25
            (1367, 1059, 751, 593),   // Version 26
            (1465, 1125, 805, 625),   // Version 27
            (1528, 1190, 868, 658),   // Version 28
            (1628, 1264, 908, 698),   // Version 29
            (1732, 1370, 982, 742),   // Version 30
            (1840, 1452, 1030, 790),  // Version 31
            (1952, 1538, 1112, 842),  // Version 32
            (2068, 1628, 1168, 898),  // Version 33
            (2188, 1722, 1228, 958),  // Version 34
            (2303, 1809, 1283, 983),  // Version 35
            (2431, 1911, 1351, 1051), // Version 36
            (2563, 1989, 1423, 1093), // Version 37
            (2699, 2099, 1499, 1139), // Version 38
            (2809, 2213, 1579, 1219), // Version 39
            (2953, 2331, 1663, 1273), // Version 40
        ];

        for (version_idx, cap) in capacities.iter().enumerate() {
            let capacity = match ecl {
                ErrorCorrectionLevel::L => cap.0,
                ErrorCorrectionLevel::M => cap.1,
                ErrorCorrectionLevel::Q => cap.2,
                ErrorCorrectionLevel::H => cap.3,
            };

            if data_len <= capacity {
                return Ok((version_idx + 1) as u8);
            }
        }

        Err("Data too large for QR code".to_string())
    }

    /// Encode data into codewords using byte mode.
    ///
    /// The encoding format is:
    /// - Mode indicator (4 bits): 0100 for byte mode
    /// - Character count (8 or 16 bits depending on version)
    /// - Data bytes
    /// - Terminator (up to 4 zero bits)
    /// - Pad to byte boundary
    /// - Pad codewords (0xEC, 0x11 alternating)
    fn encode_data(data: &[u8], version: u8, ecl: ErrorCorrectionLevel) -> Result<Vec<u8>, String> {
        let mut bits = BitBuffer::new();

        // Mode indicator: 0100 for byte mode
        bits.append_bits(0b0100, 4);

        // Character count indicator
        // Versions 1-9: 8 bits, 10-26: 16 bits, 27-40: 16 bits for byte mode
        let count_bits = if version <= 9 { 8 } else { 16 };
        bits.append_bits(data.len() as u32, count_bits);

        // Data bytes
        for &byte in data {
            bits.append_bits(byte as u32, 8);
        }

        // Get total data codewords capacity
        let total_codewords = Self::get_data_codewords(version, ecl);

        // Terminator: up to 4 zero bits
        let capacity_bits = total_codewords * 8;
        let terminator_len = std::cmp::min(4, capacity_bits.saturating_sub(bits.len()));
        bits.append_bits(0, terminator_len);

        // Pad to byte boundary
        while !bits.len().is_multiple_of(8) {
            bits.append_bits(0, 1);
        }

        // Pad codewords
        let mut codewords = bits.to_bytes();
        let mut pad_toggle = true;
        while codewords.len() < total_codewords {
            codewords.push(if pad_toggle { 0xEC } else { 0x11 });
            pad_toggle = !pad_toggle;
        }

        Ok(codewords)
    }

    /// Add Reed-Solomon error correction codewords.
    ///
    /// ## Reed-Solomon Error Correction
    ///
    /// Reed-Solomon codes work over GF(2^8) - a finite field with 256 elements.
    /// Key concepts:
    ///
    /// 1. **Generator Polynomial**: A polynomial whose roots are consecutive
    ///    powers of alpha (a primitive element of GF(2^8)).
    ///    For n EC codewords: g(x) = (x - alpha^0)(x - alpha^1)...(x - alpha^(n-1))
    ///
    /// 2. **Encoding**: Treat data as polynomial coefficients, divide by
    ///    generator polynomial. The remainder becomes EC codewords.
    ///
    /// 3. **Decoding**: Check if received polynomial is divisible by generator.
    ///    If not, solve for error locations and values using syndromes.
    fn add_error_correction(data: &[u8], version: u8, ecl: ErrorCorrectionLevel) -> Vec<u8> {
        let (num_blocks, ec_per_block) = Self::get_ec_params(version, ecl);
        let total_codewords = Self::get_total_codewords(version);
        let data_codewords = Self::get_data_codewords(version, ecl);
        let short_block_len = data_codewords / num_blocks;
        let long_blocks = data_codewords % num_blocks;

        let generator = Self::reed_solomon_generator(ec_per_block);

        let mut data_blocks: Vec<Vec<u8>> = Vec::new();
        let mut ec_blocks: Vec<Vec<u8>> = Vec::new();

        let mut offset = 0;
        for i in 0..num_blocks {
            let block_len = short_block_len + if i >= num_blocks - long_blocks { 1 } else { 0 };
            let block: Vec<u8> = data[offset..offset + block_len].to_vec();
            offset += block_len;

            let ec = Self::reed_solomon_encode(&block, &generator, ec_per_block);
            data_blocks.push(block);
            ec_blocks.push(ec);
        }

        // Interleave blocks
        let mut result = Vec::with_capacity(total_codewords);

        // Interleave data codewords
        let max_data_len = short_block_len + 1;
        for i in 0..max_data_len {
            for block in &data_blocks {
                if i < block.len() {
                    result.push(block[i]);
                }
            }
        }

        // Interleave EC codewords
        for i in 0..ec_per_block {
            for block in &ec_blocks {
                result.push(block[i]);
            }
        }

        result
    }

    /// Generate Reed-Solomon generator polynomial.
    ///
    /// The generator polynomial for n EC codewords is:
    /// g(x) = (x - alpha^0)(x - alpha^1)...(x - alpha^(n-1))
    ///
    /// We store coefficients in decreasing degree order.
    fn reed_solomon_generator(degree: usize) -> Vec<u8> {
        let mut result = vec![1u8];

        for i in 0..degree {
            let mut new_result = vec![0u8; result.len() + 1];
            let alpha_i = GF256::exp(i as u8);

            for (j, &coef) in result.iter().enumerate() {
                new_result[j] ^= GF256::mul(coef, alpha_i);
                new_result[j + 1] ^= coef;
            }

            result = new_result;
        }

        result
    }

    /// Compute Reed-Solomon error correction codewords.
    ///
    /// This performs polynomial division in GF(2^8):
    /// data(x) * x^n mod generator(x) = remainder(x)
    ///
    /// The remainder coefficients are the EC codewords.
    fn reed_solomon_encode(data: &[u8], generator: &[u8], ec_count: usize) -> Vec<u8> {
        let mut remainder = vec![0u8; ec_count];

        for &byte in data {
            let factor = byte ^ remainder[0];
            remainder.rotate_left(1);
            *remainder.last_mut().unwrap() = 0;

            for (i, &gen_coef) in generator.iter().skip(1).enumerate() {
                if i < remainder.len() {
                    remainder[i] ^= GF256::mul(gen_coef, factor);
                }
            }
        }

        remainder
    }

    /// Place finder patterns, timing patterns, and other function patterns.
    fn place_function_patterns(&mut self) {
        let size = self.modules.len();

        // Finder patterns at three corners
        self.place_finder_pattern(0, 0);
        self.place_finder_pattern(size - 7, 0);
        self.place_finder_pattern(0, size - 7);

        // Timing patterns
        self.place_timing_patterns();

        // Alignment patterns (for version 2+)
        if self.version >= 2 {
            self.place_alignment_patterns();
        }

        // Reserve format info area
        self.reserve_format_area();

        // Dark module (always black)
        self.modules[8][4 * self.version as usize + 9] = true;
        self.is_function[8][4 * self.version as usize + 9] = true;
    }

    /// Place a 7x7 finder pattern at the given position.
    ///
    /// Finder patterns enable scanners to locate and orient the QR code.
    /// Structure: 3 concentric squares (black, white, black) with white border.
    ///
    /// ```text
    /// #######
    /// #.....#
    /// #.###.#
    /// #.###.#
    /// #.###.#
    /// #.....#
    /// #######
    /// ```
    fn place_finder_pattern(&mut self, row: usize, col: usize) {
        for dr in 0..7 {
            for dc in 0..7 {
                let r = row + dr;
                let c = col + dc;

                // Determine if this module should be black
                // Black if on outer edge, or in center 3x3
                let is_edge = dr == 0 || dr == 6 || dc == 0 || dc == 6;
                let is_center = (2..=4).contains(&dr) && (2..=4).contains(&dc);
                self.modules[r][c] = is_edge || is_center;
                self.is_function[r][c] = true;
            }
        }

        // White separator around finder pattern
        self.add_separator(row, col);
    }

    /// Add white separator around a finder pattern.
    fn add_separator(&mut self, row: usize, col: usize) {
        let size = self.modules.len();

        // Determine which edges need separators based on position
        let add_bottom = row == 0;
        let add_top = row + 7 == size;
        let add_right = col == 0;
        let add_left = col + 7 == size;

        for i in 0..8 {
            // Horizontal separators
            if add_bottom && row + 7 < size {
                self.set_function_module(row + 7, col + i.min(6), false);
            }
            if add_top && row > 0 {
                self.set_function_module(row - 1, col + i.min(6), false);
            }

            // Vertical separators
            if add_right && col + 7 < size {
                self.set_function_module(row + i.min(6), col + 7, false);
            }
            if add_left && col > 0 {
                self.set_function_module(row + i.min(6), col - 1, false);
            }
        }
    }

    fn set_function_module(&mut self, row: usize, col: usize, black: bool) {
        let size = self.modules.len();
        if row < size && col < size {
            self.modules[row][col] = black;
            self.is_function[row][col] = true;
        }
    }

    /// Place timing patterns.
    ///
    /// Timing patterns are alternating black/white modules that help
    /// scanners determine module coordinates. They run between finder patterns.
    fn place_timing_patterns(&mut self) {
        let size = self.modules.len();

        for i in 8..size - 8 {
            let is_black = i % 2 == 0;
            // Horizontal timing pattern (row 6)
            if !self.is_function[6][i] {
                self.modules[6][i] = is_black;
                self.is_function[6][i] = true;
            }
            // Vertical timing pattern (column 6)
            if !self.is_function[i][6] {
                self.modules[i][6] = is_black;
                self.is_function[i][6] = true;
            }
        }
    }

    /// Place alignment patterns for version 2+.
    ///
    /// Alignment patterns help correct for image distortion in larger codes.
    /// They're 5x5 patterns placed at specific positions depending on version.
    fn place_alignment_patterns(&mut self) {
        let positions = Self::get_alignment_positions(self.version);

        for &row in &positions {
            for &col in &positions {
                // Skip if overlapping with finder patterns
                if self.is_function[row][col] {
                    continue;
                }

                self.place_alignment_pattern(row, col);
            }
        }
    }

    /// Place a single 5x5 alignment pattern centered at (row, col).
    fn place_alignment_pattern(&mut self, center_row: usize, center_col: usize) {
        for dr in 0..5 {
            for dc in 0..5 {
                let r = center_row + dr - 2;
                let c = center_col + dc - 2;

                let is_edge = dr == 0 || dr == 4 || dc == 0 || dc == 4;
                let is_center = dr == 2 && dc == 2;
                self.modules[r][c] = is_edge || is_center;
                self.is_function[r][c] = true;
            }
        }
    }

    /// Get alignment pattern positions for a given version.
    fn get_alignment_positions(version: u8) -> Vec<usize> {
        if version == 1 {
            return vec![];
        }

        let size = version as usize * 4 + 17;
        let num_align = (version / 7) as usize + 2;

        if num_align == 2 {
            return vec![6, size - 7];
        }

        // Calculate evenly spaced positions
        let first = 6;
        let last = size - 7;
        let step = ((last - first) as f64 / (num_align - 1) as f64).ceil() as usize;
        let step = if step % 2 == 1 { step + 1 } else { step };

        let mut positions = vec![first];
        let mut pos = last;
        while positions.len() < num_align {
            positions.insert(1, pos);
            pos = pos.saturating_sub(step);
        }

        positions
    }

    /// Reserve format information area (will be filled after masking).
    fn reserve_format_area(&mut self) {
        let size = self.modules.len();

        // Around top-left finder pattern
        for i in 0..9 {
            if i != 6 {
                self.is_function[8][i] = true;
                self.is_function[i][8] = true;
            }
        }

        // Around top-right and bottom-left finder patterns
        for i in 0..8 {
            self.is_function[8][size - 1 - i] = true;
            self.is_function[size - 1 - i][8] = true;
        }
    }

    /// Place data bits in the matrix using the QR code zigzag pattern.
    ///
    /// Data is placed starting from bottom-right, moving up in 2-column
    /// strips, alternating direction. Column 6 (timing pattern) is skipped.
    fn place_data_bits(&mut self, codewords: &[u8]) {
        let size = self.modules.len();
        let mut bit_idx = 0;
        let total_bits = codewords.len() * 8;

        // Start from right edge, process 2-column strips
        let mut col = size - 1;
        let mut going_up = true;

        while col > 0 {
            // Skip timing pattern column
            if col == 6 {
                col -= 1;
            }

            let rows: Vec<usize> = if going_up {
                (0..size).rev().collect()
            } else {
                (0..size).collect()
            };

            for row in rows {
                for dc in 0..2 {
                    let c = col - dc;
                    if c < size && !self.is_function[row][c] && bit_idx < total_bits {
                        let byte_idx = bit_idx / 8;
                        let bit_pos = 7 - (bit_idx % 8);
                        self.modules[row][c] = (codewords[byte_idx] >> bit_pos) & 1 == 1;
                        bit_idx += 1;
                    }
                }
            }

            going_up = !going_up;
            col = col.saturating_sub(2);
        }
    }

    /// Apply the best mask pattern to minimize problematic patterns.
    ///
    /// ## Masking
    ///
    /// Masking XORs data modules with a pattern to avoid:
    /// - Large areas of same color (hard to scan)
    /// - Patterns resembling finder patterns (false positives)
    ///
    /// 8 mask patterns are defined. We try all and pick lowest penalty.
    fn apply_best_mask(&mut self) {
        let mut best_mask = 0u8;
        let mut best_penalty = u32::MAX;

        for mask in 0..8 {
            self.apply_mask(mask);
            let penalty = self.calculate_penalty();

            if penalty < best_penalty {
                best_penalty = penalty;
                best_mask = mask;
            }

            // Undo mask to try next
            self.apply_mask(mask);
        }

        self.mask = best_mask;
        self.apply_mask(best_mask);
    }

    /// Apply a mask pattern (XOR operation, so applying twice undoes it).
    fn apply_mask(&mut self, mask: u8) {
        let size = self.modules.len();

        for row in 0..size {
            for col in 0..size {
                if !self.is_function[row][col] && Self::mask_bit(mask, row, col) {
                    self.modules[row][col] = !self.modules[row][col];
                }
            }
        }
    }

    /// Determine if a position should be flipped by a mask pattern.
    ///
    /// The 8 mask patterns (row = i, col = j):
    /// - 0: (i + j) mod 2 = 0
    /// - 1: i mod 2 = 0
    /// - 2: j mod 3 = 0
    /// - 3: (i + j) mod 3 = 0
    /// - 4: (i/2 + j/3) mod 2 = 0
    /// - 5: (i*j) mod 2 + (i*j) mod 3 = 0
    /// - 6: ((i*j) mod 2 + (i*j) mod 3) mod 2 = 0
    /// - 7: ((i+j) mod 2 + (i*j) mod 3) mod 2 = 0
    fn mask_bit(mask: u8, row: usize, col: usize) -> bool {
        let i = row;
        let j = col;
        match mask {
            0 => (i + j).is_multiple_of(2),
            1 => i.is_multiple_of(2),
            2 => j.is_multiple_of(3),
            3 => (i + j).is_multiple_of(3),
            4 => (i / 2 + j / 3).is_multiple_of(2),
            5 => (i * j) % 2 + (i * j) % 3 == 0,
            6 => ((i * j) % 2 + (i * j) % 3).is_multiple_of(2),
            7 => ((i + j) % 2 + (i * j) % 3).is_multiple_of(2),
            _ => false,
        }
    }

    /// Calculate penalty score for the current pattern.
    ///
    /// Four penalty rules:
    /// 1. Consecutive modules of same color (>=5): 3 + (length - 5)
    /// 2. 2x2 blocks of same color: 3 per block
    /// 3. Finder-like patterns: 40 each
    /// 4. Color imbalance: 10 * |50 - dark%| / 5
    fn calculate_penalty(&self) -> u32 {
        let size = self.modules.len();
        let mut penalty = 0u32;

        // Rule 1: Consecutive same-color runs
        for row in 0..size {
            penalty += self.count_run_penalty(self.modules[row].iter().copied());
        }
        for col in 0..size {
            penalty += self.count_run_penalty((0..size).map(|row| self.modules[row][col]));
        }

        // Rule 2: 2x2 blocks
        for row in 0..size - 1 {
            for col in 0..size - 1 {
                let color = self.modules[row][col];
                if color == self.modules[row][col + 1]
                    && color == self.modules[row + 1][col]
                    && color == self.modules[row + 1][col + 1]
                {
                    penalty += 3;
                }
            }
        }

        // Rule 3: Finder-like patterns (1:1:3:1:1 ratio)
        let finder_pattern = [
            true, false, true, true, true, false, true, false, false, false, false,
        ];
        let finder_rev: Vec<bool> = finder_pattern.iter().rev().copied().collect();

        for row in 0..size {
            for col in 0..=size.saturating_sub(11) {
                let slice: Vec<bool> = (0..11).map(|i| self.modules[row][col + i]).collect();
                if slice == finder_pattern || slice == finder_rev {
                    penalty += 40;
                }
            }
        }
        for col in 0..size {
            for row in 0..=size.saturating_sub(11) {
                let slice: Vec<bool> = (0..11).map(|i| self.modules[row + i][col]).collect();
                if slice == finder_pattern || slice == finder_rev {
                    penalty += 40;
                }
            }
        }

        // Rule 4: Color imbalance
        let dark_count: usize = self.modules.iter().flatten().filter(|&&m| m).count();
        let total = size * size;
        let dark_percent = (dark_count * 100) / total;
        let deviation = (dark_percent as i32 - 50).unsigned_abs();
        penalty += (deviation / 5) * 10;

        penalty
    }

    fn count_run_penalty(&self, iter: impl Iterator<Item = bool>) -> u32 {
        let mut penalty = 0u32;
        let mut run_color = false;
        let mut run_len = 0usize;

        for module in iter {
            if module == run_color {
                run_len += 1;
            } else {
                if run_len >= 5 {
                    penalty += 3 + (run_len - 5) as u32;
                }
                run_color = module;
                run_len = 1;
            }
        }

        if run_len >= 5 {
            penalty += 3 + (run_len - 5) as u32;
        }

        penalty
    }

    /// Place format information (error correction level + mask pattern).
    ///
    /// Format info is a 15-bit value: 5 data bits + 10 error correction bits.
    /// - Bits 0-1: Error correction level
    /// - Bits 2-4: Mask pattern
    /// - Bits 5-14: BCH error correction
    ///
    /// Placed in two locations for redundancy.
    fn place_format_info(&mut self) {
        let size = self.modules.len();

        // Calculate format bits
        // Format data: [EC level (2 bits)][Mask pattern (3 bits)]
        // Uses the correct EC level encoding per ISO 18004 Table C.1
        let data = (self.error_correction.format_info_bits() << 3) | (self.mask as u32);
        let format_bits = Self::calculate_format_bits(data);

        // Place around top-left finder pattern
        for i in 0..6 {
            self.modules[8][i] = (format_bits >> i) & 1 == 1;
            self.modules[5 - i][8] = (format_bits >> (i + 9)) & 1 == 1;
        }
        self.modules[8][7] = (format_bits >> 6) & 1 == 1;
        self.modules[8][8] = (format_bits >> 7) & 1 == 1;
        self.modules[7][8] = (format_bits >> 8) & 1 == 1;

        // Place around top-right and bottom-left finder patterns
        for i in 0..8 {
            self.modules[8][size - 1 - i] = (format_bits >> i) & 1 == 1;
        }
        for i in 0..7 {
            self.modules[size - 1 - i][8] = (format_bits >> (i + 8)) & 1 == 1;
        }
    }

    /// Calculate BCH(15,5) format bits.
    fn calculate_format_bits(data: u32) -> u32 {
        let mut bits = data << 10;
        let generator = 0b10100110111; // BCH generator polynomial

        for i in (0..=4).rev() {
            if (bits >> (i + 10)) & 1 == 1 {
                bits ^= generator << i;
            }
        }

        let format = (data << 10) | bits;
        format ^ 0b101010000010010 // XOR with mask pattern
    }

    /// Place version information for version 7+.
    fn place_version_info(&mut self) {
        let size = self.modules.len();
        let version_bits = Self::calculate_version_bits(self.version);

        for i in 0..18 {
            let bit = (version_bits >> i) & 1 == 1;
            let row = i / 3;
            let col = i % 3;

            // Bottom-left
            self.modules[size - 11 + col][row] = bit;
            // Top-right
            self.modules[row][size - 11 + col] = bit;
        }
    }

    /// Calculate BCH(18,6) version bits.
    fn calculate_version_bits(version: u8) -> u32 {
        let mut bits = (version as u32) << 12;
        let generator = 0b1111100100101; // BCH generator polynomial

        for i in (0..=5).rev() {
            if (bits >> (i + 12)) & 1 == 1 {
                bits ^= generator << i;
            }
        }

        ((version as u32) << 12) | bits
    }

    /// Get the size (modules per side) of this QR code.
    pub fn size(&self) -> usize {
        self.modules.len()
    }

    /// Get the module value at (row, col). true = black, false = white.
    pub fn get(&self, row: usize, col: usize) -> bool {
        self.modules[row][col]
    }

    /// Render the QR code as an SVG string.
    pub fn to_svg(&self, module_size: u32) -> String {
        let size = self.size();
        let quiet_zone = 4; // Standard quiet zone is 4 modules
        let total_size = (size + 2 * quiet_zone) * module_size as usize;

        let mut svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {} {}" width="{}" height="{}">"#,
            total_size, total_size, total_size, total_size
        );

        // White background
        svg.push_str(&format!(
            r#"<rect width="{}" height="{}" fill="white"/>"#,
            total_size, total_size
        ));

        // Black modules
        for row in 0..size {
            for col in 0..size {
                if self.modules[row][col] {
                    let x = (col + quiet_zone) * module_size as usize;
                    let y = (row + quiet_zone) * module_size as usize;
                    svg.push_str(&format!(
                        r#"<rect x="{}" y="{}" width="{}" height="{}" fill="black"/>"#,
                        x, y, module_size, module_size
                    ));
                }
            }
        }

        svg.push_str("</svg>");
        svg
    }

    /// Render the QR code as ASCII art for terminal display.
    ///
    /// Uses Unicode block characters for compact display:
    /// - Full block for black modules
    /// - Space for white modules
    ///
    /// Each module is represented by 2 characters wide for better aspect ratio.
    pub fn to_ascii(&self) -> String {
        let size = self.size();
        let quiet_zone = 2; // Smaller quiet zone for terminal
        let mut result = String::new();

        // Top quiet zone
        for _ in 0..quiet_zone {
            for _ in 0..(size + 2 * quiet_zone) * 2 {
                result.push(' ');
            }
            result.push('\n');
        }

        // QR code rows
        for row in 0..size {
            // Left quiet zone
            for _ in 0..quiet_zone * 2 {
                result.push(' ');
            }

            // Modules
            for col in 0..size {
                if self.modules[row][col] {
                    // Black module: use full block characters
                    result.push_str("\u{2588}\u{2588}");
                } else {
                    // White module: use spaces
                    result.push_str("  ");
                }
            }

            // Right quiet zone
            for _ in 0..quiet_zone * 2 {
                result.push(' ');
            }
            result.push('\n');
        }

        // Bottom quiet zone
        for _ in 0..quiet_zone {
            for _ in 0..(size + 2 * quiet_zone) * 2 {
                result.push(' ');
            }
            result.push('\n');
        }

        result
    }

    /// Render the QR code as compact ASCII using half-block characters.
    ///
    /// Uses Unicode half-block characters to display 2 rows per line:
    /// - Upper half block for top black, bottom white
    /// - Lower half block for top white, bottom black
    /// - Full block for both black
    /// - Space for both white
    ///
    /// This produces a more compact output with better proportions.
    pub fn to_ascii_compact(&self) -> String {
        let size = self.size();
        let quiet_zone = 2;
        let mut result = String::new();

        // Process rows in pairs
        let mut row = 0;
        while row < size + 2 * quiet_zone {
            for col in 0..size + 2 * quiet_zone {
                let top = if row >= quiet_zone
                    && row < size + quiet_zone
                    && col >= quiet_zone
                    && col < size + quiet_zone
                {
                    self.modules[row - quiet_zone][col - quiet_zone]
                } else {
                    false
                };

                let bottom = if row + 1 >= quiet_zone
                    && row + 1 < size + quiet_zone
                    && col >= quiet_zone
                    && col < size + quiet_zone
                {
                    self.modules[row + 1 - quiet_zone][col - quiet_zone]
                } else {
                    false
                };

                let ch = match (top, bottom) {
                    (true, true) => '\u{2588}',  // Full block
                    (true, false) => '\u{2580}', // Upper half block
                    (false, true) => '\u{2584}', // Lower half block
                    (false, false) => ' ',       // Space
                };
                result.push(ch);
            }
            result.push('\n');
            row += 2;
        }

        result
    }

    // Helper functions to get QR code parameters

    fn get_total_codewords(version: u8) -> usize {
        let size = version as usize * 4 + 17;
        let total_modules = size * size;
        let function_modules = Self::count_function_modules(version);
        (total_modules - function_modules) / 8
    }

    fn count_function_modules(version: u8) -> usize {
        // Finder patterns + separators: 3 * (8*8) = 192
        // Timing patterns (excluding overlaps): 2 * (size - 16) - 1
        // Format info: 31 (2 * 15 + 1 dark module)
        // Version info (v7+): 36
        // Alignment patterns
        let size = version as usize * 4 + 17;
        let mut count = 3 * 64 + 3 * 15; // Finders + separators

        count += 2 * (size - 16); // Timing patterns

        if version >= 2 {
            let num_align = (version / 7) as usize + 2;
            let align_patterns = num_align * num_align - 3; // Minus 3 for finder overlaps
            count += align_patterns * 25;
            count -= (num_align - 2) * 5 * 2; // Timing pattern overlaps
        }

        count += 31; // Format info
        if version >= 7 {
            count += 36; // Version info
        }

        count
    }

    fn get_data_codewords(version: u8, ecl: ErrorCorrectionLevel) -> usize {
        let (num_blocks, ec_per_block) = Self::get_ec_params(version, ecl);
        Self::get_total_codewords(version) - num_blocks * ec_per_block
    }

    fn get_ec_params(version: u8, ecl: ErrorCorrectionLevel) -> (usize, usize) {
        // Simplified table - (num_blocks, ec_codewords_per_block)
        // This is a subset; full implementation needs complete table
        let params: [[(usize, usize); 4]; 40] = [
            // Version 1
            [(1, 7), (1, 10), (1, 13), (1, 17)],
            // Version 2
            [(1, 10), (1, 16), (1, 22), (1, 28)],
            // Version 3
            [(1, 15), (1, 26), (2, 18), (2, 22)],
            // Version 4
            [(1, 20), (2, 18), (2, 26), (4, 16)],
            // Version 5
            [(1, 26), (2, 24), (4, 18), (4, 22)],
            // Version 6
            [(2, 18), (4, 16), (4, 24), (4, 28)],
            // Version 7
            [(2, 20), (4, 18), (6, 18), (5, 26)],
            // Version 8
            [(2, 24), (4, 22), (6, 22), (6, 26)],
            // Version 9
            [(2, 30), (5, 22), (8, 20), (8, 24)],
            // Version 10
            [(4, 18), (5, 26), (8, 24), (8, 28)],
            // Version 11
            [(4, 20), (5, 30), (8, 28), (11, 24)],
            // Version 12
            [(4, 24), (8, 22), (10, 26), (11, 28)],
            // Version 13
            [(4, 26), (9, 22), (12, 24), (16, 22)],
            // Version 14
            [(4, 30), (9, 24), (16, 20), (16, 24)],
            // Version 15
            [(6, 22), (10, 24), (12, 30), (18, 24)],
            // Version 16
            [(6, 24), (10, 28), (17, 24), (16, 30)],
            // Version 17
            [(6, 28), (11, 28), (16, 28), (19, 28)],
            // Version 18
            [(6, 30), (13, 26), (18, 28), (21, 28)],
            // Version 19
            [(7, 28), (14, 26), (21, 26), (25, 26)],
            // Version 20
            [(8, 28), (16, 26), (20, 30), (25, 28)],
            // Version 21
            [(8, 28), (17, 26), (23, 28), (25, 30)],
            // Version 22
            [(9, 28), (17, 28), (23, 30), (34, 24)],
            // Version 23
            [(9, 30), (18, 28), (25, 30), (30, 30)],
            // Version 24
            [(10, 30), (20, 28), (27, 30), (32, 30)],
            // Version 25
            [(12, 26), (21, 28), (29, 30), (35, 30)],
            // Version 26
            [(12, 28), (23, 28), (34, 28), (37, 30)],
            // Version 27
            [(12, 30), (25, 28), (34, 30), (40, 30)],
            // Version 28
            [(13, 30), (26, 28), (35, 30), (42, 30)],
            // Version 29
            [(14, 30), (28, 28), (38, 30), (45, 30)],
            // Version 30
            [(15, 30), (29, 28), (40, 30), (48, 30)],
            // Version 31
            [(16, 30), (31, 28), (43, 30), (51, 30)],
            // Version 32
            [(17, 30), (33, 28), (45, 30), (54, 30)],
            // Version 33
            [(18, 30), (35, 28), (48, 30), (57, 30)],
            // Version 34
            [(19, 30), (37, 28), (51, 30), (60, 30)],
            // Version 35
            [(19, 30), (38, 28), (53, 30), (63, 30)],
            // Version 36
            [(20, 30), (40, 28), (56, 30), (66, 30)],
            // Version 37
            [(21, 30), (43, 28), (59, 30), (70, 30)],
            // Version 38
            [(22, 30), (45, 28), (62, 30), (74, 30)],
            // Version 39
            [(24, 30), (47, 28), (65, 30), (77, 30)],
            // Version 40
            [(25, 30), (49, 28), (68, 30), (81, 30)],
        ];

        let idx = (version - 1) as usize;
        let ecl_idx = ecl as usize;
        params[idx][ecl_idx]
    }
}

/// Bit buffer for accumulating bits before converting to bytes.
struct BitBuffer {
    bits: Vec<bool>,
}

impl BitBuffer {
    fn new() -> Self {
        Self { bits: Vec::new() }
    }

    fn append_bits(&mut self, value: u32, count: usize) {
        for i in (0..count).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
    }

    fn len(&self) -> usize {
        self.bits.len()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bits
            .chunks(8)
            .map(|chunk| {
                let mut byte = 0u8;
                for (i, &bit) in chunk.iter().enumerate() {
                    if bit {
                        byte |= 1 << (7 - i);
                    }
                }
                byte
            })
            .collect()
    }
}

/// GF(2^8) arithmetic for Reed-Solomon encoding.
///
/// ## Galois Field GF(2^8)
///
/// A finite field with 256 elements used for Reed-Solomon codes.
///
/// Elements are represented as polynomials over GF(2) modulo an
/// irreducible polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
///
/// - Addition: XOR (polynomial addition mod 2)
/// - Multiplication: Polynomial multiplication mod the irreducible polynomial
///
/// We use log/antilog tables for efficient multiplication:
/// a * b = exp(log(a) + log(b))
struct GF256;

impl GF256 {
    /// Logarithm table (index 1-255 -> exponent)
    const LOG: [u8; 256] = Self::generate_log_table();

    /// Antilogarithm table (exponent 0-254 -> value)
    const EXP: [u8; 256] = Self::generate_exp_table();

    const fn generate_exp_table() -> [u8; 256] {
        let mut table = [0u8; 256];
        let mut x = 1u16;

        let mut i = 0;
        while i < 255 {
            table[i] = x as u8;
            x <<= 1;
            if x >= 256 {
                x ^= 0x11D; // Reduce by primitive polynomial
            }
            i += 1;
        }

        table[255] = table[0]; // Wrap around for convenience
        table
    }

    const fn generate_log_table() -> [u8; 256] {
        let exp = Self::generate_exp_table();
        let mut table = [0u8; 256];

        let mut i = 0;
        while i < 255 {
            table[exp[i] as usize] = i as u8;
            i += 1;
        }

        table
    }

    /// Multiply two elements in GF(2^8).
    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let log_sum = (Self::LOG[a as usize] as u16 + Self::LOG[b as usize] as u16) % 255;
            Self::EXP[log_sum as usize]
        }
    }

    /// Get alpha^n in GF(2^8).
    fn exp(n: u8) -> u8 {
        Self::EXP[n as usize]
    }

    /// Compute multiplicative inverse in GF(2^8).
    ///
    /// For a != 0: inv(a) = alpha^(255 - log(a))
    /// Since alpha^255 = 1, we have a * inv(a) = alpha^log(a) * alpha^(255-log(a)) = alpha^255 = 1
    #[cfg(test)]
    fn inv(a: u8) -> u8 {
        assert!(a != 0, "Cannot invert zero in GF(2^8)");
        let log_a = Self::LOG[a as usize];
        Self::EXP[(255 - log_a as u16) as usize]
    }

    /// Divide two elements in GF(2^8): a / b = a * inv(b)
    #[cfg(test)]
    fn div(a: u8, b: u8) -> u8 {
        assert!(b != 0, "Cannot divide by zero in GF(2^8)");
        if a == 0 {
            0
        } else {
            // a / b = exp(log(a) - log(b)) mod 255
            let log_a = Self::LOG[a as usize] as i16;
            let log_b = Self::LOG[b as usize] as i16;
            let log_result = ((log_a - log_b) % 255 + 255) % 255;
            Self::EXP[log_result as usize]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_simple() {
        let qr = QrCode::encode("HELLO", ErrorCorrectionLevel::M).unwrap();
        assert!(qr.size() >= 21); // Version 1 minimum
    }

    #[test]
    fn test_svg_output() {
        let qr = QrCode::encode("TEST", ErrorCorrectionLevel::L).unwrap();
        let svg = qr.to_svg(10);
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("viewBox"));
        assert!(svg.ends_with("</svg>"));
    }

    /// Test EC level format info encoding per ISO 18004:2015 Table C.1.
    ///
    /// The encoding is NOT the same as the natural ordering:
    /// - L (least recovery) = 01, not 00
    /// - M (medium recovery) = 00, not 01
    /// - Q (quartile recovery) = 11
    /// - H (highest recovery) = 10
    #[test]
    fn test_ec_level_format_info_bits() {
        assert_eq!(ErrorCorrectionLevel::L.format_info_bits(), 0b01);
        assert_eq!(ErrorCorrectionLevel::M.format_info_bits(), 0b00);
        assert_eq!(ErrorCorrectionLevel::Q.format_info_bits(), 0b11);
        assert_eq!(ErrorCorrectionLevel::H.format_info_bits(), 0b10);
    }

    /// Test format bits calculation matches known values from ISO 18004 Table C.2.
    ///
    /// Format info = (EC level << 3 | mask) with BCH(15,5) EC, XORed with 0x5412.
    /// Generator polynomial: x^10 + x^8 + x^5 + x^4 + x^2 + x + 1 (0x537).
    #[test]
    fn test_format_bits_known_values() {
        // Format: (data_bits, expected_format)
        // Data = (EC level format bits << 3) | mask
        // Values computed per ISO 18004 BCH(15,5) algorithm
        let test_cases = [
            // M-0: EC=00, mask=000 -> data=0b00000
            (0b00_000, 0b101010000010010),
            // M-1: EC=00, mask=001 -> data=0b00001
            (0b00_001, 0b101000100100101),
            // M-2: EC=00, mask=010 -> data=0b00010
            (0b00_010, 0b101111001111100),
            // L-0: EC=01, mask=000 -> data=0b01000
            (0b01_000, 0b111011111000100),
            // L-1: EC=01, mask=001 -> data=0b01001
            (0b01_001, 0b111001011110011),
            // H-0: EC=10, mask=000 -> data=0b10000
            (0b10_000, 0b001011010001001),
            // H-1: EC=10, mask=001 -> data=0b10001
            (0b10_001, 0b001001110111110),
            // Q-0: EC=11, mask=000 -> data=0b11000
            (0b11_000, 0b011010101011111),
            // Q-1: EC=11, mask=001 -> data=0b11001
            (0b11_001, 0b011000001101000),
        ];

        for (data, expected) in test_cases {
            let result = QrCode::calculate_format_bits(data);
            assert_eq!(
                result, expected,
                "Format bits mismatch for data={:#07b}: got {:#017b}, expected {:#017b}",
                data, result, expected
            );
        }
    }
}

/// GF(2^8) Property-Based Tests
///
/// A finite field must satisfy these axioms:
/// 1. (F, +) is an abelian group with identity 0
/// 2. (F \ {0}, *) is an abelian group with identity 1
/// 3. Multiplication distributes over addition
///
/// In GF(2^8), addition is XOR and multiplication uses the primitive
/// polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
#[cfg(test)]
mod gf256_tests {
    use super::*;

    /// Property: Multiplicative identity
    /// For all a in GF(2^8): a * 1 = a
    #[test]
    fn multiplicative_identity() {
        for a in 0u8..=255 {
            assert_eq!(
                GF256::mul(a, 1),
                a,
                "Multiplicative identity failed for a = {}",
                a
            );
        }
    }

    /// Property: Zero absorbs multiplication
    /// For all a in GF(2^8): a * 0 = 0
    #[test]
    fn zero_absorbs() {
        for a in 0u8..=255 {
            assert_eq!(GF256::mul(a, 0), 0, "Zero absorption failed for a = {}", a);
            assert_eq!(GF256::mul(0, a), 0, "Zero absorption failed for a = {}", a);
        }
    }

    /// Property: Commutativity of multiplication
    /// For all a, b in GF(2^8): a * b = b * a
    #[test]
    fn commutativity() {
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(
                    GF256::mul(a, b),
                    GF256::mul(b, a),
                    "Commutativity failed for a = {}, b = {}",
                    a,
                    b
                );
            }
        }
    }

    /// Property: Associativity of multiplication
    /// For all a, b, c in GF(2^8): (a * b) * c = a * (b * c)
    #[test]
    fn associativity() {
        // Exhaustive test over all triples would be 2^24 = 16M tests.
        // We sample representative values instead.
        let samples: [u8; 16] = [
            0, 1, 2, 3, 7, 15, 31, 63, 127, 128, 200, 250, 253, 254, 255, 42,
        ];

        for &a in &samples {
            for &b in &samples {
                for &c in &samples {
                    let lhs = GF256::mul(GF256::mul(a, b), c);
                    let rhs = GF256::mul(a, GF256::mul(b, c));
                    assert_eq!(
                        lhs, rhs,
                        "Associativity failed for a = {}, b = {}, c = {}",
                        a, b, c
                    );
                }
            }
        }
    }

    /// Property: Distributivity of multiplication over addition (XOR)
    /// For all a, b, c in GF(2^8): a * (b + c) = (a * b) + (a * c)
    /// where + is XOR
    #[test]
    fn distributivity() {
        let samples: [u8; 16] = [
            0, 1, 2, 3, 7, 15, 31, 63, 127, 128, 200, 250, 253, 254, 255, 42,
        ];

        for &a in &samples {
            for &b in &samples {
                for &c in &samples {
                    let lhs = GF256::mul(a, b ^ c);
                    let rhs = GF256::mul(a, b) ^ GF256::mul(a, c);
                    assert_eq!(
                        lhs, rhs,
                        "Distributivity failed for a = {}, b = {}, c = {}",
                        a, b, c
                    );
                }
            }
        }
    }

    /// Property: Multiplicative inverse
    /// For all a in GF(2^8) \ {0}: a * inv(a) = 1
    #[test]
    fn multiplicative_inverse() {
        for a in 1u8..=255 {
            let inv_a = GF256::inv(a);
            assert_eq!(
                GF256::mul(a, inv_a),
                1,
                "Inverse failed for a = {}, inv(a) = {}",
                a,
                inv_a
            );
        }
    }

    /// Property: Inverse is involutory
    /// For all a in GF(2^8) \ {0}: inv(inv(a)) = a
    #[test]
    fn inverse_involutory() {
        for a in 1u8..=255 {
            assert_eq!(
                GF256::inv(GF256::inv(a)),
                a,
                "Inverse involution failed for a = {}",
                a
            );
        }
    }

    /// Property: Division is inverse of multiplication
    /// For all a, b in GF(2^8) with b != 0: (a * b) / b = a
    #[test]
    fn division_inverse_of_multiplication() {
        for a in 0u8..=255 {
            for b in 1u8..=255 {
                let product = GF256::mul(a, b);
                assert_eq!(
                    GF256::div(product, b),
                    a,
                    "Division inverse failed for a = {}, b = {}",
                    a,
                    b
                );
            }
        }
    }

    /// Property: No zero divisors
    /// For all a, b in GF(2^8): a * b = 0 implies a = 0 or b = 0
    #[test]
    fn no_zero_divisors() {
        for a in 1u8..=255 {
            for b in 1u8..=255 {
                assert_ne!(GF256::mul(a, b), 0, "Zero divisor found: {} * {} = 0", a, b);
            }
        }
    }

    /// Property: Primitive element generates the multiplicative group
    /// alpha = 2 is the primitive element, and alpha^255 = 1
    #[test]
    fn primitive_element() {
        // alpha^0 = 1
        assert_eq!(GF256::exp(0), 1);

        // alpha^255 = 1 (the order of the multiplicative group is 255)
        // We compute this by repeated multiplication
        let alpha = 2u8;
        let mut power = 1u8;
        for i in 0..255 {
            assert_eq!(
                GF256::exp(i),
                power,
                "EXP table mismatch at i = {}: expected {}, got {}",
                i,
                power,
                GF256::exp(i)
            );
            power = GF256::mul(power, alpha);
        }
        // After 255 multiplications, we should be back to 1
        assert_eq!(power, 1, "alpha^255 should equal 1");
    }

    /// Property: LOG and EXP tables are inverses
    /// For all a in GF(2^8) \ {0}: exp(log(a)) = a
    #[test]
    fn log_exp_inverse() {
        for a in 1u8..=255 {
            let log_a = GF256::LOG[a as usize];
            let recovered = GF256::EXP[log_a as usize];
            assert_eq!(
                recovered, a,
                "LOG/EXP inverse failed for a = {}: log(a) = {}, exp(log(a)) = {}",
                a, log_a, recovered
            );
        }
    }

    /// Property: EXP table generates all non-zero elements exactly once
    /// The multiplicative group has order 255, so exp(0..255) should cover
    /// all non-zero elements.
    #[test]
    fn exp_generates_all_elements() {
        let mut seen = [false; 256];

        for i in 0u8..255 {
            let val = GF256::EXP[i as usize];
            assert!(
                !seen[val as usize],
                "Duplicate in EXP table: exp({}) = {} (already seen)",
                i, val
            );
            seen[val as usize] = true;
        }

        // Check all non-zero elements were generated
        for val in 1u8..=255 {
            assert!(
                seen[val as usize],
                "Value {} not generated by EXP table",
                val
            );
        }
    }

    /// Property: Multiplication using LOG/EXP matches direct polynomial multiplication
    /// Direct multiplication: multiply polynomials and reduce mod 0x11D
    #[test]
    fn mul_matches_polynomial_multiplication() {
        // Direct polynomial multiplication in GF(2^8)
        fn poly_mul(a: u8, b: u8) -> u8 {
            let mut result = 0u16;
            let mut a_shifted = a as u16;

            for i in 0..8 {
                if (b >> i) & 1 == 1 {
                    result ^= a_shifted;
                }
                a_shifted <<= 1;
            }

            // Reduce modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
            for i in (8..=14).rev() {
                if (result >> i) & 1 == 1 {
                    result ^= 0x11D << (i - 8);
                }
            }

            result as u8
        }

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let table_result = GF256::mul(a, b);
                let poly_result = poly_mul(a, b);
                assert_eq!(
                    table_result, poly_result,
                    "Multiplication mismatch for {} * {}: table = {}, poly = {}",
                    a, b, table_result, poly_result
                );
            }
        }
    }
}
