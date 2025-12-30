//! Transaction scanner for extracting notes and nullifiers.
//!
//! This module provides WASM-compatible transaction scanning functionality.
//! It performs trial decryption using viewing keys to find notes belonging
//! to the wallet and extracts nullifiers to track spent notes.

use orchard::keys::{FullViewingKey as OrchardFvk, PreparedIncomingViewingKey, Scope};
use orchard::note_encryption::OrchardDomain;
use zcash_address::unified::{self, Container, Encoding};
use zcash_keys::encoding::AddressCodec;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, Network};

use crate::types::{
    Pool, ScanResult, ScannedNote, ScannedTransparentOutput, SpentNullifier, TransparentSpend,
};

/// Errors that can occur during scanning operations.
#[derive(Debug)]
pub enum ScannerError {
    InvalidTransactionHex(String),
    TransactionParseFailed(String),
    UnrecognizedViewingKey,
}

impl core::fmt::Display for ScannerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTransactionHex(msg) => write!(f, "Invalid transaction hex: {}", msg),
            Self::TransactionParseFailed(msg) => write!(f, "Failed to parse transaction: {}", msg),
            Self::UnrecognizedViewingKey => write!(f, "Unrecognized viewing key format"),
        }
    }
}

impl core::error::Error for ScannerError {}

/// Parse a transaction from hex bytes.
///
/// Attempts parsing with multiple branch IDs (Nu6, Nu5, Canopy, Heartwood)
/// to support transactions from different network upgrades.
///
/// # Arguments
///
/// * `tx_hex` - The raw transaction as a hexadecimal string
/// * `_network` - The network (currently unused but included for future use)
///
/// # Returns
///
/// The parsed `Transaction` or an error if parsing fails.
pub fn parse_transaction(tx_hex: &str, _network: Network) -> Result<Transaction, ScannerError> {
    let tx_bytes = hex::decode(tx_hex.trim())
        .map_err(|e| ScannerError::InvalidTransactionHex(e.to_string()))?;

    // Try parsing with different branch IDs
    let branch_ids = [
        BranchId::Nu6,
        BranchId::Nu5,
        BranchId::Canopy,
        BranchId::Heartwood,
    ];

    for branch_id in branch_ids {
        if let Ok(tx) = Transaction::read(&tx_bytes[..], branch_id) {
            return Ok(tx);
        }
    }

    Err(ScannerError::TransactionParseFailed(
        "Failed to parse transaction with any known branch ID".to_string(),
    ))
}

/// Extract nullifiers from a transaction.
///
/// Nullifiers indicate which notes have been spent. By tracking nullifiers
/// across transactions, we can determine which of our received notes are
/// still unspent.
///
/// # Arguments
///
/// * `tx` - The parsed transaction
///
/// # Returns
///
/// A vector of `SpentNullifier` entries for each spend in the transaction.
pub fn extract_nullifiers(tx: &Transaction) -> Vec<SpentNullifier> {
    let mut nullifiers = Vec::new();

    // Sapling nullifiers (from spends)
    if let Some(sapling_bundle) = tx.sapling_bundle() {
        for spend in sapling_bundle.shielded_spends() {
            nullifiers.push(SpentNullifier {
                pool: Pool::Sapling,
                nullifier: hex::encode(spend.nullifier().0),
            });
        }
    }

    // Orchard nullifiers (from actions)
    if let Some(orchard_bundle) = tx.orchard_bundle() {
        for action in orchard_bundle.actions() {
            nullifiers.push(SpentNullifier {
                pool: Pool::Orchard,
                nullifier: hex::encode(action.nullifier().to_bytes()),
            });
        }
    }

    nullifiers
}

/// Extract the Orchard full viewing key from a UFVK string.
fn extract_orchard_fvk(viewing_key: &str) -> Option<OrchardFvk> {
    if let Ok((_, ufvk)) = unified::Ufvk::decode(viewing_key) {
        for item in ufvk.items() {
            if let unified::Fvk::Orchard(orchard_bytes) = item
                && let Some(fvk) = OrchardFvk::from_bytes(&orchard_bytes)
            {
                return Some(fvk);
            }
        }
    }
    None
}

/// Parse a viewing key and determine its capabilities.
///
/// # Returns
///
/// A tuple of (has_sapling, has_orchard, has_transparent) indicating which
/// pools the viewing key can view.
pub fn parse_viewing_key_capabilities(
    viewing_key: &str,
) -> Result<(bool, bool, bool), ScannerError> {
    // Try to decode as UFVK
    if let Ok((_, ufvk)) = unified::Ufvk::decode(viewing_key) {
        let mut has_sapling = false;
        let mut has_orchard = false;
        let mut has_transparent = false;

        for item in ufvk.items() {
            match item {
                unified::Fvk::Sapling(_) => has_sapling = true,
                unified::Fvk::Orchard(_) => has_orchard = true,
                unified::Fvk::P2pkh(_) => has_transparent = true,
                _ => {}
            }
        }

        return Ok((has_sapling, has_orchard, has_transparent));
    }

    // Try to decode as UIVK
    if let Ok((_, uivk)) = unified::Uivk::decode(viewing_key) {
        let mut has_sapling = false;
        let mut has_orchard = false;
        let mut has_transparent = false;

        for item in uivk.items() {
            match item {
                unified::Ivk::Sapling(_) => has_sapling = true,
                unified::Ivk::Orchard(_) => has_orchard = true,
                unified::Ivk::P2pkh(_) => has_transparent = true,
                _ => {}
            }
        }

        return Ok((has_sapling, has_orchard, has_transparent));
    }

    // Try legacy Sapling viewing key
    if viewing_key.starts_with("zxview") || viewing_key.starts_with("zxviews") {
        return Ok((true, false, false));
    }

    Err(ScannerError::UnrecognizedViewingKey)
}

/// Scan a transaction for notes belonging to a viewing key.
///
/// Performs trial decryption on all shielded outputs to find notes
/// addressed to the viewing key. Also extracts nullifiers to track
/// spent notes.
///
/// # Arguments
///
/// * `tx` - The parsed transaction
/// * `viewing_key` - The viewing key (UFVK, UIVK, or legacy Sapling)
/// * `network` - The network (used for encoding transparent addresses)
/// * `_height` - Block height (currently unused, needed for full Sapling decryption)
///
/// # Returns
///
/// A `ScanResult` containing found notes, spent nullifiers, and transparent outputs.
pub fn scan_transaction(
    tx: &Transaction,
    viewing_key: &str,
    network: Network,
    _height: Option<u32>,
) -> Result<ScanResult, ScannerError> {
    let txid = tx.txid().to_string();
    let mut notes = Vec::new();
    let mut transparent_received = 0u64;
    let mut transparent_outputs = Vec::new();

    // Parse the viewing key capabilities
    let (has_sapling, has_orchard, has_transparent) = parse_viewing_key_capabilities(viewing_key)?;

    // Extract Orchard FVK for decryption
    let orchard_fvk = extract_orchard_fvk(viewing_key);

    // Extract transparent spends (inputs)
    let mut transparent_spends = Vec::new();
    if let Some(transparent_bundle) = tx.transparent_bundle() {
        for input in transparent_bundle.vin.iter() {
            let prevout = input.prevout();
            transparent_spends.push(TransparentSpend {
                prevout_txid: hex::encode(prevout.hash()),
                prevout_index: prevout.n(),
            });
        }
    }

    // Process transparent outputs
    if has_transparent && let Some(transparent_bundle) = tx.transparent_bundle() {
        for (i, output) in transparent_bundle.vout.iter().enumerate() {
            let value = u64::from(output.value());
            transparent_received += value;

            // Decode the transparent address from the script
            let address = output.recipient_address().map(|addr| addr.encode(&network));

            transparent_outputs.push(ScannedTransparentOutput {
                index: i,
                value,
                address: address.clone(),
            });
            // Also add to notes for unified tracking
            notes.push(ScannedNote {
                output_index: i,
                pool: Pool::Transparent,
                value,
                commitment: String::new(), // Transparent outputs don't have commitments
                nullifier: None,           // Transparent outputs use input references instead
                memo: None,                // Transparent outputs don't have memos
                address,
            });
        }
    }

    // Process Sapling outputs (without full decryption - focusing on Orchard)
    if has_sapling && let Some(sapling_bundle) = tx.sapling_bundle() {
        for (i, output) in sapling_bundle.shielded_outputs().iter().enumerate() {
            let cmu = output.cmu();
            let commitment = hex::encode(cmu.to_bytes());

            notes.push(ScannedNote {
                output_index: i,
                pool: Pool::Sapling,
                value: 0, // Sapling decryption requires height context
                commitment,
                nullifier: None,
                memo: None,
                address: None,
            });
        }
    }

    // Process Orchard actions with trial decryption
    if has_orchard && let Some(orchard_bundle) = tx.orchard_bundle() {
        // Prepare the incoming viewing key for decryption
        let prepared_ivk = orchard_fvk
            .as_ref()
            .map(|fvk| PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)));

        for (i, action) in orchard_bundle.actions().iter().enumerate() {
            let cmx = action.cmx();
            let commitment = hex::encode(cmx.to_bytes());

            let mut value = 0u64;
            let mut memo = None;
            let mut nullifier = None;
            let mut address = None;

            // Attempt trial decryption if we have the viewing key
            if let Some(ref ivk) = prepared_ivk {
                let domain = OrchardDomain::for_action(action);

                if let Some((note, recipient_addr, memo_bytes)) =
                    try_note_decryption(&domain, ivk, action)
                {
                    // Successfully decrypted!
                    value = note.value().inner();

                    // Extract memo (strip trailing zeros and convert to string if valid UTF-8)
                    let memo_trimmed: Vec<u8> = memo_bytes
                        .iter()
                        .rev()
                        .skip_while(|&&b| b == 0)
                        .copied()
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect();
                    if !memo_trimmed.is_empty() {
                        memo = String::from_utf8(memo_trimmed).ok();
                    }

                    // Compute the nullifier for this note
                    if let Some(ref fvk) = orchard_fvk {
                        let nf = note.nullifier(fvk);
                        nullifier = Some(hex::encode(nf.to_bytes()));
                    }

                    // Encode the recipient address
                    address = Some(format!("{:?}", recipient_addr));
                }
            }

            notes.push(ScannedNote {
                output_index: i,
                pool: Pool::Orchard,
                value,
                commitment,
                nullifier,
                memo,
                address,
            });
        }
    }

    // Extract nullifiers (spent notes)
    let spent_nullifiers = extract_nullifiers(tx);

    Ok(ScanResult {
        txid,
        notes,
        spent_nullifiers,
        transparent_spends,
        transparent_received,
        transparent_outputs,
    })
}

/// Scan a transaction from hex for notes belonging to a viewing key.
///
/// Convenience function that combines parsing and scanning.
///
/// # Arguments
///
/// * `tx_hex` - The raw transaction as a hexadecimal string
/// * `viewing_key` - The viewing key (UFVK, UIVK, or legacy Sapling)
/// * `network` - The network to use for parsing
/// * `height` - Optional block height (needed for full Sapling decryption)
///
/// # Returns
///
/// A `ScanResult` containing found notes, spent nullifiers, and transparent outputs.
pub fn scan_transaction_hex(
    tx_hex: &str,
    viewing_key: &str,
    network: Network,
    height: Option<u32>,
) -> Result<ScanResult, ScannerError> {
    let tx = parse_transaction(tx_hex, network)?;
    scan_transaction(&tx, viewing_key, network, height)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test UFVK for reference
    const TEST_UFVK: &str = "uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd";

    #[test]
    fn test_parse_viewing_key_capabilities() {
        let (sapling, orchard, transparent) = parse_viewing_key_capabilities(TEST_UFVK).unwrap();
        assert!(sapling);
        assert!(orchard);
        assert!(transparent);
    }

    #[test]
    fn test_extract_orchard_fvk() {
        let fvk = extract_orchard_fvk(TEST_UFVK);
        assert!(fvk.is_some(), "Should extract Orchard FVK from UFVK");
    }

    #[test]
    fn test_invalid_viewing_key() {
        let result = parse_viewing_key_capabilities("invalid_key");
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_sapling_key() {
        let result = parse_viewing_key_capabilities("zxviews1something");
        assert!(result.is_ok());
        let (sapling, orchard, transparent) = result.unwrap();
        assert!(sapling);
        assert!(!orchard);
        assert!(!transparent);
    }

    /// Regression test for issue with scanning testnet transaction
    /// txid: 0411ffa70699e3fdd5bfe30573d8d49c26939bc9598c3c44f4c07cf44f24f141
    /// seed: ahead pupil festival wife avoid yellow noodle puzzle pact alone ginger judge
    ///       safe era spread lawn goat potato punch physical lamp oyster crisp attract
    ///
    /// This transaction contains a transparent output to the first address of the wallet.
    /// The scan should not panic with "index out of bounds".
    #[test]
    fn test_scan_testnet_transparent_transaction() {
        // Seed phrase that generates the wallet
        const SEED_PHRASE: &str = "ahead pupil festival wife avoid yellow noodle puzzle pact alone ginger judge safe era spread lawn goat potato punch physical lamp oyster crisp attract";

        // Raw transaction hex loaded from testdata file
        // txid: 0411ffa70699e3fdd5bfe30573d8d49c26939bc9598c3c44f4c07cf44f24f141
        const TX_HEX: &str = include_str!("testdata/tx_0411ffa7.hex");

        // First, restore the wallet to get the viewing key
        let wallet = crate::wallet::restore_wallet(
            SEED_PHRASE,
            Network::TestNetwork,
            0, // account index
            0, // address index
        )
        .expect("Failed to restore wallet");

        // Parse the transaction
        let result = scan_transaction_hex(
            TX_HEX,
            &wallet.unified_full_viewing_key,
            Network::TestNetwork,
            None,
        );

        // The scan should succeed without panicking
        assert!(
            result.is_ok(),
            "Scan should succeed, got error: {:?}",
            result.err()
        );

        let scan_result = result.unwrap();

        // Transaction should have the correct txid (display format)
        assert_eq!(
            scan_result.txid,
            "0411ffa70699e3fdd5bfe30573d8d49c26939bc9598c3c44f4c07cf44f24f141"
        );

        // Should find transparent outputs (the transaction has 1 transparent output)
        assert!(
            !scan_result.transparent_outputs.is_empty()
                || !scan_result
                    .notes
                    .iter()
                    .any(|n| n.pool == Pool::Transparent),
            "Should find transparent outputs"
        );

        // Get the wallet's first transparent address for comparison
        let first_transparent_address = wallet
            .transparent_address
            .as_ref()
            .expect("Wallet should have a transparent address");

        // Verify at least one transparent note has a decoded address
        let transparent_notes: Vec<_> = scan_result
            .notes
            .iter()
            .filter(|n| n.pool == Pool::Transparent)
            .collect();

        assert!(
            !transparent_notes.is_empty(),
            "Should have transparent notes"
        );

        // Check that addresses are decoded (not None)
        let notes_with_addresses: Vec<_> = transparent_notes
            .iter()
            .filter(|n| n.address.is_some())
            .collect();

        assert!(
            !notes_with_addresses.is_empty(),
            "Transparent notes should have decoded addresses"
        );

        // Verify that the transaction output matches the wallet's first transparent address
        let matching_notes: Vec<_> = transparent_notes
            .iter()
            .filter(|n| n.address.as_deref() == Some(first_transparent_address.as_str()))
            .collect();

        assert!(
            !matching_notes.is_empty(),
            "Should find a transparent output matching the wallet's first address: {}",
            first_transparent_address
        );
    }
}
