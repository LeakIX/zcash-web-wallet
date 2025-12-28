//! Transaction scanner for extracting notes and nullifiers.

use anyhow::{Context, Result, bail};
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BranchId, Network};

/// A note found in a transaction.
#[derive(Debug, Clone)]
pub struct ScannedNote {
    pub output_index: usize,
    pub pool: String,
    pub value: u64,
    pub commitment: String,
    pub nullifier: Option<String>,
    pub memo: Option<String>,
    pub address: Option<String>,
}

/// Nullifiers found in a transaction (indicating spent notes).
#[derive(Debug, Clone)]
pub struct SpentNullifier {
    pub pool: String,
    pub nullifier: String,
}

/// Result of scanning a transaction.
#[derive(Debug)]
pub struct ScanResult {
    pub txid: String,
    pub notes: Vec<ScannedNote>,
    pub spent_nullifiers: Vec<SpentNullifier>,
    pub transparent_received: u64,
    pub transparent_outputs: Vec<TransparentOutput>,
}

/// Transparent output info.
#[derive(Debug, Clone)]
pub struct TransparentOutput {
    pub index: usize,
    pub value: u64,
    pub address: Option<String>,
}

/// Parse a transaction from hex.
pub fn parse_transaction(tx_hex: &str, network: Network) -> Result<Transaction> {
    let tx_bytes = hex::decode(tx_hex).context("Invalid transaction hex")?;

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

    bail!("Failed to parse transaction with any known branch ID")
}

/// Extract nullifiers from a transaction (these indicate spent notes).
pub fn extract_nullifiers(tx: &Transaction) -> Vec<SpentNullifier> {
    let mut nullifiers = Vec::new();

    // Sapling nullifiers (from spends)
    if let Some(sapling_bundle) = tx.sapling_bundle() {
        for spend in sapling_bundle.shielded_spends() {
            nullifiers.push(SpentNullifier {
                pool: "sapling".to_string(),
                nullifier: hex::encode(spend.nullifier().0),
            });
        }
    }

    // Orchard nullifiers (from actions)
    if let Some(orchard_bundle) = tx.orchard_bundle() {
        for action in orchard_bundle.actions() {
            nullifiers.push(SpentNullifier {
                pool: "orchard".to_string(),
                nullifier: hex::encode(action.nullifier().to_bytes()),
            });
        }
    }

    nullifiers
}

/// Scan a transaction for notes belonging to a viewing key.
///
/// Note: Full note decryption requires additional context (block height, etc.)
/// For now, we extract what we can from the transaction structure.
pub fn scan_transaction(
    tx: &Transaction,
    viewing_key: &str,
    network: Network,
    height: Option<u32>,
) -> Result<ScanResult> {
    let txid = tx.txid().to_string();
    let mut notes = Vec::new();
    let mut transparent_received = 0u64;
    let mut transparent_outputs = Vec::new();

    // Parse the viewing key
    let (has_sapling, has_orchard, has_transparent) = parse_viewing_key_capabilities(viewing_key)?;

    // Process transparent outputs
    if has_transparent {
        if let Some(transparent_bundle) = tx.transparent_bundle() {
            for (i, output) in transparent_bundle.vout.iter().enumerate() {
                let value = u64::from(output.value());
                transparent_received += value;
                transparent_outputs.push(TransparentOutput {
                    index: i,
                    value,
                    address: None, // TODO: decode address from script
                });
            }
        }
    }

    // Process Sapling outputs
    if has_sapling {
        if let Some(sapling_bundle) = tx.sapling_bundle() {
            for (i, output) in sapling_bundle.shielded_outputs().iter().enumerate() {
                // Extract commitment
                let cmu = output.cmu();
                let commitment = hex::encode(cmu.to_bytes());

                // For Sapling, we need trial decryption to get the value
                // This requires the full viewing key and block height
                // For now, we record the output with unknown value
                notes.push(ScannedNote {
                    output_index: i,
                    pool: "sapling".to_string(),
                    value: 0, // Would need trial decryption
                    commitment,
                    nullifier: None, // Computed from note, not available without decryption
                    memo: None,
                    address: None,
                });
            }
        }
    }

    // Process Orchard actions
    if has_orchard {
        if let Some(orchard_bundle) = tx.orchard_bundle() {
            for (i, action) in orchard_bundle.actions().iter().enumerate() {
                // Extract commitment
                let cmx = action.cmx();
                let commitment = hex::encode(cmx.to_bytes());

                // Orchard actions contain both inputs (nullifiers) and outputs
                // The nullifier in the action is for the spent note, not the new note
                notes.push(ScannedNote {
                    output_index: i,
                    pool: "orchard".to_string(),
                    value: 0, // Would need trial decryption
                    commitment,
                    nullifier: None, // The note's nullifier would be computed after decryption
                    memo: None,
                    address: None,
                });
            }
        }
    }

    // Extract nullifiers (spent notes)
    let spent_nullifiers = extract_nullifiers(tx);

    Ok(ScanResult {
        txid,
        notes,
        spent_nullifiers,
        transparent_received,
        transparent_outputs,
    })
}

/// Parse a viewing key and determine its capabilities.
fn parse_viewing_key_capabilities(viewing_key: &str) -> Result<(bool, bool, bool)> {
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

    bail!("Unrecognized viewing key format")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_viewing_key_capabilities() {
        // Test UFVK parsing
        let ufvk = "uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd";
        let (sapling, orchard, transparent) = parse_viewing_key_capabilities(ufvk).unwrap();
        assert!(sapling);
        assert!(orchard);
        assert!(transparent);
    }
}
