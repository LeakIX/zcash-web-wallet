use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use rand::RngCore;
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::NetworkType;

/// Result type for decrypted transaction data
#[derive(Serialize, Deserialize)]
pub struct DecryptedTransaction {
    pub txid: String,
    pub sapling_outputs: Vec<DecryptedSaplingOutput>,
    pub orchard_actions: Vec<DecryptedOrchardAction>,
    pub transparent_inputs: Vec<TransparentInput>,
    pub transparent_outputs: Vec<TransparentOutput>,
    pub fee: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedSaplingOutput {
    pub index: usize,
    pub value: u64,
    pub memo: String,
    pub address: Option<String>,
    pub note_commitment: String,
    pub nullifier: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptedOrchardAction {
    pub index: usize,
    pub value: u64,
    pub memo: String,
    pub address: Option<String>,
    pub note_commitment: String,
    pub nullifier: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TransparentInput {
    pub index: usize,
    pub prevout_txid: String,
    pub prevout_index: u32,
}

#[derive(Serialize, Deserialize)]
pub struct TransparentOutput {
    pub index: usize,
    pub value: u64,
    pub script_pubkey: String,
    pub address: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ViewingKeyInfo {
    pub valid: bool,
    pub key_type: String,
    pub has_sapling: bool,
    pub has_orchard: bool,
    pub network: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DecryptionResult {
    pub success: bool,
    pub transaction: Option<DecryptedTransaction>,
    pub error: Option<String>,
}

/// Result type for wallet generation
#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub success: bool,
    pub seed_phrase: Option<String>,
    pub network: String,
    pub unified_address: Option<String>,
    pub transparent_address: Option<String>,
    pub sapling_address: Option<String>,
    pub unified_full_viewing_key: Option<String>,
    pub error: Option<String>,
}

/// Log to browser console
fn console_log(msg: &str) {
    web_sys::console::log_1(&JsValue::from_str(msg));
}

/// Parse and validate a viewing key
#[wasm_bindgen]
pub fn parse_viewing_key(key: &str) -> String {
    let result = parse_viewing_key_inner(key);
    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&ViewingKeyInfo {
            valid: false,
            key_type: String::new(),
            has_sapling: false,
            has_orchard: false,
            network: String::new(),
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

fn network_type_to_string(network: NetworkType) -> &'static str {
    match network {
        NetworkType::Main => "mainnet",
        NetworkType::Test => "testnet",
        NetworkType::Regtest => "regtest",
    }
}

fn parse_viewing_key_inner(key: &str) -> ViewingKeyInfo {
    let key = key.trim();

    // Try parsing as Unified Full Viewing Key (UFVK)
    if let Ok((network, ufvk)) = unified::Ufvk::decode(key) {
        let items = ufvk.items();
        let has_sapling = items
            .iter()
            .any(|item| matches!(item, unified::Fvk::Sapling(_)));
        let has_orchard = items
            .iter()
            .any(|item| matches!(item, unified::Fvk::Orchard(_)));

        return ViewingKeyInfo {
            valid: true,
            key_type: "UFVK".to_string(),
            has_sapling,
            has_orchard,
            network: network_type_to_string(network).to_string(),
            error: None,
        };
    }

    // Try parsing as Unified Incoming Viewing Key (UIVK)
    if let Ok((network, _uivk)) = unified::Uivk::decode(key) {
        return ViewingKeyInfo {
            valid: true,
            key_type: "UIVK".to_string(),
            has_sapling: true,
            has_orchard: true,
            network: network_type_to_string(network).to_string(),
            error: None,
        };
    }

    // Try parsing as legacy Sapling extended viewing key
    // These start with "zxviews" (mainnet) or "zxviewtestsapling" (testnet)
    if key.starts_with("zxviews") || key.starts_with("zxviewtestsapling") {
        let network = if key.starts_with("zxviews") {
            "mainnet"
        } else {
            "testnet"
        };

        // Basic validation - proper bech32 decoding
        if bech32::decode(key).is_ok() {
            return ViewingKeyInfo {
                valid: true,
                key_type: "Sapling ExtFVK".to_string(),
                has_sapling: true,
                has_orchard: false,
                network: network.to_string(),
                error: None,
            };
        }
    }

    ViewingKeyInfo {
        valid: false,
        key_type: String::new(),
        has_sapling: false,
        has_orchard: false,
        network: String::new(),
        error: Some("Unrecognized viewing key format".to_string()),
    }
}

/// Decrypt a transaction using the provided viewing key
#[wasm_bindgen]
pub fn decrypt_transaction(raw_tx_hex: &str, viewing_key: &str, network: &str) -> String {
    let result = decrypt_transaction_inner(raw_tx_hex, viewing_key, network);
    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&DecryptionResult {
            success: false,
            transaction: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

fn decrypt_transaction_inner(
    raw_tx_hex: &str,
    viewing_key: &str,
    network: &str,
) -> DecryptionResult {
    console_log(&format!("Decrypting transaction with network: {}", network));

    // Decode the raw transaction hex
    let tx_bytes = match hex::decode(raw_tx_hex.trim()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return DecryptionResult {
                success: false,
                transaction: None,
                error: Some(format!("Failed to decode transaction hex: {}", e)),
            };
        }
    };

    // Parse the transaction
    let tx = match Transaction::read(&tx_bytes[..], zcash_primitives::consensus::BranchId::Nu6) {
        Ok(tx) => tx,
        Err(e) => {
            // Try with earlier branch IDs
            match Transaction::read(&tx_bytes[..], zcash_primitives::consensus::BranchId::Nu5) {
                Ok(tx) => tx,
                Err(_) => {
                    return DecryptionResult {
                        success: false,
                        transaction: None,
                        error: Some(format!("Failed to parse transaction: {}", e)),
                    };
                }
            }
        }
    };

    let txid = tx.txid().to_string();
    console_log(&format!("Parsed transaction: {}", txid));

    let mut decrypted = DecryptedTransaction {
        txid,
        sapling_outputs: Vec::new(),
        orchard_actions: Vec::new(),
        transparent_inputs: Vec::new(),
        transparent_outputs: Vec::new(),
        fee: None,
    };

    // Extract transparent inputs and outputs
    if let Some(transparent_bundle) = tx.transparent_bundle() {
        for (i, input) in transparent_bundle.vin.iter().enumerate() {
            let prevout = input.prevout();
            decrypted.transparent_inputs.push(TransparentInput {
                index: i,
                prevout_txid: hex::encode(prevout.hash()),
                prevout_index: prevout.n(),
            });
        }

        for (i, output) in transparent_bundle.vout.iter().enumerate() {
            // Serialize the script to bytes
            let mut script_bytes = Vec::new();
            let _ = output.script_pubkey().write(&mut script_bytes);

            decrypted.transparent_outputs.push(TransparentOutput {
                index: i,
                value: u64::from(output.value()),
                script_pubkey: hex::encode(&script_bytes),
                address: None, // TODO: decode address from script
            });
        }
    }

    // Parse viewing key and attempt decryption
    let viewing_key = viewing_key.trim();

    // Try as UFVK
    if let Ok((_network, ufvk)) = unified::Ufvk::decode(viewing_key) {
        // Extract Sapling FVK if present
        for item in ufvk.items() {
            if let unified::Fvk::Sapling(_sapling_bytes) = item
                && let Some(sapling_bundle) = tx.sapling_bundle()
            {
                console_log(&format!(
                    "Attempting to decrypt {} Sapling outputs",
                    sapling_bundle.shielded_outputs().len()
                ));

                // Try to decrypt each Sapling output
                for (i, output) in sapling_bundle.shielded_outputs().iter().enumerate() {
                    // Note: Full decryption requires more context (height, etc.)
                    // For now, we'll extract what we can from the output
                    let cmu = output.cmu();
                    decrypted.sapling_outputs.push(DecryptedSaplingOutput {
                        index: i,
                        value: 0, // Requires successful decryption
                        memo: String::new(),
                        address: None,
                        note_commitment: hex::encode(cmu.to_bytes()),
                        nullifier: None,
                    });
                }
            }

            if let unified::Fvk::Orchard(_orchard_bytes) = item
                && let Some(orchard_bundle) = tx.orchard_bundle()
            {
                console_log(&format!(
                    "Attempting to decrypt {} Orchard actions",
                    orchard_bundle.actions().len()
                ));

                for (i, action) in orchard_bundle.actions().iter().enumerate() {
                    let cmx = action.cmx();
                    decrypted.orchard_actions.push(DecryptedOrchardAction {
                        index: i,
                        value: 0, // Requires successful decryption
                        memo: String::new(),
                        address: None,
                        note_commitment: hex::encode(cmx.to_bytes()),
                        nullifier: Some(hex::encode(action.nullifier().to_bytes())),
                    });
                }
            }
        }
    }

    // If no UFVK decryption happened, still extract basic info from bundles
    if decrypted.sapling_outputs.is_empty()
        && let Some(sapling_bundle) = tx.sapling_bundle()
    {
        for (i, output) in sapling_bundle.shielded_outputs().iter().enumerate() {
            let cmu = output.cmu();
            decrypted.sapling_outputs.push(DecryptedSaplingOutput {
                index: i,
                value: 0,
                memo: "(encrypted)".to_string(),
                address: None,
                note_commitment: hex::encode(cmu.to_bytes()),
                nullifier: None,
            });
        }
    }

    if decrypted.orchard_actions.is_empty()
        && let Some(orchard_bundle) = tx.orchard_bundle()
    {
        for (i, action) in orchard_bundle.actions().iter().enumerate() {
            let cmx = action.cmx();
            decrypted.orchard_actions.push(DecryptedOrchardAction {
                index: i,
                value: 0,
                memo: "(encrypted)".to_string(),
                address: None,
                note_commitment: hex::encode(cmx.to_bytes()),
                nullifier: Some(hex::encode(action.nullifier().to_bytes())),
            });
        }
    }

    DecryptionResult {
        success: true,
        transaction: Some(decrypted),
        error: None,
    }
}

/// Get version information
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Generate a new testnet wallet with a random seed phrase
#[wasm_bindgen]
pub fn generate_wallet() -> String {
    console_log("Generating new wallet...");

    // Generate random entropy for 24-word mnemonic (256 bits = 32 bytes)
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap_or_else(|_| {
        // Fallback to rand if getrandom fails
        rand::thread_rng().fill_bytes(&mut entropy);
    });

    let result = match zcash_wallet_core::generate_wallet(&entropy) {
        Ok(wallet) => {
            console_log(&format!(
                "Wallet generated: {}",
                &wallet.unified_address[..20]
            ));
            WalletData {
                success: true,
                seed_phrase: Some(wallet.seed_phrase),
                network: wallet.network,
                unified_address: Some(wallet.unified_address),
                transparent_address: wallet.transparent_address,
                sapling_address: wallet.sapling_address,
                unified_full_viewing_key: Some(wallet.unified_full_viewing_key),
                error: None,
            }
        }
        Err(e) => WalletData {
            success: false,
            seed_phrase: None,
            network: String::new(),
            unified_address: None,
            transparent_address: None,
            sapling_address: None,
            unified_full_viewing_key: None,
            error: Some(e.to_string()),
        },
    };

    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&WalletData {
            success: false,
            seed_phrase: None,
            network: String::new(),
            unified_address: None,
            transparent_address: None,
            sapling_address: None,
            unified_full_viewing_key: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

/// Restore a wallet from an existing seed phrase
#[wasm_bindgen]
pub fn restore_wallet(seed_phrase: &str) -> String {
    console_log("Restoring wallet from seed phrase...");

    let result = match zcash_wallet_core::restore_wallet(seed_phrase) {
        Ok(wallet) => {
            console_log(&format!(
                "Wallet restored: {}",
                &wallet.unified_address[..20]
            ));
            WalletData {
                success: true,
                seed_phrase: Some(wallet.seed_phrase),
                network: wallet.network,
                unified_address: Some(wallet.unified_address),
                transparent_address: wallet.transparent_address,
                sapling_address: wallet.sapling_address,
                unified_full_viewing_key: Some(wallet.unified_full_viewing_key),
                error: None,
            }
        }
        Err(e) => WalletData {
            success: false,
            seed_phrase: None,
            network: String::new(),
            unified_address: None,
            transparent_address: None,
            sapling_address: None,
            unified_full_viewing_key: None,
            error: Some(e.to_string()),
        },
    };

    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&WalletData {
            success: false,
            seed_phrase: None,
            network: String::new(),
            unified_address: None,
            transparent_address: None,
            sapling_address: None,
            unified_full_viewing_key: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_viewing_key() {
        let result = parse_viewing_key("invalid_key");
        let info: ViewingKeyInfo = serde_json::from_str(&result).unwrap();
        assert!(!info.valid);
    }
}
