//! Zcash WebAssembly module for transaction viewing and wallet operations.
//!
//! This module provides client-side Zcash functionality compiled to WebAssembly,
//! enabling privacy-preserving operations directly in the browser. All cryptographic
//! operations use the official Zcash Rust libraries.
//!
//! # Features
//!
//! - **Transaction Decryption**: Decrypt shielded transaction outputs using viewing keys
//! - **Viewing Key Parsing**: Validate and parse UFVK, UIVK, and legacy Sapling keys
//! - **Wallet Generation**: Create new wallets with BIP39 seed phrases
//! - **Wallet Restoration**: Restore wallets from existing seed phrases
//!
//! # Security
//!
//! All operations run entirely client-side. Viewing keys and seed phrases never
//! leave the browser. Transaction data is fetched from user-configured RPC endpoints.

use wasm_bindgen::prelude::*;

use html_builder::{Element, html};
use rand::RngCore;
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{Network, NetworkType};

// Re-export types from core library
pub use zcash_wallet_core::{
    DecryptedOrchardAction, DecryptedSaplingOutput, DecryptedTransaction, DecryptionResult,
    LedgerCollection, LedgerEntry, MarkSpentResult, NetworkKind, NoteCollection, Pool, ScanResult,
    ScanTransactionResult, ScannedNote, ScannedTransparentOutput, SpentNullifier, StorageResult,
    StoredNote, StoredWallet, TransparentInput, TransparentOutput, TransparentSpend,
    ViewingKeyInfo, WalletCollection, WalletResult,
};

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
            network: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

fn network_type_to_kind(network: NetworkType) -> NetworkKind {
    match network {
        NetworkType::Main => NetworkKind::Mainnet,
        NetworkType::Test => NetworkKind::Testnet,
        NetworkType::Regtest => NetworkKind::Regtest,
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
            network: Some(network_type_to_kind(network)),
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
            network: Some(network_type_to_kind(network)),
            error: None,
        };
    }

    // Try parsing as legacy Sapling extended viewing key
    // These start with "zxviews" (mainnet) or "zxviewtestsapling" (testnet)
    if key.starts_with("zxviews") || key.starts_with("zxviewtestsapling") {
        let network = if key.starts_with("zxviews") {
            NetworkKind::Mainnet
        } else {
            NetworkKind::Testnet
        };

        // Basic validation - proper bech32 decoding
        if bech32::decode(key).is_ok() {
            return ViewingKeyInfo {
                valid: true,
                key_type: "Sapling ExtFVK".to_string(),
                has_sapling: true,
                has_orchard: false,
                network: Some(network),
                error: None,
            };
        }
    }

    ViewingKeyInfo {
        valid: false,
        key_type: String::new(),
        has_sapling: false,
        has_orchard: false,
        network: None,
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

    // Parse the transaction - try newest branch IDs first
    let branch_ids = [
        zcash_primitives::consensus::BranchId::Nu6,
        zcash_primitives::consensus::BranchId::Nu5,
    ];
    // Note: For reading transactions, we try multiple branch IDs for backwards compatibility.
    // Nu6_1 uses the same transaction format as Nu6, so reading with Nu6 works for Nu6_1 txs.

    let tx = {
        let mut parsed_tx = None;
        let mut last_error = String::new();

        for branch_id in branch_ids {
            match Transaction::read(&tx_bytes[..], branch_id) {
                Ok(tx) => {
                    parsed_tx = Some(tx);
                    break;
                }
                Err(e) => {
                    last_error = format!("{}", e);
                }
            }
        }

        match parsed_tx {
            Some(tx) => tx,
            None => {
                return DecryptionResult {
                    success: false,
                    transaction: None,
                    error: Some(format!("Failed to parse transaction: {}", last_error)),
                };
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

// ============================================================================
// Transaction Signing
// ============================================================================

/// Result type for transaction signing operations
#[derive(serde::Serialize, serde::Deserialize)]
struct SignTransactionResult {
    success: bool,
    tx_hex: Option<String>,
    txid: Option<String>,
    total_input: Option<u64>,
    total_output: Option<u64>,
    fee: Option<u64>,
    error: Option<String>,
}

/// UTXO input for transaction building (matches core::transaction::Utxo)
#[derive(serde::Serialize, serde::Deserialize)]
struct UtxoInput {
    txid: String,
    vout: u32,
    value: u64,
    address: String,
    script_pubkey: Option<String>,
}

/// Recipient for transaction output (matches core::transaction::Recipient)
#[derive(serde::Serialize, serde::Deserialize)]
struct RecipientOutput {
    address: String,
    amount: u64,
}

/// Sign a transparent transaction.
///
/// Builds and signs a v5 transaction spending transparent UTXOs. The transaction
/// can be broadcast via any Zcash node RPC.
///
/// # Arguments
///
/// * `seed_phrase` - The wallet's 24-word BIP39 seed phrase
/// * `network` - The network ("mainnet" or "testnet")
/// * `account_index` - The account index (BIP32 level 3)
/// * `utxos_json` - JSON array of UTXOs to spend: `[{txid, vout, value, address}]`
/// * `recipients_json` - JSON array of recipients: `[{address, amount}]`
/// * `fee` - Transaction fee in zatoshis
/// * `expiry_height` - Block height after which tx expires (0 for no expiry)
///
/// # Returns
///
/// JSON with `{success, tx_hex, txid, total_input, total_output, fee, error}`
///
/// # Example
///
/// ```javascript
/// const utxos = JSON.stringify([{
///   txid: "abc123...",
///   vout: 0,
///   value: 100000,
///   address: "t1..."
/// }]);
/// const recipients = JSON.stringify([{
///   address: "t1...",
///   amount: 50000
/// }]);
/// const result = JSON.parse(sign_transparent_transaction(
///   seedPhrase, "testnet", 0, utxos, recipients, 1000, 0
/// ));
/// if (result.success) {
///   console.log("Signed tx:", result.tx_hex);
/// }
/// ```
#[wasm_bindgen]
pub fn sign_transparent_transaction(
    seed_phrase: &str,
    network_str: &str,
    account_index: u32,
    utxos_json: &str,
    recipients_json: &str,
    fee: u64,
    expiry_height: u32,
) -> String {
    let result = sign_transparent_transaction_inner(
        seed_phrase,
        network_str,
        account_index,
        utxos_json,
        recipients_json,
        fee,
        expiry_height,
    );
    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&SignTransactionResult {
            success: false,
            tx_hex: None,
            txid: None,
            total_input: None,
            total_output: None,
            fee: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

fn sign_transparent_transaction_inner(
    seed_phrase: &str,
    network_str: &str,
    account_index: u32,
    utxos_json: &str,
    recipients_json: &str,
    fee: u64,
    expiry_height: u32,
) -> SignTransactionResult {
    let network = parse_network(network_str);
    console_log(&format!(
        "Signing transparent transaction for {} (account {})",
        if matches!(network, Network::MainNetwork) {
            "mainnet"
        } else {
            "testnet"
        },
        account_index
    ));

    // Parse UTXOs
    let utxo_inputs: Vec<UtxoInput> = match serde_json::from_str(utxos_json) {
        Ok(u) => u,
        Err(e) => {
            return SignTransactionResult {
                success: false,
                tx_hex: None,
                txid: None,
                total_input: None,
                total_output: None,
                fee: None,
                error: Some(format!("Failed to parse UTXOs: {}", e)),
            };
        }
    };

    if utxo_inputs.is_empty() {
        return SignTransactionResult {
            success: false,
            tx_hex: None,
            txid: None,
            total_input: None,
            total_output: None,
            fee: None,
            error: Some("No UTXOs provided".to_string()),
        };
    }

    // Parse recipients
    let recipient_outputs: Vec<RecipientOutput> = match serde_json::from_str(recipients_json) {
        Ok(r) => r,
        Err(e) => {
            return SignTransactionResult {
                success: false,
                tx_hex: None,
                txid: None,
                total_input: None,
                total_output: None,
                fee: None,
                error: Some(format!("Failed to parse recipients: {}", e)),
            };
        }
    };

    if recipient_outputs.is_empty() {
        return SignTransactionResult {
            success: false,
            tx_hex: None,
            txid: None,
            total_input: None,
            total_output: None,
            fee: None,
            error: Some("No recipients provided".to_string()),
        };
    }

    // Convert to core library types
    let utxos: Vec<zcash_wallet_core::Utxo> = utxo_inputs
        .into_iter()
        .map(|u| zcash_wallet_core::Utxo {
            txid: u.txid,
            vout: u.vout,
            value: u.value,
            address: u.address,
            script_pubkey: u.script_pubkey,
        })
        .collect();

    let recipients: Vec<zcash_wallet_core::Recipient> = recipient_outputs
        .into_iter()
        .map(|r| zcash_wallet_core::Recipient {
            address: r.address,
            amount: r.amount,
        })
        .collect();

    console_log(&format!(
        "Building transaction with {} inputs and {} outputs, fee: {} zatoshis",
        utxos.len(),
        recipients.len(),
        fee
    ));

    // Build and sign the transaction
    match zcash_wallet_core::build_transparent_transaction(
        seed_phrase,
        network,
        account_index,
        utxos,
        recipients,
        fee,
        expiry_height,
    ) {
        Ok(signed) => {
            console_log(&format!(
                "Transaction signed successfully, txid: {}",
                &signed.txid[..16]
            ));
            SignTransactionResult {
                success: true,
                tx_hex: Some(signed.tx_hex),
                txid: Some(signed.txid),
                total_input: Some(signed.total_input),
                total_output: Some(signed.total_output),
                fee: Some(signed.fee),
                error: None,
            }
        }
        Err(e) => {
            console_log(&format!("Transaction signing failed: {:?}", e));
            SignTransactionResult {
                success: false,
                tx_hex: None,
                txid: None,
                total_input: None,
                total_output: None,
                fee: None,
                error: Some(format!("{:?}", e)),
            }
        }
    }
}

/// Get unspent transparent UTXOs from stored notes.
///
/// Filters stored notes to find transparent outputs that haven't been spent
/// and can be used as transaction inputs.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
///
/// # Returns
///
/// JSON array of UTXOs suitable for `sign_transparent_transaction`
#[wasm_bindgen]
pub fn get_transparent_utxos(notes_json: &str, wallet_id: &str) -> String {
    let collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&UtxoOperationResult {
                    success: false,
                    utxos: vec![],
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    // Convert unspent transparent notes to UTXOs, filtered by wallet_id
    let utxos: Vec<UtxoInput> = collection
        .notes
        .iter()
        .filter(|n| {
            n.pool == Pool::Transparent
                && n.spent_txid.is_none()
                && n.value > 0
                && n.wallet_id == wallet_id
        })
        .filter_map(|n| {
            n.address.as_ref().map(|addr| UtxoInput {
                txid: n.txid.clone(),
                vout: n.output_index,
                value: n.value,
                address: addr.clone(),
                script_pubkey: None,
            })
        })
        .collect();

    serde_json::to_string(&UtxoOperationResult {
        success: true,
        utxos,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Parse network string to Network enum
fn parse_network(network_str: &str) -> Network {
    match network_str.to_lowercase().as_str() {
        "mainnet" | "main" => Network::MainNetwork,
        _ => Network::TestNetwork,
    }
}

/// Format a Unix timestamp (seconds) as ISO 8601 string.
/// This is a simple implementation that doesn't require chrono.
fn format_iso8601(timestamp_secs: u64) -> String {
    // Calculate date components from Unix timestamp
    // Days since Unix epoch (1970-01-01)
    let days = timestamp_secs / 86400;
    let remaining_secs = timestamp_secs % 86400;

    let hours = remaining_secs / 3600;
    let minutes = (remaining_secs % 3600) / 60;
    let seconds = remaining_secs % 60;

    // Calculate year, month, day from days since epoch
    // This is a simplified calculation that works for dates from 1970-2099
    let mut year = 1970u64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for days_in_month in days_in_months.iter() {
        if remaining_days < *days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Generate a new wallet with a random seed phrase
#[wasm_bindgen]
pub fn generate_wallet(network_str: &str, account_index: u32, address_index: u32) -> String {
    let network = parse_network(network_str);
    let network_name = if matches!(network, Network::MainNetwork) {
        "mainnet"
    } else {
        "testnet"
    };
    console_log(&format!(
        "Generating new {} wallet (account {}, address {})...",
        network_name, account_index, address_index
    ));

    // Generate random entropy for 24-word mnemonic (256 bits = 32 bytes)
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).unwrap_or_else(|_| {
        // Fallback to rand if getrandom fails
        rand::thread_rng().fill_bytes(&mut entropy);
    });

    let result =
        match zcash_wallet_core::generate_wallet(&entropy, network, account_index, address_index) {
            Ok(wallet) => {
                console_log(&format!(
                    "Wallet generated: {}",
                    &wallet.unified_address[..20]
                ));
                WalletResult {
                    success: true,
                    seed_phrase: Some(wallet.seed_phrase),
                    network: wallet.network,
                    account_index: wallet.account_index,
                    address_index: wallet.address_index,
                    unified_address: Some(wallet.unified_address),
                    transparent_address: wallet.transparent_address,
                    unified_full_viewing_key: Some(wallet.unified_full_viewing_key),
                    error: None,
                }
            }
            Err(e) => WalletResult {
                success: false,
                seed_phrase: None,
                network: NetworkKind::Mainnet, // Default for error case
                account_index: 0,
                address_index: 0,
                unified_address: None,
                transparent_address: None,
                unified_full_viewing_key: None,
                error: Some(e.to_string()),
            },
        };

    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&WalletResult {
            success: false,
            seed_phrase: None,
            network: NetworkKind::Mainnet, // Default for error case
            account_index: 0,
            address_index: 0,
            unified_address: None,
            transparent_address: None,
            unified_full_viewing_key: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

/// Restore a wallet from an existing seed phrase
#[wasm_bindgen]
pub fn restore_wallet(
    seed_phrase: &str,
    network_str: &str,
    account_index: u32,
    address_index: u32,
) -> String {
    let network = parse_network(network_str);
    let network_name = if matches!(network, Network::MainNetwork) {
        "mainnet"
    } else {
        "testnet"
    };
    console_log(&format!(
        "Restoring {} wallet from seed phrase (account {}, address {})...",
        network_name, account_index, address_index
    ));

    let result =
        match zcash_wallet_core::restore_wallet(seed_phrase, network, account_index, address_index)
        {
            Ok(wallet) => {
                console_log(&format!(
                    "Wallet restored: {}",
                    &wallet.unified_address[..20]
                ));
                WalletResult {
                    success: true,
                    seed_phrase: Some(wallet.seed_phrase),
                    network: wallet.network,
                    account_index: wallet.account_index,
                    address_index: wallet.address_index,
                    unified_address: Some(wallet.unified_address),
                    transparent_address: wallet.transparent_address,
                    unified_full_viewing_key: Some(wallet.unified_full_viewing_key),
                    error: None,
                }
            }
            Err(e) => WalletResult {
                success: false,
                seed_phrase: None,
                network: NetworkKind::Mainnet, // Default for error case
                account_index: 0,
                address_index: 0,
                unified_address: None,
                transparent_address: None,
                unified_full_viewing_key: None,
                error: Some(e.to_string()),
            },
        };

    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&WalletResult {
            success: false,
            seed_phrase: None,
            network: NetworkKind::Mainnet, // Default for error case
            account_index: 0,
            address_index: 0,
            unified_address: None,
            transparent_address: None,
            unified_full_viewing_key: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

/// Derive multiple unified addresses from a seed phrase.
///
/// This is useful for scanning transactions and verifying receiving addresses.
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic
/// * `network` - The network ("mainnet" or "testnet")
/// * `account_index` - The account index (BIP32 level 3)
/// * `start_index` - The starting address/diversifier index
/// * `count` - Number of addresses to derive
///
/// # Returns
///
/// JSON string containing an array of unified addresses.
#[wasm_bindgen]
pub fn derive_unified_addresses(
    seed_phrase: &str,
    network_str: &str,
    account_index: u32,
    start_index: u32,
    count: u32,
) -> String {
    let network = parse_network(network_str);
    console_log(&format!(
        "Deriving {} unified addresses for account {} starting at {}...",
        count, account_index, start_index
    ));

    match zcash_wallet_core::derive_unified_addresses(
        seed_phrase,
        network,
        account_index,
        start_index,
        count,
    ) {
        Ok(addresses) => {
            console_log(&format!("Derived {} unified addresses", addresses.len()));
            serde_json::to_string(&addresses).unwrap_or_else(|_| "[]".to_string())
        }
        Err(e) => {
            console_log(&format!("Failed to derive unified addresses: {}", e));
            "[]".to_string()
        }
    }
}

/// Derive multiple transparent addresses from a seed phrase.
///
/// This is useful for scanning transactions - we need to check if transparent
/// outputs belong to any of our derived addresses.
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic
/// * `network` - The network ("mainnet" or "testnet")
/// * `account_index` - The account index (BIP32 level 3)
/// * `start_index` - The starting address index
/// * `count` - Number of addresses to derive
///
/// # Returns
///
/// JSON string containing an array of transparent addresses.
#[wasm_bindgen]
pub fn derive_transparent_addresses(
    seed_phrase: &str,
    network_str: &str,
    account_index: u32,
    start_index: u32,
    count: u32,
) -> String {
    let network = parse_network(network_str);
    console_log(&format!(
        "Deriving {} transparent addresses for account {} starting at {}...",
        count, account_index, start_index
    ));

    match zcash_wallet_core::derive_transparent_addresses(
        seed_phrase,
        network,
        account_index,
        start_index,
        count,
    ) {
        Ok(addresses) => {
            console_log(&format!("Derived {} addresses", addresses.len()));
            serde_json::to_string(&addresses).unwrap_or_else(|_| "[]".to_string())
        }
        Err(e) => {
            console_log(&format!("Failed to derive addresses: {}", e));
            "[]".to_string()
        }
    }
}

/// Scan a transaction for notes belonging to a viewing key.
///
/// Performs trial decryption on all shielded outputs to find notes
/// addressed to the viewing key. Also extracts nullifiers to track
/// spent notes.
///
/// # Arguments
///
/// * `raw_tx_hex` - The raw transaction as a hexadecimal string
/// * `viewing_key` - The viewing key (UFVK, UIVK, or legacy Sapling)
/// * `network` - The network ("mainnet" or "testnet")
/// * `height` - Optional block height (needed for full Sapling decryption)
///
/// # Returns
///
/// JSON string containing a `ScanTransactionResult` with found notes,
/// spent nullifiers, and transparent outputs.
#[wasm_bindgen]
pub fn scan_transaction(
    raw_tx_hex: &str,
    viewing_key: &str,
    network: &str,
    height: Option<u32>,
) -> String {
    let result = scan_transaction_inner(raw_tx_hex, viewing_key, network, height);
    serde_json::to_string(&result).unwrap_or_else(|e| {
        serde_json::to_string(&ScanTransactionResult {
            success: false,
            result: None,
            error: Some(format!("Serialization error: {}", e)),
        })
        .unwrap()
    })
}

fn scan_transaction_inner(
    raw_tx_hex: &str,
    viewing_key: &str,
    network_str: &str,
    height: Option<u32>,
) -> ScanTransactionResult {
    let network = parse_network(network_str);
    console_log(&format!(
        "Scanning transaction with {} viewing key",
        if viewing_key.starts_with("uview") {
            "UFVK"
        } else {
            "unknown"
        }
    ));

    match zcash_wallet_core::scan_transaction_hex(raw_tx_hex, viewing_key, network, height) {
        Ok(result) => {
            console_log(&format!(
                "Scan complete: {} notes found, {} nullifiers",
                result.notes.len(),
                result.spent_nullifiers.len()
            ));
            ScanTransactionResult {
                success: true,
                result: Some(result),
                error: None,
            }
        }
        Err(e) => {
            console_log(&format!("Scan failed: {}", e));
            ScanTransactionResult {
                success: false,
                result: None,
                error: Some(e.to_string()),
            }
        }
    }
}

// ============================================================================
// Note Storage Operations
// ============================================================================

/// Result type for balance calculations
#[derive(serde::Serialize, serde::Deserialize)]
struct BalanceResult {
    success: bool,
    total: u64,
    by_pool: std::collections::HashMap<String, u64>,
    error: Option<String>,
}

/// Result type for note operations that modify the collection
#[derive(serde::Serialize, serde::Deserialize)]
struct NoteOperationResult {
    success: bool,
    notes: Vec<StoredNote>,
    added: Option<bool>,
    marked_count: Option<usize>,
    /// Transparent spends that did not match any tracked notes.
    /// Present when scanning transactions out of order.
    #[serde(skip_serializing_if = "Option::is_none")]
    unmatched_transparent: Option<Vec<TransparentSpend>>,
    /// Shielded nullifiers that did not match any tracked notes.
    /// Present when scanning transactions out of order.
    #[serde(skip_serializing_if = "Option::is_none")]
    unmatched_nullifiers: Option<Vec<SpentNullifier>>,
    /// Whether any spends were unmatched (convenience field).
    #[serde(skip_serializing_if = "Option::is_none")]
    has_unmatched: Option<bool>,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct UtxoOperationResult {
    success: bool,
    utxos: Vec<UtxoInput>,
    error: Option<String>,
}

/// Create a new stored note from individual parameters.
///
/// This is useful when converting scan results to stored notes.
///
/// # Arguments
///
/// * `wallet_id` - The wallet ID this note belongs to
/// * `txid` - Transaction ID where the note was received
/// * `pool` - Pool type ("orchard", "sapling", or "transparent")
/// * `output_index` - Output index within the transaction
/// * `value` - Value in zatoshis
/// * `commitment` - Note commitment (optional, for shielded notes)
/// * `nullifier` - Nullifier (optional, for shielded notes)
/// * `memo` - Memo field (optional)
/// * `address` - Recipient address (optional)
/// * `created_at` - ISO 8601 timestamp
///
/// # Returns
///
/// JSON string containing the StoredNote or an error.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_stored_note(
    wallet_id: &str,
    txid: &str,
    pool: &str,
    output_index: u32,
    value: u64,
    commitment: Option<String>,
    nullifier: Option<String>,
    memo: Option<String>,
    address: Option<String>,
    created_at: &str,
) -> String {
    let pool_enum = match pool.to_lowercase().as_str() {
        "orchard" => Pool::Orchard,
        "sapling" => Pool::Sapling,
        "transparent" => Pool::Transparent,
        _ => {
            return serde_json::to_string(&StorageResult::<StoredNote>::err(format!(
                "Invalid pool: {}",
                pool
            )))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let id = StoredNote::generate_id(txid, pool_enum, output_index);

    let note = StoredNote {
        id,
        wallet_id: wallet_id.to_string(),
        txid: txid.to_string(),
        output_index,
        pool: pool_enum,
        value,
        commitment,
        nullifier,
        memo,
        address,
        spent_txid: None,
        spent_at_height: None,
        created_at: created_at.to_string(),
    };

    serde_json::to_string(&StorageResult::ok(note))
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Add or update a note in the notes list.
///
/// If a note with the same ID already exists, it will be updated.
/// Otherwise, the note will be added.
///
/// # Arguments
///
/// * `notes_json` - JSON array of existing StoredNotes
/// * `note_json` - JSON of the StoredNote to add/update
///
/// # Returns
///
/// JSON containing the updated notes array and whether a new note was added.
#[wasm_bindgen]
pub fn add_note_to_list(notes_json: &str, note_json: &str) -> String {
    let mut collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => {
            // Try parsing as a plain array
            match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
                Ok(notes) => NoteCollection { notes },
                Err(e) => {
                    return serde_json::to_string(&NoteOperationResult {
                        success: false,
                        notes: vec![],
                        added: None,
                        marked_count: None,
                        unmatched_transparent: None,
                        unmatched_nullifiers: None,
                        has_unmatched: None,
                        error: Some(format!("Failed to parse notes: {}", e)),
                    })
                    .unwrap_or_else(|_| {
                        r#"{"success":false,"error":"Serialization error"}"#.to_string()
                    });
                }
            }
        }
    };

    let note: StoredNote = match serde_json::from_str(note_json) {
        Ok(n) => n,
        Err(e) => {
            return serde_json::to_string(&NoteOperationResult {
                success: false,
                notes: collection.notes,
                added: None,
                marked_count: None,
                unmatched_transparent: None,
                unmatched_nullifiers: None,
                has_unmatched: None,
                error: Some(format!("Failed to parse note: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let was_added = collection.add_or_update(note);

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: collection.notes,
        added: Some(was_added),
        marked_count: None,
        unmatched_transparent: None,
        unmatched_nullifiers: None,
        has_unmatched: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Mark notes as spent by matching nullifiers.
///
/// Finds notes with matching nullifiers and sets their spent_txid.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
/// * `nullifiers_json` - JSON array of SpentNullifier objects
/// * `spending_txid` - Transaction ID where the notes were spent
/// * `spent_at_height` - Optional block height where the spend occurred
///
/// # Returns
///
/// JSON containing the updated notes array and count of marked notes.
#[wasm_bindgen]
pub fn mark_notes_spent(
    notes_json: &str,
    nullifiers_json: &str,
    spending_txid: &str,
    spent_at_height: Option<u32>,
) -> String {
    let mut collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&NoteOperationResult {
                    success: false,
                    notes: vec![],
                    added: None,
                    marked_count: None,
                    unmatched_transparent: None,
                    unmatched_nullifiers: None,
                    has_unmatched: None,
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let nullifiers: Vec<SpentNullifier> = match serde_json::from_str(nullifiers_json) {
        Ok(n) => n,
        Err(e) => {
            return serde_json::to_string(&NoteOperationResult {
                success: false,
                notes: collection.notes,
                added: None,
                marked_count: None,
                unmatched_transparent: None,
                unmatched_nullifiers: None,
                has_unmatched: None,
                error: Some(format!("Failed to parse nullifiers: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let result = collection.mark_spent_by_nullifiers(&nullifiers, spending_txid, spent_at_height);

    // Check for unmatched before extracting vectors
    let has_unmatched = result.has_unmatched();
    let unmatched_nullifiers = if result.unmatched_nullifiers.is_empty() {
        None
    } else {
        Some(result.unmatched_nullifiers)
    };

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: collection.notes,
        added: None,
        marked_count: Some(result.marked_count),
        unmatched_transparent: None,
        unmatched_nullifiers,
        has_unmatched: if has_unmatched { Some(true) } else { None },
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Mark transparent notes as spent by matching prevout references.
///
/// Finds transparent notes matching txid:output_index and sets their spent_txid.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
/// * `spends_json` - JSON array of TransparentSpend objects
/// * `spending_txid` - Transaction ID where the notes were spent
/// * `spent_at_height` - Optional block height where the spend occurred
///
/// # Returns
///
/// JSON containing the updated notes array and count of marked notes.
#[wasm_bindgen]
pub fn mark_transparent_spent(
    notes_json: &str,
    spends_json: &str,
    spending_txid: &str,
    spent_at_height: Option<u32>,
) -> String {
    let mut collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&NoteOperationResult {
                    success: false,
                    notes: vec![],
                    added: None,
                    marked_count: None,
                    unmatched_transparent: None,
                    unmatched_nullifiers: None,
                    has_unmatched: None,
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let spends: Vec<TransparentSpend> = match serde_json::from_str(spends_json) {
        Ok(s) => s,
        Err(e) => {
            return serde_json::to_string(&NoteOperationResult {
                success: false,
                notes: collection.notes,
                added: None,
                marked_count: None,
                unmatched_transparent: None,
                unmatched_nullifiers: None,
                has_unmatched: None,
                error: Some(format!("Failed to parse spends: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let result = collection.mark_spent_by_transparent(&spends, spending_txid, spent_at_height);

    // Check for unmatched before extracting vectors
    let has_unmatched = result.has_unmatched();
    let unmatched_transparent = if result.unmatched_transparent.is_empty() {
        None
    } else {
        Some(result.unmatched_transparent)
    };

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: collection.notes,
        added: None,
        marked_count: Some(result.marked_count),
        unmatched_transparent,
        unmatched_nullifiers: None,
        has_unmatched: if has_unmatched { Some(true) } else { None },
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Calculate the balance from a list of notes.
///
/// Returns the total balance and balance broken down by pool.
/// Only counts unspent notes with positive value.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
///
/// # Returns
///
/// JSON containing total balance and balance by pool.
#[wasm_bindgen]
pub fn calculate_balance(notes_json: &str) -> String {
    let collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&BalanceResult {
                    success: false,
                    total: 0,
                    by_pool: std::collections::HashMap::new(),
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let total = collection.total_balance();
    let by_pool_enum = collection.balance_by_pool();

    // Convert Pool keys to strings for JSON
    let by_pool: std::collections::HashMap<String, u64> = by_pool_enum
        .into_iter()
        .map(|(k, v)| (k.as_str().to_string(), v))
        .collect();

    serde_json::to_string(&BalanceResult {
        success: true,
        total,
        by_pool,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Get all unspent notes with positive value.
///
/// Filters the notes list to only include notes that haven't been spent
/// and have a value greater than zero.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
///
/// # Returns
///
/// JSON array of unspent StoredNotes.
#[wasm_bindgen]
pub fn get_unspent_notes(notes_json: &str) -> String {
    let collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&NoteOperationResult {
                    success: false,
                    notes: vec![],
                    added: None,
                    marked_count: None,
                    unmatched_transparent: None,
                    unmatched_nullifiers: None,
                    has_unmatched: None,
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let unspent: Vec<StoredNote> = collection.unspent_notes().into_iter().cloned().collect();

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: unspent,
        added: None,
        marked_count: None,
        unmatched_transparent: None,
        unmatched_nullifiers: None,
        has_unmatched: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Get notes for a specific wallet.
///
/// Filters the notes list to only include notes belonging to the specified wallet.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNotes
/// * `wallet_id` - The wallet ID to filter by
///
/// # Returns
///
/// JSON array of StoredNotes belonging to the wallet.
#[wasm_bindgen]
pub fn get_notes_for_wallet(notes_json: &str, wallet_id: &str) -> String {
    let collection: NoteCollection = match serde_json::from_str(notes_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredNote>>(notes_json) {
            Ok(notes) => NoteCollection { notes },
            Err(e) => {
                return serde_json::to_string(&NoteOperationResult {
                    success: false,
                    notes: vec![],
                    added: None,
                    marked_count: None,
                    unmatched_transparent: None,
                    unmatched_nullifiers: None,
                    has_unmatched: None,
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let wallet_notes: Vec<StoredNote> = collection
        .notes_for_wallet(wallet_id)
        .into_iter()
        .cloned()
        .collect();

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: wallet_notes,
        added: None,
        marked_count: None,
        unmatched_transparent: None,
        unmatched_nullifiers: None,
        has_unmatched: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

// ============================================================================
// Wallet Storage Operations
// ============================================================================

/// Result type for wallet operations that modify the collection
#[derive(serde::Serialize, serde::Deserialize)]
struct WalletOperationResult {
    success: bool,
    wallets: Vec<StoredWallet>,
    wallet: Option<StoredWallet>,
    error: Option<String>,
}

/// Create a new stored wallet from a WalletResult.
///
/// Generates a unique ID and timestamp, and creates a StoredWallet
/// ready for persistence.
///
/// # Arguments
///
/// * `wallet_result_json` - JSON of WalletResult from generate/restore
/// * `alias` - User-friendly name for the wallet
/// * `timestamp_ms` - Current timestamp in milliseconds (from JavaScript Date.now())
///
/// # Returns
///
/// JSON string containing the StoredWallet or an error.
#[wasm_bindgen]
pub fn create_stored_wallet(wallet_result_json: &str, alias: &str, timestamp_ms: u64) -> String {
    let wallet_result: WalletResult = match serde_json::from_str(wallet_result_json) {
        Ok(w) => w,
        Err(e) => {
            return serde_json::to_string(&StorageResult::<StoredWallet>::err(format!(
                "Failed to parse wallet result: {}",
                e
            )))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    if !wallet_result.success {
        return serde_json::to_string(&StorageResult::<StoredWallet>::err(
            wallet_result
                .error
                .unwrap_or_else(|| "Wallet generation failed".to_string()),
        ))
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
    }

    // Validate required fields
    let seed_phrase = match &wallet_result.seed_phrase {
        Some(s) => s.clone(),
        None => {
            return serde_json::to_string(&StorageResult::<StoredWallet>::err(
                "Missing seed phrase",
            ))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let unified_address = match &wallet_result.unified_address {
        Some(a) => a.clone(),
        None => {
            return serde_json::to_string(&StorageResult::<StoredWallet>::err(
                "Missing unified address",
            ))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let transparent_address = match &wallet_result.transparent_address {
        Some(a) => a.clone(),
        None => {
            return serde_json::to_string(&StorageResult::<StoredWallet>::err(
                "Missing transparent address",
            ))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let ufvk = match &wallet_result.unified_full_viewing_key {
        Some(k) => k.clone(),
        None => {
            return serde_json::to_string(&StorageResult::<StoredWallet>::err(
                "Missing viewing key",
            ))
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    // Generate ID and timestamp
    let id = format!("wallet_{}", timestamp_ms);

    // Convert timestamp to ISO 8601
    // JavaScript should pass the ISO timestamp directly, but we'll create a simple one from ms
    let secs = timestamp_ms / 1000;
    let created_at = format_iso8601(secs);

    let wallet = StoredWallet {
        id,
        alias: alias.to_string(),
        network: wallet_result.network,
        seed_phrase,
        account_index: wallet_result.account_index,
        unified_address,
        transparent_address,
        unified_full_viewing_key: ufvk,
        created_at,
    };

    serde_json::to_string(&StorageResult::ok(wallet))
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Add a wallet to the wallets list.
///
/// Checks for duplicate aliases (case-insensitive) before adding.
///
/// # Arguments
///
/// * `wallets_json` - JSON array of existing StoredWallets
/// * `wallet_json` - JSON of the StoredWallet to add
///
/// # Returns
///
/// JSON containing the updated wallets array or an error if alias exists.
#[wasm_bindgen]
pub fn add_wallet_to_list(wallets_json: &str, wallet_json: &str) -> String {
    let mut collection: WalletCollection = match serde_json::from_str(wallets_json) {
        Ok(c) => c,
        Err(_) => {
            // Try parsing as a plain array
            match serde_json::from_str::<Vec<StoredWallet>>(wallets_json) {
                Ok(wallets) => WalletCollection { wallets },
                Err(e) => {
                    return serde_json::to_string(&WalletOperationResult {
                        success: false,
                        wallets: vec![],
                        wallet: None,
                        error: Some(format!("Failed to parse wallets: {}", e)),
                    })
                    .unwrap_or_else(|_| {
                        r#"{"success":false,"error":"Serialization error"}"#.to_string()
                    });
                }
            }
        }
    };

    let wallet: StoredWallet = match serde_json::from_str(wallet_json) {
        Ok(w) => w,
        Err(e) => {
            return serde_json::to_string(&WalletOperationResult {
                success: false,
                wallets: collection.wallets,
                wallet: None,
                error: Some(format!("Failed to parse wallet: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    // Check for duplicate alias
    if let Err(e) = collection.add(wallet.clone()) {
        return serde_json::to_string(&WalletOperationResult {
            success: false,
            wallets: collection.wallets,
            wallet: None,
            error: Some(e),
        })
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
    }

    serde_json::to_string(&WalletOperationResult {
        success: true,
        wallets: collection.wallets,
        wallet: Some(wallet),
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Check if a wallet alias already exists (case-insensitive).
///
/// # Arguments
///
/// * `wallets_json` - JSON array of StoredWallets
/// * `alias` - The alias to check
///
/// # Returns
///
/// `true` if the alias exists, `false` otherwise.
#[wasm_bindgen]
pub fn wallet_alias_exists(wallets_json: &str, alias: &str) -> bool {
    let collection: WalletCollection = match serde_json::from_str(wallets_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredWallet>>(wallets_json) {
            Ok(wallets) => WalletCollection { wallets },
            Err(_) => return false,
        },
    };

    collection.alias_exists(alias)
}

/// Delete a wallet from the wallets list by ID.
///
/// # Arguments
///
/// * `wallets_json` - JSON array of StoredWallets
/// * `wallet_id` - The ID of the wallet to delete
///
/// # Returns
///
/// JSON containing the updated wallets array.
#[wasm_bindgen]
pub fn delete_wallet_from_list(wallets_json: &str, wallet_id: &str) -> String {
    let mut collection: WalletCollection = match serde_json::from_str(wallets_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredWallet>>(wallets_json) {
            Ok(wallets) => WalletCollection { wallets },
            Err(e) => {
                return serde_json::to_string(&WalletOperationResult {
                    success: false,
                    wallets: vec![],
                    wallet: None,
                    error: Some(format!("Failed to parse wallets: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let deleted = collection.delete(wallet_id);

    serde_json::to_string(&WalletOperationResult {
        success: deleted,
        wallets: collection.wallets,
        wallet: None,
        error: if deleted {
            None
        } else {
            Some(format!("Wallet not found: {}", wallet_id))
        },
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Get a wallet by ID.
///
/// # Arguments
///
/// * `wallets_json` - JSON array of StoredWallets
/// * `wallet_id` - The ID of the wallet to find
///
/// # Returns
///
/// JSON containing the wallet if found, or an error.
#[wasm_bindgen]
pub fn get_wallet_by_id(wallets_json: &str, wallet_id: &str) -> String {
    let collection: WalletCollection = match serde_json::from_str(wallets_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredWallet>>(wallets_json) {
            Ok(wallets) => WalletCollection { wallets },
            Err(e) => {
                return serde_json::to_string(&WalletOperationResult {
                    success: false,
                    wallets: vec![],
                    wallet: None,
                    error: Some(format!("Failed to parse wallets: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    match collection.get_by_id(wallet_id) {
        Some(wallet) => serde_json::to_string(&WalletOperationResult {
            success: true,
            wallets: vec![],
            wallet: Some(wallet.clone()),
            error: None,
        })
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string()),
        None => serde_json::to_string(&WalletOperationResult {
            success: false,
            wallets: vec![],
            wallet: None,
            error: Some(format!("Wallet not found: {}", wallet_id)),
        })
        .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string()),
    }
}

/// Get all wallets from the collection.
///
/// Useful for listing wallets in the UI.
///
/// # Arguments
///
/// * `wallets_json` - JSON array of StoredWallets
///
/// # Returns
///
/// JSON containing the wallets array.
#[wasm_bindgen]
pub fn get_all_wallets(wallets_json: &str) -> String {
    let collection: WalletCollection = match serde_json::from_str(wallets_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<StoredWallet>>(wallets_json) {
            Ok(wallets) => WalletCollection { wallets },
            Err(e) => {
                return serde_json::to_string(&WalletOperationResult {
                    success: false,
                    wallets: vec![],
                    wallet: None,
                    error: Some(format!("Failed to parse wallets: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    serde_json::to_string(&WalletOperationResult {
        success: true,
        wallets: collection.wallets,
        wallet: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

// ============================================================================
// Input Validation Functions
// ============================================================================

/// Result type for validation operations
#[derive(serde::Serialize, serde::Deserialize)]
struct ValidationResult {
    valid: bool,
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    word_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<u32>,
}

impl ValidationResult {
    fn ok() -> Self {
        ValidationResult {
            valid: true,
            error: None,
            address_type: None,
            word_count: None,
            count: None,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        ValidationResult {
            valid: false,
            error: Some(message.into()),
            address_type: None,
            word_count: None,
            count: None,
        }
    }
}

/// Validate a transaction ID (txid).
///
/// A valid txid is a 64-character hexadecimal string.
///
/// # Arguments
///
/// * `txid` - The transaction ID to validate
///
/// # Returns
///
/// JSON with `{valid: bool, error?: string}`
#[wasm_bindgen]
pub fn validate_txid(txid: &str) -> String {
    let txid = txid.trim();

    if txid.is_empty() {
        return serde_json::to_string(&ValidationResult::err("Transaction ID is required"))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    if txid.len() != 64 {
        return serde_json::to_string(&ValidationResult::err(format!(
            "Transaction ID must be 64 characters, got {}",
            txid.len()
        )))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    // Check if all characters are valid hex
    if !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return serde_json::to_string(&ValidationResult::err(
            "Transaction ID must contain only hexadecimal characters (0-9, a-f, A-F)",
        ))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    serde_json::to_string(&ValidationResult::ok())
        .unwrap_or_else(|_| r#"{"valid":true}"#.to_string())
}

/// Validate a Zcash address.
///
/// Supports transparent (t-addr), Sapling (zs), and unified addresses (u).
///
/// # Arguments
///
/// * `address` - The address to validate
/// * `network` - The network ("mainnet" or "testnet")
///
/// # Returns
///
/// JSON with `{valid: bool, address_type?: string, error?: string}`
#[wasm_bindgen]
pub fn validate_address(address: &str, network: &str) -> String {
    let address = address.trim();

    if address.is_empty() {
        return serde_json::to_string(&ValidationResult::err("Address is required"))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    let is_mainnet = matches!(network.to_lowercase().as_str(), "mainnet" | "main");

    // Check for unified address
    if address.starts_with("u1") || address.starts_with("utest1") {
        let expected_prefix = if is_mainnet { "u1" } else { "utest1" };
        if (is_mainnet && !address.starts_with("u1"))
            || (!is_mainnet && !address.starts_with("utest1"))
        {
            return serde_json::to_string(&ValidationResult::err(format!(
                "Unified address should start with '{}' for {}",
                expected_prefix,
                if is_mainnet { "mainnet" } else { "testnet" }
            )))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }

        // Try to decode the unified address
        if zcash_address::unified::Address::decode(address).is_ok() {
            let mut result = ValidationResult::ok();
            result.address_type = Some("unified".to_string());
            return serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"valid":true,"address_type":"unified"}"#.to_string());
        }
        return serde_json::to_string(&ValidationResult::err("Invalid unified address encoding"))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    // Check for Sapling address
    if address.starts_with("zs") || address.starts_with("ztestsapling") {
        let expected_prefix = if is_mainnet { "zs" } else { "ztestsapling" };
        if (is_mainnet && !address.starts_with("zs"))
            || (!is_mainnet && !address.starts_with("ztestsapling"))
        {
            return serde_json::to_string(&ValidationResult::err(format!(
                "Sapling address should start with '{}' for {}",
                expected_prefix,
                if is_mainnet { "mainnet" } else { "testnet" }
            )))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }

        // Basic bech32 validation
        if bech32::decode(address).is_ok() {
            let mut result = ValidationResult::ok();
            result.address_type = Some("sapling".to_string());
            return serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"valid":true,"address_type":"sapling"}"#.to_string());
        } else {
            return serde_json::to_string(&ValidationResult::err(
                "Invalid Sapling address encoding",
            ))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }
    }

    // Check for transparent address
    if address.starts_with('t') {
        let expected_prefix = if is_mainnet { "t1" } else { "tm" };
        if (is_mainnet && !address.starts_with("t1")) || (!is_mainnet && !address.starts_with("tm"))
        {
            return serde_json::to_string(&ValidationResult::err(format!(
                "Transparent address should start with '{}' for {}",
                expected_prefix,
                if is_mainnet { "mainnet" } else { "testnet" }
            )))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }

        // Basic base58check validation (length check)
        if address.len() >= 26 && address.len() <= 35 {
            let mut result = ValidationResult::ok();
            result.address_type = Some("transparent".to_string());
            return serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"valid":true,"address_type":"transparent"}"#.to_string());
        } else {
            return serde_json::to_string(&ValidationResult::err(
                "Invalid transparent address length",
            ))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }
    }

    serde_json::to_string(&ValidationResult::err(
        "Unrecognized address format. Expected unified (u1/utest1), Sapling (zs/ztestsapling), or transparent (t1/tm) address",
    ))
    .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string())
}

/// Validate a BIP39 seed phrase.
///
/// Checks word count and basic format. Valid phrases have 12, 15, 18, 21, or 24 words.
///
/// # Arguments
///
/// * `seed_phrase` - The seed phrase to validate
///
/// # Returns
///
/// JSON with `{valid: bool, word_count?: u8, error?: string}`
#[wasm_bindgen]
pub fn validate_seed_phrase(seed_phrase: &str) -> String {
    let seed_phrase = seed_phrase.trim();

    if seed_phrase.is_empty() {
        return serde_json::to_string(&ValidationResult::err("Seed phrase is required"))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    let words: Vec<&str> = seed_phrase.split_whitespace().collect();
    let word_count = words.len();

    // Valid BIP39 word counts
    let valid_counts = [12, 15, 18, 21, 24];
    if !valid_counts.contains(&word_count) {
        return serde_json::to_string(&ValidationResult::err(format!(
            "Seed phrase must have 12, 15, 18, 21, or 24 words, got {}",
            word_count
        )))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    // Check that all words are lowercase alphabetic
    for word in &words {
        if !word.chars().all(|c| c.is_ascii_lowercase()) {
            return serde_json::to_string(&ValidationResult::err(
                "Seed phrase words must contain only lowercase letters",
            ))
            .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
        }
    }

    // Basic validation passed (format and word count)
    // Note: Full BIP39 wordlist validation happens during wallet creation
    // to minimize dependencies in the WASM module
    let mut result = ValidationResult::ok();
    result.word_count = Some(word_count as u8);
    serde_json::to_string(&result)
        .unwrap_or_else(|_| format!(r#"{{"valid":true,"word_count":{}}}"#, word_count))
}

/// Validate an address derivation range.
///
/// Checks that from <= to and the count doesn't exceed the maximum.
///
/// # Arguments
///
/// * `from_index` - Starting index
/// * `to_index` - Ending index (inclusive)
/// * `max_count` - Maximum allowed count
///
/// # Returns
///
/// JSON with `{valid: bool, count?: u32, error?: string}`
#[wasm_bindgen]
pub fn validate_address_range(from_index: u32, to_index: u32, max_count: u32) -> String {
    if from_index > to_index {
        return serde_json::to_string(&ValidationResult::err(
            "From index must be less than or equal to To index",
        ))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    let count = to_index - from_index + 1;

    if count > max_count {
        return serde_json::to_string(&ValidationResult::err(format!(
            "Range too large: {} addresses requested, maximum is {}",
            count, max_count
        )))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    let mut result = ValidationResult::ok();
    result.count = Some(count);
    serde_json::to_string(&result)
        .unwrap_or_else(|_| format!(r#"{{"valid":true,"count":{}}}"#, count))
}

/// Validate an account index.
///
/// Account indices must be less than 2^31 (hardened derivation limit).
///
/// # Arguments
///
/// * `index` - The account index to validate
///
/// # Returns
///
/// JSON with `{valid: bool, error?: string}`
#[wasm_bindgen]
pub fn validate_account_index(index: u32) -> String {
    // BIP32 hardened derivation uses indices >= 2^31
    // Account indices should be < 2^31
    const MAX_ACCOUNT_INDEX: u32 = 0x7FFFFFFF;

    if index > MAX_ACCOUNT_INDEX {
        return serde_json::to_string(&ValidationResult::err(format!(
            "Account index must be less than {}, got {}",
            MAX_ACCOUNT_INDEX, index
        )))
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization error"}"#.to_string());
    }

    serde_json::to_string(&ValidationResult::ok())
        .unwrap_or_else(|_| r#"{"valid":true}"#.to_string())
}

// ============================================================================
// Ledger Operations
// ============================================================================

/// Result type for ledger operations
#[derive(serde::Serialize, serde::Deserialize)]
struct LedgerOperationResult {
    success: bool,
    entries: Vec<LedgerEntry>,
    entry: Option<LedgerEntry>,
    ledger: Option<LedgerCollection>,
    is_new: Option<bool>,
    balance: Option<i64>,
    csv: Option<String>,
    error: Option<String>,
}

/// Create a ledger entry from a scan result.
///
/// Takes the scan result, wallet ID, and information about which notes were
/// received and spent, and creates a LedgerEntry for the transaction.
///
/// # Arguments
///
/// * `scan_result_json` - JSON of ScanResult from scanning a transaction
/// * `wallet_id` - The wallet ID this entry belongs to
/// * `received_note_ids_json` - JSON array of note IDs that were received
/// * `spent_note_ids_json` - JSON array of note IDs that were spent
/// * `spent_values_json` - JSON array of values (u64) for spent notes
/// * `timestamp` - ISO 8601 timestamp for created_at/updated_at
///
/// # Returns
///
/// JSON containing the created LedgerEntry or an error.
#[wasm_bindgen]
pub fn create_ledger_entry(scan_result_json: &str, wallet_id: &str) -> String {
    let scan_result: ScanResult = match serde_json::from_str(scan_result_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&LedgerOperationResult {
                success: false,
                entries: vec![],
                entry: None,
                ledger: None,
                is_new: None,
                balance: None,
                csv: None,
                error: Some(format!("Failed to parse scan result: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    // Generate note IDs from scan result
    let received_note_ids: Vec<String> = scan_result
        .notes
        .iter()
        .enumerate()
        .map(|(i, _)| format!("{}:{}:{}", scan_result.txid, wallet_id, i))
        .collect();

    // Spent note IDs from nullifiers
    let spent_note_ids: Vec<String> = scan_result
        .spent_nullifiers
        .iter()
        .map(|n| n.nullifier.clone())
        .collect();

    // We don't know spent values from scan result, so we pass empty
    let spent_values: Vec<u64> = vec![];

    // Get current timestamp using js_sys::Date
    let date = js_sys::Date::new_0();
    let timestamp = date.to_iso_string().as_string().unwrap_or_default();

    let entry = LedgerEntry::from_scan_result(
        &scan_result,
        wallet_id,
        received_note_ids,
        spent_note_ids,
        &spent_values,
        &timestamp,
    );

    serde_json::to_string(&LedgerOperationResult {
        success: true,
        entries: vec![],
        entry: Some(entry),
        ledger: None,
        is_new: None,
        balance: None,
        csv: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Add or update a ledger entry in a collection.
///
/// If an entry with the same wallet_id and txid exists, it will be updated.
/// Otherwise, a new entry will be added.
///
/// # Arguments
///
/// * `ledger_json` - JSON of the ledger collection (array of entries)
/// * `entry_json` - JSON of the LedgerEntry to add
///
/// # Returns
///
/// JSON containing the updated ledger and whether the entry was new.
#[wasm_bindgen]
pub fn add_ledger_entry(ledger_json: &str, entry_json: &str) -> String {
    let mut collection: LedgerCollection = match serde_json::from_str(ledger_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<LedgerEntry>>(ledger_json) {
            Ok(entries) => LedgerCollection { entries },
            Err(e) => {
                return serde_json::to_string(&LedgerOperationResult {
                    success: false,
                    entries: vec![],
                    entry: None,
                    ledger: None,
                    is_new: None,
                    balance: None,
                    csv: None,
                    error: Some(format!("Failed to parse ledger: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let entry: LedgerEntry = match serde_json::from_str(entry_json) {
        Ok(e) => e,
        Err(e) => {
            return serde_json::to_string(&LedgerOperationResult {
                success: false,
                entries: collection.entries.clone(),
                entry: None,
                ledger: Some(collection),
                is_new: None,
                balance: None,
                csv: None,
                error: Some(format!("Failed to parse ledger entry: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let is_new = collection.add_or_update(entry);

    serde_json::to_string(&LedgerOperationResult {
        success: true,
        entries: collection.entries.clone(),
        entry: None,
        ledger: Some(collection),
        is_new: Some(is_new),
        balance: None,
        csv: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Get ledger entries for a specific wallet.
///
/// Returns entries sorted by block_height descending (newest first).
///
/// # Arguments
///
/// * `ledger_json` - JSON of the ledger collection
/// * `wallet_id` - The wallet ID to filter by
///
/// # Returns
///
/// JSON containing the filtered entries.
#[wasm_bindgen]
pub fn get_ledger_for_wallet(ledger_json: &str, wallet_id: &str) -> String {
    let collection: LedgerCollection = match serde_json::from_str(ledger_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<LedgerEntry>>(ledger_json) {
            Ok(entries) => LedgerCollection { entries },
            Err(e) => {
                return serde_json::to_string(&LedgerOperationResult {
                    success: false,
                    entries: vec![],
                    entry: None,
                    ledger: None,
                    is_new: None,
                    balance: None,
                    csv: None,
                    error: Some(format!("Failed to parse ledger: {}", e)),
                })
                .unwrap_or_else(|_| {
                    r#"{"success":false,"error":"Serialization error"}"#.to_string()
                });
            }
        },
    };

    let wallet_entries: Vec<LedgerEntry> = collection
        .entries_for_wallet(wallet_id)
        .into_iter()
        .cloned()
        .collect();

    serde_json::to_string(&LedgerOperationResult {
        success: true,
        entries: wallet_entries,
        entry: None,
        ledger: None,
        is_new: None,
        balance: None,
        csv: None,
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string())
}

/// Compute balance from ledger entries.
///
/// Sums the net_change of all entries for the wallet.
///
/// # Arguments
///
/// * `ledger_json` - JSON of the ledger collection
/// * `wallet_id` - The wallet ID to compute balance for
///
/// # Returns
///
/// JSON containing the balance (can be negative if outgoing exceeds incoming).
#[wasm_bindgen]
pub fn compute_ledger_balance(ledger_json: &str, wallet_id: &str) -> String {
    let collection: LedgerCollection = match serde_json::from_str(ledger_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<LedgerEntry>>(ledger_json) {
            Ok(entries) => LedgerCollection { entries },
            Err(e) => {
                return format!(
                    r#"{{"success":false,"error":"Failed to parse ledger: {}"}}"#,
                    e
                );
            }
        },
    };

    let balance = collection.compute_balance(wallet_id);

    format!(r#"{{"success":true,"balance":{}}}"#, balance)
}

/// Export ledger entries as CSV for tax reporting.
///
/// # Arguments
///
/// * `ledger_json` - JSON of the ledger collection
/// * `wallet_id` - The wallet ID to export
///
/// # Returns
///
/// JSON containing the CSV string or an error.
#[wasm_bindgen]
pub fn export_ledger_csv(ledger_json: &str, wallet_id: &str) -> String {
    let collection: LedgerCollection = match serde_json::from_str(ledger_json) {
        Ok(c) => c,
        Err(_) => match serde_json::from_str::<Vec<LedgerEntry>>(ledger_json) {
            Ok(entries) => LedgerCollection { entries },
            Err(e) => {
                return format!(
                    r#"{{"success":false,"error":"Failed to parse ledger: {}"}}"#,
                    e
                );
            }
        },
    };

    let csv = collection.export_csv(wallet_id);

    // Return as JSON with the CSV content
    match serde_json::to_string(&serde_json::json!({
        "success": true,
        "csv": csv
    })) {
        Ok(json) => json,
        Err(_) => r#"{"success":false,"error":"Serialization error"}"#.to_string(),
    }
}

// ============================================================================
// HTML Generation (using html-builder library)
// ============================================================================

/// Format a zatoshi value as ZEC with 8 decimal places.
fn format_zec(zatoshis: u64) -> String {
    let zec = zatoshis as f64 / 100_000_000.0;
    format!("{:.8}", zec)
}

/// Generate HTML for a balance display card.
///
/// Creates a Bootstrap card component showing the wallet balance.
///
/// # Arguments
///
/// * `balance_zatoshis` - The balance in zatoshis (1 ZEC = 100,000,000 zatoshis)
/// * `wallet_alias` - Optional wallet name to display
///
/// # Returns
///
/// HTML string for the balance card.
#[wasm_bindgen]
pub fn render_balance_card(balance_zatoshis: u64, wallet_alias: Option<String>) -> String {
    let balance_zec = format_zec(balance_zatoshis);
    let title = wallet_alias.unwrap_or_else(|| "Balance".to_string());

    html! {
        div.class("card").class("mb-3") {
            div.class("card-body").class("text-center") {
                h6.class("card-subtitle").class("mb-2").class("text-muted") {
                    #title
                }
                h2.class("card-title").class("mb-0") {
                    span.class("text-primary") {
                        #balance_zec
                    }
                    " "
                    small.class("text-muted") {
                        "ZEC"
                    }
                }
            }
        }
    }
    .render()
}

/// Generate HTML for the scanner balance card with pool breakdown.
///
/// Creates a card showing total balance and breakdown by pool (Orchard, Sapling, Transparent).
///
/// # Arguments
///
/// * `balance_zatoshis` - The total balance in zatoshis
/// * `pool_balances_json` - JSON object with pool balances: {"orchard": u64, "sapling": u64, "transparent": u64}
///
/// # Returns
///
/// HTML string for the balance card with pool breakdown.
#[wasm_bindgen]
pub fn render_scanner_balance_card(balance_zatoshis: u64, pool_balances_json: &str) -> String {
    use std::collections::HashMap;

    let balance_zec = format_zec(balance_zatoshis);
    let pool_balances: HashMap<String, u64> =
        serde_json::from_str(pool_balances_json).unwrap_or_default();

    // Sort pools for consistent ordering
    let mut pools: Vec<_> = pool_balances.iter().collect();
    pools.sort_by_key(|(k, _)| match k.as_str() {
        "orchard" => 0,
        "sapling" => 1,
        "transparent" => 2,
        _ => 3,
    });

    Element::new("div")
        .class("card")
        .class("shadow-sm")
        .child("div", |header| {
            header.class("card-header").child("h5", |h5| {
                h5.class("mb-0")
                    .class("fw-semibold")
                    .child("i", |i| i.class("bi").class("bi-cash-coin").class("me-1"))
                    .text(" Total Balance")
            })
        })
        .child("div", |body| {
            let mut body = body.class("card-body");

            // Total balance
            body = body.child("p", |p| {
                p.class("display-5")
                    .class("mb-3")
                    .class("text-success")
                    .class("fw-bold")
                    .text(&balance_zec)
                    .text(" ZEC")
            });

            // Pool breakdown header
            body = body.child("h6", |h6| h6.class("text-muted").text("By Pool"));

            // Pool breakdown items
            if pools.is_empty() {
                body = body.child("p", |p| p.class("text-muted").text("No notes tracked yet."));
            } else {
                for (pool, amount) in &pools {
                    let pool_label = pool
                        .chars()
                        .next()
                        .map(|c| c.to_uppercase().to_string())
                        .unwrap_or_default()
                        + &pool[1..];
                    let pool_class = match pool.as_str() {
                        "orchard" => "text-success",
                        "sapling" => "text-primary",
                        "transparent" => "text-warning",
                        _ => "text-secondary",
                    };
                    let amount_zec = format_zec(**amount);

                    body = body.child("p", |p| {
                        p.class("mb-1")
                            .child("span", |span| span.class(pool_class).text(&pool_label))
                            .text(": ")
                            .child("strong", |strong| strong.text(&amount_zec).text(" ZEC"))
                    });
                }
            }

            body
        })
        .render()
}

/// Generate HTML for the notes table in the scanner view.
///
/// Creates a responsive table showing all tracked notes with pool, value, memo, and status.
///
/// # Arguments
///
/// * `notes_json` - JSON array of StoredNote objects
///
/// # Returns
///
/// HTML string for the complete notes table.
#[wasm_bindgen]
pub fn render_notes_table(notes_json: &str) -> String {
    let mut notes: Vec<StoredNote> = match serde_json::from_str(notes_json) {
        Ok(n) => n,
        Err(_) => return String::new(),
    };

    // Sort: unspent first, then by value descending
    notes.sort_by(
        |a, b| match (a.spent_txid.is_some(), b.spent_txid.is_some()) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => b.value.cmp(&a.value),
        },
    );

    let notes_count = notes.len();

    // Build table body rows
    let mut tbody = Element::new("tbody");
    for note in &notes {
        let pool_class = match note.pool {
            Pool::Orchard => "text-success",
            Pool::Sapling => "text-primary",
            Pool::Transparent => "text-warning",
        };
        let is_spent = note.spent_txid.is_some();
        let row_class = if is_spent {
            "text-muted text-decoration-line-through"
        } else {
            ""
        };
        let value_text = if note.value > 0 {
            format!("{} ZEC", format_zec(note.value))
        } else {
            "-".to_string()
        };
        let memo_text = note
            .memo
            .as_ref()
            .map(|m| {
                if m.len() > 30 {
                    format!("{}...", &m[..30])
                } else {
                    m.clone()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        tbody = tbody.child("tr", |tr| {
            let mut tr = tr;
            if !row_class.is_empty() {
                tr = tr.class(row_class);
            }
            tr.child("td", |td| {
                td.child("span", |span| {
                    span.class(pool_class).text(note.pool.as_str())
                })
            })
            .child("td", |td| td.text(&value_text))
            .child("td", |td| td.text(&memo_text))
            .child("td", |td| {
                if is_spent {
                    td.child("span", |span| {
                        span.class("badge").class("bg-secondary").text("Spent")
                    })
                } else {
                    td.child("span", |span| {
                        span.class("badge").class("bg-success").text("Unspent")
                    })
                }
            })
        });
    }

    // Build complete table
    Element::new("div")
        .class("table-responsive")
        .child("table", |table| {
            table
                .class("table")
                .class("table-sm")
                .child("thead", |thead| {
                    thead.child("tr", |tr| {
                        tr.child("th", |th| th.text("Pool"))
                            .child("th", |th| th.text("Value"))
                            .child("th", |th| th.text("Memo"))
                            .child("th", |th| th.text("Status"))
                    })
                })
                .raw(tbody.render())
        })
        .child("p", |p| {
            p.class("small")
                .class("text-muted")
                .text(format!("Total notes: {}", notes_count))
        })
        .render()
}

/// Generate HTML for the ledger/transaction history table in the scanner view.
///
/// Creates a responsive table showing transaction history with date, txid, amounts, and pool.
///
/// # Arguments
///
/// * `entries_json` - JSON array of LedgerEntry objects
/// * `network` - Network name ("mainnet" or "testnet") for explorer links
///
/// # Returns
///
/// HTML string for the complete ledger table.
#[wasm_bindgen]
pub fn render_ledger_table(entries_json: &str, network: &str) -> String {
    let mut entries: Vec<LedgerEntry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    // Sort by date descending
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let entries_count = entries.len();
    let explorer_base = if network == "mainnet" {
        "https://zcashexplorer.app"
    } else {
        "https://testnet.zcashexplorer.app"
    };

    // Build table body rows
    let mut tbody = Element::new("tbody");
    for entry in &entries {
        let date = entry.created_at.split('T').next().unwrap_or("-");

        let row_class = if entry.net_change > 0 {
            "table-success"
        } else if entry.net_change < 0 {
            "table-danger"
        } else {
            ""
        };

        let net_formatted = if entry.net_change >= 0 {
            format!("+{}", format_zec(entry.net_change as u64))
        } else {
            format!("-{}", format_zec((-entry.net_change) as u64))
        };

        let received_text = if entry.value_received > 0 {
            format!("+{}", format_zec(entry.value_received))
        } else {
            "-".to_string()
        };

        let spent_text = if entry.value_spent > 0 {
            format!("-{}", format_zec(entry.value_spent))
        } else {
            "-".to_string()
        };

        let pool_badge_class = match entry.primary_pool.as_str() {
            "orchard" => "bg-info",
            "sapling" => "bg-primary",
            "transparent" => "bg-warning text-dark",
            "mixed" => "bg-secondary",
            _ => "bg-secondary",
        };
        let pool_name = entry
            .primary_pool
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string() + &entry.primary_pool[1..])
            .unwrap_or_else(|| "Unknown".to_string());

        let memo_text = entry
            .memos
            .first()
            .map(|m: &String| {
                if m.len() > 20 {
                    format!("{}...", &m[..20])
                } else {
                    m.clone()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let txid_short = if entry.txid.len() > 12 {
            format!(
                "{}...{}",
                &entry.txid[..8],
                &entry.txid[entry.txid.len() - 4..]
            )
        } else {
            entry.txid.clone()
        };
        let txid_url = format!("{}/transactions/{}", explorer_base, entry.txid);

        tbody = tbody.child("tr", |tr| {
            let mut tr = tr;
            if !row_class.is_empty() {
                tr = tr.class(row_class);
            }
            tr.child("td", |td| td.class("small").text(date))
                .child("td", |td| {
                    td.class("small").child("a", |a| {
                        a.attr("href", &txid_url)
                            .attr("target", "_blank")
                            .attr("rel", "noopener noreferrer")
                            .class("mono")
                            .attr("title", &entry.txid)
                            .text(&txid_short)
                    })
                })
                .child("td", |td| {
                    td.class("text-end")
                        .class("text-success")
                        .text(&received_text)
                })
                .child("td", |td| {
                    td.class("text-end").class("text-danger").text(&spent_text)
                })
                .child("td", |td| {
                    td.class("text-end").class("fw-bold").text(&net_formatted)
                })
                .child("td", |td| {
                    td.child("span", |span| {
                        span.class("badge").class(pool_badge_class).text(&pool_name)
                    })
                })
                .child("td", |td| td.class("small").text(&memo_text))
        });
    }

    // Build complete structure
    Element::new("div")
        .child("div", |header| {
            header
                .class("d-flex")
                .class("justify-content-between")
                .class("align-items-center")
                .class("mb-3")
                .child("h6", |h6| {
                    h6.class("mb-0")
                        .child("i", |i| {
                            i.class("bi").class("bi-journal-text").class("me-1")
                        })
                        .text(" Transaction History")
                })
                .child("button", |btn| {
                    btn.class("btn")
                        .class("btn-sm")
                        .class("btn-outline-secondary")
                        .attr("onclick", "downloadLedgerCsv()")
                        .child("i", |i| i.class("bi").class("bi-download").class("me-1"))
                        .text(" Export CSV")
                })
        })
        .child("div", |wrapper| {
            wrapper.class("table-responsive").child("table", |table| {
                table
                    .class("table")
                    .class("table-sm")
                    .child("thead", |thead| {
                        thead.child("tr", |tr| {
                            tr.child("th", |th| th.text("Date"))
                                .child("th", |th| th.text("TxID"))
                                .child("th", |th| th.class("text-end").text("Received"))
                                .child("th", |th| th.class("text-end").text("Spent"))
                                .child("th", |th| th.class("text-end").text("Net"))
                                .child("th", |th| th.text("Pool"))
                                .child("th", |th| th.text("Memo"))
                        })
                    })
                    .raw(tbody.render())
            })
        })
        .child("p", |p| {
            p.class("small")
                .class("text-muted")
                .text(format!("Total transactions: {}", entries_count))
        })
        .render()
}

/// Generate HTML for the simple view transaction list.
///
/// Creates a list of transaction items for the Simple view with icons, dates,
/// explorer links, and amounts.
///
/// # Arguments
///
/// * `entries_json` - JSON array of LedgerEntry objects
/// * `network` - Network name ("mainnet" or "testnet") for explorer links
///
/// # Returns
///
/// HTML string for the transaction list items.
#[wasm_bindgen]
pub fn render_simple_transaction_list(entries_json: &str, network: &str) -> String {
    let mut entries: Vec<LedgerEntry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    // Sort by date descending and take top 10
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let entries: Vec<_> = entries.into_iter().take(10).collect();

    let explorer_base = if network == "mainnet" {
        "https://zcashexplorer.app"
    } else {
        "https://testnet.zcashexplorer.app"
    };

    let mut container = Element::new("div");

    for entry in &entries {
        let is_incoming = entry.net_change > 0;
        let icon_class = if is_incoming {
            "bi-arrow-down-left"
        } else {
            "bi-arrow-up-right"
        };
        let color_class = if is_incoming {
            "text-success"
        } else {
            "text-danger"
        };
        let direction_text = if is_incoming { "Received" } else { "Sent" };
        let sign = if is_incoming { "+" } else { "" };

        let amount = if entry.net_change >= 0 {
            entry.net_change as u64
        } else {
            (-entry.net_change) as u64
        };
        let amount_zec = format_zec(amount);

        let txid_short_start = &entry.txid[..core::cmp::min(6, entry.txid.len())];
        let txid_short_end = if entry.txid.len() > 10 {
            &entry.txid[entry.txid.len() - 4..]
        } else {
            ""
        };
        let txid_display = format!("{}...{}", txid_short_start, txid_short_end);
        let explorer_url = format!("{}/transactions/{}", explorer_base, entry.txid);

        container = container.child("div", |item| {
            item.class("list-group-item")
                .class("d-flex")
                .class("justify-content-between")
                .class("align-items-center")
                .child("div", |left| {
                    left.class("d-flex")
                        .class("align-items-center")
                        .child("i", |i| {
                            i.class("bi")
                                .class(icon_class)
                                .class(color_class)
                                .class("fs-4")
                                .class("me-3")
                        })
                        .child("div", |info| {
                            info.child("div", |d| d.class("fw-semibold").text(direction_text))
                                .child("small", |s| {
                                    s.class("text-body-secondary").text(&entry.created_at)
                                })
                                .child("div", |link_div| {
                                    link_div.class("small").child("a", |a| {
                                        a.attr("href", &explorer_url)
                                            .attr("target", "_blank")
                                            .attr("rel", "noopener noreferrer")
                                            .class("text-decoration-none")
                                            .child("code", |code| code.text(&txid_display))
                                            .child("i", |i| {
                                                i.class("bi")
                                                    .class("bi-box-arrow-up-right")
                                                    .class("ms-1")
                                                    .class("small")
                                            })
                                    })
                                })
                        })
                })
                .child("div", |right| {
                    right.class("text-end").child("div", |amount_div| {
                        amount_div
                            .class(color_class)
                            .class("fw-semibold")
                            .text(sign)
                            .text(&amount_zec)
                            .text(" ZEC")
                    })
                })
        });
    }

    container.render()
}

/// Generate HTML for a success alert with explorer link.
///
/// Creates a dismissible Bootstrap alert for successful transactions.
///
/// # Arguments
///
/// * `txid` - The transaction ID
/// * `network` - Network name ("mainnet" or "testnet") for explorer links
///
/// # Returns
///
/// HTML string for the success alert.
#[wasm_bindgen]
pub fn render_success_alert(txid: &str, network: &str) -> String {
    let explorer_base = if network == "mainnet" {
        "https://zcashexplorer.app"
    } else {
        "https://testnet.zcashexplorer.app"
    };
    let explorer_url = format!("{}/transactions/{}", explorer_base, txid);

    Element::new("div")
        .class("alert")
        .class("alert-success")
        .class("alert-dismissible")
        .class("fade")
        .class("show")
        .attr("role", "alert")
        .child("i", |i| {
            i.class("bi").class("bi-check-circle").class("me-2")
        })
        .child("strong", |s| s.text("Transaction sent!"))
        .child("br", |br| br)
        .child("a", |a| {
            a.attr("href", &explorer_url)
                .attr("target", "_blank")
                .attr("rel", "noopener noreferrer")
                .class("alert-link")
                .text("View on explorer")
        })
        .child("button", |btn| {
            btn.attr("type", "button")
                .class("btn-close")
                .attr("data-bs-dismiss", "alert")
                .attr("aria-label", "Close")
        })
        .render()
}

/// Generate HTML for transparent inputs in the decrypt viewer.
///
/// # Arguments
///
/// * `inputs_json` - JSON array of TransparentInput objects
///
/// # Returns
///
/// HTML string for the inputs section, or empty string if no inputs.
#[wasm_bindgen]
pub fn render_transparent_inputs(inputs_json: &str) -> String {
    let inputs: Vec<TransparentInput> = match serde_json::from_str(inputs_json) {
        Ok(i) => i,
        Err(_) => return String::new(),
    };

    if inputs.is_empty() {
        return String::new();
    }

    let mut container = Element::new("div").child("p", |p| {
        p.class("fw-semibold")
            .class("mb-2")
            .text(format!("Inputs ({})", inputs.len()))
    });

    for input in &inputs {
        container = container.child("div", |card| {
            card.class("card")
                .class("output-card")
                .class("transparent")
                .class("mb-2")
                .child("div", |body| {
                    body.class("card-body")
                        .class("py-2")
                        .class("px-3")
                        .child("small", |s| {
                            s.class("text-muted")
                                .text(format!("Input #{}", input.index))
                        })
                        .child("div", |d| {
                            d.class("mono")
                                .class("small")
                                .class("text-truncate")
                                .text(format!(
                                    "Prev: {}:{}",
                                    input.prevout_txid, input.prevout_index
                                ))
                        })
                })
        });
    }

    container.render()
}

/// Generate HTML for transparent outputs in the decrypt viewer.
///
/// # Arguments
///
/// * `outputs_json` - JSON array of TransparentOutput objects
///
/// # Returns
///
/// HTML string for the outputs section, or empty string if no outputs.
#[wasm_bindgen]
pub fn render_transparent_outputs(outputs_json: &str) -> String {
    let outputs: Vec<TransparentOutput> = match serde_json::from_str(outputs_json) {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    if outputs.is_empty() {
        return String::new();
    }

    let mut container = Element::new("div").child("p", |p| {
        p.class("fw-semibold")
            .class("mb-2")
            .text(format!("Outputs ({})", outputs.len()))
    });

    for output in &outputs {
        let value_zec = format_zec(output.value);

        container = container.child("div", |card| {
            card.class("card")
                .class("output-card")
                .class("transparent")
                .class("mb-2")
                .child("div", |body| {
                    let mut b = body
                        .class("card-body")
                        .class("py-2")
                        .class("px-3")
                        .child("small", |s| {
                            s.class("text-muted")
                                .text(format!("Output #{}", output.index))
                        })
                        .child("div", |d| {
                            d.child("strong", |s| s.text(&value_zec)).text(" ZEC")
                        });

                    if let Some(ref addr) = output.address {
                        b = b.child("div", |d| {
                            d.class("mono")
                                .class("small")
                                .class("text-truncate")
                                .text(addr)
                        });
                    }

                    b
                })
        });
    }

    container.render()
}

/// Generate HTML for Sapling outputs in the decrypt viewer.
///
/// # Arguments
///
/// * `outputs_json` - JSON array of DecryptedSaplingOutput objects
///
/// # Returns
///
/// HTML string for the Sapling outputs section.
#[wasm_bindgen]
pub fn render_sapling_outputs(outputs_json: &str) -> String {
    let outputs: Vec<DecryptedSaplingOutput> = match serde_json::from_str(outputs_json) {
        Ok(o) => o,
        Err(_) => return String::new(),
    };

    let mut container = Element::new("div");

    for output in &outputs {
        container = container.child("div", |card| {
            card.class("card")
                .class("output-card")
                .class("sapling")
                .class("mb-2")
                .child("div", |body| {
                    let mut b =
                        body.class("card-body")
                            .class("py-2")
                            .class("px-3")
                            .child("small", |s| {
                                s.class("text-muted")
                                    .text(format!("Output #{}", output.index))
                            });

                    if output.value > 0 {
                        let value_zec = format_zec(output.value);
                        b = b.child("div", |d| {
                            d.child("strong", |s| s.text(&value_zec)).text(" ZEC")
                        });
                    }

                    if !output.memo.is_empty() && output.memo != "(encrypted)" {
                        b = b.child("div", |d| {
                            d.class("small").text("Memo: ").text(&output.memo)
                        });
                    }

                    b = b.child("div", |d| {
                        d.class("mono")
                            .class("small")
                            .class("text-truncate")
                            .class("text-muted")
                            .text("Commitment: ")
                            .text(&output.note_commitment)
                    });

                    if let Some(ref nullifier) = output.nullifier {
                        b = b.child("div", |d| {
                            d.class("mono")
                                .class("small")
                                .class("text-truncate")
                                .class("text-muted")
                                .text("Nullifier: ")
                                .text(nullifier)
                        });
                    }

                    b
                })
        });
    }

    container.render()
}

/// Generate HTML for Orchard actions in the decrypt viewer.
///
/// # Arguments
///
/// * `actions_json` - JSON array of DecryptedOrchardAction objects
///
/// # Returns
///
/// HTML string for the Orchard actions section.
#[wasm_bindgen]
pub fn render_orchard_actions(actions_json: &str) -> String {
    let actions: Vec<DecryptedOrchardAction> = match serde_json::from_str(actions_json) {
        Ok(a) => a,
        Err(_) => return String::new(),
    };

    let mut container = Element::new("div");

    for action in &actions {
        container = container.child("div", |card| {
            card.class("card")
                .class("output-card")
                .class("orchard")
                .class("mb-2")
                .child("div", |body| {
                    let mut b =
                        body.class("card-body")
                            .class("py-2")
                            .class("px-3")
                            .child("small", |s| {
                                s.class("text-muted")
                                    .text(format!("Action #{}", action.index))
                            });

                    if action.value > 0 {
                        let value_zec = format_zec(action.value);
                        b = b.child("div", |d| {
                            d.child("strong", |s| s.text(&value_zec)).text(" ZEC")
                        });
                    }

                    if !action.memo.is_empty() && action.memo != "(encrypted)" {
                        b = b.child("div", |d| {
                            d.class("small").text("Memo: ").text(&action.memo)
                        });
                    }

                    b = b.child("div", |d| {
                        d.class("mono")
                            .class("small")
                            .class("text-truncate")
                            .class("text-muted")
                            .text("Commitment: ")
                            .text(&action.note_commitment)
                    });

                    if let Some(ref nullifier) = action.nullifier {
                        b = b.child("div", |d| {
                            d.class("mono")
                                .class("small")
                                .class("text-truncate")
                                .class("text-muted")
                                .text("Nullifier: ")
                                .text(nullifier)
                        });
                    }

                    b
                })
        });
    }

    container.render()
}

/// Generate HTML for a note/UTXO list item.
///
/// Creates a list group item showing note details.
///
/// # Arguments
///
/// * `note_json` - JSON of StoredNote
///
/// # Returns
///
/// HTML string for the note list item.
#[wasm_bindgen]
pub fn render_note_item(note_json: &str) -> String {
    let note: StoredNote = match serde_json::from_str(note_json) {
        Ok(n) => n,
        Err(_) => return String::new(),
    };

    let value_zec = format_zec(note.value);
    let pool_badge_class = match note.pool {
        Pool::Orchard => "bg-success",
        Pool::Sapling => "bg-primary",
        Pool::Transparent => "bg-warning text-dark",
    };
    let pool_name = note.pool.as_str();
    let is_spent = note.spent_txid.is_some();
    let status_class = if is_spent { "text-muted" } else { "" };
    let txid_short = if note.txid.len() > 16 {
        format!("{}...", &note.txid[..16])
    } else {
        note.txid.clone()
    };

    // Build HTML using the builder API
    let mut item = Element::new("div")
        .class("list-group-item")
        .class("d-flex")
        .class("justify-content-between")
        .class("align-items-center");

    if !status_class.is_empty() {
        item = item.class(status_class);
    }

    item.child("div", |div| {
        div.child("span", |span| {
            span.class("badge")
                .class(pool_badge_class)
                .class("me-2")
                .text(pool_name)
        })
        .child("small", |small| small.class("text-muted").text(&txid_short))
    })
    .child("div", |div| {
        let mut d = div.child("span", |span| {
            span.class("fw-bold").text(&value_zec).text(" ZEC")
        });

        if is_spent {
            d = d.child("span", |span| {
                span.class("badge")
                    .class("bg-secondary")
                    .class("ms-2")
                    .text("Spent")
            });
        }

        d
    })
    .render()
}

/// Generate HTML for a transaction list item.
///
/// Creates a list group item showing transaction details from a ledger entry.
///
/// # Arguments
///
/// * `entry_json` - JSON of LedgerEntry
///
/// # Returns
///
/// HTML string for the transaction list item.
#[wasm_bindgen]
pub fn render_transaction_item(entry_json: &str) -> String {
    let entry: LedgerEntry = match serde_json::from_str(entry_json) {
        Ok(e) => e,
        Err(_) => return String::new(),
    };

    let is_incoming = entry.net_change >= 0;
    let amount = if is_incoming {
        entry.net_change as u64
    } else {
        (-entry.net_change) as u64
    };
    let amount_zec = format_zec(amount);
    let sign = if is_incoming { "+" } else { "-" };
    let amount_class = if is_incoming {
        "text-success"
    } else {
        "text-danger"
    };
    let icon_class = if is_incoming {
        "bi-arrow-down-circle"
    } else {
        "bi-arrow-up-circle"
    };
    let txid_short = if entry.txid.len() > 16 {
        format!("{}...", &entry.txid[..16])
    } else {
        entry.txid.clone()
    };
    let date = entry
        .created_at
        .split('T')
        .next()
        .unwrap_or(&entry.created_at);
    let direction_text = if is_incoming { "Received" } else { "Sent" };

    // Build HTML using the builder API
    Element::new("div")
        .class("list-group-item")
        .class("d-flex")
        .class("justify-content-between")
        .class("align-items-center")
        .child("div", |div| {
            div.class("d-flex")
                .class("align-items-center")
                .child("i", |i| {
                    i.class("bi")
                        .class(icon_class)
                        .class("fs-4")
                        .class("me-3")
                        .class(amount_class)
                })
                .child("div", |inner| {
                    inner
                        .child("div", |d| d.class("fw-bold").text(direction_text))
                        .child("small", |s| s.class("text-muted").text(&txid_short))
                })
        })
        .child("div", |div| {
            div.class("text-end")
                .child("div", |d| {
                    d.class("fw-bold")
                        .class(amount_class)
                        .text(sign)
                        .text(&amount_zec)
                        .text(" ZEC")
                })
                .child("small", |s| s.class("text-muted").text(date))
        })
        .render()
}

/// Generate HTML for an empty state message.
///
/// Creates a centered message for empty lists.
///
/// # Arguments
///
/// * `message` - The message to display
/// * `icon_class` - Bootstrap icon class (e.g., "bi-inbox")
///
/// # Returns
///
/// HTML string for the empty state.
#[wasm_bindgen]
pub fn render_empty_state(message: &str, icon_class: &str) -> String {
    // Build HTML using the builder API
    Element::new("div")
        .class("text-center")
        .class("py-5")
        .class("text-muted")
        .child("i", |i| {
            i.class("bi").class(icon_class).class("fs-1").class("mb-3")
        })
        .child("p", |p| p.class("mb-0").text(message))
        .render()
}

/// Generate HTML for the send UTXOs table.
///
/// Creates a table displaying available transparent UTXOs for sending.
///
/// # Arguments
///
/// * `utxos_json` - JSON array of StoredNote objects (filtered to transparent)
/// * `network` - Network name ("mainnet" or "testnet") for explorer links
///
/// # Returns
///
/// HTML string for the UTXOs table.
#[wasm_bindgen]
pub fn render_send_utxos_table(utxos_json: &str, network: &str) -> String {
    let utxos: Vec<StoredNote> = match serde_json::from_str(utxos_json) {
        Ok(u) => u,
        Err(_) => return String::new(),
    };

    if utxos.is_empty() {
        return render_empty_state(
            "No transparent UTXOs available for this wallet.",
            "bi-inbox",
        );
    }

    let explorer_base = if network == "mainnet" {
        "https://zcashexplorer.app"
    } else {
        "https://testnet.zcashexplorer.app"
    };

    let mut tbody = Element::new("tbody");

    for utxo in &utxos {
        let txid_url = format!("{}/transactions/{}", explorer_base, utxo.txid);
        let txid_short_start = &utxo.txid[..core::cmp::min(6, utxo.txid.len())];
        let txid_short_end = if utxo.txid.len() > 10 {
            &utxo.txid[utxo.txid.len() - 4..]
        } else {
            ""
        };
        let txid_display = format!("{}...{}", txid_short_start, txid_short_end);
        let value_zec = format_zec(utxo.value);

        let addr_display = match &utxo.address {
            Some(addr) if addr.len() > 14 => {
                let start = &addr[..8];
                let end = &addr[addr.len() - 6..];
                format!("{}...{}", start, end)
            }
            Some(addr) => addr.clone(),
            None => "-".to_string(),
        };

        tbody = tbody.child("tr", |tr| {
            tr.child("td", |td| {
                td.class("mono").class("small").child("a", |a| {
                    a.attr("href", &txid_url)
                        .attr("target", "_blank")
                        .attr("rel", "noopener noreferrer")
                        .attr("title", &utxo.txid)
                        .text(&txid_display)
                })
            })
            .child("td", |td| td.text(format!("{}", utxo.output_index)))
            .child("td", |td| {
                td.class("text-end").text(&value_zec).text(" ZEC")
            })
            .child("td", |td| {
                td.class("mono").class("small").text(&addr_display)
            })
        });
    }

    Element::new("div")
        .child("div", |wrapper| {
            wrapper.class("table-responsive").child("table", |table| {
                table
                    .class("table")
                    .class("table-sm")
                    .child("thead", |thead| {
                        thead.child("tr", |tr| {
                            tr.child("th", |th| th.text("TxID"))
                                .child("th", |th| th.text("Index"))
                                .child("th", |th| th.class("text-end").text("Value"))
                                .child("th", |th| th.text("Address"))
                        })
                    })
                    .raw(tbody.render())
            })
        })
        .child("p", |p| {
            p.class("small")
                .class("text-muted")
                .class("mb-0")
                .text(format!("{} UTXO(s) available", utxos.len()))
        })
        .render()
}

/// Generate HTML for a broadcast result alert.
///
/// Creates a Bootstrap alert for displaying broadcast results.
///
/// # Arguments
///
/// * `message` - The message to display
/// * `alert_type` - Bootstrap alert type ("success", "danger", "warning", "info")
///
/// # Returns
///
/// HTML string for the alert.
#[wasm_bindgen]
pub fn render_broadcast_result(message: &str, alert_type: &str) -> String {
    Element::new("div")
        .class("alert")
        .class(format!("alert-{}", alert_type))
        .text(message)
        .render()
}

/// Derived address entry for address viewer.
#[derive(serde::Deserialize)]
struct DerivedAddress {
    index: u32,
    transparent: String,
    unified: String,
    #[serde(rename = "isSaved")]
    is_saved: bool,
}

/// Generate HTML for the derived addresses table.
///
/// Creates a table displaying derived transparent and unified addresses with
/// duplicate detection and copy buttons.
///
/// # Arguments
///
/// * `addresses_json` - JSON array of DerivedAddress objects
/// * `network` - Network name ("mainnet" or "testnet") for explorer links
///
/// # Returns
///
/// HTML string for the addresses table including duplicate warning if applicable.
#[wasm_bindgen]
pub fn render_derived_addresses_table(addresses_json: &str, network: &str) -> String {
    let addresses: Vec<DerivedAddress> = match serde_json::from_str(addresses_json) {
        Ok(a) => a,
        Err(_) => return String::new(),
    };

    if addresses.is_empty() {
        return render_empty_state("No addresses derived.", "bi-card-list");
    }

    let explorer_base = if network == "mainnet" {
        "https://zcashexplorer.app"
    } else {
        "https://testnet.zcashexplorer.app"
    };

    // Detect duplicates - track first occurrence of each unified address
    let mut first_occurrence: std::collections::HashMap<&str, u32> =
        std::collections::HashMap::new();
    let mut duplicate_indices: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for addr in &addresses {
        if let Some(&first_idx) = first_occurrence.get(addr.unified.as_str()) {
            duplicate_indices.insert(addr.index);
            // Keep track of the first occurrence for the badge tooltip
            let _ = first_idx;
        } else {
            first_occurrence.insert(&addr.unified, addr.index);
        }
    }

    let duplicate_count = duplicate_indices.len();

    let mut container = Element::new("div");

    // Add duplicate warning if needed
    if duplicate_count > 0 {
        container = container.child("div", |alert| {
            alert
                .class("alert")
                .class("alert-warning")
                .class("py-2")
                .class("mb-3")
                .class("sapling-note")
                .child("i", |i| {
                    i.class("bi").class("bi-exclamation-triangle").class("me-1")
                })
                .child("strong", |s| s.text("Duplicate addresses detected:"))
                .text(format!(
                    " {} indices produce duplicate unified addresses \
                     due to Sapling diversifier behavior. Avoid reusing these addresses.",
                    duplicate_count
                ))
        });
    }

    // Build table body
    let mut tbody = Element::new("tbody");

    for (idx, addr) in addresses.iter().enumerate() {
        let explorer_url = format!("{}/addresses/{}", explorer_base, addr.transparent);
        let is_duplicate = duplicate_indices.contains(&addr.index);

        // Truncate addresses for display
        let transparent_display = if addr.transparent.len() > 14 {
            format!(
                "{}...{}",
                &addr.transparent[..8],
                &addr.transparent[addr.transparent.len() - 6..]
            )
        } else {
            addr.transparent.clone()
        };

        let unified_display = if addr.unified.len() > 18 {
            format!(
                "{}...{}",
                &addr.unified[..10],
                &addr.unified[addr.unified.len() - 8..]
            )
        } else {
            addr.unified.clone()
        };

        let transparent_id = format!("copy-transparent-{}", idx);
        let unified_id = format!("copy-unified-{}", idx);

        let first_idx = first_occurrence.get(addr.unified.as_str()).copied();

        tbody = tbody.child("tr", |tr| {
            let mut row = tr;
            if is_duplicate {
                row = row.class("table-warning");
            }

            row.child("td", |td| {
                td.class("text-muted").class("align-middle").text(format!("{}", addr.index))
            })
            .child("td", |td| {
                td.child("div", |d| {
                    d.class("d-flex").class("align-items-center").child("a", |a| {
                        a.attr("href", &explorer_url)
                            .attr("target", "_blank")
                            .attr("rel", "noopener noreferrer")
                            .class("mono")
                            .class("small")
                            .class("text-truncate")
                            .attr("style", "max-width: 150px;")
                            .attr("title", &addr.transparent)
                            .text(&transparent_display)
                    })
                    .child("button", |btn| {
                        btn.attr("id", &transparent_id)
                            .class("btn")
                            .class("btn-sm")
                            .class("btn-link")
                            .class("p-0")
                            .class("text-muted")
                            .class("ms-1")
                            .attr(
                                "onclick",
                                format!("copyAddress('{}', '{}')", &addr.transparent, &transparent_id),
                            )
                            .attr("title", "Copy address")
                            .child("i", |i| i.class("bi").class("bi-clipboard"))
                    })
                })
            })
            .child("td", |td| {
                td.child("div", |d| {
                    let mut div = d.class("d-flex").class("align-items-center").child("span", |s| {
                        s.class("mono")
                            .class("small")
                            .class("text-truncate")
                            .attr("style", "max-width: 200px;")
                            .attr("title", &addr.unified)
                            .text(&unified_display)
                    })
                    .child("button", |btn| {
                        btn.attr("id", &unified_id)
                            .class("btn")
                            .class("btn-sm")
                            .class("btn-link")
                            .class("p-0")
                            .class("text-muted")
                            .class("ms-1")
                            .attr(
                                "onclick",
                                format!("copyAddress('{}', '{}')", &addr.unified, &unified_id),
                            )
                            .attr("title", "Copy address")
                            .child("i", |i| i.class("bi").class("bi-clipboard"))
                    });

                    if let Some(first) = first_idx.filter(|_| is_duplicate) {
                        div = div.child("span", |span| {
                            span.class("badge")
                                .class("bg-warning")
                                .class("text-dark")
                                .class("ms-1")
                                .attr(
                                    "title",
                                    format!(
                                        "This address is identical to index {} due to Sapling diversifier behavior. Avoid reusing.",
                                        first
                                    ),
                                )
                                .child("i", |i| {
                                    i.class("bi").class("bi-exclamation-triangle-fill")
                                })
                                .text(" Duplicate")
                        });
                    }

                    div
                })
            })
            .child("td", |td| {
                td.class("text-center").class("align-middle").child("i", |i| {
                    if addr.is_saved {
                        i.class("bi")
                            .class("bi-check-circle-fill")
                            .class("text-success")
                            .attr("title", "Saved to wallet")
                    } else {
                        i.class("bi")
                            .class("bi-circle")
                            .class("text-muted")
                            .attr("title", "Not saved")
                    }
                })
            })
        });
    }

    // Build complete table structure
    container = container.child("div", |wrapper| {
        wrapper.class("table-responsive").child("table", |table| {
            table
                .class("table")
                .class("table-sm")
                .class("table-hover")
                .class("mb-0")
                .child("thead", |thead| {
                    thead.child("tr", |tr| {
                        tr.child("th", |th| th.attr("style", "width: 60px;").text("Index"))
                            .child("th", |th| th.text("Transparent Address"))
                            .child("th", |th| th.text("Unified Address"))
                            .child("th", |th| {
                                th.attr("style", "width: 60px;")
                                    .class("text-center")
                                    .text("Saved")
                            })
                    })
                })
                .raw(tbody.render())
        })
    });

    container.render()
}

/// Generate HTML for a dismissible info/success alert.
///
/// Creates a Bootstrap dismissible alert for address operations.
///
/// # Arguments
///
/// * `message` - The message to display
/// * `alert_type` - Bootstrap alert type ("success", "info", "warning", "danger")
/// * `icon_class` - Bootstrap icon class (e.g., "bi-check-circle", "bi-info-circle")
///
/// # Returns
///
/// HTML string for the dismissible alert.
#[wasm_bindgen]
pub fn render_dismissible_alert(message: &str, alert_type: &str, icon_class: &str) -> String {
    Element::new("div")
        .class("alert")
        .class(format!("alert-{}", alert_type))
        .class("alert-dismissible")
        .class("fade")
        .class("show")
        .class("mb-3")
        .child("i", |i| i.class("bi").class(icon_class).class("me-1"))
        .text(format!(" {}", message))
        .child("button", |btn| {
            btn.attr("type", "button")
                .class("btn-close")
                .attr("data-bs-dismiss", "alert")
        })
        .render()
}

/// Saved wallet entry for wallet list.
#[derive(serde::Deserialize)]
struct SavedWallet {
    id: String,
    alias: String,
    network: String,
    unified_address: Option<String>,
}

/// Generate HTML for the saved wallets list.
///
/// Creates a list group displaying saved wallets with view/delete buttons.
///
/// # Arguments
///
/// * `wallets_json` - JSON array of SavedWallet objects
///
/// # Returns
///
/// HTML string for the wallets list.
#[wasm_bindgen]
pub fn render_saved_wallets_list(wallets_json: &str) -> String {
    let wallets: Vec<SavedWallet> = match serde_json::from_str(wallets_json) {
        Ok(w) => w,
        Err(_) => return String::new(),
    };

    if wallets.is_empty() {
        return Element::new("div")
            .class("text-muted")
            .class("text-center")
            .class("py-3")
            .child("i", |i| i.class("bi").class("bi-wallet2").class("fs-3"))
            .child("p", |p| {
                p.class("mb-0").class("mt-2").text("No wallets saved yet.")
            })
            .render();
    }

    let mut list_group = Element::new("div").class("list-group");

    for wallet in &wallets {
        let network_badge_class = if wallet.network == "mainnet" {
            "bg-success"
        } else {
            "bg-warning text-dark"
        };

        let address_display = match &wallet.unified_address {
            Some(addr) if addr.len() > 20 => format!("{}...", &addr[..20]),
            Some(addr) => addr.clone(),
            None => "No address".to_string(),
        };

        let view_onclick = format!("viewWalletDetails('{}')", wallet.id);
        let delete_onclick = format!("confirmDeleteWallet('{}')", wallet.id);

        list_group = list_group.child("div", |item| {
            item.class("list-group-item").child("div", |wrapper| {
                wrapper
                    .class("d-flex")
                    .class("justify-content-between")
                    .class("align-items-start")
                    .child("div", |info| {
                        info.child("h6", |h6| {
                            h6.class("mb-1")
                                .text(&wallet.alias)
                                .text(" ")
                                .child("span", |badge| {
                                    badge
                                        .class("badge")
                                        .class(network_badge_class)
                                        .text(&wallet.network)
                                })
                        })
                        .child("small", |small| {
                            small
                                .class("text-muted")
                                .class("mono")
                                .text(&address_display)
                        })
                    })
                    .child("div", |btns| {
                        btns.class("btn-group")
                            .class("btn-group-sm")
                            .child("button", |btn| {
                                btn.class("btn")
                                    .class("btn-outline-secondary")
                                    .attr("onclick", &view_onclick)
                                    .attr("title", "View details")
                                    .child("i", |i| i.class("bi").class("bi-eye"))
                            })
                            .child("button", |btn| {
                                btn.class("btn")
                                    .class("btn-outline-danger")
                                    .attr("onclick", &delete_onclick)
                                    .attr("title", "Delete")
                                    .child("i", |i| i.class("bi").class("bi-trash"))
                            })
                    })
            })
        });
    }

    list_group.render()
}

/// Contact data structure for rendering
#[derive(Debug, serde::Deserialize)]
struct Contact {
    id: String,
    name: String,
    address: String,
    network: String,
}

/// Render a list of contacts as HTML.
///
/// # Arguments
///
/// * `contacts_json` - JSON string containing an array of contact objects
///
/// # Returns
///
/// HTML string containing a list-group of contacts with edit/delete buttons,
/// or an empty state message if no contacts exist.
#[wasm_bindgen]
pub fn render_contacts_list(contacts_json: &str) -> String {
    let contacts: Vec<Contact> = match serde_json::from_str(contacts_json) {
        Ok(c) => c,
        Err(_) => return render_empty_state("Failed to load contacts", "bi-exclamation-triangle"),
    };

    if contacts.is_empty() {
        return render_empty_state(
            "No contacts yet. Add your first contact above.",
            "bi-person-plus",
        );
    }

    let mut list_group = Element::new("div").class("list-group");

    for contact in &contacts {
        let network_badge_class = if contact.network == "mainnet" {
            "bg-success"
        } else {
            "bg-info"
        };

        let address_short = if contact.address.len() > 24 {
            format!(
                "{}...{}",
                &contact.address[..12],
                &contact.address[contact.address.len() - 8..]
            )
        } else {
            contact.address.clone()
        };

        let copy_onclick = format!(
            "copyContactAddress('{}')",
            contact.address.replace('\'', "\\'")
        );
        let edit_onclick = format!("editContact('{}')", contact.id);
        let delete_onclick = format!("confirmDeleteContact('{}')", contact.id);

        list_group = list_group.child("div", |item| {
            item.class("list-group-item")
                .class("contact-item")
                .attr("data-name", contact.name.to_lowercase())
                .attr("data-address", contact.address.to_lowercase())
                .child("div", |wrapper| {
                    wrapper
                        .class("d-flex")
                        .class("justify-content-between")
                        .class("align-items-start")
                        .child("div", |info| {
                            info.class("flex-grow-1")
                                .class("me-2")
                                .attr("role", "button")
                                .attr("onclick", &edit_onclick)
                                .child("h6", |h6| {
                                    h6.class("mb-1").text(&contact.name).text(" ").child(
                                        "span",
                                        |badge| {
                                            badge
                                                .class("badge")
                                                .class(network_badge_class)
                                                .text(&contact.network)
                                        },
                                    )
                                })
                                .child("small", |small| {
                                    small
                                        .class("text-muted")
                                        .class("mono")
                                        .attr("title", &contact.address)
                                        .text(&address_short)
                                })
                        })
                        .child("div", |btns| {
                            btns.class("btn-group")
                                .class("btn-group-sm")
                                .child("button", |btn| {
                                    btn.class("btn")
                                        .class("btn-outline-primary")
                                        .attr("onclick", &copy_onclick)
                                        .attr("title", "Copy address")
                                        .child("i", |i| i.class("bi").class("bi-clipboard"))
                                })
                                .child("button", |btn| {
                                    btn.class("btn")
                                        .class("btn-outline-secondary")
                                        .attr("onclick", &edit_onclick)
                                        .attr("title", "Edit")
                                        .child("i", |i| i.class("bi").class("bi-pencil"))
                                })
                                .child("button", |btn| {
                                    btn.class("btn")
                                        .class("btn-outline-danger")
                                        .attr("onclick", &delete_onclick)
                                        .attr("title", "Delete")
                                        .child("i", |i| i.class("bi").class("bi-trash"))
                                })
                        })
                })
        });
    }

    list_group.render()
}

/// Render contacts as dropdown options for address selection.
///
/// # Arguments
///
/// * `contacts_json` - JSON string containing an array of contact objects
/// * `network` - Network filter ("mainnet", "testnet", or empty for all)
///
/// # Returns
///
/// HTML string containing option elements for a select dropdown.
#[wasm_bindgen]
pub fn render_contacts_dropdown(contacts_json: &str, network: &str) -> String {
    let contacts: Vec<Contact> = match serde_json::from_str(contacts_json) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };

    let filtered: Vec<&Contact> = if network.is_empty() {
        contacts.iter().collect()
    } else {
        contacts.iter().filter(|c| c.network == network).collect()
    };

    if filtered.is_empty() {
        return String::new();
    }

    let mut options = Element::new("optgroup").attr("label", "Contacts");

    for contact in filtered {
        let address_short = if contact.address.len() > 20 {
            format!("{}...", &contact.address[..20])
        } else {
            contact.address.clone()
        };

        let label = format!("{} ({})", contact.name, address_short);

        options = options.child("option", |opt| {
            opt.attr("value", &contact.address).text(&label)
        });
    }

    options.render()
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

    #[test]
    fn test_render_balance_card() {
        let html = render_balance_card(123456789, Some("Test Wallet".to_string()));
        assert!(html.contains("1.23456789"));
        assert!(html.contains("Test Wallet"));
        assert!(html.contains("ZEC"));
        assert!(html.contains("card"));
    }

    #[test]
    fn test_render_empty_state() {
        let html = render_empty_state("No transactions yet", "bi-inbox");
        assert!(html.contains("No transactions yet"));
        assert!(html.contains("bi-inbox"));
    }

    #[test]
    fn test_format_zec() {
        assert_eq!(format_zec(100_000_000), "1.00000000");
        assert_eq!(format_zec(123456789), "1.23456789");
        assert_eq!(format_zec(0), "0.00000000");
    }
}
