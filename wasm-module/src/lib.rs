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

use rand::RngCore;
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{Network, NetworkType};

// Re-export types from core library
pub use zcash_wallet_core::{
    DecryptedOrchardAction, DecryptedSaplingOutput, DecryptedTransaction, DecryptionResult,
    NetworkKind, NoteCollection, Pool, ScanResult, ScanTransactionResult, ScannedNote,
    ScannedTransparentOutput, SpentNullifier, StorageResult, StoredNote, StoredWallet,
    TransparentInput, TransparentOutput, TransparentSpend, ViewingKeyInfo, WalletCollection,
    WalletResult,
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
///
/// # Returns
///
/// JSON containing the updated notes array and count of marked notes.
#[wasm_bindgen]
pub fn mark_notes_spent(notes_json: &str, nullifiers_json: &str, spending_txid: &str) -> String {
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
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                error: Some(format!("Failed to parse nullifiers: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let marked_count = collection.mark_spent_by_nullifiers(&nullifiers, spending_txid);

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: collection.notes,
        added: None,
        marked_count: Some(marked_count),
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
///
/// # Returns
///
/// JSON containing the updated notes array and count of marked notes.
#[wasm_bindgen]
pub fn mark_transparent_spent(notes_json: &str, spends_json: &str, spending_txid: &str) -> String {
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
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                error: Some(format!("Failed to parse spends: {}", e)),
            })
            .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
        }
    };

    let marked_count = collection.mark_spent_by_transparent(&spends, spending_txid);

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: collection.notes,
        added: None,
        marked_count: Some(marked_count),
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
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
            }
        },
    };

    let unspent: Vec<StoredNote> = collection
        .unspent_notes()
        .into_iter()
        .cloned()
        .collect();

    serde_json::to_string(&NoteOperationResult {
        success: true,
        notes: unspent,
        added: None,
        marked_count: None,
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
                    error: Some(format!("Failed to parse notes: {}", e)),
                })
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
                .unwrap_or_else(|_| r#"{"success":false,"error":"Serialization error"}"#.to_string());
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
