//! Shared data types for Zcash wallet operations.
//!
//! This module contains data structures used across the codebase for
//! representing transactions, viewing keys, and wallet data.

use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::Network;

/// Network identifier for Zcash operations.
///
/// This enum provides a serde-compatible wrapper around network identification,
/// serializing as lowercase strings ("mainnet", "testnet", "regtest") for
/// JSON compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkKind {
    /// Zcash mainnet - real value transactions.
    Mainnet,
    /// Zcash testnet - for development and testing.
    Testnet,
    /// Zcash regtest - local regression testing.
    Regtest,
}

impl NetworkKind {
    /// Convert to the zcash_protocol Network type.
    ///
    /// Note: Regtest is treated as TestNetwork since zcash_protocol
    /// doesn't have a separate Regtest variant.
    pub fn to_network(self) -> Network {
        match self {
            NetworkKind::Mainnet => Network::MainNetwork,
            NetworkKind::Testnet | NetworkKind::Regtest => Network::TestNetwork,
        }
    }

    /// Get the string representation of the network.
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkKind::Mainnet => "mainnet",
            NetworkKind::Testnet => "testnet",
            NetworkKind::Regtest => "regtest",
        }
    }
}

impl From<Network> for NetworkKind {
    fn from(network: Network) -> Self {
        match network {
            Network::MainNetwork => NetworkKind::Mainnet,
            Network::TestNetwork => NetworkKind::Testnet,
        }
    }
}

impl core::fmt::Display for NetworkKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for NetworkKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NetworkKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Ok(NetworkKind::Mainnet),
            "testnet" | "test" => Ok(NetworkKind::Testnet),
            "regtest" => Ok(NetworkKind::Regtest),
            _ => Err(serde::de::Error::custom(format!("unknown network: {}", s))),
        }
    }
}

/// Type of viewing key.
///
/// Represents the different types of Zcash viewing keys that can be parsed
/// and used for transaction decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewingKeyType {
    /// Unified Full Viewing Key - can view all shielded pools.
    Ufvk,
    /// Unified Incoming Viewing Key - can detect incoming transactions.
    Uivk,
    /// Legacy Sapling Extended Full Viewing Key - Sapling pool only.
    SaplingExtFvk,
}

impl ViewingKeyType {
    /// Get the string representation of the viewing key type (lowercase, for serialization).
    pub fn as_str(&self) -> &'static str {
        match self {
            ViewingKeyType::Ufvk => "ufvk",
            ViewingKeyType::Uivk => "uivk",
            ViewingKeyType::SaplingExtFvk => "sapling_extfvk",
        }
    }

    /// Get the user-friendly display name of the viewing key type.
    pub fn display_name(&self) -> &'static str {
        match self {
            ViewingKeyType::Ufvk => "UFVK",
            ViewingKeyType::Uivk => "UIVK",
            ViewingKeyType::SaplingExtFvk => "Sapling ExtFVK",
        }
    }
}

impl core::fmt::Display for ViewingKeyType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for ViewingKeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ViewingKeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "ufvk" => Ok(ViewingKeyType::Ufvk),
            "uivk" => Ok(ViewingKeyType::Uivk),
            "sapling_extfvk" | "sapling extfvk" => Ok(ViewingKeyType::SaplingExtFvk),
            _ => Err(serde::de::Error::custom(format!(
                "unknown viewing key type: {}",
                s
            ))),
        }
    }
}

/// A fully parsed and decrypted Zcash transaction.
///
/// Contains all components of a transaction including transparent inputs/outputs
/// and shielded data from Sapling and Orchard pools. Shielded outputs are
/// decrypted using the provided viewing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedTransaction {
    /// The transaction identifier (hash) as a hex string.
    pub txid: String,
    /// Decrypted Sapling shielded outputs.
    pub sapling_outputs: Vec<DecryptedSaplingOutput>,
    /// Decrypted Orchard shielded actions.
    pub orchard_actions: Vec<DecryptedOrchardAction>,
    /// Transparent inputs spending previous outputs.
    pub transparent_inputs: Vec<TransparentInput>,
    /// Transparent outputs creating new UTXOs.
    pub transparent_outputs: Vec<TransparentOutput>,
    /// Transaction fee in zatoshis, if calculable.
    pub fee: Option<u64>,
}

/// A decrypted Sapling shielded output.
///
/// Represents a note received in the Sapling shielded pool. The value and memo
/// are only available if the output was successfully decrypted with the viewing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedSaplingOutput {
    /// Zero-based index of this output within the transaction's Sapling bundle.
    pub index: usize,
    /// Note value in zatoshis (1 ZEC = 100,000,000 zatoshis). Zero if not decrypted.
    pub value: u64,
    /// Memo field contents. Empty or "(encrypted)" if not decrypted.
    pub memo: String,
    /// Recipient address, if available from decryption.
    pub address: Option<String>,
    /// Note commitment (cmu) as a hex string. Used to identify the note on-chain.
    pub note_commitment: String,
    /// Nullifier as a hex string. Used to detect when this note is spent.
    pub nullifier: Option<String>,
}

/// A decrypted Orchard shielded action.
///
/// Represents a note in the Orchard shielded pool. Orchard uses "actions" which
/// combine an input (spend) and output (receive) in a single structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedOrchardAction {
    /// Zero-based index of this action within the transaction's Orchard bundle.
    pub index: usize,
    /// Note value in zatoshis. Zero if not decrypted.
    pub value: u64,
    /// Memo field contents. Empty or "(encrypted)" if not decrypted.
    pub memo: String,
    /// Recipient address, if available from decryption.
    pub address: Option<String>,
    /// Note commitment (cmx) as a hex string.
    pub note_commitment: String,
    /// Nullifier as a hex string. Present for all Orchard actions.
    pub nullifier: Option<String>,
}

/// A transparent transaction input.
///
/// References a previous transaction output (UTXO) being spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentInput {
    /// Zero-based index of this input within the transaction.
    pub index: usize,
    /// Transaction ID of the output being spent, as a hex string.
    pub prevout_txid: String,
    /// Output index within the referenced transaction.
    pub prevout_index: u32,
}

/// A transparent transaction output.
///
/// Creates a new UTXO that can be spent by the holder of the corresponding private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentOutput {
    /// Zero-based index of this output within the transaction.
    pub index: usize,
    /// Output value in zatoshis.
    pub value: u64,
    /// The locking script (scriptPubKey) as a hex string.
    pub script_pubkey: String,
    /// Decoded transparent address, if the script is a standard P2PKH or P2SH.
    pub address: Option<String>,
}

/// Information about a parsed viewing key.
///
/// Returned by `parse_viewing_key` to indicate whether a key is valid
/// and what capabilities it provides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewingKeyInfo {
    /// Whether the viewing key was successfully parsed.
    pub valid: bool,
    /// Type of viewing key. None if the key is invalid.
    pub key_type: Option<ViewingKeyType>,
    /// User-friendly display name for the key type. None if the key is invalid.
    pub key_type_display: Option<String>,
    /// Whether the key can view Sapling shielded transactions.
    pub has_sapling: bool,
    /// Whether the key can view Orchard shielded transactions.
    pub has_orchard: bool,
    /// Network the key is valid for.
    pub network: Option<NetworkKind>,
    /// Error message if parsing failed.
    pub error: Option<String>,
}

/// Result of a transaction decryption operation.
///
/// Wraps the decryption result with success/error status for easy
/// handling in JavaScript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionResult {
    /// Whether decryption completed without errors.
    pub success: bool,
    /// The decrypted transaction data, if successful.
    pub transaction: Option<DecryptedTransaction>,
    /// Error message if decryption failed.
    pub error: Option<String>,
}

// ============================================================================
// Scanner Types
// ============================================================================

/// Pool identifier for Zcash value transfers.
///
/// Zcash has three pools: Transparent (public), Sapling (shielded), and Orchard (shielded).
/// This enum provides type-safe pool identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pool {
    /// Transparent pool (public, like Bitcoin).
    Transparent,
    /// Sapling shielded pool (introduced in Sapling upgrade).
    Sapling,
    /// Orchard shielded pool (introduced in NU5).
    Orchard,
}

impl Pool {
    /// Get the string representation of the pool.
    pub fn as_str(&self) -> &'static str {
        match self {
            Pool::Transparent => "transparent",
            Pool::Sapling => "sapling",
            Pool::Orchard => "orchard",
        }
    }
}

impl core::fmt::Display for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Pool {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Pool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "transparent" => Ok(Pool::Transparent),
            "sapling" => Ok(Pool::Sapling),
            "orchard" => Ok(Pool::Orchard),
            _ => Err(serde::de::Error::custom(format!("unknown pool: {}", s))),
        }
    }
}

/// A note/output found during transaction scanning.
///
/// Represents either a shielded note (Sapling or Orchard) discovered by trial
/// decryption, or a transparent output. Contains all relevant data for balance tracking.
///
/// For transparent outputs, `commitment` and `nullifier` will be empty/None since
/// transparent outputs don't use these cryptographic mechanisms. Instead, transparent
/// outputs are identified by txid:output_index and spent via transparent inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedNote {
    /// Zero-based index of this output within the transaction.
    pub output_index: usize,
    /// The pool this note/output belongs to.
    pub pool: Pool,
    /// Value in zatoshis. Zero if decryption failed (shielded only).
    pub value: u64,
    /// Note commitment as a hex string (cmu for Sapling, cmx for Orchard).
    /// Empty for transparent outputs.
    pub commitment: String,
    /// Nullifier for shielded notes, used to detect when it's spent.
    /// None for transparent outputs (they use input references instead).
    pub nullifier: Option<String>,
    /// Memo field contents if decrypted and valid UTF-8.
    /// None for transparent outputs.
    pub memo: Option<String>,
    /// Recipient address if available.
    pub address: Option<String>,
}

/// A nullifier found in a transaction, indicating a spent shielded note.
///
/// When scanning transactions, nullifiers reveal which shielded notes have been spent.
/// By tracking nullifiers, we can compute the wallet's unspent balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentNullifier {
    /// The shielded pool this nullifier belongs to.
    pub pool: Pool,
    /// The nullifier as a hex string.
    pub nullifier: String,
}

/// A transparent input found in a transaction, indicating a spent transparent output.
///
/// Transparent outputs are spent by referencing them via txid:output_index.
/// By tracking these inputs, we can mark transparent outputs as spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparentSpend {
    /// Transaction ID of the output being spent, as a hex string.
    pub prevout_txid: String,
    /// Output index within the referenced transaction.
    pub prevout_index: u32,
}

/// Result of marking notes as spent.
///
/// Contains both the count of notes that were marked as spent and
/// any spends that could not be matched to existing notes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MarkSpentResult {
    /// Number of notes that were marked as spent.
    pub marked_count: usize,
    /// Transparent spends that did not match any tracked notes.
    /// These may indicate transactions scanned out of order.
    pub unmatched_transparent: Vec<TransparentSpend>,
    /// Shielded nullifiers that did not match any tracked notes.
    /// These may indicate transactions scanned out of order.
    pub unmatched_nullifiers: Vec<SpentNullifier>,
}

impl MarkSpentResult {
    /// Check if there are any unmatched spends.
    pub fn has_unmatched(&self) -> bool {
        !self.unmatched_transparent.is_empty() || !self.unmatched_nullifiers.is_empty()
    }
}

/// A transparent output found during scanning.
///
/// Simpler than `TransparentOutput` - only contains data needed for balance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedTransparentOutput {
    /// Zero-based index of this output within the transaction.
    pub index: usize,
    /// Output value in zatoshis.
    pub value: u64,
    /// Decoded transparent address, if available.
    pub address: Option<String>,
}

/// Result of scanning a transaction for notes and nullifiers.
///
/// Contains all notes/outputs belonging to the wallet found in the transaction,
/// as well as nullifiers and transparent spends that indicate previously-received
/// notes/outputs being spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Transaction ID as a hex string.
    pub txid: String,
    /// Notes/outputs found belonging to the viewing key (shielded and transparent).
    pub notes: Vec<ScannedNote>,
    /// Nullifiers found (indicating spent shielded notes).
    pub spent_nullifiers: Vec<SpentNullifier>,
    /// Transparent inputs found (indicating spent transparent outputs).
    pub transparent_spends: Vec<TransparentSpend>,
    /// Total transparent value received (for quick reference).
    pub transparent_received: u64,
    /// Raw transparent outputs (kept for backward compatibility).
    pub transparent_outputs: Vec<ScannedTransparentOutput>,
}

/// Result of a transaction scan operation.
///
/// Wraps the scan result with success/error status for JavaScript interop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTransactionResult {
    /// Whether scanning completed without errors.
    pub success: bool,
    /// The scan result, if successful.
    pub result: Option<ScanResult>,
    /// Error message if scanning failed.
    pub error: Option<String>,
}

// ============================================================================
// Wallet Types
// ============================================================================

/// Result of a wallet generation or restoration operation.
///
/// Contains the wallet's addresses, viewing key, and seed phrase.
/// All sensitive data should be handled carefully by the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletResult {
    /// Whether the wallet operation completed successfully.
    pub success: bool,
    /// The 24-word BIP39 seed phrase. Handle with extreme care.
    pub seed_phrase: Option<String>,
    /// Network the wallet was generated for.
    pub network: NetworkKind,
    /// BIP32/ZIP32 account index used for derivation.
    pub account_index: u32,
    /// Address/diversifier index used for derivation.
    pub address_index: u32,
    /// Unified address containing all receiver types.
    pub unified_address: Option<String>,
    /// Legacy transparent address (t-addr).
    pub transparent_address: Option<String>,
    /// Unified Full Viewing Key for watching incoming transactions.
    pub unified_full_viewing_key: Option<String>,
    /// Error message if the operation failed.
    pub error: Option<String>,
}

// ============================================================================
// Storage Types (SQLite-compatible)
// ============================================================================
//
// These types are designed to be compatible with SQLite storage while also
// working with localStorage JSON serialization. They follow relational
// database conventions with primary keys and foreign key relationships.

/// A wallet stored in the database/localStorage.
///
/// Represents the "wallets" table with the following columns:
/// - id: TEXT PRIMARY KEY
/// - alias: TEXT NOT NULL
/// - network: TEXT NOT NULL
/// - seed_phrase: TEXT NOT NULL
/// - account_index: INTEGER NOT NULL
/// - unified_address: TEXT
/// - transparent_address: TEXT
/// - unified_full_viewing_key: TEXT
/// - created_at: TEXT (ISO 8601)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredWallet {
    /// Unique wallet identifier (e.g., "wallet_1234567890").
    pub id: String,
    /// User-friendly name for the wallet.
    pub alias: String,
    /// Network this wallet is for.
    pub network: NetworkKind,
    /// The 24-word BIP39 seed phrase. Handle with extreme care.
    pub seed_phrase: String,
    /// BIP32/ZIP32 account index.
    pub account_index: u32,
    /// Primary unified address (at index 0).
    pub unified_address: String,
    /// Primary transparent address (at index 0).
    pub transparent_address: String,
    /// Unified Full Viewing Key for scanning.
    pub unified_full_viewing_key: String,
    /// Creation timestamp in ISO 8601 format.
    pub created_at: String,
}

impl StoredWallet {
    /// Generate a unique wallet ID based on current timestamp.
    pub fn generate_id() -> String {
        // In WASM, we'll use a timestamp passed from JavaScript
        // For now, use a placeholder format
        format!(
            "wallet_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        )
    }

    /// Create a new StoredWallet from wallet generation result.
    pub fn from_wallet_result(
        result: &WalletResult,
        alias: String,
        id: String,
        created_at: String,
    ) -> Option<Self> {
        if !result.success {
            return None;
        }

        Some(StoredWallet {
            id,
            alias,
            network: result.network,
            seed_phrase: result.seed_phrase.clone()?,
            account_index: result.account_index,
            unified_address: result.unified_address.clone()?,
            transparent_address: result.transparent_address.clone()?,
            unified_full_viewing_key: result.unified_full_viewing_key.clone()?,
            created_at,
        })
    }
}

/// A derived address stored in the database/localStorage.
///
/// Represents both transparent_addresses and unified_addresses tables:
/// - wallet_id: TEXT NOT NULL (FK to wallets)
/// - address_index: INTEGER NOT NULL
/// - address: TEXT NOT NULL
/// - PRIMARY KEY (wallet_id, address_index)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivedAddress {
    /// Foreign key to the wallet.
    pub wallet_id: String,
    /// The derivation index.
    pub address_index: u32,
    /// The derived address string.
    pub address: String,
}

/// A note stored in the database/localStorage.
///
/// Represents the "notes" table with the following columns:
/// - id: TEXT PRIMARY KEY (txid-pool-output_index)
/// - wallet_id: TEXT NOT NULL (FK to wallets)
/// - txid: TEXT NOT NULL
/// - output_index: INTEGER NOT NULL
/// - pool: TEXT NOT NULL
/// - value: INTEGER NOT NULL (zatoshis)
/// - commitment: TEXT
/// - nullifier: TEXT
/// - memo: TEXT
/// - address: TEXT
/// - spent_txid: TEXT (null if unspent)
/// - spent_at_height: INTEGER (null if unspent)
/// - created_at: TEXT (ISO 8601)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredNote {
    /// Unique note identifier: "{txid}-{pool}-{output_index}".
    pub id: String,
    /// Foreign key to the wallet that owns this note.
    pub wallet_id: String,
    /// Transaction ID where this note was received.
    pub txid: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// The pool this note belongs to.
    pub pool: Pool,
    /// Value in zatoshis.
    pub value: u64,
    /// Note commitment (cmu for Sapling, cmx for Orchard).
    /// Empty for transparent outputs.
    pub commitment: Option<String>,
    /// Nullifier for shielded notes.
    /// None for transparent outputs.
    pub nullifier: Option<String>,
    /// Memo field contents if available.
    pub memo: Option<String>,
    /// Recipient address if available.
    pub address: Option<String>,
    /// Transaction ID where this note was spent, if spent.
    pub spent_txid: Option<String>,
    /// Block height where this note was spent, if spent.
    pub spent_at_height: Option<u32>,
    /// Creation timestamp in ISO 8601 format.
    pub created_at: String,
}

impl StoredNote {
    /// Generate the unique ID for a note.
    pub fn generate_id(txid: &str, pool: Pool, output_index: u32) -> String {
        format!("{}-{}-{}", txid, pool.as_str(), output_index)
    }

    /// Create a new StoredNote from a scanned note.
    pub fn from_scanned_note(
        note: &ScannedNote,
        txid: &str,
        wallet_id: &str,
        created_at: &str,
    ) -> Self {
        let id = Self::generate_id(txid, note.pool, note.output_index as u32);
        StoredNote {
            id,
            wallet_id: wallet_id.to_string(),
            txid: txid.to_string(),
            output_index: note.output_index as u32,
            pool: note.pool,
            value: note.value,
            commitment: if note.commitment.is_empty() {
                None
            } else {
                Some(note.commitment.clone())
            },
            nullifier: note.nullifier.clone(),
            memo: note.memo.clone(),
            address: note.address.clone(),
            spent_txid: None,
            spent_at_height: None,
            created_at: created_at.to_string(),
        }
    }

    /// Mark this note as spent.
    pub fn mark_spent(&mut self, spent_txid: &str, spent_at_height: Option<u32>) {
        self.spent_txid = Some(spent_txid.to_string());
        self.spent_at_height = spent_at_height;
    }

    /// Check if this note is spent.
    pub fn is_spent(&self) -> bool {
        self.spent_txid.is_some()
    }

    /// Check if this note has a positive value.
    pub fn has_value(&self) -> bool {
        self.value > 0
    }
}

/// Collection of notes for balance calculation and storage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoteCollection {
    /// All stored notes.
    pub notes: Vec<StoredNote>,
}

impl NoteCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self { notes: Vec::new() }
    }

    /// Add or update a note in the collection.
    /// Returns true if a new note was added, false if an existing note was updated.
    pub fn add_or_update(&mut self, note: StoredNote) -> bool {
        if let Some(existing) = self.notes.iter_mut().find(|n| n.id == note.id) {
            *existing = note;
            false
        } else {
            self.notes.push(note);
            true
        }
    }

    /// Mark notes as spent by matching nullifiers.
    /// Returns a result containing the count of notes marked and any unmatched nullifiers.
    pub fn mark_spent_by_nullifiers(
        &mut self,
        nullifiers: &[SpentNullifier],
        spending_txid: &str,
        spent_at_height: Option<u32>,
    ) -> MarkSpentResult {
        let mut result = MarkSpentResult::default();
        for nf in nullifiers {
            let mut found = false;
            for note in &mut self.notes {
                if note.nullifier.as_deref() == Some(&nf.nullifier) && note.spent_txid.is_none() {
                    note.mark_spent(spending_txid, spent_at_height);
                    result.marked_count += 1;
                    found = true;
                    break; // Each nullifier should only match one note
                }
            }
            if !found {
                result.unmatched_nullifiers.push(nf.clone());
            }
        }
        result
    }

    /// Mark transparent notes as spent by matching prevout references.
    /// Returns a result containing the count of notes marked and any unmatched spends.
    pub fn mark_spent_by_transparent(
        &mut self,
        spends: &[TransparentSpend],
        spending_txid: &str,
        spent_at_height: Option<u32>,
    ) -> MarkSpentResult {
        let mut result = MarkSpentResult::default();
        for spend in spends {
            let mut found = false;
            for note in &mut self.notes {
                if note.pool == Pool::Transparent
                    && note.txid == spend.prevout_txid
                    && note.output_index == spend.prevout_index
                    && note.spent_txid.is_none()
                {
                    note.mark_spent(spending_txid, spent_at_height);
                    result.marked_count += 1;
                    found = true;
                    break; // Each spend should only match one note
                }
            }
            if !found {
                result.unmatched_transparent.push(spend.clone());
            }
        }
        result
    }

    /// Get all unspent notes with positive value.
    pub fn unspent_notes(&self) -> Vec<&StoredNote> {
        self.notes
            .iter()
            .filter(|n| !n.is_spent() && n.has_value())
            .collect()
    }

    /// Calculate total balance of unspent notes.
    pub fn total_balance(&self) -> u64 {
        self.unspent_notes().iter().map(|n| n.value).sum()
    }

    /// Calculate balance by pool.
    pub fn balance_by_pool(&self) -> std::collections::HashMap<Pool, u64> {
        let mut balances = std::collections::HashMap::new();
        for note in self.unspent_notes() {
            *balances.entry(note.pool).or_insert(0) += note.value;
        }
        balances
    }

    /// Get all notes for a specific wallet.
    pub fn notes_for_wallet(&self, wallet_id: &str) -> Vec<&StoredNote> {
        self.notes
            .iter()
            .filter(|n| n.wallet_id == wallet_id)
            .collect()
    }
}

// ============================================================================
// Ledger Types
// ============================================================================

/// A ledger entry representing a single transaction in the wallet's history.
///
/// Each entry aggregates all notes (received and spent) from a single transaction,
/// providing a transaction-level view for history display and tax reporting.
/// The primary key is (wallet_id, txid).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Transaction ID (primary key component).
    pub txid: String,
    /// Foreign key to the wallet this entry belongs to (primary key component).
    pub wallet_id: String,
    /// Block height where this transaction was mined (None if unconfirmed).
    pub block_height: Option<u32>,
    /// Block timestamp as ISO 8601 string (None if unconfirmed).
    pub timestamp: Option<String>,
    /// Total value received in this transaction (sum of all received notes).
    pub value_received: u64,
    /// Total value spent in this transaction (sum of notes we spent).
    pub value_spent: u64,
    /// Net change to wallet balance (received - spent as signed integer).
    /// Positive = incoming, negative = outgoing.
    pub net_change: i64,
    /// Transaction fee in zatoshis (if we paid it, otherwise 0).
    pub fee_paid: u64,
    /// IDs of notes received in this transaction.
    pub received_note_ids: Vec<String>,
    /// IDs of notes spent in this transaction (notes that were ours).
    pub spent_note_ids: Vec<String>,
    /// Aggregated memos from received notes (non-empty memos only).
    pub memos: Vec<String>,
    /// Primary pool involved: "orchard", "sapling", "transparent", or "mixed".
    pub primary_pool: String,
    /// When this entry was first created/scanned (ISO 8601).
    pub created_at: String,
    /// When this entry was last updated (ISO 8601).
    pub updated_at: String,
}

impl LedgerEntry {
    /// Generate the unique ID for a ledger entry.
    pub fn generate_id(wallet_id: &str, txid: &str) -> String {
        format!("{}-{}", wallet_id, txid)
    }

    /// Check if this is an incoming transaction (net positive).
    pub fn is_incoming(&self) -> bool {
        self.net_change > 0
    }

    /// Check if this is an outgoing transaction (net negative).
    pub fn is_outgoing(&self) -> bool {
        self.net_change < 0
    }

    /// Create a ledger entry from a scan result and note information.
    ///
    /// # Arguments
    /// * `scan_result` - The result from scanning a transaction
    /// * `wallet_id` - The wallet this entry belongs to
    /// * `received_note_ids` - IDs of notes that were added to our wallet
    /// * `spent_note_ids` - IDs of notes that were spent (from previous transactions)
    /// * `spent_values` - Values of the notes that were spent
    /// * `timestamp` - Current timestamp for created_at/updated_at
    pub fn from_scan_result(
        scan_result: &ScanResult,
        wallet_id: &str,
        received_note_ids: Vec<String>,
        spent_note_ids: Vec<String>,
        spent_values: &[u64],
        timestamp: &str,
    ) -> Self {
        // Calculate value received from notes
        let value_received: u64 = scan_result
            .notes
            .iter()
            .filter(|n| n.value > 0)
            .map(|n| n.value)
            .sum();

        // Calculate value spent
        let value_spent: u64 = spent_values.iter().sum();

        // Net change (signed)
        let net_change = value_received as i64 - value_spent as i64;

        // Collect non-empty memos
        let memos: Vec<String> = scan_result
            .notes
            .iter()
            .filter_map(|n| n.memo.clone())
            .filter(|m| !m.is_empty())
            .collect();

        // Determine primary pool
        let pools: std::collections::HashSet<Pool> =
            scan_result.notes.iter().map(|n| n.pool).collect();
        let primary_pool = if pools.len() > 1 {
            "mixed".to_string()
        } else if pools.contains(&Pool::Orchard) {
            "orchard".to_string()
        } else if pools.contains(&Pool::Sapling) {
            "sapling".to_string()
        } else if pools.contains(&Pool::Transparent) {
            "transparent".to_string()
        } else {
            "unknown".to_string()
        };

        LedgerEntry {
            txid: scan_result.txid.clone(),
            wallet_id: wallet_id.to_string(),
            block_height: None,
            timestamp: None,
            value_received,
            value_spent,
            net_change,
            fee_paid: 0, // Fee calculation requires knowing all inputs belonged to us
            received_note_ids,
            spent_note_ids,
            memos,
            primary_pool,
            created_at: timestamp.to_string(),
            updated_at: timestamp.to_string(),
        }
    }
}

/// Collection of ledger entries for storage and manipulation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LedgerCollection {
    /// All ledger entries.
    pub entries: Vec<LedgerEntry>,
}

impl LedgerCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Get an entry by wallet_id and txid.
    pub fn get_entry(&self, wallet_id: &str, txid: &str) -> Option<&LedgerEntry> {
        self.entries
            .iter()
            .find(|e| e.wallet_id == wallet_id && e.txid == txid)
    }

    /// Get a mutable entry by wallet_id and txid.
    pub fn get_entry_mut(&mut self, wallet_id: &str, txid: &str) -> Option<&mut LedgerEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.wallet_id == wallet_id && e.txid == txid)
    }

    /// Add or update an entry in the collection.
    /// Returns true if a new entry was added, false if an existing entry was updated.
    pub fn add_or_update(&mut self, entry: LedgerEntry) -> bool {
        if let Some(existing) = self.get_entry_mut(&entry.wallet_id, &entry.txid) {
            // Update existing entry
            existing.block_height = entry.block_height.or(existing.block_height);
            existing.timestamp = entry.timestamp.or(existing.timestamp.take());
            existing.value_received = entry.value_received;
            existing.value_spent = entry.value_spent;
            existing.net_change = entry.net_change;
            existing.fee_paid = entry.fee_paid;
            existing.received_note_ids = entry.received_note_ids;
            existing.spent_note_ids = entry.spent_note_ids;
            existing.memos = entry.memos;
            existing.primary_pool = entry.primary_pool;
            existing.updated_at = entry.updated_at;
            false
        } else {
            self.entries.push(entry);
            true
        }
    }

    /// Get all entries for a wallet, sorted by block_height descending (newest first).
    /// Entries without block_height come first (unconfirmed).
    pub fn entries_for_wallet(&self, wallet_id: &str) -> Vec<&LedgerEntry> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.wallet_id == wallet_id)
            .collect();
        // Sort: None (unconfirmed) first, then by height descending
        entries.sort_by(|a, b| match (&b.block_height, &a.block_height) {
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (Some(_), None) => core::cmp::Ordering::Less,
            (Some(bh), Some(ah)) => bh.cmp(ah),
            (None, None) => core::cmp::Ordering::Equal,
        });
        entries
    }

    /// Compute balance from ledger entries by summing net changes.
    /// This should match the balance computed from notes.
    pub fn compute_balance(&self, wallet_id: &str) -> i64 {
        self.entries
            .iter()
            .filter(|e| e.wallet_id == wallet_id)
            .map(|e| e.net_change)
            .sum()
    }

    /// Get entries within a date range (for tax reporting).
    /// Dates should be in ISO 8601 format.
    pub fn entries_in_range(
        &self,
        wallet_id: &str,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Vec<&LedgerEntry> {
        self.entries
            .iter()
            .filter(|e| {
                if e.wallet_id != wallet_id {
                    return false;
                }
                if let Some(ts) = &e.timestamp {
                    if let Some(from_ts) = from
                        && ts.as_str() < from_ts
                    {
                        return false;
                    }
                    if let Some(to_ts) = to
                        && ts.as_str() > to_ts
                    {
                        return false;
                    }
                    true
                } else {
                    // Include entries without timestamp
                    true
                }
            })
            .collect()
    }

    /// Export ledger entries as CSV for tax reporting.
    pub fn export_csv(&self, wallet_id: &str) -> String {
        let mut csv =
            String::from("Date,TxID,Received (ZEC),Sent (ZEC),Net (ZEC),Fee (ZEC),Pool,Memo\n");

        for entry in self.entries_for_wallet(wallet_id) {
            let date = entry.timestamp.as_deref().unwrap_or("");
            let received = entry.value_received as f64 / 100_000_000.0;
            let sent = entry.value_spent as f64 / 100_000_000.0;
            let net = entry.net_change as f64 / 100_000_000.0;
            let fee = entry.fee_paid as f64 / 100_000_000.0;
            let memo = entry.memos.join("; ").replace('"', "\"\"");

            csv.push_str(&format!(
                "{},\"{}\",{:.8},{:.8},{:.8},{:.8},{},\"{}\"\n",
                date, entry.txid, received, sent, net, fee, entry.primary_pool, memo
            ));
        }

        csv
    }
}

/// Collection of wallets for storage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WalletCollection {
    /// All stored wallets.
    pub wallets: Vec<StoredWallet>,
}

impl WalletCollection {
    /// Create a new empty collection.
    pub fn new() -> Self {
        Self {
            wallets: Vec::new(),
        }
    }

    /// Check if a wallet alias already exists (case-insensitive).
    pub fn alias_exists(&self, alias: &str) -> bool {
        let normalized = alias.to_lowercase();
        self.wallets
            .iter()
            .any(|w| w.alias.to_lowercase() == normalized)
    }

    /// Add a wallet to the collection.
    /// Returns an error if the alias already exists.
    pub fn add(&mut self, wallet: StoredWallet) -> Result<(), String> {
        if self.alias_exists(&wallet.alias) {
            return Err(format!(
                "A wallet named \"{}\" already exists",
                wallet.alias
            ));
        }
        self.wallets.push(wallet);
        Ok(())
    }

    /// Get a wallet by ID.
    pub fn get_by_id(&self, id: &str) -> Option<&StoredWallet> {
        self.wallets.iter().find(|w| w.id == id)
    }

    /// Delete a wallet by ID.
    /// Returns true if a wallet was deleted.
    pub fn delete(&mut self, id: &str) -> bool {
        let len_before = self.wallets.len();
        self.wallets.retain(|w| w.id != id);
        self.wallets.len() < len_before
    }
}

/// Result of a storage operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageResult<T> {
    /// Whether the operation succeeded.
    pub success: bool,
    /// The result data, if successful.
    pub data: Option<T>,
    /// Error message, if failed.
    pub error: Option<String>,
}

impl<T> StorageResult<T> {
    /// Create a successful result.
    pub fn ok(data: T) -> Self {
        StorageResult {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error result.
    pub fn err(message: impl Into<String>) -> Self {
        StorageResult {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Pool serialization tests
    // ========================================================================

    #[test]
    fn test_pool_serialization() {
        assert_eq!(
            serde_json::to_string(&Pool::Transparent).unwrap(),
            "\"transparent\""
        );
        assert_eq!(
            serde_json::to_string(&Pool::Sapling).unwrap(),
            "\"sapling\""
        );
        assert_eq!(
            serde_json::to_string(&Pool::Orchard).unwrap(),
            "\"orchard\""
        );
    }

    #[test]
    fn test_pool_deserialization() {
        assert_eq!(
            serde_json::from_str::<Pool>("\"transparent\"").unwrap(),
            Pool::Transparent
        );
        assert_eq!(
            serde_json::from_str::<Pool>("\"sapling\"").unwrap(),
            Pool::Sapling
        );
        assert_eq!(
            serde_json::from_str::<Pool>("\"orchard\"").unwrap(),
            Pool::Orchard
        );
        // Case insensitive
        assert_eq!(
            serde_json::from_str::<Pool>("\"ORCHARD\"").unwrap(),
            Pool::Orchard
        );
    }

    #[test]
    fn test_pool_deserialization_error() {
        assert!(serde_json::from_str::<Pool>("\"invalid\"").is_err());
    }

    // ========================================================================
    // ViewingKeyType serialization tests
    // ========================================================================

    #[test]
    fn test_viewing_key_type_serialization() {
        assert_eq!(
            serde_json::to_string(&ViewingKeyType::Ufvk).unwrap(),
            "\"ufvk\""
        );
        assert_eq!(
            serde_json::to_string(&ViewingKeyType::Uivk).unwrap(),
            "\"uivk\""
        );
        assert_eq!(
            serde_json::to_string(&ViewingKeyType::SaplingExtFvk).unwrap(),
            "\"sapling_extfvk\""
        );
    }

    #[test]
    fn test_viewing_key_type_deserialization() {
        assert_eq!(
            serde_json::from_str::<ViewingKeyType>("\"ufvk\"").unwrap(),
            ViewingKeyType::Ufvk
        );
        assert_eq!(
            serde_json::from_str::<ViewingKeyType>("\"uivk\"").unwrap(),
            ViewingKeyType::Uivk
        );
        assert_eq!(
            serde_json::from_str::<ViewingKeyType>("\"sapling_extfvk\"").unwrap(),
            ViewingKeyType::SaplingExtFvk
        );
        // Case insensitive
        assert_eq!(
            serde_json::from_str::<ViewingKeyType>("\"UFVK\"").unwrap(),
            ViewingKeyType::Ufvk
        );
        // Alternative format
        assert_eq!(
            serde_json::from_str::<ViewingKeyType>("\"sapling extfvk\"").unwrap(),
            ViewingKeyType::SaplingExtFvk
        );
    }

    #[test]
    fn test_viewing_key_type_deserialization_error() {
        assert!(serde_json::from_str::<ViewingKeyType>("\"invalid\"").is_err());
    }

    #[test]
    fn test_viewing_key_type_display() {
        assert_eq!(ViewingKeyType::Ufvk.to_string(), "ufvk");
        assert_eq!(ViewingKeyType::Uivk.to_string(), "uivk");
        assert_eq!(ViewingKeyType::SaplingExtFvk.to_string(), "sapling_extfvk");
    }

    // ========================================================================
    // NetworkKind serialization tests
    // ========================================================================

    #[test]
    fn test_network_kind_serialization() {
        assert_eq!(
            serde_json::to_string(&NetworkKind::Mainnet).unwrap(),
            "\"mainnet\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkKind::Testnet).unwrap(),
            "\"testnet\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkKind::Regtest).unwrap(),
            "\"regtest\""
        );
    }

    #[test]
    fn test_network_kind_deserialization() {
        assert_eq!(
            serde_json::from_str::<NetworkKind>("\"mainnet\"").unwrap(),
            NetworkKind::Mainnet
        );
        assert_eq!(
            serde_json::from_str::<NetworkKind>("\"testnet\"").unwrap(),
            NetworkKind::Testnet
        );
        assert_eq!(
            serde_json::from_str::<NetworkKind>("\"main\"").unwrap(),
            NetworkKind::Mainnet
        );
        assert_eq!(
            serde_json::from_str::<NetworkKind>("\"test\"").unwrap(),
            NetworkKind::Testnet
        );
    }

    // ========================================================================
    // StoredNote tests
    // ========================================================================

    #[test]
    fn test_stored_note_generate_id() {
        let id = StoredNote::generate_id("abc123", Pool::Orchard, 5);
        assert_eq!(id, "abc123-orchard-5");

        let id = StoredNote::generate_id("def456", Pool::Transparent, 0);
        assert_eq!(id, "def456-transparent-0");
    }

    #[test]
    fn test_stored_note_from_scanned_note() {
        let scanned = ScannedNote {
            output_index: 2,
            pool: Pool::Sapling,
            value: 100_000_000,
            commitment: "cmu123".to_string(),
            nullifier: Some("nf456".to_string()),
            memo: Some("test memo".to_string()),
            address: Some("zs1addr".to_string()),
        };

        let stored = StoredNote::from_scanned_note(
            &scanned,
            "txid789",
            "wallet_123",
            "2024-01-01T00:00:00Z",
        );

        assert_eq!(stored.id, "txid789-sapling-2");
        assert_eq!(stored.wallet_id, "wallet_123");
        assert_eq!(stored.txid, "txid789");
        assert_eq!(stored.output_index, 2);
        assert_eq!(stored.pool, Pool::Sapling);
        assert_eq!(stored.value, 100_000_000);
        assert_eq!(stored.commitment, Some("cmu123".to_string()));
        assert_eq!(stored.nullifier, Some("nf456".to_string()));
        assert_eq!(stored.memo, Some("test memo".to_string()));
        assert_eq!(stored.address, Some("zs1addr".to_string()));
        assert_eq!(stored.spent_txid, None);
        assert_eq!(stored.created_at, "2024-01-01T00:00:00Z");
    }

    #[test]
    fn test_stored_note_is_spent() {
        let mut note = StoredNote {
            id: "test-orchard-0".to_string(),
            wallet_id: "wallet_1".to_string(),
            txid: "test".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 1000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(!note.is_spent());
        assert!(note.has_value());

        note.mark_spent("spending_tx", Some(100));
        assert!(note.is_spent());
        assert_eq!(note.spent_at_height, Some(100));
    }

    #[test]
    fn test_stored_note_serialization_roundtrip() {
        let note = StoredNote {
            id: "txid-orchard-0".to_string(),
            wallet_id: "wallet_123".to_string(),
            txid: "txid".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 50_000_000,
            commitment: Some("cmx123".to_string()),
            nullifier: Some("nf789".to_string()),
            memo: Some("Hello".to_string()),
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&note).unwrap();
        let deserialized: StoredNote = serde_json::from_str(&json).unwrap();
        assert_eq!(note, deserialized);
    }

    // ========================================================================
    // NoteCollection tests
    // ========================================================================

    #[test]
    fn test_note_collection_add_or_update() {
        let mut collection = NoteCollection::new();

        let note1 = StoredNote {
            id: "tx1-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 1000,
            commitment: None,
            nullifier: Some("nf1".to_string()),
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        // Add new note
        assert!(collection.add_or_update(note1.clone()));
        assert_eq!(collection.notes.len(), 1);

        // Update existing note
        let mut note1_updated = note1.clone();
        note1_updated.value = 2000;
        assert!(!collection.add_or_update(note1_updated));
        assert_eq!(collection.notes.len(), 1);
        assert_eq!(collection.notes[0].value, 2000);
    }

    #[test]
    fn test_note_collection_mark_spent_by_nullifiers() {
        let mut collection = NoteCollection::new();

        collection.notes.push(StoredNote {
            id: "tx1-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 1000,
            commitment: None,
            nullifier: Some("nf1".to_string()),
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        collection.notes.push(StoredNote {
            id: "tx2-sapling-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx2".to_string(),
            output_index: 0,
            pool: Pool::Sapling,
            value: 2000,
            commitment: None,
            nullifier: Some("nf2".to_string()),
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        let nullifiers = vec![SpentNullifier {
            pool: Pool::Orchard,
            nullifier: "nf1".to_string(),
        }];

        let result = collection.mark_spent_by_nullifiers(&nullifiers, "spending_tx", Some(100));
        assert_eq!(result.marked_count, 1);
        assert!(result.unmatched_nullifiers.is_empty());
        assert!(collection.notes[0].is_spent());
        assert_eq!(collection.notes[0].spent_at_height, Some(100));
        assert!(!collection.notes[1].is_spent());
    }

    #[test]
    fn test_note_collection_mark_spent_by_transparent() {
        let mut collection = NoteCollection::new();

        collection.notes.push(StoredNote {
            id: "tx1-transparent-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Transparent,
            value: 1000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: Some("t1addr".to_string()),
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        let spends = vec![TransparentSpend {
            prevout_txid: "tx1".to_string(),
            prevout_index: 0,
        }];

        let result = collection.mark_spent_by_transparent(&spends, "spending_tx", Some(200));
        assert_eq!(result.marked_count, 1);
        assert!(result.unmatched_transparent.is_empty());
        assert!(collection.notes[0].is_spent());
        assert_eq!(collection.notes[0].spent_at_height, Some(200));
    }

    #[test]
    fn test_note_collection_mark_spent_unmatched_nullifiers() {
        let mut collection = NoteCollection::new();

        // Collection has one note with nf1
        collection.notes.push(StoredNote {
            id: "tx1-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 1000,
            commitment: None,
            nullifier: Some("nf1".to_string()),
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Try to spend nf1 (exists) and nf_unknown (doesn't exist)
        let nullifiers = vec![
            SpentNullifier {
                pool: Pool::Orchard,
                nullifier: "nf1".to_string(),
            },
            SpentNullifier {
                pool: Pool::Sapling,
                nullifier: "nf_unknown".to_string(),
            },
        ];

        let result = collection.mark_spent_by_nullifiers(&nullifiers, "spending_tx", Some(100));
        assert_eq!(result.marked_count, 1);
        assert_eq!(result.unmatched_nullifiers.len(), 1);
        assert_eq!(result.unmatched_nullifiers[0].nullifier, "nf_unknown");
        assert!(result.has_unmatched());
    }

    #[test]
    fn test_note_collection_mark_spent_unmatched_transparent() {
        let mut collection = NoteCollection::new();

        // Collection has one transparent note
        collection.notes.push(StoredNote {
            id: "tx1-transparent-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Transparent,
            value: 1000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: Some("t1addr".to_string()),
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Try to spend tx1:0 (exists) and tx_unknown:0 (doesn't exist)
        let spends = vec![
            TransparentSpend {
                prevout_txid: "tx1".to_string(),
                prevout_index: 0,
            },
            TransparentSpend {
                prevout_txid: "tx_unknown".to_string(),
                prevout_index: 0,
            },
        ];

        let result = collection.mark_spent_by_transparent(&spends, "spending_tx", Some(200));
        assert_eq!(result.marked_count, 1);
        assert_eq!(result.unmatched_transparent.len(), 1);
        assert_eq!(result.unmatched_transparent[0].prevout_txid, "tx_unknown");
        assert!(result.has_unmatched());
    }

    #[test]
    fn test_note_collection_balance() {
        let mut collection = NoteCollection::new();

        // Unspent orchard note
        collection.notes.push(StoredNote {
            id: "tx1-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx1".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 1000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Unspent sapling note
        collection.notes.push(StoredNote {
            id: "tx2-sapling-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx2".to_string(),
            output_index: 0,
            pool: Pool::Sapling,
            value: 2000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: None,
            spent_txid: None,
            spent_at_height: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Spent note (should not count)
        collection.notes.push(StoredNote {
            id: "tx3-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "tx3".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 5000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: None,
            spent_txid: Some("tx4".to_string()),
            spent_at_height: Some(300),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        assert_eq!(collection.total_balance(), 3000);
        assert_eq!(collection.unspent_notes().len(), 2);

        let by_pool = collection.balance_by_pool();
        assert_eq!(*by_pool.get(&Pool::Orchard).unwrap_or(&0), 1000);
        assert_eq!(*by_pool.get(&Pool::Sapling).unwrap_or(&0), 2000);
    }

    // ========================================================================
    // StoredWallet tests
    // ========================================================================

    #[test]
    fn test_stored_wallet_serialization_roundtrip() {
        let wallet = StoredWallet {
            id: "wallet_123".to_string(),
            alias: "My Wallet".to_string(),
            network: NetworkKind::Testnet,
            seed_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            account_index: 0,
            unified_address: "utest1...".to_string(),
            transparent_address: "tm1...".to_string(),
            unified_full_viewing_key: "uviewtest1...".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&wallet).unwrap();
        let deserialized: StoredWallet = serde_json::from_str(&json).unwrap();
        assert_eq!(wallet, deserialized);
    }

    // ========================================================================
    // WalletCollection tests
    // ========================================================================

    #[test]
    fn test_wallet_collection_alias_exists() {
        let mut collection = WalletCollection::new();

        collection.wallets.push(StoredWallet {
            id: "wallet_1".to_string(),
            alias: "My Wallet".to_string(),
            network: NetworkKind::Testnet,
            seed_phrase: "test".to_string(),
            account_index: 0,
            unified_address: "u1".to_string(),
            transparent_address: "t1".to_string(),
            unified_full_viewing_key: "ufvk1".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Case-insensitive match
        assert!(collection.alias_exists("My Wallet"));
        assert!(collection.alias_exists("my wallet"));
        assert!(collection.alias_exists("MY WALLET"));
        assert!(!collection.alias_exists("Other Wallet"));
    }

    #[test]
    fn test_wallet_collection_add_duplicate_alias() {
        let mut collection = WalletCollection::new();

        let wallet1 = StoredWallet {
            id: "wallet_1".to_string(),
            alias: "My Wallet".to_string(),
            network: NetworkKind::Testnet,
            seed_phrase: "test1".to_string(),
            account_index: 0,
            unified_address: "u1".to_string(),
            transparent_address: "t1".to_string(),
            unified_full_viewing_key: "ufvk1".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let wallet2 = StoredWallet {
            id: "wallet_2".to_string(),
            alias: "my wallet".to_string(), // Same alias, different case
            network: NetworkKind::Testnet,
            seed_phrase: "test2".to_string(),
            account_index: 0,
            unified_address: "u2".to_string(),
            transparent_address: "t2".to_string(),
            unified_full_viewing_key: "ufvk2".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(collection.add(wallet1).is_ok());
        assert!(collection.add(wallet2).is_err());
        assert_eq!(collection.wallets.len(), 1);
    }

    #[test]
    fn test_wallet_collection_get_and_delete() {
        let mut collection = WalletCollection::new();

        let wallet = StoredWallet {
            id: "wallet_1".to_string(),
            alias: "Test".to_string(),
            network: NetworkKind::Testnet,
            seed_phrase: "test".to_string(),
            account_index: 0,
            unified_address: "u1".to_string(),
            transparent_address: "t1".to_string(),
            unified_full_viewing_key: "ufvk1".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        collection.add(wallet).unwrap();

        assert!(collection.get_by_id("wallet_1").is_some());
        assert!(collection.get_by_id("wallet_2").is_none());

        assert!(collection.delete("wallet_1"));
        assert!(!collection.delete("wallet_1")); // Already deleted
        assert!(collection.get_by_id("wallet_1").is_none());
    }

    // ========================================================================
    // DerivedAddress tests
    // ========================================================================

    #[test]
    fn test_derived_address_serialization() {
        let addr = DerivedAddress {
            wallet_id: "wallet_1".to_string(),
            address_index: 5,
            address: "tm1abc...".to_string(),
        };

        let json = serde_json::to_string(&addr).unwrap();
        let deserialized: DerivedAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, deserialized);
    }

    // ========================================================================
    // LedgerEntry tests
    // ========================================================================

    #[test]
    fn test_ledger_entry_generate_id() {
        let id = LedgerEntry::generate_id("wallet_1", "txid123");
        assert_eq!(id, "wallet_1-txid123");
    }

    #[test]
    fn test_ledger_entry_is_incoming_outgoing() {
        let mut entry = LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: None,
            timestamp: None,
            value_received: 1000,
            value_spent: 0,
            net_change: 1000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        assert!(entry.is_incoming());
        assert!(!entry.is_outgoing());

        entry.net_change = -500;
        assert!(!entry.is_incoming());
        assert!(entry.is_outgoing());

        entry.net_change = 0;
        assert!(!entry.is_incoming());
        assert!(!entry.is_outgoing());
    }

    #[test]
    fn test_ledger_entry_from_scan_result() {
        let scan_result = ScanResult {
            txid: "txid123".to_string(),
            notes: vec![
                ScannedNote {
                    output_index: 0,
                    pool: Pool::Orchard,
                    value: 1000,
                    commitment: "cmu1".to_string(),
                    nullifier: Some("nf1".to_string()),
                    memo: Some("Hello".to_string()),
                    address: None,
                },
                ScannedNote {
                    output_index: 1,
                    pool: Pool::Orchard,
                    value: 500,
                    commitment: "cmu2".to_string(),
                    nullifier: Some("nf2".to_string()),
                    memo: None,
                    address: None,
                },
            ],
            spent_nullifiers: vec![],
            transparent_spends: vec![],
            transparent_received: 0,
            transparent_outputs: vec![],
        };

        let entry = LedgerEntry::from_scan_result(
            &scan_result,
            "wallet_1",
            vec!["note1".to_string(), "note2".to_string()],
            vec!["spent_note".to_string()],
            &[200],
            "2024-01-01T12:00:00Z",
        );

        assert_eq!(entry.txid, "txid123");
        assert_eq!(entry.wallet_id, "wallet_1");
        assert_eq!(entry.value_received, 1500);
        assert_eq!(entry.value_spent, 200);
        assert_eq!(entry.net_change, 1300);
        assert_eq!(entry.memos, vec!["Hello".to_string()]);
        assert_eq!(entry.primary_pool, "orchard");
        assert_eq!(entry.received_note_ids.len(), 2);
        assert_eq!(entry.spent_note_ids.len(), 1);
    }

    #[test]
    fn test_ledger_entry_serialization_roundtrip() {
        let entry = LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: Some(1000),
            timestamp: Some("2024-01-01T12:00:00Z".to_string()),
            value_received: 5000,
            value_spent: 1000,
            net_change: 4000,
            fee_paid: 100,
            received_note_ids: vec!["note1".to_string()],
            spent_note_ids: vec!["note2".to_string()],
            memos: vec!["Test memo".to_string()],
            primary_pool: "sapling".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: LedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    // ========================================================================
    // LedgerCollection tests
    // ========================================================================

    #[test]
    fn test_ledger_collection_add_or_update() {
        let mut collection = LedgerCollection::new();

        let entry1 = LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: None,
            timestamp: None,
            value_received: 1000,
            value_spent: 0,
            net_change: 1000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        // Add new entry
        assert!(collection.add_or_update(entry1.clone()));
        assert_eq!(collection.entries.len(), 1);

        // Update existing entry
        let mut entry1_updated = entry1.clone();
        entry1_updated.value_received = 2000;
        entry1_updated.net_change = 2000;
        entry1_updated.block_height = Some(500);
        assert!(!collection.add_or_update(entry1_updated));
        assert_eq!(collection.entries.len(), 1);
        assert_eq!(collection.entries[0].value_received, 2000);
        assert_eq!(collection.entries[0].block_height, Some(500));
    }

    #[test]
    fn test_ledger_collection_get_entry() {
        let mut collection = LedgerCollection::new();

        let entry = LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: None,
            timestamp: None,
            value_received: 1000,
            value_spent: 0,
            net_change: 1000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        collection.add_or_update(entry);

        assert!(collection.get_entry("w1", "tx1").is_some());
        assert!(collection.get_entry("w1", "tx2").is_none());
        assert!(collection.get_entry("w2", "tx1").is_none());
    }

    #[test]
    fn test_ledger_collection_entries_for_wallet() {
        let mut collection = LedgerCollection::new();

        // Add entries for wallet w1
        collection.add_or_update(LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: Some(100),
            timestamp: None,
            value_received: 1000,
            value_spent: 0,
            net_change: 1000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        });

        collection.add_or_update(LedgerEntry {
            txid: "tx2".to_string(),
            wallet_id: "w1".to_string(),
            block_height: Some(200),
            timestamp: None,
            value_received: 2000,
            value_spent: 0,
            net_change: 2000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "sapling".to_string(),
            created_at: "2024-01-02T00:00:00Z".to_string(),
            updated_at: "2024-01-02T00:00:00Z".to_string(),
        });

        // Add entry for wallet w2
        collection.add_or_update(LedgerEntry {
            txid: "tx3".to_string(),
            wallet_id: "w2".to_string(),
            block_height: Some(150),
            timestamp: None,
            value_received: 500,
            value_spent: 0,
            net_change: 500,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "transparent".to_string(),
            created_at: "2024-01-01T12:00:00Z".to_string(),
            updated_at: "2024-01-01T12:00:00Z".to_string(),
        });

        let w1_entries = collection.entries_for_wallet("w1");
        assert_eq!(w1_entries.len(), 2);
        // Should be sorted by block_height descending (200, then 100)
        assert_eq!(w1_entries[0].block_height, Some(200));
        assert_eq!(w1_entries[1].block_height, Some(100));

        let w2_entries = collection.entries_for_wallet("w2");
        assert_eq!(w2_entries.len(), 1);
    }

    #[test]
    fn test_ledger_collection_compute_balance() {
        let mut collection = LedgerCollection::new();

        // Incoming transaction
        collection.add_or_update(LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: None,
            timestamp: None,
            value_received: 1000,
            value_spent: 0,
            net_change: 1000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        });

        // Outgoing transaction
        collection.add_or_update(LedgerEntry {
            txid: "tx2".to_string(),
            wallet_id: "w1".to_string(),
            block_height: None,
            timestamp: None,
            value_received: 0,
            value_spent: 300,
            net_change: -300,
            fee_paid: 10,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec![],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-02T00:00:00Z".to_string(),
            updated_at: "2024-01-02T00:00:00Z".to_string(),
        });

        assert_eq!(collection.compute_balance("w1"), 700);
        assert_eq!(collection.compute_balance("w2"), 0);
    }

    #[test]
    fn test_ledger_collection_export_csv() {
        let mut collection = LedgerCollection::new();

        collection.add_or_update(LedgerEntry {
            txid: "tx1".to_string(),
            wallet_id: "w1".to_string(),
            block_height: Some(100),
            timestamp: Some("2024-01-01T12:00:00Z".to_string()),
            value_received: 100_000_000, // 1 ZEC
            value_spent: 0,
            net_change: 100_000_000,
            fee_paid: 0,
            received_note_ids: vec![],
            spent_note_ids: vec![],
            memos: vec!["Test memo".to_string()],
            primary_pool: "orchard".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        });

        let csv = collection.export_csv("w1");
        assert!(csv.contains("Date,TxID,Received (ZEC),Sent (ZEC),Net (ZEC),Fee (ZEC),Pool,Memo"));
        assert!(csv.contains("2024-01-01T12:00:00Z"));
        assert!(csv.contains("tx1"));
        assert!(csv.contains("1.00000000")); // 1 ZEC received
        assert!(csv.contains("orchard"));
        assert!(csv.contains("Test memo"));
    }
}
