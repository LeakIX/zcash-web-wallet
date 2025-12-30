//! Transparent transaction building and signing.
//!
//! This module provides functionality to build and sign transparent (t-address)
//! transactions. Shielded transaction signing (Sapling/Orchard) is not yet
//! supported due to the computational cost of proof generation in WASM.
//!
//! The signing process follows ZIP 244 for transaction signature hashes.

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::transaction::sighash::{SignableInput, signature_hash};
use zcash_primitives::transaction::txid::TxIdDigester;
use zcash_primitives::transaction::{TransactionData, TxId, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::{TransparentBuilder, TransparentSigningSet};
use zcash_transparent::bundle::{OutPoint, TxOut};
use zcash_transparent::keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex};
use zip32::AccountId;

use crate::types::{Pool, StoredNote};

/// Errors that can occur during transaction operations.
#[derive(Debug)]
pub enum TransactionError {
    /// Invalid seed phrase.
    InvalidSeedPhrase(String),
    /// Failed to derive spending key.
    SpendingKeyDerivation(String),
    /// Invalid input data.
    InvalidInput(String),
    /// Invalid output data.
    InvalidOutput(String),
    /// Insufficient funds.
    InsufficientFunds { available: u64, required: u64 },
    /// Address not found in wallet.
    AddressNotFound(String),
    /// Transaction building failed.
    BuildFailed(String),
    /// Signing failed.
    SigningFailed(String),
}

impl core::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSeedPhrase(msg) => write!(f, "Invalid seed phrase: {}", msg),
            Self::SpendingKeyDerivation(msg) => {
                write!(f, "Failed to derive spending key: {}", msg)
            }
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::InvalidOutput(msg) => write!(f, "Invalid output: {}", msg),
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(
                    f,
                    "Insufficient funds: available {} zatoshis, required {} zatoshis",
                    available, required
                )
            }
            Self::AddressNotFound(addr) => {
                write!(
                    f,
                    "Address not found in wallet (checked indices 0-999): {}",
                    addr
                )
            }
            Self::BuildFailed(msg) => write!(f, "Transaction build failed: {}", msg),
            Self::SigningFailed(msg) => write!(f, "Transaction signing failed: {}", msg),
        }
    }
}

impl core::error::Error for TransactionError {}

/// A UTXO (unspent transparent output) to be spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID where this output was created.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in zatoshis.
    pub value: u64,
    /// The transparent address that owns this output.
    pub address: String,
    /// The locking script (scriptPubKey) as a hex string.
    /// If not provided, it will be derived from the address.
    pub script_pubkey: Option<String>,
}

impl Utxo {
    /// Create a Utxo from a StoredNote.
    ///
    /// Returns None if the note is not a transparent output or is missing required data.
    pub fn from_stored_note(note: &StoredNote) -> Option<Self> {
        if note.pool != Pool::Transparent {
            return None;
        }

        let address = note.address.as_ref()?.clone();

        Some(Utxo {
            txid: note.txid.clone(),
            vout: note.output_index,
            value: note.value,
            address,
            script_pubkey: None,
        })
    }

    /// Get unspent transparent UTXOs from a list of stored notes.
    pub fn from_stored_notes(notes: &[StoredNote]) -> Vec<Self> {
        notes
            .iter()
            .filter(|n| n.pool == Pool::Transparent && n.spent_txid.is_none() && n.value > 0)
            .filter_map(Self::from_stored_note)
            .collect()
    }
}

/// A recipient for a transparent transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// The recipient's address (transparent or unified).
    pub address: String,
    /// Amount to send in zatoshis.
    pub amount: u64,
}

/// Result of building a transparent transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The signed transaction as a hex string.
    pub tx_hex: String,
    /// The transaction ID (txid).
    pub txid: String,
    /// Total input value in zatoshis.
    pub total_input: u64,
    /// Total output value in zatoshis (excluding fee).
    pub total_output: u64,
    /// Fee in zatoshis.
    pub fee: u64,
}

/// Unsigned transaction bundle ready for signing.
/// This is an intermediate representation used for staged signing.
pub struct UnsignedTransaction {
    /// The unsigned transparent bundle.
    pub bundle: zcash_transparent::bundle::Bundle<zcash_transparent::builder::Unauthorized>,
    /// Signing keys collected during building.
    pub signing_set: TransparentSigningSet,
    /// Total input value in zatoshis.
    pub total_input: u64,
    /// Total output value in zatoshis (excluding fee).
    pub total_output: u64,
    /// Fee in zatoshis.
    pub fee: u64,
    /// The network this transaction is for.
    pub network: Network,
}

/// Find the address index for a given transparent address.
///
/// This function iterates through address indices (0 to max_index) to find
/// which index produces the given address.
///
/// # Arguments
///
/// * `seed_phrase` - The wallet's seed phrase
/// * `network` - The network (mainnet or testnet)
/// * `account` - The account index
/// * `address` - The transparent address to find
/// * `max_index` - Maximum index to search (default 1000)
///
/// # Returns
///
/// The address index if found, or None.
pub fn find_address_index(
    seed_phrase: &str,
    network: Network,
    account: u32,
    address: &str,
    max_index: u32,
) -> Option<u32> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim()).ok()?;
    let seed = mnemonic.to_seed("");

    let account_id = AccountId::try_from(account).ok()?;
    let usk = UnifiedSpendingKey::from_seed(&network, &seed, account_id).ok()?;
    let ufvk = usk.to_unified_full_viewing_key();

    let tfvk = ufvk.transparent()?;
    let ivk = tfvk.derive_external_ivk().ok()?;

    for i in 0..max_index {
        if let Some(child_index) = NonHardenedChildIndex::from_index(i)
            && let Ok(addr) = ivk.derive_address(child_index)
        {
            let encoded = addr.encode(&network);
            if encoded == address {
                return Some(i);
            }
        }
    }

    None
}

/// Derive the transparent account private key.
fn derive_transparent_account_key(
    seed_phrase: &str,
    network: Network,
    account: u32,
) -> Result<AccountPrivKey, TransactionError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim())
        .map_err(|e| TransactionError::InvalidSeedPhrase(e.to_string()))?;
    let seed = mnemonic.to_seed("");

    let account_id = AccountId::try_from(account).map_err(|_| {
        TransactionError::SpendingKeyDerivation("Invalid account index".to_string())
    })?;
    let usk = UnifiedSpendingKey::from_seed(&network, &seed, account_id)
        .map_err(|e| TransactionError::SpendingKeyDerivation(format!("{:?}", e)))?;

    Ok(usk.transparent().clone())
}

/// Parse a transparent address from a string.
fn parse_transparent_address(
    address: &str,
    network: Network,
) -> Result<TransparentAddress, TransactionError> {
    TransparentAddress::decode(&network, address).map_err(|_| {
        TransactionError::InvalidOutput(format!("Invalid transparent address: {}", address))
    })
}

/// Parse a transaction ID from a hex string.
fn parse_txid(txid_hex: &str) -> Result<TxId, TransactionError> {
    let bytes = hex::decode(txid_hex)
        .map_err(|e| TransactionError::InvalidInput(format!("Invalid txid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(TransactionError::InvalidInput(format!(
            "Invalid txid length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    // TxId expects bytes in reversed order (little-endian)
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&bytes);
    txid_bytes.reverse();

    Ok(TxId::from_bytes(txid_bytes))
}

/// Build an unsigned transparent transaction.
///
/// This creates the transaction structure and collects signing keys,
/// but does not compute sighashes or apply signatures.
///
/// # Arguments
///
/// * `seed_phrase` - The wallet's seed phrase
/// * `network` - The network (mainnet or testnet)
/// * `account` - The account index
/// * `utxos` - The UTXOs to spend
/// * `recipients` - The recipients and amounts
/// * `fee` - The transaction fee in zatoshis
///
/// # Returns
///
/// An `UnsignedTransaction` containing the bundle and signing keys.
pub fn build_unsigned_transaction(
    seed_phrase: &str,
    network: Network,
    account: u32,
    utxos: Vec<Utxo>,
    recipients: Vec<Recipient>,
    fee: u64,
) -> Result<UnsignedTransaction, TransactionError> {
    // Validate inputs
    if utxos.is_empty() {
        return Err(TransactionError::InvalidInput(
            "At least one UTXO is required".to_string(),
        ));
    }
    if recipients.is_empty() {
        return Err(TransactionError::InvalidOutput(
            "At least one recipient is required".to_string(),
        ));
    }

    // Calculate totals
    let total_input: u64 = utxos.iter().map(|u| u.value).sum();
    let total_output: u64 = recipients.iter().map(|r| r.amount).sum();
    let required = total_output + fee;

    if total_input < required {
        return Err(TransactionError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    // Derive the account private key
    let account_privkey = derive_transparent_account_key(seed_phrase, network, account)?;

    // Build the transparent bundle and collect signing keys
    let mut builder = TransparentBuilder::empty();
    let mut signing_set = TransparentSigningSet::new();

    // Add inputs
    for utxo in &utxos {
        // Find the address index for this UTXO
        let address_index = find_address_index(seed_phrase, network, account, &utxo.address, 1000)
            .ok_or_else(|| TransactionError::AddressNotFound(utxo.address.clone()))?;

        let child_index = NonHardenedChildIndex::from_index(address_index).ok_or_else(|| {
            TransactionError::InvalidInput(format!("Invalid address index: {}", address_index))
        })?;

        // Derive the secret key and compute the public key
        let secret_key = account_privkey
            .derive_external_secret_key(child_index)
            .map_err(|e| TransactionError::SpendingKeyDerivation(format!("{:?}", e)))?;

        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // Add the secret key to the signing set
        signing_set.add_key(secret_key);

        // Parse the outpoint
        let txid = parse_txid(&utxo.txid)?;
        let outpoint = OutPoint::new(*txid.as_ref(), utxo.vout);

        // Create the TxOut (previous output being spent)
        let value = Zatoshis::from_u64(utxo.value)
            .map_err(|_| TransactionError::InvalidInput("Invalid UTXO value".to_string()))?;

        let address = parse_transparent_address(&utxo.address, network)?;
        let script_pubkey = address.script();

        let txout = TxOut::new(value, script_pubkey.into());

        // Add the input
        builder
            .add_input(pubkey, outpoint, txout)
            .map_err(|e| TransactionError::BuildFailed(format!("Failed to add input: {:?}", e)))?;
    }

    // Add outputs
    for recipient in &recipients {
        let address = parse_transparent_address(&recipient.address, network)?;
        let value = Zatoshis::from_u64(recipient.amount)
            .map_err(|_| TransactionError::InvalidOutput("Invalid output value".to_string()))?;

        builder
            .add_output(&address, value)
            .map_err(|e| TransactionError::BuildFailed(format!("Failed to add output: {:?}", e)))?;
    }

    // Add change output if needed
    let change = total_input - required;
    if change > 0 {
        // Send change back to the first input address
        let change_address = parse_transparent_address(&utxos[0].address, network)?;
        let change_value = Zatoshis::from_u64(change)
            .map_err(|_| TransactionError::InvalidOutput("Invalid change value".to_string()))?;

        builder
            .add_output(&change_address, change_value)
            .map_err(|e| {
                TransactionError::BuildFailed(format!("Failed to add change output: {:?}", e))
            })?;
    }

    // Build the unsigned bundle
    let unsigned_bundle = builder
        .build()
        .ok_or_else(|| TransactionError::BuildFailed("Failed to build bundle".to_string()))?;

    Ok(UnsignedTransaction {
        bundle: unsigned_bundle,
        signing_set,
        total_input,
        total_output,
        fee,
        network,
    })
}

/// Build and sign a transparent transaction.
///
/// This creates a fully signed v5 transaction that can be broadcast to the network.
/// The transaction only contains transparent inputs and outputs (no shielded components).
///
/// # Arguments
///
/// * `seed_phrase` - The wallet's seed phrase
/// * `network` - The network (mainnet or testnet)
/// * `account` - The account index
/// * `utxos` - The UTXOs to spend
/// * `recipients` - The recipients and amounts
/// * `fee` - The transaction fee in zatoshis
/// * `expiry_height` - Block height after which the transaction expires (0 for no expiry)
///
/// # Returns
///
/// A `SignedTransaction` containing the signed transaction hex and metadata.
pub fn build_transparent_transaction(
    seed_phrase: &str,
    network: Network,
    account: u32,
    utxos: Vec<Utxo>,
    recipients: Vec<Recipient>,
    fee: u64,
    expiry_height: u32,
) -> Result<SignedTransaction, TransactionError> {
    // Build the unsigned transaction
    let unsigned =
        build_unsigned_transaction(seed_phrase, network, account, utxos, recipients, fee)?;

    // Get the consensus branch ID for the network
    // Use NU6 (latest network upgrade) for mainnet, NU6 for testnet as well
    let branch_id = BranchId::Nu6;
    let lock_time = 0; // No time lock

    // Create the unsigned TransactionData with only transparent bundle
    let unauthed_tx: TransactionData<zcash_primitives::transaction::Unauthorized> =
        TransactionData::from_parts(
            TxVersion::V5,
            branch_id,
            lock_time,
            BlockHeight::from_u32(expiry_height),
            Some(unsigned.bundle.clone()),
            None, // No Sprout bundle
            None, // No Sapling bundle
            None, // No Orchard bundle
        );

    // Compute the transaction ID parts for sighash computation
    let txid_parts = unauthed_tx.digest(TxIdDigester);

    // Sign the transparent bundle
    let signed_bundle = unsigned
        .bundle
        .apply_signatures(
            |input| {
                *signature_hash(
                    &unauthed_tx,
                    &SignableInput::Transparent(input),
                    &txid_parts,
                )
                .as_ref()
            },
            &unsigned.signing_set,
        )
        .map_err(|e| TransactionError::SigningFailed(format!("{:?}", e)))?;

    // Create the final signed transaction
    let signed_tx: TransactionData<zcash_primitives::transaction::Authorized> =
        TransactionData::from_parts(
            TxVersion::V5,
            branch_id,
            lock_time,
            BlockHeight::from_u32(expiry_height),
            Some(signed_bundle),
            None, // No Sprout bundle
            None, // No Sapling bundle
            None, // No Orchard bundle
        );

    // Compute the transaction ID
    let txid_parts_signed = signed_tx.digest(TxIdDigester);
    let hash_bytes: &[u8] = txid_parts_signed.header_digest.as_bytes();
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(hash_bytes);
    let txid = TxId::from_bytes(txid_bytes);

    // Serialize the transaction to bytes
    let tx_bytes = serialize_transaction(&signed_tx)?;
    let tx_hex = hex::encode(&tx_bytes);

    Ok(SignedTransaction {
        tx_hex,
        txid: hex::encode(txid.as_ref()),
        total_input: unsigned.total_input,
        total_output: unsigned.total_output,
        fee: unsigned.fee,
    })
}

/// Serialize a signed transaction to bytes.
fn serialize_transaction(
    tx: &TransactionData<zcash_primitives::transaction::Authorized>,
) -> Result<Vec<u8>, TransactionError> {
    use std::io::Write;

    let mut bytes = Vec::new();

    // Write transaction version (v5 = 0x05 with overwinter flag)
    // v5 transactions have header = 0x050000080 (little-endian)
    let version_header: u32 = 0x80000005; // Overwinter flag (0x80000000) | version 5
    bytes
        .write_all(&version_header.to_le_bytes())
        .map_err(|e| TransactionError::BuildFailed(format!("Failed to write version: {}", e)))?;

    // Write nVersionGroupId for v5 (ZIP 225)
    let version_group_id: u32 = 0x26A7270A;
    bytes
        .write_all(&version_group_id.to_le_bytes())
        .map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write version group id: {}", e))
        })?;

    // Write consensus branch ID
    let branch_id: u32 = u32::from(BranchId::Nu6);
    bytes
        .write_all(&branch_id.to_le_bytes())
        .map_err(|e| TransactionError::BuildFailed(format!("Failed to write branch id: {}", e)))?;

    // Write lock time
    let lock_time: u32 = 0;
    bytes
        .write_all(&lock_time.to_le_bytes())
        .map_err(|e| TransactionError::BuildFailed(format!("Failed to write lock time: {}", e)))?;

    // Write expiry height
    let expiry_height: u32 = tx.expiry_height().into();
    bytes.write_all(&expiry_height.to_le_bytes()).map_err(|e| {
        TransactionError::BuildFailed(format!("Failed to write expiry height: {}", e))
    })?;

    // Write transparent bundle
    if let Some(bundle) = tx.transparent_bundle() {
        // Write vin count (CompactSize)
        write_compact_size(&mut bytes, bundle.vin.len())?;

        // Write each input
        for vin in &bundle.vin {
            // Write prevout txid (32 bytes)
            let prevout = vin.prevout();
            let txid_bytes: &[u8; 32] = prevout.txid().as_ref();
            bytes.write_all(txid_bytes).map_err(|e| {
                TransactionError::BuildFailed(format!("Failed to write input txid: {}", e))
            })?;

            // Write prevout index
            bytes.write_all(&prevout.n().to_le_bytes()).map_err(|e| {
                TransactionError::BuildFailed(format!("Failed to write input index: {}", e))
            })?;

            // Write scriptSig
            let script_sig = vin.script_sig();
            write_compact_size(&mut bytes, script_sig.0.0.len())?;
            bytes.write_all(&script_sig.0.0).map_err(|e| {
                TransactionError::BuildFailed(format!("Failed to write scriptSig: {}", e))
            })?;

            // Write sequence
            bytes
                .write_all(&vin.sequence().to_le_bytes())
                .map_err(|e| {
                    TransactionError::BuildFailed(format!("Failed to write sequence: {}", e))
                })?;
        }

        // Write vout count (CompactSize)
        write_compact_size(&mut bytes, bundle.vout.len())?;

        // Write each output
        for vout in &bundle.vout {
            // Write value (8 bytes)
            bytes
                .write_all(&u64::from(vout.value()).to_le_bytes())
                .map_err(|e| {
                    TransactionError::BuildFailed(format!("Failed to write output value: {}", e))
                })?;

            // Write scriptPubKey
            let script_pubkey = vout.script_pubkey();
            write_compact_size(&mut bytes, script_pubkey.0.0.len())?;
            bytes.write_all(&script_pubkey.0.0).map_err(|e| {
                TransactionError::BuildFailed(format!("Failed to write scriptPubKey: {}", e))
            })?;
        }
    } else {
        // Empty transparent bundle
        write_compact_size(&mut bytes, 0)?; // vin count
        write_compact_size(&mut bytes, 0)?; // vout count
    }

    // Write empty Sapling bundle (nSpendsSapling = 0, nOutputsSapling = 0)
    write_compact_size(&mut bytes, 0)?; // nSpendsSapling
    write_compact_size(&mut bytes, 0)?; // nOutputsSapling

    // Write empty Orchard bundle (nActionsOrchard = 0)
    write_compact_size(&mut bytes, 0)?; // nActionsOrchard

    Ok(bytes)
}

/// Write a CompactSize integer.
fn write_compact_size(bytes: &mut Vec<u8>, n: usize) -> Result<(), TransactionError> {
    use std::io::Write;

    if n < 253 {
        bytes.write_all(&[n as u8]).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
    } else if n <= 0xFFFF {
        bytes.write_all(&[253]).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
        bytes.write_all(&(n as u16).to_le_bytes()).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
    } else if n <= 0xFFFFFFFF {
        bytes.write_all(&[254]).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
        bytes.write_all(&(n as u32).to_le_bytes()).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
    } else {
        bytes.write_all(&[255]).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
        bytes.write_all(&(n as u64).to_le_bytes()).map_err(|e| {
            TransactionError::BuildFailed(format!("Failed to write compact size: {}", e))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_find_address_index() {
        // First, derive an address at a known index
        let addresses = crate::wallet::derive_transparent_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            0,
            10,
        )
        .unwrap();

        // Now find it
        let index = find_address_index(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            &addresses[5],
            100,
        );
        assert_eq!(index, Some(5));
    }

    #[test]
    fn test_find_address_index_not_found() {
        let index = find_address_index(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            "tmInvalidAddress",
            10,
        );
        assert_eq!(index, None);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![Utxo {
            txid: "abc123".to_string(),
            vout: 0,
            value: 1000,
            address: "tmXXX".to_string(),
            script_pubkey: None,
        }];
        let recipients = vec![Recipient {
            address: "tmYYY".to_string(),
            amount: 2000,
        }];

        let result = build_transparent_transaction(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            utxos,
            recipients,
            1000,
            0, // No expiry
        );

        match result {
            Err(TransactionError::InsufficientFunds {
                available,
                required,
            }) => {
                assert_eq!(available, 1000);
                assert_eq!(required, 3000);
            }
            _ => panic!("Expected InsufficientFunds error"),
        }
    }

    #[test]
    fn test_build_unsigned_with_valid_utxo() {
        // Derive an address first
        let addresses = crate::wallet::derive_transparent_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            0,
            1,
        )
        .unwrap();

        let utxos = vec![Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            value: 100000,
            address: addresses[0].clone(),
            script_pubkey: None,
        }];

        // Use a valid testnet address as recipient
        let recipients = vec![Recipient {
            address: addresses[0].clone(), // Send to self for testing
            amount: 50000,
        }];

        let result = build_unsigned_transaction(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            utxos,
            recipients,
            10000,
        );

        assert!(result.is_ok());
        let unsigned = result.unwrap();
        assert_eq!(unsigned.total_input, 100000);
        assert_eq!(unsigned.total_output, 50000);
        assert_eq!(unsigned.fee, 10000);
        assert_eq!(unsigned.bundle.vin.len(), 1);
        // 1 recipient + 1 change output
        assert_eq!(unsigned.bundle.vout.len(), 2);
    }

    #[test]
    fn test_utxo_from_stored_note_transparent() {
        let note = StoredNote {
            id: "test-transparent-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "abc123def456".to_string(),
            output_index: 2,
            pool: Pool::Transparent,
            value: 100000,
            commitment: None,
            nullifier: None,
            memo: None,
            address: Some("tmXXXYYYZZZ".to_string()),
            spent_txid: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let utxo = Utxo::from_stored_note(&note);
        assert!(utxo.is_some());

        let utxo = utxo.unwrap();
        assert_eq!(utxo.txid, "abc123def456");
        assert_eq!(utxo.vout, 2);
        assert_eq!(utxo.value, 100000);
        assert_eq!(utxo.address, "tmXXXYYYZZZ");
    }

    #[test]
    fn test_utxo_from_stored_note_shielded() {
        let note = StoredNote {
            id: "test-orchard-0".to_string(),
            wallet_id: "w1".to_string(),
            txid: "abc123def456".to_string(),
            output_index: 0,
            pool: Pool::Orchard,
            value: 100000,
            commitment: Some("cmx".to_string()),
            nullifier: Some("nf".to_string()),
            memo: None,
            address: None,
            spent_txid: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let utxo = Utxo::from_stored_note(&note);
        assert!(utxo.is_none()); // Shielded notes can't be converted to UTXOs
    }

    #[test]
    fn test_utxo_from_stored_notes_filters_correctly() {
        let notes = vec![
            // Unspent transparent - should be included
            StoredNote {
                id: "test-transparent-0".to_string(),
                wallet_id: "w1".to_string(),
                txid: "tx1".to_string(),
                output_index: 0,
                pool: Pool::Transparent,
                value: 100000,
                commitment: None,
                nullifier: None,
                memo: None,
                address: Some("tm1".to_string()),
                spent_txid: None,
                created_at: "2024-01-01T00:00:00Z".to_string(),
            },
            // Spent transparent - should NOT be included
            StoredNote {
                id: "test-transparent-1".to_string(),
                wallet_id: "w1".to_string(),
                txid: "tx2".to_string(),
                output_index: 0,
                pool: Pool::Transparent,
                value: 200000,
                commitment: None,
                nullifier: None,
                memo: None,
                address: Some("tm2".to_string()),
                spent_txid: Some("spending_tx".to_string()),
                created_at: "2024-01-01T00:00:00Z".to_string(),
            },
            // Orchard note - should NOT be included
            StoredNote {
                id: "test-orchard-0".to_string(),
                wallet_id: "w1".to_string(),
                txid: "tx3".to_string(),
                output_index: 0,
                pool: Pool::Orchard,
                value: 300000,
                commitment: Some("cmx".to_string()),
                nullifier: Some("nf".to_string()),
                memo: None,
                address: None,
                spent_txid: None,
                created_at: "2024-01-01T00:00:00Z".to_string(),
            },
        ];

        let utxos = Utxo::from_stored_notes(&notes);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "tx1");
    }

    #[test]
    fn test_build_signed_transaction() {
        // Derive an address first
        let addresses = crate::wallet::derive_transparent_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            0,
            1,
        )
        .unwrap();

        let utxos = vec![Utxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            vout: 0,
            value: 100000,
            address: addresses[0].clone(),
            script_pubkey: None,
        }];

        let recipients = vec![Recipient {
            address: addresses[0].clone(), // Send to self for testing
            amount: 50000,
        }];

        let result = build_transparent_transaction(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            utxos,
            recipients,
            10000,
            0, // No expiry
        );

        // The transaction should be successfully built and signed
        assert!(result.is_ok(), "Transaction signing failed: {:?}", result);
        let signed = result.unwrap();

        // Verify transaction metadata
        assert_eq!(signed.total_input, 100000);
        assert_eq!(signed.total_output, 50000);
        assert_eq!(signed.fee, 10000);

        // Verify we got a hex-encoded transaction
        assert!(!signed.tx_hex.is_empty());
        assert!(
            hex::decode(&signed.tx_hex).is_ok(),
            "tx_hex is not valid hex"
        );

        // Verify txid is a valid 32-byte hex
        assert_eq!(signed.txid.len(), 64);
        assert!(hex::decode(&signed.txid).is_ok(), "txid is not valid hex");
    }
}
