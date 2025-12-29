//! Wallet derivation for Zcash.
//!
//! This module provides functions to generate and restore Zcash wallets
//! from BIP39 seed phrases. Supports both mainnet and testnet with
//! BIP32/ZIP32 address hierarchy derivation.
//!
//! # Address Uniqueness
//!
//! ## Transparent Addresses
//!
//! Transparent addresses are derived using BIP32/BIP44 paths. Each address
//! index produces a **unique** address. There are no "invalid" indices for
//! transparent derivation.
//!
//! ## Unified Addresses (Sapling Diversifier Behavior)
//!
//! Unified addresses contain multiple receiver types (Orchard, Sapling, and
//! optionally transparent). The derivation uses a **diversifier index** to
//! generate unique addresses.
//!
//! **Important:** Not all diversifier indices produce valid Sapling diversifiers.
//! Approximately **50%** (half) of indices are valid for Sapling. When an invalid
//! diversifier index is requested, the `find_address` function automatically
//! skips to the next valid index.
//!
//! This means:
//! - Consecutive indices may produce the **same** unified address
//! - For example, indices 2 and 3 might both resolve to the same valid
//!   diversifier (e.g., index 4), producing identical addresses
//! - Orchard diversifiers are always valid, but unified addresses require
//!   valid Sapling diversifiers too
//!
//! This is expected behavior defined by the Zcash protocol (ZIP-32/ZIP-316).
//!
//! ### Example
//!
//! ```text
//! Index 0 -> Valid   -> Unique Address A
//! Index 1 -> Valid   -> Unique Address B
//! Index 2 -> Invalid -> Skips to Index 4 -> Address C
//! Index 3 -> Invalid -> Skips to Index 4 -> Address C (duplicate!)
//! Index 4 -> Valid   -> Address C
//! Index 5 -> Invalid -> Skips to Index 6 -> Address D
//! ```

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::Network;
use zcash_transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
use zip32::{AccountId, DiversifierIndex};

use crate::types::NetworkKind;

/// Errors that can occur during wallet operations.
#[derive(Debug)]
pub enum WalletError {
    InvalidSeedPhrase(String),
    MnemonicGeneration(String),
    SpendingKeyDerivation(String),
    AddressGeneration(String),
    InvalidAccountIndex(String),
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSeedPhrase(msg) => write!(f, "Invalid seed phrase: {}", msg),
            Self::MnemonicGeneration(msg) => write!(f, "Failed to generate mnemonic: {}", msg),
            Self::SpendingKeyDerivation(msg) => write!(f, "Failed to derive spending key: {}", msg),
            Self::AddressGeneration(msg) => write!(f, "Failed to generate address: {}", msg),
            Self::InvalidAccountIndex(msg) => write!(f, "Invalid account index: {}", msg),
        }
    }
}

impl core::error::Error for WalletError {}

/// Information about a derived wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    /// The 24-word BIP39 seed phrase.
    pub seed_phrase: String,
    /// The network the wallet was derived for.
    pub network: NetworkKind,
    /// The account index (BIP32 level 3, ZIP32 account).
    pub account_index: u32,
    /// The address index (diversifier index for shielded addresses).
    pub address_index: u32,
    /// The unified address containing all receiver types.
    pub unified_address: String,
    /// The transparent (t-addr) address.
    pub transparent_address: Option<String>,
    /// The Unified Full Viewing Key.
    pub unified_full_viewing_key: String,
}

/// Generate a new wallet with a random seed phrase.
///
/// # Arguments
///
/// * `entropy` - 32 bytes of random entropy for generating the mnemonic.
/// * `network` - The network to use (MainNetwork or TestNetwork).
/// * `account_index` - The account index (BIP32 level 3, default 0).
/// * `address_index` - The address/diversifier index (default 0).
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn generate_wallet(
    entropy: &[u8; 32],
    network: Network,
    account_index: u32,
    address_index: u32,
) -> Result<WalletInfo, WalletError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|e| WalletError::MnemonicGeneration(e.to_string()))?;

    let seed_phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed("");

    derive_wallet(&seed, seed_phrase, network, account_index, address_index)
}

/// Restore a wallet from an existing seed phrase.
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic.
/// * `network` - The network to use (MainNetwork or TestNetwork).
/// * `account_index` - The account index (BIP32 level 3, default 0).
/// * `address_index` - The address/diversifier index (default 0).
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn restore_wallet(
    seed_phrase: &str,
    network: Network,
    account_index: u32,
    address_index: u32,
) -> Result<WalletInfo, WalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim())
        .map_err(|e| WalletError::InvalidSeedPhrase(e.to_string()))?;

    let seed = mnemonic.to_seed("");
    derive_wallet(
        &seed,
        mnemonic.to_string(),
        network,
        account_index,
        address_index,
    )
}

/// Derive wallet addresses and keys from a seed.
///
/// # Arguments
///
/// * `seed` - The 64-byte seed derived from the mnemonic.
/// * `seed_phrase` - The original seed phrase string.
/// * `network` - The network to derive addresses for.
/// * `account_index` - The account index (BIP32 level 3).
/// * `address_index` - The address/diversifier index.
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn derive_wallet(
    seed: &[u8],
    seed_phrase: String,
    network: Network,
    account_index: u32,
    address_index: u32,
) -> Result<WalletInfo, WalletError> {
    // Convert account index to AccountId
    let account = AccountId::try_from(account_index).map_err(|_| {
        WalletError::InvalidAccountIndex(format!(
            "Account index {} is out of valid range",
            account_index
        ))
    })?;

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::from_seed(&network, seed, account)
        .map_err(|e| WalletError::SpendingKeyDerivation(format!("{:?}", e)))?;

    // Get the unified full viewing key
    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_encoded = ufvk.encode(&network);

    // Create diversifier index from address_index
    let diversifier_index = DiversifierIndex::from(address_index);

    // Generate unified address at the specified diversifier index
    // Use find_address to find a valid diversifier starting from the given index
    let (ua, actual_index) = ufvk
        .find_address(diversifier_index, UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| WalletError::AddressGeneration(format!("{:?}", e)))?;
    let ua_encoded = ua.encode(&network);

    // Convert the actual diversifier index back to u32 for storage
    // Use try_from since DiversifierIndex could theoretically exceed u32::MAX
    let actual_address_index: u32 = u32::try_from(actual_index).unwrap_or(address_index);

    // Get transparent address at the specified index
    // Note: For transparent addresses, we use the address index directly
    let transparent_address = if let Some(tfvk) = ufvk.transparent() {
        match tfvk.derive_external_ivk() {
            Ok(ivk) => {
                // Convert address_index to NonHardenedChildIndex
                if let Some(child_index) = NonHardenedChildIndex::from_index(address_index) {
                    // Derive transparent address at the specified index
                    match ivk.derive_address(child_index) {
                        Ok(addr) => Some(addr.encode(&network)),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    } else {
        None
    };

    Ok(WalletInfo {
        seed_phrase,
        network: NetworkKind::from(network),
        account_index,
        address_index: actual_address_index,
        unified_address: ua_encoded,
        transparent_address,
        unified_full_viewing_key: ufvk_encoded,
    })
}

/// Derive multiple unified addresses from a seed phrase.
///
/// This is useful for scanning transactions - we need to check if shielded
/// outputs belong to any of our derived addresses.
///
/// # Sapling Diversifier Note
///
/// **Important:** The returned vector may contain duplicate addresses. This is
/// because not all diversifier indices produce valid Sapling diversifiers
/// (approximately 50% are valid per ZIP-32). When an invalid index is encountered,
/// `find_address` skips to the next valid diversifier, which may result in
/// consecutive indices producing the same address.
///
/// For example, if indices 2 and 3 are both invalid, they will both skip to
/// index 4's diversifier, producing identical addresses.
///
/// This is expected behavior per the Zcash protocol (ZIP-32/ZIP-316).
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic.
/// * `network` - The network to derive addresses for.
/// * `account_index` - The account index (BIP32 level 3).
/// * `start_index` - The starting address/diversifier index.
/// * `count` - Number of addresses to derive.
///
/// # Returns
///
/// A vector of unified addresses (may contain duplicates due to Sapling
/// diversifier behavior).
pub fn derive_unified_addresses(
    seed_phrase: &str,
    network: Network,
    account_index: u32,
    start_index: u32,
    count: u32,
) -> Result<Vec<String>, WalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim())
        .map_err(|e| WalletError::InvalidSeedPhrase(e.to_string()))?;

    let seed = mnemonic.to_seed("");

    // Convert account index to AccountId
    let account = AccountId::try_from(account_index).map_err(|_| {
        WalletError::InvalidAccountIndex(format!(
            "Account index {} is out of valid range",
            account_index
        ))
    })?;

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::from_seed(&network, &seed, account)
        .map_err(|e| WalletError::SpendingKeyDerivation(format!("{:?}", e)))?;

    // Get the unified full viewing key
    let ufvk = usk.to_unified_full_viewing_key();

    let mut addresses = Vec::with_capacity(count as usize);

    // Derive unified addresses at each diversifier index
    for i in start_index..(start_index + count) {
        let diversifier_index = DiversifierIndex::from(i);
        if let Ok((ua, _)) =
            ufvk.find_address(diversifier_index, UnifiedAddressRequest::AllAvailableKeys)
        {
            addresses.push(ua.encode(&network));
        }
    }

    Ok(addresses)
}

/// Derive multiple transparent addresses from a seed phrase.
///
/// This is useful for scanning transactions - we need to check if transparent
/// outputs belong to any of our derived addresses.
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic.
/// * `network` - The network to derive addresses for.
/// * `account_index` - The account index (BIP32 level 3).
/// * `start_index` - The starting address index.
/// * `count` - Number of addresses to derive.
///
/// # Returns
///
/// A vector of transparent addresses.
pub fn derive_transparent_addresses(
    seed_phrase: &str,
    network: Network,
    account_index: u32,
    start_index: u32,
    count: u32,
) -> Result<Vec<String>, WalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim())
        .map_err(|e| WalletError::InvalidSeedPhrase(e.to_string()))?;

    let seed = mnemonic.to_seed("");

    // Convert account index to AccountId
    let account = AccountId::try_from(account_index).map_err(|_| {
        WalletError::InvalidAccountIndex(format!(
            "Account index {} is out of valid range",
            account_index
        ))
    })?;

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::from_seed(&network, &seed, account)
        .map_err(|e| WalletError::SpendingKeyDerivation(format!("{:?}", e)))?;

    // Get the unified full viewing key
    let ufvk = usk.to_unified_full_viewing_key();

    let mut addresses = Vec::with_capacity(count as usize);

    // Get transparent addresses
    if let Some(tfvk) = ufvk.transparent()
        && let Ok(ivk) = tfvk.derive_external_ivk()
    {
        for i in start_index..(start_index + count) {
            if let Some(child_index) = NonHardenedChildIndex::from_index(i)
                && let Ok(addr) = ivk.derive_address(child_index)
            {
                addresses.push(addr.encode(&network));
            }
        }
    }

    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vector: a fixed seed phrase and its expected derived addresses
    const TEST_SEED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_wallet_is_deterministic_testnet() {
        let wallet1 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        let wallet2 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        assert_eq!(wallet1.unified_address, wallet2.unified_address);
        assert_eq!(wallet1.transparent_address, wallet2.transparent_address);
        assert_eq!(
            wallet1.unified_full_viewing_key,
            wallet2.unified_full_viewing_key
        );
    }

    #[test]
    fn test_derive_wallet_testnet_addresses() {
        let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        // Verify addresses are non-empty and have expected prefixes for testnet
        assert_eq!(wallet.network, NetworkKind::Testnet);
        assert_eq!(wallet.account_index, 0);
        assert!(
            wallet.unified_address.starts_with("utest"),
            "unified address should start with 'utest' for testnet"
        );
        assert!(
            wallet
                .transparent_address
                .as_ref()
                .map(|s| s.starts_with("tm"))
                .unwrap_or(false),
            "transparent address should start with 'tm' for testnet"
        );
        assert!(
            wallet.unified_full_viewing_key.starts_with("uviewtest"),
            "UFVK should start with 'uviewtest' for testnet"
        );
    }

    #[test]
    fn test_derive_wallet_mainnet_addresses() {
        let wallet = restore_wallet(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        // Verify addresses are non-empty and have expected prefixes for mainnet
        assert_eq!(wallet.network, NetworkKind::Mainnet);
        assert_eq!(wallet.account_index, 0);
        assert!(
            wallet.unified_address.starts_with("u1"),
            "unified address should start with 'u1' for mainnet"
        );
        assert!(
            wallet
                .transparent_address
                .as_ref()
                .map(|s| s.starts_with("t1"))
                .unwrap_or(false),
            "transparent address should start with 't1' for mainnet"
        );
        assert!(
            wallet.unified_full_viewing_key.starts_with("uview1"),
            "UFVK should start with 'uview1' for mainnet"
        );
    }

    #[test]
    fn test_derive_wallet_known_vector_testnet() {
        // This test uses a known seed and verifies exact output
        // If this test fails after a library update, it indicates a breaking change
        let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        // These are the expected values for the standard BIP39 test vector
        // "abandon abandon ... art" on Zcash testnet
        assert_eq!(
            wallet.transparent_address,
            Some("tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd".to_string()),
            "transparent address mismatch - library may have changed derivation"
        );

        assert_eq!(
            wallet.unified_full_viewing_key,
            "uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd",
            "UFVK mismatch - library may have changed derivation"
        );
    }

    #[test]
    fn test_different_seeds_produce_different_wallets() {
        let wallet1 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        // Different seed phrase
        let different_seed = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        let wallet2 = restore_wallet(different_seed, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        assert_ne!(
            wallet1.unified_address, wallet2.unified_address,
            "different seeds should produce different unified addresses"
        );
        assert_ne!(
            wallet1.transparent_address, wallet2.transparent_address,
            "different seeds should produce different transparent addresses"
        );
        assert_ne!(
            wallet1.unified_full_viewing_key, wallet2.unified_full_viewing_key,
            "different seeds should produce different UFVKs"
        );
    }

    #[test]
    fn test_same_seed_different_networks() {
        let testnet_wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        let mainnet_wallet = restore_wallet(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0)
            .expect("wallet derivation should succeed");

        // Same seed should produce different addresses on different networks
        assert_ne!(
            testnet_wallet.unified_address, mainnet_wallet.unified_address,
            "same seed should produce different addresses on different networks"
        );
        assert_ne!(
            testnet_wallet.transparent_address, mainnet_wallet.transparent_address,
            "same seed should produce different transparent addresses on different networks"
        );
    }

    #[test]
    fn test_restore_invalid_seed_fails() {
        let result = restore_wallet("invalid seed phrase", Network::TestNetwork, 0, 0);
        assert!(result.is_err(), "should fail with invalid seed phrase");
    }

    #[test]
    fn test_generate_wallet_testnet() {
        let entropy = [0u8; 32]; // Deterministic for testing
        let wallet = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
            .expect("wallet generation should succeed");

        assert!(!wallet.seed_phrase.is_empty());
        assert!(!wallet.unified_address.is_empty());
        assert!(wallet.transparent_address.is_some());
        assert!(!wallet.unified_full_viewing_key.is_empty());
        assert_eq!(wallet.network, NetworkKind::Testnet);
        assert_eq!(wallet.account_index, 0);
        assert_eq!(wallet.address_index, 0);
    }

    #[test]
    fn test_generate_wallet_mainnet() {
        let entropy = [0u8; 32]; // Deterministic for testing
        let wallet = generate_wallet(&entropy, Network::MainNetwork, 0, 0)
            .expect("wallet generation should succeed");

        assert!(!wallet.seed_phrase.is_empty());
        assert!(wallet.unified_address.starts_with("u1"));
        assert!(
            wallet
                .transparent_address
                .as_ref()
                .map(|s| s.starts_with("t1"))
                .unwrap_or(false)
        );
        assert!(wallet.unified_full_viewing_key.starts_with("uview1"));
        assert_eq!(wallet.network, NetworkKind::Mainnet);
        assert_eq!(wallet.account_index, 0);
        assert_eq!(wallet.address_index, 0);
    }

    #[test]
    fn test_different_account_indices() {
        let wallet0 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        let wallet1 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 1, 0)
            .expect("wallet derivation should succeed");

        assert_ne!(
            wallet0.unified_address, wallet1.unified_address,
            "different accounts should produce different unified addresses"
        );
        assert_ne!(
            wallet0.transparent_address, wallet1.transparent_address,
            "different accounts should produce different transparent addresses"
        );
        assert_ne!(
            wallet0.unified_full_viewing_key, wallet1.unified_full_viewing_key,
            "different accounts should produce different UFVKs"
        );
        assert_eq!(wallet0.account_index, 0);
        assert_eq!(wallet1.account_index, 1);
    }

    #[test]
    fn test_different_address_indices() {
        let wallet0 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        let wallet1 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 1)
            .expect("wallet derivation should succeed");

        assert_ne!(
            wallet0.unified_address, wallet1.unified_address,
            "different address indices should produce different unified addresses"
        );
        assert_ne!(
            wallet0.transparent_address, wallet1.transparent_address,
            "different address indices should produce different transparent addresses"
        );
        // Same account should have same UFVK
        assert_eq!(
            wallet0.unified_full_viewing_key, wallet1.unified_full_viewing_key,
            "same account should have same UFVK regardless of address index"
        );
        assert_eq!(wallet0.address_index, 0);
        assert_eq!(wallet1.address_index, 1);
    }

    // =========================================================================
    // Regression tests for address derivation at different indices (Issue #51)
    // =========================================================================

    #[test]
    fn test_transparent_address_derivation_regression() {
        // Test derivation at specific indices
        // These values were captured from the current implementation and serve
        // as regression tests to detect any changes in derivation logic.
        let addresses = derive_transparent_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,   // account index
            0,   // start index
            100, // count
        )
        .expect("derivation should succeed");

        // Verify address at index 0 matches the known wallet derivation
        let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        assert_eq!(
            addresses[0],
            wallet.transparent_address.unwrap(),
            "transparent address at index 0 should match wallet derivation"
        );

        // Verify all addresses are unique (transparent addresses should be unique)
        let unique_count = addresses
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(
            unique_count,
            addresses.len(),
            "all derived transparent addresses should be unique"
        );

        // Verify all addresses have correct prefix
        for addr in &addresses {
            assert!(
                addr.starts_with("tm"),
                "testnet transparent address should start with 'tm'"
            );
        }
    }

    #[test]
    fn test_transparent_address_known_values_testnet() {
        // Regression test with hardcoded expected values for the standard BIP39 test vector
        // If these values change, it indicates a breaking change in derivation logic.
        let addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 11)
                .expect("derivation should succeed");

        // Known values for testnet transparent addresses at indices 0-10
        let expected = [
            "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd",
            "tmVNYZhAQMp61GkauCYV5R4eVKpxzzMZBJF",
            "tmRSjpqFr1j7P3WBXWFgsRuhQbHaiJBXXRW",
            "tm9kikz8PQd5MycWhWVoQTUMVZWc3ZSTQhK",
            "tmLPjXjbVNVmVVRidMqtNMA1qKxECkzRYZb",
            "tmThgiqZedVKDxxdghpVwx2xLAd7SLPv1Y7",
            "tmJkkSBtcXubDmGU5B8K6x9KuiQn4mL8HKT",
            "tmJ4ZQtgpJ5u4kg271iDDBVN5BSBqeMB2vv",
            "tmNkX2tj76BgjZ8QiiyKY48S8qes2rrAkMt",
            "tmXwLcGMqtojBmcJQZYYHS48U2c4SWZjqjg",
            "tmHBscZuX1bqL5F3WbY9D8pRkJFLXQngsTR",
        ];

        for (i, (actual, expected)) in addresses.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                actual, expected,
                "transparent address mismatch at index {}: got {}, expected {}",
                i, actual, expected
            );
        }
    }

    #[test]
    fn test_transparent_address_known_values_mainnet() {
        let addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 11)
                .expect("derivation should succeed");

        let expected = [
            "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F",
            "t1QArW6GKrvHngPMPn9cjAk2A9rjKenbhmc",
            "t1eD9JjoWnwMppWvgVbV2xZ9UhNNScPjh4C",
            "t1NPeWksS1wHCD49e4RSjteeGx6zCq2hF2n",
            "t1XN7c6eGuMZTusTWg8tsSm34Lwi3yvhLXv",
            "t1feU67psWJQCwME9tsWq2yLzg5VoNAUd5N",
            "t1fh83WS4uQAH9iiPhqSih4cQYJsmb2Ebyb",
            "t1WdzBz3S7ngE9oqXT6srz1MA19MNgnTUvt",
            "t1NHbs4gi5zLgHmrTKMN5fcEd7WZsCyfmZG",
            "t1gWSBjnM4ULq7s4RrJyPVWev8rCRVPSXrk",
            "t1V8w3SG3f1n8vCCSzCQ7iFsFs1rdfpoTFi",
        ];

        for (i, (actual, expected)) in addresses.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                actual, expected,
                "mainnet transparent address mismatch at index {}: got {}, expected {}",
                i, actual, expected
            );
        }
    }

    #[test]
    fn test_unified_address_known_values_testnet() {
        // Regression test with hardcoded expected values
        let addresses = derive_unified_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 5)
            .expect("derivation should succeed");

        let expected = [
            "utest1cqt4k0wjtvhalr5xfsd2s8enlgn72a3zcvecg7zg55qyyku4z4u5t9yansklfuznvuz077hfu2s8gq50nlln5x4wdxhjleapsn9fs6aua6z9kgpypckjxeku3xzh9qaqj96lk9lpq958ruem58kdfstaec8s725rz4l52xtrlj4cudds53aflght5c433gqkk6h8qvn6vq3u2wxuea5",
            "utest18v9xkrysfmwf9hr4q05p6x4j8p8e0kfrjvd4q5c4run3e8rp5lyp0uxw328kneznz8ee4v67dcwxnu9x2r3pe6ew6ke0g5sfw6uxy96zlw3zyqls0gxnryw0uh2h3cga9vf5ndes0gc39n8tlgx2r82ummv4cwp2xwan7fwmsxaaqcvx4w63f37nl93pvrwemht3yss0kvgqsn2h3yj",
            "utest1te4fv8ttz4wn9324g4z6zwmfqc0df56qdzck5f5f69hshxg9xwdsgkzvkrxa50997sqhjj3v3ct5t0ynea5rc42cw44zv6fleryv6rev9rds54lzhne86x3lrzdftgkl5gp0wnzfqeg7enpmwvyfwtee46clfv7fz7v7dkmx6lf4mqfewm838etkfmhfdqktgcvsxp70ewncw3r3h3g",
            "utest1584ks4v9pwmea9c8gzrmyywtakh4hyzf5ws5tjrlerqq6sfnmajtkgc4kjv5ld2tkn2wwm6gwucwu82y4dz77kg3v0fm099hyh49p00mc9pl4kqdldc3n4yjy4me4p6mggf8l50frtscp6xvzvhqhg4djm3sugvte5shzdx0vwanvpmzqntkr9c2y25qw9dqt6gt8cep3ffwzh76dx0",
            "utest10pdde234pem6htca00fw68mn5xkv4pjtz766vmkpm0fszqsgjgyqxv2yzp0xs0fvp8zu5y695jjzvges0fqhsxhtfmynx5qamy8pnkxkc6vnztkyvjndzhx2wgh8vv6s32kunqkutf6qkut8j6u83xffwfqlvgvffa6pq6ylxkpgsht0cs4wg2g8agsv9xargrq623ll0edj64rpv3t",
        ];

        for (i, (actual, expected)) in addresses.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                actual, expected,
                "testnet unified address mismatch at index {}: got {}, expected {}",
                i, actual, expected
            );
        }
    }

    #[test]
    fn test_unified_address_known_values_mainnet() {
        let addresses = derive_unified_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 5)
            .expect("derivation should succeed");

        let expected = [
            "u16sw4v6wy7f4jzdny55yzl020tp3yqg3c85dc6n7mmq0urfm6adqg79hxmyk85ufn4lun4pfh5q48cc3kvxhxm3w978eqqecdd260gkzjrkun6z7m9mcrt2zszaj0mvk6ufux2zteqwh57cq906hz3rkg63duaeqsvjelv9h5srct0zq8rvlv23wz5hed7zuatqd7p6p4ztugc4t4w2g",
            "u1wzfync9q7mh8d7r9n2xxdqsyfx62su8em5653t9p5n2yaw6j2km730pu7phcs0j9vk7u8egjhm47k4d7r2uvzns3d7pdvv444km7ngzd3rcy3j6q5lsl563ej5hhtkuaf8flpjl76lmawna8thq0jcj57ncc2knrwgralx60v3jv35s9jsx8fkg76qp6p84d7xah7qrmrmrvgf9rhrq",
            "u1l47x3uqwucgkqkw3er2m7ljnnqjzaw33xgz57cslyx50tlnp7ctz7vvkwhp900zjry88dl88wecxt2pp27u49yg8l5r7yxj3595sghs4h6jrf29tc220247x55uttf8g3qutczax32jwydj72ze2a22xw06fcx2anqsume3t4gyuwp230lqntzxrz7qen9ylnmhlqr5ssxpu7wcenfn",
            "u1l47x3uqwucgkqkw3er2m7ljnnqjzaw33xgz57cslyx50tlnp7ctz7vvkwhp900zjry88dl88wecxt2pp27u49yg8l5r7yxj3595sghs4h6jrf29tc220247x55uttf8g3qutczax32jwydj72ze2a22xw06fcx2anqsume3t4gyuwp230lqntzxrz7qen9ylnmhlqr5ssxpu7wcenfn",
            "u1ntpny3ye6h2cjz4ddpse9xhum3kj2dg320a8392usqf6wzl49et0a5r4c2nan9wwcf7yqrz863skgm9tcfqx0m6wxx5zayc9sskazlvppyvxmrkzxcq57yw36xqea7undvgv8q46cecky0csavswpl3e6e0d03t3cu3h6eh2ntgcwm8r07sxsfa20699cdc4v6z3lf0n278cxf624xn",
        ];

        for (i, (actual, expected)) in addresses.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                actual, expected,
                "mainnet unified address mismatch at index {}: got {}, expected {}",
                i, actual, expected
            );
        }
    }

    #[test]
    fn test_viewing_key_known_values() {
        // Known viewing keys for testnet accounts 0, 1, 2
        let testnet_expected = [
            "uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd",
            "uviewtest1dhvev7n65razxvmdfxy95j787rpu74fe3yyl4j70mt0mw6z3u2kyujax2vxhfazagvsdhsxyqjyjxau4uyklzktxgjrqnm2xk9rcmucm7hq6gv49pq3p3wrn0dn8z07e37p277rsk8rn0ffgqqnl49927vc053k2fs3mkvhwfyhasjze62waaguynmh3fws5gz5klmxl803dshsekra7cwwhde7h0kvwmdkfdwewcdqpjz79088gplj5uptw7zlsg0hlfjtx3sah0mn2en3rqk42gpwsr4wr8qrh36kt5g82vk8wdv5jr0vrcxdv6wppqv6vsmymzel0j6lj94zaq76t43hqdush5d2rp88d2rqlangsqm62z5tf75fjz8sktehj6r9r0fm93qs8lm5vga4avhtpw6de9qfjpd5rxze6hfq9y2gvwskchj9nxche6qnvr5v6sszgx27zrxst5q4dxtg0w9r0rrw7uyxqnk2as443as4xy4l4",
            "uviewtest14dgt80533jn30s3jzv0h8nnzc4dt8zvtyqeqtrlcmvhv20ed4z39r79un6su307u8nhguk9elzdweau4zped4s0aqht2ke30zjkr8wafuah38hn0mww439r5an9mjtek8c5k7add7ed0yd45k6eyhrg5gcl7adpman4l8yl36k9gzk74mqyfxlcqwj054nceqwfuzlwe5xuf7sfzx4yuw43q24y9w2juc5an0engy33xl2mwv50z6crz2yvugwskjzk62473kv3s32h89dk88sqqgp6jz95l42q478gz33cl7z3yah2q6krawr97tk5cxn5glw29hz82jpfmhtwkn923ej9l8ws7sj3fvsachtfeq7g44ker72d6edypllewgesnhr923fxp0ct06pvtvjksqhnhpwmrt3cgnu2u58jjnuted6apycs5h9e8xmrm273ff0d4fqfy8uz0v0ckx4cxfjfnaa9z5vqq9tc76qht6nqusysxfzh4",
        ];

        for (account, expected) in testnet_expected.iter().enumerate() {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, account as u32, 0)
                .expect("wallet derivation should succeed");
            assert_eq!(
                &wallet.unified_full_viewing_key, expected,
                "testnet UFVK mismatch for account {}: got {}, expected {}",
                account, wallet.unified_full_viewing_key, expected
            );
        }

        // Known viewing keys for mainnet accounts 0, 1, 2
        let mainnet_expected = [
            "uview1wj07tp4y3rwzjplg68c3lum2avq4v3j0w0mf0urdlxzthnfr26q8ssz9hvylspj638tuh2r233gaxm2qh27gj6m9q25prk7gt8xwqzmwxm580tg0f5llvr7d6h4y6jc2t7zl7lz9ge60ta6226jyysgk8xpu2wqxesrw4q2mydrhj5dea5l9scl0p3l4ayqgfej54wex5aa2ylq89nyqg94l4lh6dawuc2e3s8v7737zn7p5fl96hhpjqg4jucnp2r2jjqxev3z7lp3k9ulfpl2gw0lng8vfe8hj8afggqzdwxgfaq6dy82guvh34kv4q5ay7gq6n0ujg7exu0mgznpr4wf0agjdhnd4k6af5md3f3msqedw364vx3lyd3hwekvrulywa4c0ja4ze2fxtcm0vrz0278g9n37y0jg6dx847g3peyq9lwmm04ac3tt4sldnrcfc5ew3k0aqgycnryfvv44zxzng485ks27wky2ulfy9q8hu97l",
            "uview1fzmv506uqhq5ktmj9ldyf7ww00avknney4zpdh73n9suwjhx9je7tswv93e4uxmeunn23cqc2wg0e3l4eqvq0qhheh0hdzznmp4pwlmp9mfa3klm3a28d436anavapwecctk3ul4qqcaankh0lgk5jz9jl4t82p4j03505h92k92d5t23y6rmktp9z0dc7a0v0dzjgl2qtdcrq4z6kmf6xy78xqwqxq27v39r2d3tpwfpzkdjccenxsee7vlv8t533p4y3pckf6xzcq7e226nev4yuevvtfsrxgj0lxxzt9x8949jwn8kdwyslzyjcugk8f2akux3rjgwprtwxpcux26nk8ujk2llrjpg77l2mj9ac6lmva2zeawzwtyrtsmdgrs75snd2exdge33kll6dj4spp6wvrfczjnkrqugy8qm4y238nt850ezpmsse9z0w4rs2klj0hydnkxssasc3cndrvzr55l8u6mfyhm9peg0v8htg4j39u4",
            "uview1lwrudrcshvvqd3c0dj7l30wx0zfthzvkdw82q07ylw4pppk7mymjwqc7c3y2fl7spq4ypd64hkz93w99nhu5qcc4ctynf5gz0xuqugqfgg7q6hv5a88kaa3w657z7rm2u2ssnrynz3qnsjsurfagqp8qm2hxw70agztdrd82h4tdaqwhfec2kyl4y8d3ef04pw308mn5xdk57rvt99cfyz95ndc4yarf8q8w20wkreqk95s2gk3kfxn882zc00kml2238y25v820747dyj93j9nylf56z49ddwcpzm9je3yqzdf0fzwgm3d9vl225z6y927pqzcewkztfh2a9w4truyhqxeh4d0nw2ty9p7zvy904wqvwa49udz70pydf6w75zhjrh92cl6qqmcpe7n642007qas5h0wx4d7hvtmtu5hh9c9yktcy7u0hu9p30asa7gx4ac9ur87p9rwvnxxp76n04zpcmst289y8u5s7pcdgen3xcfa2kwm",
        ];

        for (account, expected) in mainnet_expected.iter().enumerate() {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::MainNetwork, account as u32, 0)
                .expect("wallet derivation should succeed");
            assert_eq!(
                &wallet.unified_full_viewing_key, expected,
                "mainnet UFVK mismatch for account {}: got {}, expected {}",
                account, wallet.unified_full_viewing_key, expected
            );
        }
    }

    #[test]
    fn test_different_account_addresses_known_values() {
        // Known transparent addresses for testnet accounts 0, 1, 2 at index 0
        let testnet_transparent_expected = [
            "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd",
            "tmFHMD21fowpyfY4wv1WcBHkzfhD5rW51Ds",
            "tmBoHxWs8iDkhpUi7jYVFN6aKieWjHVSQcB",
        ];

        for (account, expected) in testnet_transparent_expected.iter().enumerate() {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, account as u32, 0)
                .expect("wallet derivation should succeed");
            assert_eq!(
                wallet.transparent_address.as_ref().unwrap(),
                expected,
                "testnet transparent address mismatch for account {}: got {}, expected {}",
                account,
                wallet.transparent_address.as_ref().unwrap(),
                expected
            );
        }

        // Known unified addresses for testnet accounts 0, 1, 2 at index 0
        let testnet_unified_expected = [
            "utest1cqt4k0wjtvhalr5xfsd2s8enlgn72a3zcvecg7zg55qyyku4z4u5t9yansklfuznvuz077hfu2s8gq50nlln5x4wdxhjleapsn9fs6aua6z9kgpypckjxeku3xzh9qaqj96lk9lpq958ruem58kdfstaec8s725rz4l52xtrlj4cudds53aflght5c433gqkk6h8qvn6vq3u2wxuea5",
            "utest134n9sjw63v6n5mfg6wyn3475yw4lp9ejmjeftrdmuz7kld0kgcpw7ql8we7kcurclnznlx9veet8kk44y5u00vtzf4x37502p2jk30hefla25ag3ehx7dkzztngycusx5kcfwrz5rhd838krt4sfzqx28haj6h234m4rvj85dvy7y7df4rlkln8r0kavn4r268seyy0t93q86wyaaz0",
            "utest1f5x7a4p6e4svnsyhwesms4jheplek0hjrtlq9pckjyft5gvet7pf4c3zq53qascteg2rl7vkadamhjy9wukcwwrr0td2m2t92m4y6ywyypr36hvzq2z5ghhwzdn9625x7cezxaa67g0hq4hrucaj30y0k59cssdy3k9f66kjpmm65ntjmludkdf5mdtuj0qpyaxkfj92ysua5pjv855",
        ];

        for (account, expected) in testnet_unified_expected.iter().enumerate() {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, account as u32, 0)
                .expect("wallet derivation should succeed");
            assert_eq!(
                &wallet.unified_address, expected,
                "testnet unified address mismatch for account {}: got {}, expected {}",
                account, wallet.unified_address, expected
            );
        }
    }

    #[test]
    fn test_unified_address_derivation_regression() {
        // Test derivation at specific indices
        let addresses = derive_unified_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,   // account index
            0,   // start index
            100, // count
        )
        .expect("derivation should succeed");

        // Verify addresses start with expected prefix
        for (i, addr) in addresses.iter().enumerate() {
            assert!(
                addr.starts_with("utest"),
                "testnet unified address at index {} should start with 'utest'",
                i
            );
        }

        // Note: Unified addresses may have duplicates because find_address()
        // returns the next valid diversifier. Multiple input indices may
        // resolve to the same valid diversifier, producing the same address.
        // This is expected behavior for Sapling diversifiers.
        let unique_count = addresses
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            unique_count > 0,
            "should have at least some unique addresses"
        );

        // Verify first address matches wallet derivation at index 0
        let wallet_0 = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0)
            .expect("wallet derivation should succeed");
        assert_eq!(
            addresses[0], wallet_0.unified_address,
            "unified address at index 0 should match wallet derivation"
        );
    }

    #[test]
    fn test_transparent_derivation_deterministic() {
        // Verify that calling derive_transparent_addresses multiple times
        // produces the same results
        let addresses1 =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
                .expect("derivation should succeed");

        let addresses2 =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
                .expect("derivation should succeed");

        assert_eq!(addresses1, addresses2, "derivation should be deterministic");
    }

    #[test]
    fn test_unified_derivation_deterministic() {
        let addresses1 = derive_unified_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
            .expect("derivation should succeed");

        let addresses2 = derive_unified_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
            .expect("derivation should succeed");

        assert_eq!(addresses1, addresses2, "derivation should be deterministic");
    }

    #[test]
    fn test_cross_verification_transparent() {
        // Verify that derive_transparent_addresses produces the same addresses
        // as individual wallet derivations
        let batch_addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
                .expect("batch derivation should succeed");

        for i in 0..10u32 {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, i)
                .expect("wallet derivation should succeed");

            assert_eq!(
                batch_addresses[i as usize],
                wallet.transparent_address.unwrap(),
                "batch address at index {} should match wallet derivation",
                i
            );
        }
    }

    #[test]
    fn test_cross_verification_unified() {
        // Verify that derive_unified_addresses produces the same addresses
        // as individual wallet derivations
        let batch_addresses =
            derive_unified_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 10)
                .expect("batch derivation should succeed");

        for i in 0..10u32 {
            let wallet = restore_wallet(TEST_SEED_PHRASE, Network::TestNetwork, 0, i)
                .expect("wallet derivation should succeed");

            assert_eq!(
                batch_addresses[i as usize], wallet.unified_address,
                "batch address at index {} should match wallet derivation",
                i
            );
        }
    }

    #[test]
    fn test_derivation_with_offset() {
        // Test that derivation with start_index offset works correctly
        let all_addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 20)
                .expect("derivation should succeed");

        let offset_addresses = derive_transparent_addresses(
            TEST_SEED_PHRASE,
            Network::TestNetwork,
            0,
            10, // start at index 10
            10,
        )
        .expect("derivation should succeed");

        // Addresses starting at index 10 should match
        assert_eq!(
            &all_addresses[10..20],
            &offset_addresses[..],
            "offset derivation should match"
        );
    }

    #[test]
    fn test_different_accounts_produce_different_addresses() {
        let account0 =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 0, 0, 5)
                .expect("derivation should succeed");

        let account1 =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::TestNetwork, 1, 0, 5)
                .expect("derivation should succeed");

        // No address from account 0 should appear in account 1
        for addr in &account0 {
            assert!(
                !account1.contains(addr),
                "different accounts should produce completely different addresses"
            );
        }
    }

    #[test]
    fn test_mainnet_transparent_addresses() {
        let addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 5)
                .expect("derivation should succeed");

        for addr in &addresses {
            assert!(
                addr.starts_with("t1"),
                "mainnet transparent address should start with 't1'"
            );
        }
    }

    #[test]
    fn test_mainnet_unified_addresses() {
        let addresses = derive_unified_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 5)
            .expect("derivation should succeed");

        for addr in &addresses {
            assert!(
                addr.starts_with("u1"),
                "mainnet unified address should start with 'u1'"
            );
        }
    }

    // =========================================================================
    // Property-based tests (PBT) using random seeds
    // These tests verify address prefix properties hold for any valid seed
    // =========================================================================

    #[test]
    fn test_pbt_testnet_transparent_address_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Run multiple iterations with random seeds
        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet
                    .transparent_address
                    .as_ref()
                    .map(|s| s.starts_with("tm"))
                    .unwrap_or(false),
                "testnet transparent address should start with 'tm' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_mainnet_transparent_address_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::MainNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet
                    .transparent_address
                    .as_ref()
                    .map(|s| s.starts_with("t1"))
                    .unwrap_or(false),
                "mainnet transparent address should start with 't1' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_testnet_unified_address_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet.unified_address.starts_with("utest"),
                "testnet unified address should start with 'utest' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_mainnet_unified_address_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::MainNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet.unified_address.starts_with("u1"),
                "mainnet unified address should start with 'u1' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_testnet_ufvk_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet.unified_full_viewing_key.starts_with("uviewtest"),
                "testnet UFVK should start with 'uviewtest' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_mainnet_ufvk_prefix() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::MainNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert!(
                wallet.unified_full_viewing_key.starts_with("uview1"),
                "mainnet UFVK should start with 'uview1' for any seed"
            );
        }
    }

    #[test]
    fn test_pbt_seed_phrase_is_24_words() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let entropy: [u8; 32] = rng.r#gen();
            let wallet = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");

            let word_count = wallet.seed_phrase.split_whitespace().count();
            assert_eq!(
                word_count, 24,
                "generated seed phrase should have 24 words for any entropy"
            );
        }
    }

    #[test]
    fn test_pbt_deterministic_derivation() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..5 {
            let entropy: [u8; 32] = rng.r#gen();

            let wallet1 = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");
            let wallet2 = generate_wallet(&entropy, Network::TestNetwork, 0, 0)
                .expect("wallet generation should succeed");

            assert_eq!(
                wallet1.unified_address, wallet2.unified_address,
                "same entropy should produce same addresses"
            );
            assert_eq!(
                wallet1.transparent_address, wallet2.transparent_address,
                "same entropy should produce same transparent addresses"
            );
            assert_eq!(
                wallet1.unified_full_viewing_key, wallet2.unified_full_viewing_key,
                "same entropy should produce same UFVK"
            );
        }
    }

    #[test]
    fn test_pbt_different_entropy_different_addresses() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let entropy1: [u8; 32] = rng.r#gen();
        let entropy2: [u8; 32] = rng.r#gen();

        // Ensure they're different (astronomically unlikely to be same)
        assert_ne!(entropy1, entropy2, "random entropy should be different");

        let wallet1 = generate_wallet(&entropy1, Network::TestNetwork, 0, 0)
            .expect("wallet generation should succeed");
        let wallet2 = generate_wallet(&entropy2, Network::TestNetwork, 0, 0)
            .expect("wallet generation should succeed");

        assert_ne!(
            wallet1.unified_address, wallet2.unified_address,
            "different entropy should produce different addresses"
        );
        assert_ne!(
            wallet1.transparent_address, wallet2.transparent_address,
            "different entropy should produce different transparent addresses"
        );
    }

    /// Test that verifies unified address uniqueness behavior at different indices.
    ///
    /// IMPORTANT: Due to Sapling diversifier behavior, not all diversifier indices
    /// produce valid diversifiers. The `find_address` function skips invalid
    /// diversifiers and returns the next valid one. This means consecutive indices
    /// may produce the SAME unified address.
    ///
    /// For example, if index 2 and 3 both have invalid diversifiers, both will
    /// skip to index 4's diversifier, producing identical addresses.
    #[test]
    fn test_unified_address_index_uniqueness_behavior() {
        // Derive addresses at indices 0-9
        let addresses = derive_unified_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 10)
            .expect("derivation should succeed");

        // Count unique addresses
        let unique: std::collections::HashSet<_> = addresses.iter().collect();
        let unique_count = unique.len();

        // Print the actual uniqueness for visibility
        eprintln!(
            "Unified addresses: {} indices -> {} unique addresses",
            addresses.len(),
            unique_count
        );

        // With 10 indices, we expect at least 5 unique addresses (50%)
        // In practice, about 87.5% of Sapling diversifier indices are valid
        assert!(
            unique_count >= 5,
            "expected at least 5 unique addresses from 10 indices, got {}",
            unique_count
        );

        // Document which indices produce duplicates
        for i in 1..addresses.len() {
            if addresses[i] == addresses[i - 1] {
                eprintln!(
                    "Note: index {} produces same address as index {} (both found same valid diversifier)",
                    i,
                    i - 1
                );
            }
        }
    }

    /// Test that transparent addresses are ALWAYS unique at each index.
    /// Unlike unified addresses, transparent addresses don't have the diversifier
    /// validity issue - each index produces a distinct address.
    #[test]
    fn test_transparent_address_always_unique_per_index() {
        let addresses =
            derive_transparent_addresses(TEST_SEED_PHRASE, Network::MainNetwork, 0, 0, 100)
                .expect("derivation should succeed");

        // Verify ALL transparent addresses are unique
        let unique: std::collections::HashSet<_> = addresses.iter().collect();
        assert_eq!(
            unique.len(),
            addresses.len(),
            "every transparent address index MUST produce a unique address"
        );

        // Verify adjacent indices never produce the same address
        for i in 1..addresses.len() {
            assert_ne!(
                addresses[i],
                addresses[i - 1],
                "adjacent transparent addresses at indices {} and {} must be different",
                i,
                i - 1
            );
        }
    }
}
