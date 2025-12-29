//! Wallet derivation for Zcash.
//!
//! This module provides functions to generate and restore Zcash wallets
//! from BIP39 seed phrases. Supports both mainnet and testnet with
//! BIP32/ZIP32 address hierarchy derivation.

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::Network;
use zcash_transparent::keys::{IncomingViewingKey, NonHardenedChildIndex};
use zip32::{AccountId, DiversifierIndex};

use crate::types::NetworkKind;

/// Errors that can occur during wallet operations.
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),

    #[error("Failed to generate mnemonic: {0}")]
    MnemonicGeneration(String),

    #[error("Failed to derive spending key: {0}")]
    SpendingKeyDerivation(String),

    #[error("Failed to generate address: {0}")]
    AddressGeneration(String),

    #[error("Invalid account index: {0}")]
    InvalidAccountIndex(String),
}

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
/// A vector of unified addresses.
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
}
