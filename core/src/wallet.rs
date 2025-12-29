//! Wallet derivation for Zcash testnet.
//!
//! This module provides functions to generate and restore Zcash wallets
//! from BIP39 seed phrases.

use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::Network;
use zcash_transparent::keys::IncomingViewingKey;
use zip32::AccountId;

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
}

/// Information about a derived wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    /// The 24-word BIP39 seed phrase.
    pub seed_phrase: String,
    /// The network (always "testnet" for now).
    pub network: String,
    /// The unified address containing all receiver types.
    pub unified_address: String,
    /// The transparent (t-addr) address.
    pub transparent_address: Option<String>,
    /// The Sapling (z-addr) address.
    pub sapling_address: Option<String>,
    /// The Unified Full Viewing Key.
    pub unified_full_viewing_key: String,
}

/// Generate a new wallet with a random seed phrase.
///
/// # Arguments
///
/// * `entropy` - 32 bytes of random entropy for generating the mnemonic.
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn generate_wallet(entropy: &[u8; 32]) -> Result<WalletInfo, WalletError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|e| WalletError::MnemonicGeneration(e.to_string()))?;

    let seed_phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed("");

    derive_wallet(&seed, seed_phrase)
}

/// Restore a wallet from an existing seed phrase.
///
/// # Arguments
///
/// * `seed_phrase` - A valid 24-word BIP39 mnemonic.
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn restore_wallet(seed_phrase: &str) -> Result<WalletInfo, WalletError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase.trim())
        .map_err(|e| WalletError::InvalidSeedPhrase(e.to_string()))?;

    let seed = mnemonic.to_seed("");
    derive_wallet(&seed, mnemonic.to_string())
}

/// Derive wallet addresses and keys from a seed.
///
/// # Arguments
///
/// * `seed` - The 64-byte seed derived from the mnemonic.
/// * `seed_phrase` - The original seed phrase string.
///
/// # Returns
///
/// A `WalletInfo` containing the seed phrase and derived addresses.
pub fn derive_wallet(seed: &[u8], seed_phrase: String) -> Result<WalletInfo, WalletError> {
    let network = Network::TestNetwork;
    let account = AccountId::ZERO;

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::from_seed(&network, seed, account)
        .map_err(|e| WalletError::SpendingKeyDerivation(format!("{:?}", e)))?;

    // Get the unified full viewing key
    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_encoded = ufvk.encode(&network);

    // Generate unified address with all available receivers
    let (ua, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| WalletError::AddressGeneration(format!("{:?}", e)))?;
    let ua_encoded = ua.encode(&network);

    // Get transparent address
    let transparent_address = if let Some(tfvk) = ufvk.transparent() {
        match tfvk.derive_external_ivk() {
            Ok(ivk) => Some(ivk.default_address().0.encode(&network)),
            Err(_) => None,
        }
    } else {
        None
    };

    // Get Sapling address if available
    let sapling_address = ufvk.sapling().map(|dfvk| {
        let (_, payment_address) = dfvk.default_address();
        payment_address.encode(&network)
    });

    Ok(WalletInfo {
        seed_phrase,
        network: "testnet".to_string(),
        unified_address: ua_encoded,
        transparent_address,
        sapling_address,
        unified_full_viewing_key: ufvk_encoded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vector: a fixed seed phrase and its expected derived addresses
    const TEST_SEED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_wallet_is_deterministic() {
        let wallet1 = restore_wallet(TEST_SEED_PHRASE).expect("wallet derivation should succeed");
        let wallet2 = restore_wallet(TEST_SEED_PHRASE).expect("wallet derivation should succeed");

        assert_eq!(wallet1.unified_address, wallet2.unified_address);
        assert_eq!(wallet1.transparent_address, wallet2.transparent_address);
        assert_eq!(wallet1.sapling_address, wallet2.sapling_address);
        assert_eq!(
            wallet1.unified_full_viewing_key,
            wallet2.unified_full_viewing_key
        );
    }

    #[test]
    fn test_derive_wallet_produces_expected_addresses() {
        let wallet = restore_wallet(TEST_SEED_PHRASE).expect("wallet derivation should succeed");

        // Verify addresses are non-empty and have expected prefixes for testnet
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
            wallet
                .sapling_address
                .as_ref()
                .map(|s| s.starts_with("ztestsapling"))
                .unwrap_or(false),
            "sapling address should start with 'ztestsapling' for testnet"
        );
        assert!(
            wallet.unified_full_viewing_key.starts_with("uviewtest"),
            "UFVK should start with 'uviewtest' for testnet"
        );
    }

    #[test]
    fn test_derive_wallet_known_vector() {
        // This test uses a known seed and verifies exact output
        // If this test fails after a library update, it indicates a breaking change
        let wallet = restore_wallet(TEST_SEED_PHRASE).expect("wallet derivation should succeed");

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
        let wallet1 = restore_wallet(TEST_SEED_PHRASE).expect("wallet derivation should succeed");

        // Different seed phrase
        let different_seed = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        let wallet2 = restore_wallet(different_seed).expect("wallet derivation should succeed");

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
    fn test_restore_invalid_seed_fails() {
        let result = restore_wallet("invalid seed phrase");
        assert!(result.is_err(), "should fail with invalid seed phrase");
    }

    #[test]
    fn test_generate_wallet_produces_valid_wallet() {
        let entropy = [0u8; 32]; // Deterministic for testing
        let wallet = generate_wallet(&entropy).expect("wallet generation should succeed");

        assert!(!wallet.seed_phrase.is_empty());
        assert!(!wallet.unified_address.is_empty());
        assert!(wallet.transparent_address.is_some());
        assert!(wallet.sapling_address.is_some());
        assert!(!wallet.unified_full_viewing_key.is_empty());
    }
}
