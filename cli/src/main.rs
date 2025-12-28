use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rand::rngs::OsRng;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::Network;
use zcash_transparent::keys::IncomingViewingKey;
use zip32::AccountId;

mod db;
mod rpc;
mod scanner;

#[derive(Parser)]
#[command(name = "zcash-wallet")]
#[command(about = "Zcash testnet wallet CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new testnet wallet
    Generate {
        /// Output file path (wallet is saved as JSON)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Restore wallet from seed phrase
    Restore {
        /// The 24-word seed phrase
        #[arg(short, long)]
        seed: String,
    },
    /// Show faucet information
    Faucet,
    /// Configure settings (e.g., RPC URL)
    Config {
        /// RPC URL for Zcash node
        #[arg(long)]
        rpc_url: Option<String>,
        /// Database file path
        #[arg(long, default_value = "notes.db")]
        db: String,
    },
    /// Scan a transaction for notes
    Scan {
        /// Transaction ID to fetch via RPC
        #[arg(long, conflicts_with = "raw")]
        txid: Option<String>,
        /// Raw transaction hex (alternative to txid)
        #[arg(long, conflicts_with = "txid")]
        raw: Option<String>,
        /// Wallet file containing viewing key
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Database file path
        #[arg(long, default_value = "notes.db")]
        db: String,
        /// Block height (optional, for better decryption)
        #[arg(long)]
        height: Option<u32>,
    },
    /// Show balance from tracked notes
    Balance {
        /// Database file path
        #[arg(long, default_value = "notes.db")]
        db: String,
    },
    /// List all tracked notes
    Notes {
        /// Database file path
        #[arg(long, default_value = "notes.db")]
        db: String,
        /// Show all notes including spent
        #[arg(long)]
        all: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output } => generate_wallet(&output),
        Commands::Restore { seed } => restore_wallet(&seed),
        Commands::Faucet => show_faucet_info(),
        Commands::Config { rpc_url, db } => configure(&db, rpc_url),
        Commands::Scan {
            txid,
            raw,
            wallet,
            db,
            height,
        } => scan_transaction(&db, &wallet, txid, raw, height),
        Commands::Balance { db } => show_balance(&db),
        Commands::Notes { db, all } => list_notes(&db, all),
    }
}

fn generate_wallet(output_path: &str) -> Result<()> {
    // Check if output file already exists
    let path = Path::new(output_path);
    if path.exists() {
        bail!(
            "Output file '{}' already exists. Choose a different filename or remove the existing file.",
            output_path
        );
    }

    // Generate random entropy for 24-word mnemonic (256 bits = 32 bytes)
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    let seed_phrase = mnemonic.to_string();

    // Derive wallet from seed
    let seed = mnemonic.to_seed("");
    let wallet = derive_wallet(&seed)?;

    // Create JSON wallet data
    let wallet_json = serde_json::json!({
        "seed_phrase": seed_phrase,
        "network": "testnet",
        "unified_address": wallet.unified_address,
        "unified_full_viewing_key": wallet.ufvk,
        "transparent_address": wallet.transparent_address,
        "sapling_address": wallet.sapling_address,
    });

    // Write wallet to file
    let json_string = serde_json::to_string_pretty(&wallet_json)?;
    fs::write(path, &json_string).context("Failed to write wallet file")?;

    // Print summary to console
    println!("============================================================");
    println!("           ZCASH TESTNET WALLET GENERATED");
    println!("============================================================");
    println!();
    println!("Wallet saved to: {}", output_path);
    println!();
    println!("IMPORTANT: Keep this file secure! It contains your seed phrase.");
    println!();
    println!("------------------------------------------------------------");
    println!("ADDRESSES (use these with the faucet)");
    println!("------------------------------------------------------------");
    println!();
    println!("Unified Address (recommended):");
    println!("  {}", wallet.unified_address);
    println!();
    println!("Transparent Address:");
    println!("  {}", wallet.transparent_address);
    println!();
    if let Some(ref sapling) = wallet.sapling_address {
        println!("Sapling Address:");
        println!("  {}", sapling);
        println!();
    }
    println!("------------------------------------------------------------");
    println!("VIEWING KEY (use this with the transaction viewer)");
    println!("------------------------------------------------------------");
    println!();
    println!("Unified Full Viewing Key:");
    println!("  {}", wallet.ufvk);
    println!();
    println!("============================================================");
    println!();
    println!("Next steps:");
    println!("  1. Copy your Unified or Transparent address");
    println!("  2. Go to https://testnet.zecfaucet.com/");
    println!("  3. Paste your address and request testnet ZEC");
    println!("  4. Use the viewing key in the web viewer to see transactions");
    println!();

    Ok(())
}

fn restore_wallet(seed_phrase: &str) -> Result<()> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed_phrase)
        .context("Invalid seed phrase")?;

    let seed = mnemonic.to_seed("");
    let wallet = derive_wallet(&seed)?;

    println!("============================================================");
    println!("           WALLET RESTORED FROM SEED");
    println!("============================================================");
    println!();
    println!("Unified Address:");
    println!("  {}", wallet.unified_address);
    println!();
    println!("Transparent Address:");
    println!("  {}", wallet.transparent_address);
    println!();
    if let Some(ref sapling) = wallet.sapling_address {
        println!("Sapling Address:");
        println!("  {}", sapling);
        println!();
    }
    println!("Unified Full Viewing Key:");
    println!("  {}", wallet.ufvk);
    println!();

    Ok(())
}

fn show_faucet_info() -> Result<()> {
    println!("============================================================");
    println!("           ZCASH TESTNET FAUCET");
    println!("============================================================");
    println!();
    println!("To get testnet ZEC:");
    println!();
    println!("  1. Generate a wallet: zcash-wallet generate");
    println!("  2. Go to: https://testnet.zecfaucet.com/");
    println!("  3. Enter your address and solve the captcha");
    println!("  4. You'll receive testnet ZEC (TAZ)");
    println!();
    println!("Note: Testnet ZEC has no real value and is only for testing.");
    println!();

    Ok(())
}

fn configure(db_path: &str, rpc_url: Option<String>) -> Result<()> {
    let db = db::Database::open(db_path)?;

    if let Some(url) = rpc_url {
        db.set_config("rpc_url", &url)?;
        println!("RPC URL set to: {}", url);
    }

    // Show current config
    println!();
    println!("Current configuration:");
    println!("  Database: {}", db_path);
    if let Some(url) = db.get_config("rpc_url")? {
        println!("  RPC URL: {}", url);
    } else {
        println!("  RPC URL: (not configured)");
    }
    println!();

    Ok(())
}

fn scan_transaction(
    db_path: &str,
    wallet_path: &str,
    txid: Option<String>,
    raw_hex: Option<String>,
    height: Option<u32>,
) -> Result<()> {
    // Load wallet to get viewing key
    let wallet_content = fs::read_to_string(wallet_path)
        .with_context(|| format!("Failed to read wallet file: {}", wallet_path))?;
    let wallet_json: serde_json::Value =
        serde_json::from_str(&wallet_content).context("Failed to parse wallet JSON")?;
    let viewing_key = wallet_json["unified_full_viewing_key"]
        .as_str()
        .context("Wallet missing unified_full_viewing_key")?;

    // Get transaction hex
    let tx_hex = if let Some(hex) = raw_hex {
        hex
    } else if let Some(ref txid) = txid {
        // Fetch via RPC
        let db = db::Database::open(db_path)?;
        let rpc_url = db
            .get_config("rpc_url")?
            .context("RPC URL not configured. Run: zcash-wallet config --rpc-url <url>")?;
        let client = rpc::RpcClient::new(&rpc_url);
        println!("Fetching transaction {} from RPC...", txid);
        client.get_raw_transaction(txid)?
    } else {
        bail!("Must provide either --txid or --raw");
    };

    // Parse and scan transaction
    let network = Network::TestNetwork;
    let tx = scanner::parse_transaction(&tx_hex, network)?;
    let result = scanner::scan_transaction(&tx, viewing_key, network, height)?;

    // Open database
    let db = db::Database::open(db_path)?;

    // Store notes
    let mut notes_added = 0;
    for note in &result.notes {
        let inserted = db.insert_note(
            &result.txid,
            note.output_index as i64,
            &note.pool,
            note.value as i64,
            Some(note.commitment.as_str()),
            note.nullifier.as_deref(),
            note.memo.as_deref(),
            note.address.as_deref(),
            height.map(|h| h as i64),
        )?;
        if inserted {
            notes_added += 1;
        }
    }

    // Check for spent nullifiers
    let nullifier_strings: Vec<String> = result
        .spent_nullifiers
        .iter()
        .map(|n| n.nullifier.clone())
        .collect();
    let notes_spent = db.mark_spent_by_nullifiers(&nullifier_strings, &result.txid)?;

    // Print results
    println!();
    println!("============================================================");
    println!("           TRANSACTION SCANNED");
    println!("============================================================");
    println!();
    println!("Transaction ID: {}", result.txid);
    println!();
    println!("Notes found: {}", result.notes.len());
    println!("  New notes added to database: {}", notes_added);
    println!();
    println!(
        "Nullifiers in transaction: {}",
        result.spent_nullifiers.len()
    );
    println!("  Notes marked as spent: {}", notes_spent);
    println!();

    if !result.notes.is_empty() {
        println!("------------------------------------------------------------");
        println!("NOTES RECEIVED");
        println!("------------------------------------------------------------");
        for note in &result.notes {
            println!();
            println!("  Pool: {}", note.pool);
            println!("  Index: {}", note.output_index);
            println!("  Value: {} ZEC", format_zatoshi(note.value));
            println!(
                "  Commitment: {}...",
                &note.commitment[..16.min(note.commitment.len())]
            );
        }
        println!();
    }

    if !result.spent_nullifiers.is_empty() {
        println!("------------------------------------------------------------");
        println!("NULLIFIERS (spent notes)");
        println!("------------------------------------------------------------");
        for nullifier in &result.spent_nullifiers {
            println!("  [{}] {}...", nullifier.pool, &nullifier.nullifier[..16]);
        }
        println!();
    }

    // Show updated balance
    let balance = db.get_balance()?;
    println!("============================================================");
    println!("Current balance: {} ZEC", format_zatoshi(balance as u64));
    println!("============================================================");
    println!();

    Ok(())
}

fn show_balance(db_path: &str) -> Result<()> {
    let db = db::Database::open(db_path)?;

    let total_balance = db.get_balance()?;
    let balances_by_pool = db.get_balance_by_pool()?;

    println!();
    println!("============================================================");
    println!("           WALLET BALANCE");
    println!("============================================================");
    println!();
    println!("Total: {} ZEC", format_zatoshi(total_balance as u64));
    println!();

    if !balances_by_pool.is_empty() {
        println!("By pool:");
        for (pool, balance) in balances_by_pool {
            println!("  {}: {} ZEC", pool, format_zatoshi(balance as u64));
        }
        println!();
    }

    Ok(())
}

fn list_notes(db_path: &str, show_all: bool) -> Result<()> {
    let db = db::Database::open(db_path)?;

    let notes = if show_all {
        db.get_all_notes()?
    } else {
        db.get_unspent_notes()?
    };

    println!();
    println!("============================================================");
    if show_all {
        println!("           ALL NOTES");
    } else {
        println!("           UNSPENT NOTES");
    }
    println!("============================================================");
    println!();

    if notes.is_empty() {
        println!("No notes found.");
        println!();
        return Ok(());
    }

    for note in &notes {
        let status = if note.spent_txid.is_some() {
            "SPENT"
        } else {
            "UNSPENT"
        };
        println!("------------------------------------------------------------");
        println!("Note #{} [{}]", note.id, status);
        println!("------------------------------------------------------------");
        println!("  Transaction: {}", note.txid);
        println!("  Output Index: {}", note.output_index);
        println!("  Pool: {}", note.pool);
        println!("  Value: {} ZEC", format_zatoshi(note.value as u64));
        if let Some(ref commitment) = note.commitment {
            println!(
                "  Commitment: {}...",
                &commitment[..16.min(commitment.len())]
            );
        }
        if let Some(ref nullifier) = note.nullifier {
            println!("  Nullifier: {}...", &nullifier[..16.min(nullifier.len())]);
        }
        if let Some(ref spent_txid) = note.spent_txid {
            println!("  Spent in: {}", spent_txid);
        }
        println!();
    }

    let total: i64 = notes
        .iter()
        .filter(|n| n.spent_txid.is_none())
        .map(|n| n.value)
        .sum();
    println!("============================================================");
    println!("Total unspent: {} ZEC", format_zatoshi(total as u64));
    println!("============================================================");
    println!();

    Ok(())
}

/// Format zatoshi amount as ZEC with 8 decimal places.
fn format_zatoshi(zatoshi: u64) -> String {
    let zec = zatoshi as f64 / 100_000_000.0;
    format!("{:.8}", zec)
}

struct WalletInfo {
    unified_address: String,
    transparent_address: String,
    sapling_address: Option<String>,
    ufvk: String,
}

fn derive_wallet(seed: &[u8]) -> Result<WalletInfo> {
    let network = Network::TestNetwork;
    let account = AccountId::ZERO;

    // Create UnifiedSpendingKey from seed
    let usk = UnifiedSpendingKey::from_seed(&network, seed, account)
        .map_err(|e| anyhow::anyhow!("Failed to derive spending key: {:?}", e))?;

    // Get the unified full viewing key
    let ufvk = usk.to_unified_full_viewing_key();

    // Encode UFVK
    let ufvk_encoded = ufvk.encode(&network);

    // Generate unified address with all available receivers
    let (ua, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| anyhow::anyhow!("Failed to generate address: {:?}", e))?;
    let ua_encoded = ua.encode(&network);

    // Get transparent address
    let transparent_address = if let Some(tfvk) = ufvk.transparent() {
        let taddr = tfvk
            .derive_external_ivk()
            .map_err(|e| anyhow::anyhow!("Failed to derive transparent key: {:?}", e))?
            .default_address()
            .0;
        taddr.encode(&network)
    } else {
        "Not available".to_string()
    };

    // Get Sapling address if available
    let sapling_address = ufvk.sapling().map(|dfvk| {
        let (_, payment_address) = dfvk.default_address();
        payment_address.encode(&network)
    });

    Ok(WalletInfo {
        unified_address: ua_encoded,
        transparent_address,
        sapling_address,
        ufvk: ufvk_encoded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known test vector: a fixed seed phrase and its expected derived addresses
    const TEST_SEED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn test_derive_wallet_is_deterministic() {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_SEED_PHRASE)
            .expect("valid test seed phrase");
        let seed = mnemonic.to_seed("");

        let wallet1 = derive_wallet(&seed).expect("wallet derivation should succeed");
        let wallet2 = derive_wallet(&seed).expect("wallet derivation should succeed");

        assert_eq!(wallet1.unified_address, wallet2.unified_address);
        assert_eq!(wallet1.transparent_address, wallet2.transparent_address);
        assert_eq!(wallet1.sapling_address, wallet2.sapling_address);
        assert_eq!(wallet1.ufvk, wallet2.ufvk);
    }

    #[test]
    fn test_derive_wallet_produces_expected_addresses() {
        // Test that the known seed phrase produces consistent, expected results
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_SEED_PHRASE)
            .expect("valid test seed phrase");
        let seed = mnemonic.to_seed("");

        let wallet = derive_wallet(&seed).expect("wallet derivation should succeed");

        // Verify addresses are non-empty and have expected prefixes for testnet
        assert!(
            wallet.unified_address.starts_with("utest"),
            "unified address should start with 'utest' for testnet"
        );
        assert!(
            wallet.transparent_address.starts_with("tm"),
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
            wallet.ufvk.starts_with("uviewtest"),
            "UFVK should start with 'uviewtest' for testnet"
        );
    }

    #[test]
    fn test_derive_wallet_known_vector() {
        // This test uses a known seed and verifies exact output
        // If this test fails after a library update, it indicates a breaking change
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, TEST_SEED_PHRASE)
            .expect("valid test seed phrase");
        let seed = mnemonic.to_seed("");

        let wallet = derive_wallet(&seed).expect("wallet derivation should succeed");

        // These are the expected values for the standard BIP39 test vector
        // "abandon abandon ... art" on Zcash testnet
        assert_eq!(
            wallet.transparent_address, "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd",
            "transparent address mismatch - library may have changed derivation"
        );

        assert_eq!(
            wallet.ufvk,
            "uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd",
            "UFVK mismatch - library may have changed derivation"
        );
    }

    #[test]
    fn test_different_seeds_produce_different_wallets() {
        let mnemonic1 = Mnemonic::parse_in_normalized(Language::English, TEST_SEED_PHRASE)
            .expect("valid test seed phrase");
        let seed1 = mnemonic1.to_seed("");

        // Different seed phrase
        let different_seed = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        let mnemonic2 = Mnemonic::parse_in_normalized(Language::English, different_seed)
            .expect("valid test seed phrase");
        let seed2 = mnemonic2.to_seed("");

        let wallet1 = derive_wallet(&seed1).expect("wallet derivation should succeed");
        let wallet2 = derive_wallet(&seed2).expect("wallet derivation should succeed");

        assert_ne!(
            wallet1.unified_address, wallet2.unified_address,
            "different seeds should produce different unified addresses"
        );
        assert_ne!(
            wallet1.transparent_address, wallet2.transparent_address,
            "different seeds should produce different transparent addresses"
        );
        assert_ne!(
            wallet1.ufvk, wallet2.ufvk,
            "different seeds should produce different UFVKs"
        );
    }
}
