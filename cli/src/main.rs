use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rand::rngs::OsRng;
use zcash_protocol::consensus::Network;

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
        /// Output file path (wallet is saved as JSON if provided)
        #[arg(short, long)]
        output: Option<String>,
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
        Commands::Restore { seed, output } => restore_wallet(&seed, output.as_deref()),
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

    // Use core library for wallet derivation
    let wallet = zcash_wallet_core::generate_wallet(&entropy)
        .map_err(|e| anyhow::anyhow!("Failed to generate wallet: {}", e))?;

    // Create JSON wallet data
    let wallet_json = serde_json::json!({
        "seed_phrase": wallet.seed_phrase,
        "network": wallet.network,
        "unified_address": wallet.unified_address,
        "unified_full_viewing_key": wallet.unified_full_viewing_key,
        "transparent_address": wallet.transparent_address,
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
    if let Some(ref transparent) = wallet.transparent_address {
        println!("Transparent Address:");
        println!("  {}", transparent);
        println!();
    }
    println!("------------------------------------------------------------");
    println!("VIEWING KEY (use this with the transaction viewer)");
    println!("------------------------------------------------------------");
    println!();
    println!("Unified Full Viewing Key:");
    println!("  {}", wallet.unified_full_viewing_key);
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

fn restore_wallet(seed_phrase: &str, output_path: Option<&str>) -> Result<()> {
    // Use core library for wallet restoration
    let wallet = zcash_wallet_core::restore_wallet(seed_phrase)
        .map_err(|e| anyhow::anyhow!("Failed to restore wallet: {}", e))?;

    // Save to file if output path is provided
    if let Some(path_str) = output_path {
        let path = Path::new(path_str);
        if path.exists() {
            bail!(
                "Output file '{}' already exists. Choose a different filename or remove the existing file.",
                path_str
            );
        }

        let wallet_json = serde_json::json!({
            "seed_phrase": wallet.seed_phrase,
            "network": wallet.network,
            "unified_address": wallet.unified_address,
            "unified_full_viewing_key": wallet.unified_full_viewing_key,
            "transparent_address": wallet.transparent_address,
        });

        let json_string = serde_json::to_string_pretty(&wallet_json)?;
        fs::write(path, &json_string).context("Failed to write wallet file")?;
    }

    println!("============================================================");
    println!("           WALLET RESTORED FROM SEED");
    println!("============================================================");
    println!();
    if let Some(path) = output_path {
        println!("Wallet saved to: {}", path);
        println!();
    }
    println!("Unified Address:");
    println!("  {}", wallet.unified_address);
    println!();
    if let Some(ref transparent) = wallet.transparent_address {
        println!("Transparent Address:");
        println!("  {}", transparent);
        println!();
    }
    println!("Unified Full Viewing Key:");
    println!("  {}", wallet.unified_full_viewing_key);
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
