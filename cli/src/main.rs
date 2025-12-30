use std::fs;
use std::path::Path;

use clap::{Parser, Subcommand};
use rand::RngCore;
use rand::rngs::OsRng;
use zcash_protocol::consensus::Network;
use zcash_wallet_core::{parse_transaction, scan_transaction as scan_tx};

mod db;
mod error;
mod rpc;

use error::{CliError, Result};

#[derive(Parser)]
#[command(name = "zcash-wallet")]
#[command(about = "Zcash testnet wallet CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet
    Generate {
        /// Output file path (wallet is saved as JSON)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
        /// Use mainnet instead of testnet
        #[arg(long)]
        mainnet: bool,
        /// Account index (BIP32 level 3, ZIP32 account). Default: 0
        #[arg(long, default_value = "0")]
        account: u32,
        /// Address index (diversifier index for shielded addresses). Default: 0
        #[arg(long, default_value = "0")]
        address_index: u32,
    },
    /// Restore wallet from seed phrase
    Restore {
        /// The 24-word seed phrase
        #[arg(short, long)]
        seed: String,
        /// Output file path (wallet is saved as JSON if provided)
        #[arg(short, long)]
        output: Option<String>,
        /// Use mainnet instead of testnet
        #[arg(long)]
        mainnet: bool,
        /// Account index (BIP32 level 3, ZIP32 account). Default: 0
        #[arg(long, default_value = "0")]
        account: u32,
        /// Address index (diversifier index for shielded addresses). Default: 0
        #[arg(long, default_value = "0")]
        address_index: u32,
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
    /// Sign a transparent transaction (t-address spending)
    SendTransparent {
        /// Wallet file containing seed phrase
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Database file path (for UTXOs)
        #[arg(long, default_value = "notes.db")]
        db: String,
        /// Recipient address
        #[arg(short, long)]
        to: String,
        /// Amount in zatoshis
        #[arg(short, long)]
        amount: u64,
        /// Fee in zatoshis (default: 10000 = 0.0001 ZEC)
        #[arg(long, default_value = "10000")]
        fee: u64,
        /// Block height for expiry (0 = no expiry)
        #[arg(long, default_value = "0")]
        expiry_height: u32,
    },
    /// Show transaction history (ledger)
    Ledger {
        /// Database file path
        #[arg(long, default_value = "notes.db")]
        db: String,
        /// Export as CSV to file
        #[arg(long)]
        export: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            output,
            mainnet,
            account,
            address_index,
        } => generate_wallet(&output, mainnet, account, address_index),
        Commands::Restore {
            seed,
            output,
            mainnet,
            account,
            address_index,
        } => restore_wallet(&seed, output.as_deref(), mainnet, account, address_index),
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
        Commands::SendTransparent {
            wallet,
            db,
            to,
            amount,
            fee,
            expiry_height,
        } => send_transparent(&wallet, &db, &to, amount, fee, expiry_height),
        Commands::Ledger { db, export } => show_ledger(&db, export.as_deref()),
    }
}

fn generate_wallet(
    output_path: &str,
    mainnet: bool,
    account: u32,
    address_index: u32,
) -> Result<()> {
    // Check if output file already exists
    let path = Path::new(output_path);
    if path.exists() {
        return Err(CliError::FileExists(output_path.to_string()));
    }

    let network = if mainnet {
        Network::MainNetwork
    } else {
        Network::TestNetwork
    };
    let network_name = if mainnet { "MAINNET" } else { "TESTNET" };

    // Generate random entropy for 24-word mnemonic (256 bits = 32 bytes)
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    // Use core library for wallet derivation
    let wallet = zcash_wallet_core::generate_wallet(&entropy, network, account, address_index)
        .map_err(|e| CliError::Wallet(e.to_string()))?;

    // Create JSON wallet data
    let wallet_json = serde_json::json!({
        "seed_phrase": wallet.seed_phrase,
        "network": wallet.network,
        "account_index": wallet.account_index,
        "address_index": wallet.address_index,
        "unified_address": wallet.unified_address,
        "unified_full_viewing_key": wallet.unified_full_viewing_key,
        "transparent_address": wallet.transparent_address,
    });

    // Write wallet to file
    let json_string = serde_json::to_string_pretty(&wallet_json)?;
    fs::write(path, &json_string).map_err(|e| CliError::FileWrite {
        path: output_path.to_string(),
        source: e,
    })?;

    // Print summary to console
    println!("============================================================");
    println!("           ZCASH {} WALLET GENERATED", network_name);
    println!("============================================================");
    println!();
    println!("Wallet saved to: {}", output_path);
    println!();
    println!("IMPORTANT: Keep this file secure! It contains your seed phrase.");
    println!();
    println!("------------------------------------------------------------");
    println!("DERIVATION PATH");
    println!("------------------------------------------------------------");
    println!();
    println!("Account: {}", wallet.account_index);
    println!("Address Index: {}", wallet.address_index);
    println!();
    println!("------------------------------------------------------------");
    println!("ADDRESSES");
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
    if mainnet {
        println!("WARNING: This is a mainnet wallet. Any ZEC sent to these");
        println!("addresses has real monetary value. Keep your seed phrase safe!");
    } else {
        println!("Next steps:");
        println!("  1. Copy your Unified or Transparent address");
        println!("  2. Go to https://testnet.zecfaucet.com/");
        println!("  3. Paste your address and request testnet ZEC");
        println!("  4. Use the viewing key in the web viewer to see transactions");
    }
    println!();

    Ok(())
}

fn restore_wallet(
    seed_phrase: &str,
    output_path: Option<&str>,
    mainnet: bool,
    account: u32,
    address_index: u32,
) -> Result<()> {
    let network = if mainnet {
        Network::MainNetwork
    } else {
        Network::TestNetwork
    };
    let network_name = if mainnet { "MAINNET" } else { "TESTNET" };

    // Use core library for wallet restoration
    let wallet = zcash_wallet_core::restore_wallet(seed_phrase, network, account, address_index)
        .map_err(|e| CliError::Wallet(e.to_string()))?;

    // Save to file if output path is provided
    if let Some(path_str) = output_path {
        let path = Path::new(path_str);
        if path.exists() {
            return Err(CliError::FileExists(path_str.to_string()));
        }

        let wallet_json = serde_json::json!({
            "seed_phrase": wallet.seed_phrase,
            "network": wallet.network,
            "account_index": wallet.account_index,
            "address_index": wallet.address_index,
            "unified_address": wallet.unified_address,
            "unified_full_viewing_key": wallet.unified_full_viewing_key,
            "transparent_address": wallet.transparent_address,
        });

        let json_string = serde_json::to_string_pretty(&wallet_json)?;
        fs::write(path, &json_string).map_err(|e| CliError::FileWrite {
            path: path_str.to_string(),
            source: e,
        })?;
    }

    println!("============================================================");
    println!("           {} WALLET RESTORED FROM SEED", network_name);
    println!("============================================================");
    println!();
    if let Some(path) = output_path {
        println!("Wallet saved to: {}", path);
        println!();
    }
    println!("------------------------------------------------------------");
    println!("DERIVATION PATH");
    println!("------------------------------------------------------------");
    println!();
    println!("Account: {}", wallet.account_index);
    println!("Address Index: {}", wallet.address_index);
    println!();
    println!("------------------------------------------------------------");
    println!("ADDRESSES");
    println!("------------------------------------------------------------");
    println!();
    println!("Unified Address:");
    println!("  {}", wallet.unified_address);
    println!();
    if let Some(ref transparent) = wallet.transparent_address {
        println!("Transparent Address:");
        println!("  {}", transparent);
        println!();
    }
    println!("------------------------------------------------------------");
    println!("VIEWING KEY");
    println!("------------------------------------------------------------");
    println!();
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
    // Load wallet to get viewing key and network
    let wallet_content = fs::read_to_string(wallet_path).map_err(|e| CliError::FileRead {
        path: wallet_path.to_string(),
        source: e,
    })?;
    let wallet_json: serde_json::Value =
        serde_json::from_str(&wallet_content).map_err(|e| CliError::JsonParse {
            context: "wallet file".to_string(),
            source: e,
        })?;
    let viewing_key = wallet_json["unified_full_viewing_key"]
        .as_str()
        .ok_or_else(|| CliError::MissingField("unified_full_viewing_key".to_string()))?;

    // Get network from wallet file
    let network_str = wallet_json["network"].as_str().unwrap_or("testnet");
    let network = match network_str {
        "mainnet" => Network::MainNetwork,
        _ => Network::TestNetwork,
    };

    // Get transaction hex
    let tx_hex = if let Some(hex) = raw_hex {
        hex
    } else if let Some(ref txid) = txid {
        // Fetch via RPC
        let db = db::Database::open(db_path)?;
        let rpc_url = db.get_config("rpc_url")?.ok_or_else(|| {
            CliError::ConfigMissing(
                "RPC URL not configured. Run: zcash-wallet config --rpc-url <url>".to_string(),
            )
        })?;
        let client = rpc::RpcClient::new(&rpc_url);
        println!("Fetching transaction {} from RPC...", txid);
        client.get_raw_transaction(txid)?
    } else {
        return Err(CliError::InvalidArgument(
            "Must provide either --txid or --raw".to_string(),
        ));
    };

    // Parse and scan transaction
    let tx = parse_transaction(&tx_hex, network)?;
    let result = scan_tx(&tx, viewing_key, network, height)?;

    // Open database
    let db = db::Database::open(db_path)?;

    // Store notes
    let mut notes_added = 0;
    for note in &result.notes {
        let inserted = db.insert_note(
            &result.txid,
            note.output_index as i64,
            note.pool.as_str(),
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

    // Create ledger entry
    let value_received: i64 = result.notes.iter().map(|n| n.value as i64).sum();
    let value_spent: i64 = 0; // We don't know spent values from scan result
    let net_change = value_received - value_spent;
    let primary_pool = if result.notes.is_empty() {
        "unknown"
    } else {
        // Use the pool of the first note (or "mixed" if multiple pools)
        let pools: std::collections::HashSet<_> =
            result.notes.iter().map(|n| n.pool.as_str()).collect();
        if pools.len() == 1 {
            result.notes[0].pool.as_str()
        } else {
            "mixed"
        }
    };
    let memos: String = result
        .notes
        .iter()
        .filter_map(|n| n.memo.as_ref())
        .filter(|m| !m.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let memos_opt = if memos.is_empty() {
        None
    } else {
        Some(memos.as_str())
    };

    db.upsert_ledger_entry(
        &result.txid,
        height.map(|h| h as i64),
        value_received,
        value_spent,
        net_change,
        0, // fee_paid unknown
        primary_pool,
        memos_opt,
    )?;

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

fn send_transparent(
    wallet_path: &str,
    db_path: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    expiry_height: u32,
) -> Result<()> {
    // Load wallet to get seed phrase and network
    let wallet_content = fs::read_to_string(wallet_path).map_err(|e| CliError::FileRead {
        path: wallet_path.to_string(),
        source: e,
    })?;
    let wallet_json: serde_json::Value =
        serde_json::from_str(&wallet_content).map_err(|e| CliError::JsonParse {
            context: "wallet file".to_string(),
            source: e,
        })?;

    let seed_phrase = wallet_json["seed_phrase"]
        .as_str()
        .ok_or_else(|| CliError::MissingField("seed_phrase".to_string()))?;

    let account_index = wallet_json["account_index"].as_u64().unwrap_or(0) as u32;

    // Get network from wallet file
    let network_str = wallet_json["network"].as_str().unwrap_or("testnet");
    let network = match network_str {
        "mainnet" => Network::MainNetwork,
        _ => Network::TestNetwork,
    };

    // Get unspent transparent UTXOs from database
    let db = db::Database::open(db_path)?;
    let notes = db.get_unspent_notes()?;

    // Filter for transparent notes with addresses
    let utxos: Vec<zcash_wallet_core::Utxo> = notes
        .iter()
        .filter(|n| n.pool == "transparent" && n.address.is_some())
        .map(|n| zcash_wallet_core::Utxo {
            txid: n.txid.clone(),
            vout: n.output_index as u32,
            value: n.value as u64,
            address: n.address.clone().unwrap(),
            script_pubkey: None,
        })
        .collect();

    if utxos.is_empty() {
        return Err(CliError::InsufficientFunds(
            "No unspent transparent UTXOs available".to_string(),
        ));
    }

    // Calculate total available
    let total_available: u64 = utxos.iter().map(|u| u.value).sum();
    let total_required = amount + fee;

    if total_available < total_required {
        return Err(CliError::InsufficientFunds(format!(
            "Insufficient funds: have {} zatoshis, need {} zatoshis (amount: {}, fee: {})",
            total_available, total_required, amount, fee
        )));
    }

    println!();
    println!("============================================================");
    println!("           SIGN TRANSPARENT TRANSACTION");
    println!("============================================================");
    println!();
    println!("Network: {}", network_str);
    println!("From wallet: {}", wallet_path);
    println!("To: {}", to_address);
    println!(
        "Amount: {} ZEC ({} zatoshis)",
        format_zatoshi(amount),
        amount
    );
    println!("Fee: {} ZEC ({} zatoshis)", format_zatoshi(fee), fee);
    println!("Total: {} ZEC", format_zatoshi(total_required));
    println!(
        "Available UTXOs: {} ({} ZEC)",
        utxos.len(),
        format_zatoshi(total_available)
    );
    if expiry_height > 0 {
        println!("Expires at block: {}", expiry_height);
    }
    println!();

    // Create recipient
    let recipients = vec![zcash_wallet_core::Recipient {
        address: to_address.to_string(),
        amount,
    }];

    // Build and sign transaction
    println!("Signing transaction...");
    let signed = zcash_wallet_core::build_transparent_transaction(
        seed_phrase,
        network,
        account_index,
        utxos,
        recipients,
        fee,
        expiry_height,
    )
    .map_err(|e| CliError::Transaction(format!("{:?}", e)))?;

    println!();
    println!("============================================================");
    println!("           TRANSACTION SIGNED SUCCESSFULLY");
    println!("============================================================");
    println!();
    println!("Transaction ID: {}", signed.txid);
    println!("Total input: {} ZEC", format_zatoshi(signed.total_input));
    println!("Total output: {} ZEC", format_zatoshi(signed.total_output));
    println!("Fee: {} ZEC", format_zatoshi(signed.fee));
    println!();
    println!("Raw transaction hex:");
    println!();
    println!("{}", signed.tx_hex);
    println!();
    println!("------------------------------------------------------------");
    println!("To broadcast this transaction:");
    println!("  1. Use a Zcash node RPC: zcash-cli sendrawtransaction <hex>");
    println!("  2. Or use a block explorer's broadcast feature");
    println!("------------------------------------------------------------");
    println!();

    Ok(())
}

fn show_ledger(db_path: &str, export_path: Option<&str>) -> Result<()> {
    let db = db::Database::open(db_path)?;

    // Export to CSV if requested
    if let Some(path) = export_path {
        let csv = db.export_ledger_csv()?;
        std::fs::write(path, &csv).map_err(|e| CliError::FileWrite {
            path: path.to_string(),
            source: e,
        })?;
        println!("Ledger exported to: {}", path);
        return Ok(());
    }

    let entries = db.get_ledger_entries()?;

    println!();
    println!("============================================================");
    println!("           TRANSACTION HISTORY (LEDGER)");
    println!("============================================================");
    println!();

    if entries.is_empty() {
        println!("No transactions in ledger.");
        println!();
        println!("Scan transactions to build your transaction history.");
        println!();
        return Ok(());
    }

    for entry in &entries {
        let direction = if entry.net_change >= 0 {
            "RECEIVED"
        } else {
            "SENT"
        };
        println!("------------------------------------------------------------");
        println!("Transaction [{}]", direction);
        println!("------------------------------------------------------------");
        println!("  TxID: {}", entry.txid);
        if let Some(height) = entry.height {
            println!("  Height: {}", height);
        }
        println!("  Pool: {}", entry.primary_pool);
        println!(
            "  Received: {} ZEC",
            format_zatoshi(entry.value_received as u64)
        );
        println!("  Spent: {} ZEC", format_zatoshi(entry.value_spent as u64));
        let sign = if entry.net_change >= 0 { "+" } else { "" };
        println!(
            "  Net: {}{} ZEC",
            sign,
            format_zatoshi(entry.net_change.unsigned_abs())
        );
        if let Some(ref memos) = entry.memos
            && !memos.is_empty()
        {
            println!(
                "  Memo: {}",
                if memos.len() > 50 {
                    format!("{}...", &memos[..50])
                } else {
                    memos.clone()
                }
            );
        }
        println!("  Date: {}", entry.created_at);
        println!();
    }

    let ledger_balance = db.get_ledger_balance()?;
    let sign = if ledger_balance >= 0 { "" } else { "-" };
    println!("============================================================");
    println!(
        "Ledger Balance: {}{} ZEC",
        sign,
        format_zatoshi(ledger_balance.unsigned_abs())
    );
    println!("Total Transactions: {}", entries.len());
    println!("============================================================");
    println!();
    println!("Tip: Use --export <file.csv> to export for tax reporting.");
    println!();

    Ok(())
}
