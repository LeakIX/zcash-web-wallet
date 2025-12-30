//! SQLite database module for storing notes, nullifiers, and ledger entries.

use crate::error::{CliError, Result};
use rusqlite::{Connection, params};
use std::path::Path;

/// Represents a tracked note in the database.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Note {
    pub id: i64,
    pub txid: String,
    pub output_index: i64,
    pub pool: String,
    pub value: i64,
    pub commitment: Option<String>,
    pub nullifier: Option<String>,
    pub memo: Option<String>,
    pub address: Option<String>,
    pub height: Option<i64>,
    pub spent_txid: Option<String>,
}

/// Represents a ledger entry (transaction-level view).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LedgerEntry {
    pub id: i64,
    pub txid: String,
    pub height: Option<i64>,
    pub timestamp: Option<String>,
    pub value_received: i64,
    pub value_spent: i64,
    pub net_change: i64,
    pub fee_paid: i64,
    pub primary_pool: String,
    pub memos: Option<String>,
    pub created_at: String,
}

/// Database handle for note storage.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| CliError::Database(format!("Failed to open database: {}", e)))?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(|e| CliError::Database(format!("Failed to open in-memory database: {}", e)))?;
        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    /// Initialize the database schema.
    fn init(&self) -> Result<()> {
        self.conn
            .execute_batch(
                r#"
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL,
                output_index INTEGER NOT NULL,
                pool TEXT NOT NULL,
                value INTEGER NOT NULL,
                commitment TEXT,
                nullifier TEXT,
                memo TEXT,
                address TEXT,
                height INTEGER,
                spent_txid TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(txid, output_index, pool)
            );

            CREATE INDEX IF NOT EXISTS idx_nullifier ON notes(nullifier);
            CREATE INDEX IF NOT EXISTS idx_spent ON notes(spent_txid);

            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txid TEXT NOT NULL UNIQUE,
                height INTEGER,
                timestamp TEXT,
                value_received INTEGER NOT NULL DEFAULT 0,
                value_spent INTEGER NOT NULL DEFAULT 0,
                net_change INTEGER NOT NULL DEFAULT 0,
                fee_paid INTEGER NOT NULL DEFAULT 0,
                primary_pool TEXT NOT NULL DEFAULT 'unknown',
                memos TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_ledger_height ON ledger(height);
            "#,
            )
            .map_err(|e| {
                CliError::Database(format!("Failed to initialize database schema: {}", e))
            })?;
        Ok(())
    }

    /// Get a configuration value.
    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM config WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Set a configuration value.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Insert a new note. Returns Ok(true) if inserted, Ok(false) if already exists.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_note(
        &self,
        txid: &str,
        output_index: i64,
        pool: &str,
        value: i64,
        commitment: Option<&str>,
        nullifier: Option<&str>,
        memo: Option<&str>,
        address: Option<&str>,
        height: Option<i64>,
    ) -> Result<bool> {
        let result = self.conn.execute(
            r#"
            INSERT OR IGNORE INTO notes
            (txid, output_index, pool, value, commitment, nullifier, memo, address, height)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                txid,
                output_index,
                pool,
                value,
                commitment,
                nullifier,
                memo,
                address,
                height
            ],
        )?;
        Ok(result > 0)
    }

    /// Get all unspent notes (where spent_txid is NULL).
    pub fn get_unspent_notes(&self) -> Result<Vec<Note>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, txid, output_index, pool, value, commitment, nullifier,
                   memo, address, height, spent_txid
            FROM notes
            WHERE spent_txid IS NULL
            ORDER BY id
            "#,
        )?;
        let notes = stmt
            .query_map([], |row| {
                Ok(Note {
                    id: row.get(0)?,
                    txid: row.get(1)?,
                    output_index: row.get(2)?,
                    pool: row.get(3)?,
                    value: row.get(4)?,
                    commitment: row.get(5)?,
                    nullifier: row.get(6)?,
                    memo: row.get(7)?,
                    address: row.get(8)?,
                    height: row.get(9)?,
                    spent_txid: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(notes)
    }

    /// Get all notes (including spent).
    pub fn get_all_notes(&self) -> Result<Vec<Note>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, txid, output_index, pool, value, commitment, nullifier,
                   memo, address, height, spent_txid
            FROM notes
            ORDER BY id
            "#,
        )?;
        let notes = stmt
            .query_map([], |row| {
                Ok(Note {
                    id: row.get(0)?,
                    txid: row.get(1)?,
                    output_index: row.get(2)?,
                    pool: row.get(3)?,
                    value: row.get(4)?,
                    commitment: row.get(5)?,
                    nullifier: row.get(6)?,
                    memo: row.get(7)?,
                    address: row.get(8)?,
                    height: row.get(9)?,
                    spent_txid: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(notes)
    }

    /// Mark notes as spent by matching nullifiers.
    /// Returns the number of notes marked as spent.
    pub fn mark_spent_by_nullifiers(
        &self,
        nullifiers: &[String],
        spending_txid: &str,
    ) -> Result<usize> {
        let mut count = 0;
        for nullifier in nullifiers {
            let updated = self.conn.execute(
                "UPDATE notes SET spent_txid = ?1 WHERE nullifier = ?2 AND spent_txid IS NULL",
                params![spending_txid, nullifier],
            )?;
            count += updated;
        }
        Ok(count)
    }

    /// Calculate the total balance of unspent notes.
    pub fn get_balance(&self) -> Result<i64> {
        let balance: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(value), 0) FROM notes WHERE spent_txid IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(balance)
    }

    /// Get balance by pool type.
    pub fn get_balance_by_pool(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT pool, COALESCE(SUM(value), 0)
            FROM notes
            WHERE spent_txid IS NULL
            GROUP BY pool
            ORDER BY pool
            "#,
        )?;
        let balances = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(balances)
    }

    // =========================================================================
    // Ledger methods
    // =========================================================================

    /// Insert or update a ledger entry. Returns Ok(true) if inserted, Ok(false) if updated.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_ledger_entry(
        &self,
        txid: &str,
        height: Option<i64>,
        value_received: i64,
        value_spent: i64,
        net_change: i64,
        fee_paid: i64,
        primary_pool: &str,
        memos: Option<&str>,
    ) -> Result<bool> {
        let result = self.conn.execute(
            r#"
            INSERT INTO ledger
            (txid, height, value_received, value_spent, net_change, fee_paid, primary_pool, memos)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(txid) DO UPDATE SET
                height = COALESCE(?2, height),
                value_received = ?3,
                value_spent = ?4,
                net_change = ?5,
                fee_paid = ?6,
                primary_pool = ?7,
                memos = COALESCE(?8, memos)
            "#,
            params![
                txid,
                height,
                value_received,
                value_spent,
                net_change,
                fee_paid,
                primary_pool,
                memos,
            ],
        )?;
        Ok(result > 0)
    }

    /// Get all ledger entries.
    pub fn get_ledger_entries(&self) -> Result<Vec<LedgerEntry>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, txid, height, timestamp, value_received, value_spent,
                   net_change, fee_paid, primary_pool, memos, created_at
            FROM ledger
            ORDER BY created_at DESC, id DESC
            "#,
        )?;
        let entries = stmt
            .query_map([], |row| {
                Ok(LedgerEntry {
                    id: row.get(0)?,
                    txid: row.get(1)?,
                    height: row.get(2)?,
                    timestamp: row.get(3)?,
                    value_received: row.get(4)?,
                    value_spent: row.get(5)?,
                    net_change: row.get(6)?,
                    fee_paid: row.get(7)?,
                    primary_pool: row.get(8)?,
                    memos: row.get(9)?,
                    created_at: row.get(10)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(entries)
    }

    /// Get ledger balance (sum of net changes).
    pub fn get_ledger_balance(&self) -> Result<i64> {
        let balance: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(net_change), 0) FROM ledger",
            [],
            |row| row.get(0),
        )?;
        Ok(balance)
    }

    /// Export ledger as CSV.
    pub fn export_ledger_csv(&self) -> Result<String> {
        let entries = self.get_ledger_entries()?;
        let mut csv = String::from(
            "txid,height,timestamp,value_received,value_spent,net_change,fee_paid,primary_pool,memos,created_at\n",
        );

        for entry in entries {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                entry.txid,
                entry.height.map_or(String::new(), |h| h.to_string()),
                entry.timestamp.unwrap_or_default(),
                entry.value_received,
                entry.value_spent,
                entry.net_change,
                entry.fee_paid,
                entry.primary_pool,
                entry.memos.unwrap_or_default().replace(',', ";"),
                entry.created_at,
            ));
        }

        Ok(csv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_init() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.get_balance().unwrap() == 0);
    }

    #[test]
    fn test_insert_and_get_notes() {
        let db = Database::open_in_memory().unwrap();

        // Insert a note
        let inserted = db
            .insert_note(
                "abc123",
                0,
                "sapling",
                1000000,
                Some("commitment1"),
                Some("nullifier1"),
                None,
                None,
                Some(100),
            )
            .unwrap();
        assert!(inserted);

        // Try to insert duplicate (should be ignored)
        let inserted_again = db
            .insert_note(
                "abc123",
                0,
                "sapling",
                1000000,
                Some("commitment1"),
                Some("nullifier1"),
                None,
                None,
                Some(100),
            )
            .unwrap();
        assert!(!inserted_again);

        // Check balance
        assert_eq!(db.get_balance().unwrap(), 1000000);

        // Get notes
        let notes = db.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value, 1000000);
    }

    #[test]
    fn test_mark_spent() {
        let db = Database::open_in_memory().unwrap();

        // Insert two notes
        db.insert_note(
            "tx1",
            0,
            "sapling",
            1000000,
            Some("c1"),
            Some("n1"),
            None,
            None,
            None,
        )
        .unwrap();
        db.insert_note(
            "tx2",
            0,
            "orchard",
            2000000,
            Some("c2"),
            Some("n2"),
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(db.get_balance().unwrap(), 3000000);

        // Spend the first note
        let spent = db
            .mark_spent_by_nullifiers(&["n1".to_string()], "tx3")
            .unwrap();
        assert_eq!(spent, 1);

        // Balance should now be only the second note
        assert_eq!(db.get_balance().unwrap(), 2000000);

        // Check unspent notes
        let notes = db.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].txid, "tx2");
    }

    #[test]
    fn test_config() {
        let db = Database::open_in_memory().unwrap();

        assert!(db.get_config("rpc_url").unwrap().is_none());

        db.set_config("rpc_url", "http://localhost:8232").unwrap();
        assert_eq!(
            db.get_config("rpc_url").unwrap(),
            Some("http://localhost:8232".to_string())
        );
    }
}
