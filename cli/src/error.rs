//! CLI error types.
//!
//! This module defines error types for the CLI, avoiding external dependencies
//! like `anyhow` or `thiserror`.

use core::fmt;

/// Errors that can occur in the CLI.
#[derive(Debug)]
pub enum CliError {
    /// File already exists
    FileExists(String),
    /// Failed to read file
    FileRead {
        path: String,
        source: std::io::Error,
    },
    /// Failed to write file
    FileWrite {
        path: String,
        source: std::io::Error,
    },
    /// Failed to parse JSON
    JsonParse {
        context: String,
        source: serde_json::Error,
    },
    /// Missing required field in JSON
    MissingField(String),
    /// Wallet operation failed
    Wallet(String),
    /// RPC operation failed
    Rpc(String),
    /// RPC error from server
    RpcServer { code: i64, message: String },
    /// Database operation failed
    Database(String),
    /// SQLite error
    Sqlite(rusqlite::Error),
    /// Configuration missing
    ConfigMissing(String),
    /// Invalid argument
    InvalidArgument(String),
    /// Transaction parsing failed
    Transaction(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileExists(path) => write!(
                f,
                "File '{}' already exists. Choose a different filename or remove the existing file.",
                path
            ),
            Self::FileRead { path, source } => {
                write!(f, "Failed to read file '{}': {}", path, source)
            }
            Self::FileWrite { path, source } => {
                write!(f, "Failed to write file '{}': {}", path, source)
            }
            Self::JsonParse { context, source } => {
                write!(f, "Failed to parse JSON ({}): {}", context, source)
            }
            Self::MissingField(field) => write!(f, "Missing required field: {}", field),
            Self::Wallet(msg) => write!(f, "Wallet error: {}", msg),
            Self::Rpc(msg) => write!(f, "RPC error: {}", msg),
            Self::RpcServer { code, message } => write!(f, "RPC error {}: {}", code, message),
            Self::Database(msg) => write!(f, "Database error: {}", msg),
            Self::Sqlite(e) => write!(f, "SQLite error: {}", e),
            Self::ConfigMissing(key) => write!(f, "Configuration not set: {}", key),
            Self::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
            Self::Transaction(msg) => write!(f, "Transaction error: {}", msg),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead { source, .. } => Some(source),
            Self::FileWrite { source, .. } => Some(source),
            Self::JsonParse { source, .. } => Some(source),
            Self::Sqlite(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CliError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonParse {
            context: "parsing".to_string(),
            source: e,
        }
    }
}

impl From<zcash_wallet_core::ScannerError> for CliError {
    fn from(e: zcash_wallet_core::ScannerError) -> Self {
        Self::Transaction(e.to_string())
    }
}

/// Result type alias for CLI operations.
pub type Result<T> = core::result::Result<T, CliError>;
