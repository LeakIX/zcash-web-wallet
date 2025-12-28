//! Zcash RPC client for fetching transaction data.

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// RPC client for communicating with a Zcash node.
pub struct RpcClient {
    url: String,
    client: Client,
    auth: Option<(String, String)>,
}

/// RPC request structure.
#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: Vec<Value>,
}

/// RPC response structure.
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcError>,
}

/// RPC error structure.
#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Transaction info returned by getrawtransaction with verbose=1.
#[derive(Debug, Deserialize)]
pub struct TransactionInfo {
    pub hex: String,
    pub txid: String,
    #[serde(default)]
    pub blockhash: Option<String>,
    #[serde(default)]
    pub blocktime: Option<i64>,
    #[serde(default)]
    pub confirmations: Option<i64>,
    #[serde(default)]
    pub height: Option<i64>,
}

impl RpcClient {
    /// Create a new RPC client.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
            auth: None,
        }
    }

    /// Create a new RPC client with authentication.
    pub fn with_auth(url: &str, username: &str, password: &str) -> Self {
        Self {
            url: url.to_string(),
            client: Client::new(),
            auth: Some((username.to_string(), password.to_string())),
        }
    }

    /// Make an RPC call.
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value> {
        let request = RpcRequest {
            jsonrpc: "1.0",
            id: "zcash-wallet",
            method,
            params,
        };

        let mut req = self.client.post(&self.url).json(&request);

        if let Some((ref user, ref pass)) = self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let response: RpcResponse = req
            .send()
            .context("Failed to send RPC request")?
            .json()
            .context("Failed to parse RPC response")?;

        if let Some(error) = response.error {
            bail!("RPC error {}: {}", error.code, error.message);
        }

        response.result.context("Empty RPC result")
    }

    /// Get raw transaction hex by txid.
    pub fn get_raw_transaction(&self, txid: &str) -> Result<String> {
        let result = self.call("getrawtransaction", vec![Value::String(txid.to_string())])?;
        result
            .as_str()
            .map(|s| s.to_string())
            .context("Expected string result from getrawtransaction")
    }

    /// Get transaction info with verbose output.
    pub fn get_transaction_info(&self, txid: &str) -> Result<TransactionInfo> {
        let result = self.call(
            "getrawtransaction",
            vec![Value::String(txid.to_string()), Value::Number(1.into())],
        )?;
        serde_json::from_value(result).context("Failed to parse transaction info")
    }

    /// Get current block count.
    pub fn get_block_count(&self) -> Result<i64> {
        let result = self.call("getblockcount", vec![])?;
        result
            .as_i64()
            .context("Expected integer result from getblockcount")
    }

    /// Get blockchain info.
    pub fn get_blockchain_info(&self) -> Result<Value> {
        self.call("getblockchaininfo", vec![])
    }

    /// Test connection by calling getblockchaininfo.
    pub fn test_connection(&self) -> Result<()> {
        self.get_blockchain_info()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RpcClient::new("http://127.0.0.1:18232");
        assert_eq!(client.url, "http://127.0.0.1:18232");
    }

    #[test]
    fn test_client_with_auth() {
        let client = RpcClient::with_auth("http://127.0.0.1:18232", "user", "pass");
        assert!(client.auth.is_some());
    }
}
