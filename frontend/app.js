// Zcash Web Wallet - Frontend Application

// WASM module instance
let wasmModule = null;

// LocalStorage keys
const STORAGE_KEYS = {
  endpoints: "zcash_viewer_endpoints",
  selectedEndpoint: "zcash_viewer_selected_endpoint",
};

// Default RPC endpoints (users can add their own)
const DEFAULT_ENDPOINTS = [
  {
    name: "Tatum - mainnet (rate limited)",
    url: "https://zcash-mainnet.gateway.tatum.io/",
    network: "mainnet",
  },
  {
    name: "Tatum - testnet (rate limited)",
    url: "https://zcash-testnet.gateway.tatum.io/",
    network: "testnet",
  },
  {
    name: "Local Node (mainnet)",
    url: "http://127.0.0.1:8232",
    network: "mainnet",
  },
  {
    name: "Local Node (testnet)",
    url: "http://127.0.0.1:18232",
    network: "testnet",
  },
];

// Initialize WASM module
async function initWasm() {
  try {
    const wasm = await import("./pkg/zcash_tx_viewer.js");
    await wasm.default();
    wasmModule = wasm;
    console.log("WASM module loaded successfully");
    return true;
  } catch (error) {
    console.error("Failed to load WASM module:", error);
    showError("Failed to load decryption module. Please refresh the page.");
    return false;
  }
}

// Endpoint management
function loadEndpoints() {
  const stored = localStorage.getItem(STORAGE_KEYS.endpoints);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return [...DEFAULT_ENDPOINTS];
    }
  }
  return [...DEFAULT_ENDPOINTS];
}

function saveEndpoints(endpoints) {
  localStorage.setItem(STORAGE_KEYS.endpoints, JSON.stringify(endpoints));
}

function getSelectedEndpoint() {
  return localStorage.getItem(STORAGE_KEYS.selectedEndpoint) || "";
}

function setSelectedEndpoint(url) {
  localStorage.setItem(STORAGE_KEYS.selectedEndpoint, url);
}

function renderEndpoints() {
  const endpoints = loadEndpoints();
  const select = document.getElementById("rpcEndpoint");
  const selectedUrl = getSelectedEndpoint();

  select.innerHTML = '<option value="">-- Select an endpoint --</option>';

  endpoints.forEach((endpoint) => {
    const option = document.createElement("option");
    option.value = endpoint.url;
    option.textContent = `${endpoint.name} (${endpoint.url})`;
    if (endpoint.url === selectedUrl) {
      option.selected = true;
    }
    select.appendChild(option);
  });
}

function addEndpoint(url) {
  if (!url || !url.trim()) return false;

  url = url.trim();

  // Basic URL validation
  try {
    new URL(url);
  } catch {
    return false;
  }

  const endpoints = loadEndpoints();

  // Check for duplicates
  if (endpoints.some((e) => e.url === url)) {
    return false;
  }

  endpoints.push({
    name: "Custom",
    url: url,
    network: "unknown",
  });

  saveEndpoints(endpoints);
  renderEndpoints();

  // Select the newly added endpoint
  document.getElementById("rpcEndpoint").value = url;
  setSelectedEndpoint(url);

  return true;
}

// DOM Elements
const form = document.getElementById("decryptForm");
const viewingKeyInput = document.getElementById("viewingKey");
const txidInput = document.getElementById("txid");
const networkSelect = document.getElementById("network");
const submitBtn = document.getElementById("submitBtn");
const keyInfo = document.getElementById("keyInfo");
const resultsDiv = document.getElementById("results");
const placeholderDiv = document.getElementById("placeholder");
const errorAlert = document.getElementById("errorAlert");
const errorMessage = document.getElementById("errorMessage");
const rpcEndpointSelect = document.getElementById("rpcEndpoint");
const newEndpointInput = document.getElementById("newEndpoint");
const addEndpointBtn = document.getElementById("addEndpointBtn");
const testEndpointBtn = document.getElementById("testEndpointBtn");
const endpointStatus = document.getElementById("endpointStatus");

// Validate viewing key on input
viewingKeyInput.addEventListener("input", debounce(validateViewingKey, 300));

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

async function validateViewingKey() {
  const key = viewingKeyInput.value.trim();
  if (!key) {
    keyInfo.innerHTML = "";
    return;
  }

  if (!wasmModule) {
    keyInfo.innerHTML =
      '<span class="text-warning">WASM module not loaded</span>';
    return;
  }

  try {
    const resultJson = wasmModule.parse_viewing_key(key);
    const result = JSON.parse(resultJson);

    if (result.valid) {
      const capabilities = [];
      if (result.has_sapling) capabilities.push("Sapling");
      if (result.has_orchard) capabilities.push("Orchard");

      keyInfo.innerHTML = `
        <span class="text-success">
          Valid ${result.key_type} (${result.network})
          ${capabilities.length > 0 ? "- " + capabilities.join(", ") : ""}
        </span>
      `;

      // Auto-select network if detected
      if (result.network === "mainnet" || result.network === "testnet") {
        networkSelect.value = result.network;
      }
    } else {
      keyInfo.innerHTML = `<span class="text-danger">${result.error || "Invalid viewing key"}</span>`;
    }
  } catch (error) {
    console.error("Key validation error:", error);
    keyInfo.innerHTML = '<span class="text-danger">Error validating key</span>';
  }
}

// RPC endpoint selection
rpcEndpointSelect.addEventListener("change", () => {
  setSelectedEndpoint(rpcEndpointSelect.value);
  updateEndpointStatus();
});

// Add endpoint button
addEndpointBtn.addEventListener("click", () => {
  const url = newEndpointInput.value;
  if (addEndpoint(url)) {
    newEndpointInput.value = "";
    updateEndpointStatus("Endpoint added successfully", "success");
  } else {
    updateEndpointStatus("Invalid URL or endpoint already exists", "danger");
  }
});

// Test endpoint button
testEndpointBtn.addEventListener("click", async () => {
  await testEndpoint();
});

async function testEndpoint() {
  const rpcEndpoint = rpcEndpointSelect.value;

  if (!rpcEndpoint) {
    updateEndpointStatus("Please select an endpoint first", "warning");
    return;
  }

  // Show testing status
  testEndpointBtn.disabled = true;
  const originalContent = testEndpointBtn.innerHTML;
  testEndpointBtn.innerHTML =
    '<span class="spinner-border spinner-border-sm" role="status"></span>';
  updateEndpointStatus("Testing connection...", "info");

  try {
    const rpcRequest = {
      jsonrpc: "1.0",
      id: "test",
      method: "getblockchaininfo",
      params: [],
    };

    const response = await fetch(rpcEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(rpcRequest),
    });

    if (!response.ok) {
      if (response.status === 429) {
        throw new Error("Rate limited - please wait a moment and try again");
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.error) {
      throw new Error(data.error.message || "RPC error");
    }

    const chain = data.result.chain;
    const blocks = data.result.blocks;
    updateEndpointStatus(
      `Connected: ${chain} network, block height ${blocks.toLocaleString()}`,
      "success",
      5000
    );
  } catch (error) {
    let errorMsg = error.message;
    if (
      error.message.includes("Failed to fetch") ||
      error.message.includes("NetworkError")
    ) {
      errorMsg = "Connection failed (CORS issue or endpoint unreachable)";
    }
    updateEndpointStatus(`Error: ${errorMsg}`, "danger");
  } finally {
    testEndpointBtn.disabled = false;
    testEndpointBtn.innerHTML = originalContent;
  }
}

function updateEndpointStatus(message, type, duration = 3000) {
  if (message) {
    endpointStatus.innerHTML = `<span class="text-${type}">${message}</span>`;
    if (duration > 0) {
      setTimeout(() => {
        endpointStatus.innerHTML = "";
      }, duration);
    }
  } else {
    endpointStatus.innerHTML = "";
  }
}

// Form submission
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  await decryptTransaction();
});

async function decryptTransaction() {
  const viewingKey = viewingKeyInput.value.trim();
  const txid = txidInput.value.trim();
  const network = networkSelect.value;
  const rpcEndpoint = rpcEndpointSelect.value;

  if (!rpcEndpoint) {
    showError("Please select an RPC endpoint.");
    return;
  }

  if (!viewingKey || !txid) {
    showError("Please enter both a viewing key and transaction ID.");
    return;
  }

  if (!wasmModule) {
    showError("WASM module not loaded. Please refresh the page.");
    return;
  }

  // Validate txid format (64 hex characters)
  if (!/^[a-fA-F0-9]{64}$/.test(txid)) {
    showError(
      "Invalid transaction ID format. Expected 64 hexadecimal characters."
    );
    return;
  }

  setLoading(true);
  hideError();

  try {
    // Fetch raw transaction from RPC endpoint
    const rawTx = await fetchRawTransaction(rpcEndpoint, txid);

    if (!rawTx) {
      showError(
        "Failed to fetch transaction. Please check the transaction ID and RPC endpoint."
      );
      setLoading(false);
      return;
    }

    // Decrypt transaction using WASM
    const resultJson = wasmModule.decrypt_transaction(
      rawTx,
      viewingKey,
      network
    );
    const result = JSON.parse(resultJson);

    if (result.success && result.transaction) {
      displayResults(result.transaction);
    } else {
      showError(result.error || "Failed to decrypt transaction.");
    }
  } catch (error) {
    console.error("Decryption error:", error);
    showError(`Error: ${error.message}`);
  } finally {
    setLoading(false);
  }
}

async function fetchRawTransaction(rpcEndpoint, txid) {
  const rpcRequest = {
    jsonrpc: "1.0",
    id: "zcash-viewer",
    method: "getrawtransaction",
    params: [txid, 0],
  };

  try {
    const response = await fetch(rpcEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(rpcRequest),
    });

    if (!response.ok) {
      if (response.status === 429) {
        throw new Error("Rate limited - please wait a moment and try again");
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.error) {
      throw new Error(data.error.message || "RPC error");
    }

    return data.result;
  } catch (error) {
    console.error("Failed to fetch transaction:", error);

    // Provide helpful error message for CORS issues
    if (
      error.message.includes("Failed to fetch") ||
      error.message.includes("NetworkError")
    ) {
      throw new Error(
        "Network error. This may be a CORS issue. " +
          "Try using a local node with CORS enabled or a CORS proxy."
      );
    }

    throw error;
  }
}

function displayResults(tx) {
  placeholderDiv.classList.add("d-none");
  resultsDiv.classList.remove("d-none");

  document.getElementById("txidValue").textContent = tx.txid;

  // Transparent section
  const transparentSection = document.getElementById("transparentSection");
  const transparentInputs = document.getElementById("transparentInputs");
  const transparentOutputs = document.getElementById("transparentOutputs");

  if (tx.transparent_inputs.length > 0 || tx.transparent_outputs.length > 0) {
    transparentSection.classList.remove("d-none");

    // Inputs
    if (tx.transparent_inputs.length > 0) {
      transparentInputs.innerHTML = `
        <p class="fw-semibold mb-2">Inputs (${tx.transparent_inputs.length})</p>
        ${tx.transparent_inputs
          .map(
            (input) => `
          <div class="card output-card transparent mb-2">
            <div class="card-body py-2 px-3">
              <small class="text-muted">Input #${input.index}</small>
              <div class="mono small text-truncate">
                Prev: ${input.prevout_txid}:${input.prevout_index}
              </div>
            </div>
          </div>
        `
          )
          .join("")}
      `;
    } else {
      transparentInputs.innerHTML = "";
    }

    // Outputs
    if (tx.transparent_outputs.length > 0) {
      transparentOutputs.innerHTML = `
        <p class="fw-semibold mb-2">Outputs (${tx.transparent_outputs.length})</p>
        ${tx.transparent_outputs
          .map(
            (output) => `
          <div class="card output-card transparent mb-2">
            <div class="card-body py-2 px-3">
              <small class="text-muted">Output #${output.index}</small>
              <div><strong>${formatZatoshi(output.value)}</strong> ZEC</div>
              ${output.address ? `<div class="mono small text-truncate">${output.address}</div>` : ""}
            </div>
          </div>
        `
          )
          .join("")}
      `;
    } else {
      transparentOutputs.innerHTML = "";
    }
  } else {
    transparentSection.classList.add("d-none");
  }

  // Sapling section
  const saplingSection = document.getElementById("saplingSection");
  const saplingOutputs = document.getElementById("saplingOutputs");

  if (tx.sapling_outputs.length > 0) {
    saplingSection.classList.remove("d-none");
    saplingOutputs.innerHTML = tx.sapling_outputs
      .map(
        (output) => `
        <div class="card output-card sapling mb-2">
          <div class="card-body py-2 px-3">
            <small class="text-muted">Output #${output.index}</small>
            ${output.value > 0 ? `<div><strong>${formatZatoshi(output.value)}</strong> ZEC</div>` : ""}
            ${output.memo && output.memo !== "(encrypted)" ? `<div class="small">Memo: ${escapeHtml(output.memo)}</div>` : ""}
            <div class="mono small text-truncate text-muted">
              Commitment: ${output.note_commitment}
            </div>
            ${output.nullifier ? `<div class="mono small text-truncate text-muted">Nullifier: ${output.nullifier}</div>` : ""}
          </div>
        </div>
      `
      )
      .join("");
  } else {
    saplingSection.classList.add("d-none");
  }

  // Orchard section
  const orchardSection = document.getElementById("orchardSection");
  const orchardActions = document.getElementById("orchardActions");

  if (tx.orchard_actions.length > 0) {
    orchardSection.classList.remove("d-none");
    orchardActions.innerHTML = tx.orchard_actions
      .map(
        (action) => `
        <div class="card output-card orchard mb-2">
          <div class="card-body py-2 px-3">
            <small class="text-muted">Action #${action.index}</small>
            ${action.value > 0 ? `<div><strong>${formatZatoshi(action.value)}</strong> ZEC</div>` : ""}
            ${action.memo && action.memo !== "(encrypted)" ? `<div class="small">Memo: ${escapeHtml(action.memo)}</div>` : ""}
            <div class="mono small text-truncate text-muted">
              Commitment: ${action.note_commitment}
            </div>
            ${action.nullifier ? `<div class="mono small text-truncate text-muted">Nullifier: ${action.nullifier}</div>` : ""}
          </div>
        </div>
      `
      )
      .join("");
  } else {
    orchardSection.classList.add("d-none");
  }

  // No shielded data message
  const noShieldedData = document.getElementById("noShieldedData");
  if (tx.sapling_outputs.length === 0 && tx.orchard_actions.length === 0) {
    noShieldedData.classList.remove("d-none");
  } else {
    noShieldedData.classList.add("d-none");
  }
}

function formatZatoshi(zatoshi) {
  return (zatoshi / 100000000).toFixed(8);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function setLoading(loading) {
  if (loading) {
    submitBtn.classList.add("loading");
    submitBtn.disabled = true;
  } else {
    submitBtn.classList.remove("loading");
    submitBtn.disabled = false;
  }
}

function showError(message) {
  placeholderDiv.classList.add("d-none");
  resultsDiv.classList.remove("d-none");
  errorAlert.classList.remove("d-none");
  errorMessage.textContent = message;
}

function hideError() {
  errorAlert.classList.add("d-none");
}

// Theme management
const THEME_KEY = "zcash_viewer_theme";

function getStoredTheme() {
  return localStorage.getItem(THEME_KEY);
}

function setStoredTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
}

function getPreferredTheme() {
  const stored = getStoredTheme();
  if (stored) {
    return stored;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  updateThemeIcon(theme);
  setStoredTheme(theme);
}

function updateThemeIcon(theme) {
  const icon = document.getElementById("themeIcon");
  if (icon) {
    icon.className = theme === "dark" ? "bi bi-sun-fill" : "bi bi-moon-fill";
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  setTheme(next);
}

// ===========================================================================
// Wallet Generation
// ===========================================================================

let currentWalletData = null;

function initWalletUI() {
  const generateBtn = document.getElementById("generateWalletBtn");
  const restoreBtn = document.getElementById("restoreWalletBtn");
  const downloadBtn = document.getElementById("downloadWalletBtn");
  const copySeedBtn = document.getElementById("copySeedBtn");
  const copyUfvkBtn = document.getElementById("copyUfvkBtn");

  if (generateBtn) {
    generateBtn.addEventListener("click", generateWallet);
  }
  if (restoreBtn) {
    restoreBtn.addEventListener("click", restoreWallet);
  }
  if (downloadBtn) {
    downloadBtn.addEventListener("click", downloadWallet);
  }
  if (copySeedBtn) {
    copySeedBtn.addEventListener("click", () =>
      copyToClipboard("seedPhraseDisplay", copySeedBtn)
    );
  }
  if (copyUfvkBtn) {
    copyUfvkBtn.addEventListener("click", () =>
      copyToClipboard("ufvkDisplay", copyUfvkBtn)
    );
  }
}

async function generateWallet() {
  if (!wasmModule) {
    showWalletError("WASM module not loaded. Please refresh the page.");
    return;
  }

  const btn = document.getElementById("generateWalletBtn");
  setWalletLoading(btn, true);

  try {
    const resultJson = wasmModule.generate_wallet();
    const result = JSON.parse(resultJson);

    if (result.success) {
      currentWalletData = result;
      displayWalletResult(result);
    } else {
      showWalletError(result.error || "Failed to generate wallet");
    }
  } catch (error) {
    console.error("Wallet generation error:", error);
    showWalletError(`Error: ${error.message}`);
  } finally {
    setWalletLoading(btn, false);
  }
}

async function restoreWallet() {
  const seedInput = document.getElementById("restoreSeed");
  const seedPhrase = seedInput.value.trim();

  if (!seedPhrase) {
    showWalletError("Please enter a seed phrase");
    return;
  }

  if (!wasmModule) {
    showWalletError("WASM module not loaded. Please refresh the page.");
    return;
  }

  const btn = document.getElementById("restoreWalletBtn");
  setWalletLoading(btn, true);

  try {
    const resultJson = wasmModule.restore_wallet(seedPhrase);
    const result = JSON.parse(resultJson);

    if (result.success) {
      currentWalletData = result;
      displayWalletResult(result);
    } else {
      showWalletError(result.error || "Failed to restore wallet");
    }
  } catch (error) {
    console.error("Wallet restore error:", error);
    showWalletError(`Error: ${error.message}`);
  } finally {
    setWalletLoading(btn, false);
  }
}

function displayWalletResult(wallet) {
  const resultsDiv = document.getElementById("walletResults");
  const placeholderDiv = document.getElementById("walletPlaceholder");
  const errorDiv = document.getElementById("walletError");
  const successDiv = document.getElementById("walletSuccess");

  placeholderDiv.classList.add("d-none");
  resultsDiv.classList.remove("d-none");
  errorDiv.classList.add("d-none");
  successDiv.classList.remove("d-none");

  document.getElementById("seedPhraseDisplay").textContent =
    wallet.seed_phrase || "";
  document.getElementById("unifiedAddressDisplay").textContent =
    wallet.unified_address || "";
  document.getElementById("transparentAddressDisplay").textContent =
    wallet.transparent_address || "";
  document.getElementById("ufvkDisplay").textContent =
    wallet.unified_full_viewing_key || "";
}

function showWalletError(message) {
  const resultsDiv = document.getElementById("walletResults");
  const placeholderDiv = document.getElementById("walletPlaceholder");
  const errorDiv = document.getElementById("walletError");
  const successDiv = document.getElementById("walletSuccess");

  placeholderDiv.classList.add("d-none");
  resultsDiv.classList.remove("d-none");
  errorDiv.classList.remove("d-none");
  successDiv.classList.add("d-none");

  document.getElementById("walletErrorMsg").textContent = message;
}

function setWalletLoading(btn, loading) {
  const spinner = btn.querySelector(".loading-spinner");
  const text = btn.querySelector(".btn-text");

  if (loading) {
    btn.disabled = true;
    if (spinner) spinner.classList.remove("d-none");
    if (text) text.classList.add("d-none");
  } else {
    btn.disabled = false;
    if (spinner) spinner.classList.add("d-none");
    if (text) text.classList.remove("d-none");
  }
}

function downloadWallet() {
  if (!currentWalletData) {
    showWalletError("No wallet data to download");
    return;
  }

  const walletJson = {
    seed_phrase: currentWalletData.seed_phrase,
    network: currentWalletData.network,
    unified_address: currentWalletData.unified_address,
    transparent_address: currentWalletData.transparent_address,
    unified_full_viewing_key: currentWalletData.unified_full_viewing_key,
    generated_at: new Date().toISOString(),
  };

  const blob = new Blob([JSON.stringify(walletJson, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `zcash-testnet-wallet-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyToClipboard(elementId, btn) {
  const element = document.getElementById(elementId);
  const text = element.textContent;

  navigator.clipboard
    .writeText(text)
    .then(() => {
      const originalHtml = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-check me-1"></i> Copied!';
      btn.classList.add("btn-success");
      btn.classList.remove("btn-outline-secondary");

      setTimeout(() => {
        btn.innerHTML = originalHtml;
        btn.classList.remove("btn-success");
        btn.classList.add("btn-outline-secondary");
      }, 2000);
    })
    .catch((err) => {
      console.error("Failed to copy:", err);
    });
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", async () => {
  // Set initial theme
  setTheme(getPreferredTheme());

  // Theme toggle button
  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);
  }

  renderEndpoints();
  initWalletUI();
  await initWasm();
});
