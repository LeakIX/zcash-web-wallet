// Zcash Web Wallet - Frontend Application

// WASM module instance
let wasmModule = null;

// LocalStorage keys
const STORAGE_KEYS = {
  endpoints: "zcash_viewer_endpoints",
  selectedEndpoint: "zcash_viewer_selected_endpoint",
  notes: "zcash_viewer_notes",
  scanViewingKey: "zcash_viewer_scan_viewing_key",
  wallets: "zcash_viewer_wallets",
  selectedWallet: "zcash_viewer_selected_wallet",
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
// Note Storage (localStorage)
// ===========================================================================

function loadNotes() {
  const stored = localStorage.getItem(STORAGE_KEYS.notes);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }
  return [];
}

function saveNotes(notes) {
  localStorage.setItem(STORAGE_KEYS.notes, JSON.stringify(notes));
}

function addNote(note, txid) {
  const notes = loadNotes();
  // Create a unique ID for the note
  const noteId = `${txid}-${note.pool}-${note.output_index}`;

  // Check if note already exists
  const existingIndex = notes.findIndex((n) => n.id === noteId);
  if (existingIndex >= 0) {
    // Update existing note
    notes[existingIndex] = { ...note, id: noteId, txid, spentTxid: null };
  } else {
    // Add new note
    notes.push({ ...note, id: noteId, txid, spentTxid: null });
  }

  saveNotes(notes);
  return existingIndex < 0; // Return true if newly added
}

function markNotesSpent(nullifiers, spendingTxid) {
  const notes = loadNotes();
  let markedCount = 0;

  for (const nf of nullifiers) {
    for (const note of notes) {
      if (note.nullifier === nf.nullifier && !note.spentTxid) {
        note.spentTxid = spendingTxid;
        markedCount++;
      }
    }
  }

  if (markedCount > 0) {
    saveNotes(notes);
  }
  return markedCount;
}

function markTransparentSpent(transparentSpends, spendingTxid) {
  const notes = loadNotes();
  let markedCount = 0;

  for (const spend of transparentSpends) {
    for (const note of notes) {
      // Match transparent notes by txid and output_index
      if (
        note.pool === "transparent" &&
        note.txid === spend.prevout_txid &&
        note.output_index === spend.prevout_index &&
        !note.spentTxid
      ) {
        note.spentTxid = spendingTxid;
        markedCount++;
      }
    }
  }

  if (markedCount > 0) {
    saveNotes(notes);
  }
  return markedCount;
}

function getUnspentNotes() {
  return loadNotes().filter((n) => !n.spentTxid && n.value > 0);
}

function getAllNotes() {
  return loadNotes();
}

function getBalance() {
  return getUnspentNotes().reduce((sum, n) => sum + n.value, 0);
}

function getBalanceByPool() {
  const notes = getUnspentNotes();
  const balances = {};

  for (const note of notes) {
    if (!balances[note.pool]) {
      balances[note.pool] = 0;
    }
    balances[note.pool] += note.value;
  }

  return balances;
}

function clearNotes() {
  localStorage.removeItem(STORAGE_KEYS.notes);
}

// ===========================================================================
// Wallet Storage (localStorage)
// ===========================================================================

function loadWallets() {
  const stored = localStorage.getItem(STORAGE_KEYS.wallets);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }
  return [];
}

function saveWallets(wallets) {
  localStorage.setItem(STORAGE_KEYS.wallets, JSON.stringify(wallets));
}

function addWallet(
  wallet,
  alias,
  transparentAddresses = [],
  unifiedAddresses = []
) {
  const wallets = loadWallets();

  // Generate unique ID
  const id = `wallet_${Date.now()}`;

  const walletEntry = {
    id,
    alias: alias || `Wallet ${wallets.length + 1}`,
    network: wallet.network,
    seed_phrase: wallet.seed_phrase,
    account_index: wallet.account_index,
    unified_address: wallet.unified_address,
    transparent_address: wallet.transparent_address,
    unified_full_viewing_key: wallet.unified_full_viewing_key,
    transparent_addresses: transparentAddresses, // Array of derived transparent addresses
    unified_addresses: unifiedAddresses, // Array of derived unified addresses
    created_at: new Date().toISOString(),
  };

  wallets.push(walletEntry);
  saveWallets(wallets);

  return walletEntry;
}

function getWallet(id) {
  const wallets = loadWallets();
  return wallets.find((w) => w.id === id);
}

function deleteWallet(id) {
  const wallets = loadWallets();
  const filtered = wallets.filter((w) => w.id !== id);
  saveWallets(filtered);

  // Clear selection if deleted wallet was selected
  if (getSelectedWalletId() === id) {
    setSelectedWalletId("");
  }
}

function getSelectedWalletId() {
  return localStorage.getItem(STORAGE_KEYS.selectedWallet) || "";
}

function setSelectedWalletId(id) {
  localStorage.setItem(STORAGE_KEYS.selectedWallet, id);
}

function getSelectedWallet() {
  const id = getSelectedWalletId();
  return id ? getWallet(id) : null;
}

function walletAliasExists(alias) {
  if (!alias) return false;
  const wallets = loadWallets();
  const normalizedAlias = alias.toLowerCase().trim();
  return wallets.some((w) => w.alias.toLowerCase().trim() === normalizedAlias);
}

// ===========================================================================
// Transaction Scanner
// ===========================================================================

function initScannerUI() {
  const scanBtn = document.getElementById("scanTxBtn");
  const clearNotesBtn = document.getElementById("clearNotesBtn");
  const goToWalletTab = document.getElementById("goToWalletTab");
  const walletSelect = document.getElementById("scanWalletSelect");

  if (scanBtn) {
    scanBtn.addEventListener("click", scanTransaction);
  }
  if (clearNotesBtn) {
    clearNotesBtn.addEventListener("click", () => {
      if (confirm("Are you sure you want to clear all tracked notes?")) {
        clearNotes();
        updateBalanceDisplay();
        updateNotesDisplay();
      }
    });
  }
  if (goToWalletTab) {
    goToWalletTab.addEventListener("click", (e) => {
      e.preventDefault();
      // Switch to wallet tab
      const walletTab = document.getElementById("wallet-tab");
      if (walletTab) {
        walletTab.click();
      }
    });
  }
  if (walletSelect) {
    walletSelect.addEventListener("change", () => {
      setSelectedWalletId(walletSelect.value);
      // Auto-select network based on wallet
      const wallet = getSelectedWallet();
      if (wallet) {
        const networkSelect = document.getElementById("scanNetwork");
        if (networkSelect && wallet.network) {
          networkSelect.value = wallet.network;
        }
      }
    });
  }

  // Populate wallet selector
  populateScannerWallets();

  // Initial display update
  updateBalanceDisplay();
  updateNotesDisplay();
}

function populateScannerWallets() {
  const walletSelect = document.getElementById("scanWalletSelect");
  const noWalletsWarning = document.getElementById("noWalletsWarning");
  if (!walletSelect) return;

  const wallets = loadWallets();
  const selectedId = getSelectedWalletId();

  walletSelect.innerHTML = '<option value="">-- Select a wallet --</option>';

  for (const wallet of wallets) {
    const option = document.createElement("option");
    option.value = wallet.id;
    option.textContent = `${wallet.alias} (${wallet.network})`;
    if (wallet.id === selectedId) {
      option.selected = true;
    }
    walletSelect.appendChild(option);
  }

  // Show/hide no wallets warning
  if (noWalletsWarning) {
    if (wallets.length === 0) {
      noWalletsWarning.classList.remove("d-none");
    } else {
      noWalletsWarning.classList.add("d-none");
    }
  }
}

async function scanTransaction() {
  const txidInput = document.getElementById("scanTxid");
  const walletSelect = document.getElementById("scanWalletSelect");
  const networkSelect = document.getElementById("scanNetwork");
  const heightInput = document.getElementById("scanHeight");
  const rpcSelect = document.getElementById("scanRpcEndpoint");

  const txid = txidInput?.value.trim();
  const walletId = walletSelect?.value;
  const network = networkSelect?.value || "testnet";
  const height = heightInput?.value ? parseInt(heightInput.value, 10) : null;
  const rpcEndpoint = rpcSelect?.value;

  if (!walletId) {
    showScanError("Please select a wallet.");
    return;
  }

  const wallet = getWallet(walletId);
  if (!wallet) {
    showScanError("Selected wallet not found.");
    return;
  }

  const viewingKey = wallet.unified_full_viewing_key;
  if (!viewingKey) {
    showScanError("Selected wallet has no viewing key.");
    return;
  }

  if (!txid) {
    showScanError("Please enter a transaction ID.");
    return;
  }

  if (!rpcEndpoint) {
    showScanError("Please select an RPC endpoint.");
    return;
  }

  if (!wasmModule) {
    showScanError("WASM module not loaded. Please refresh the page.");
    return;
  }

  // Validate txid format
  if (!/^[a-fA-F0-9]{64}$/.test(txid)) {
    showScanError(
      "Invalid transaction ID format. Expected 64 hexadecimal characters."
    );
    return;
  }

  setScanLoading(true);
  hideScanError();

  try {
    // Fetch raw transaction
    const rawTx = await fetchRawTransaction(rpcEndpoint, txid);

    if (!rawTx) {
      showScanError("Failed to fetch transaction.");
      setScanLoading(false);
      return;
    }

    // Scan transaction using WASM
    const resultJson = wasmModule.scan_transaction(
      rawTx,
      viewingKey,
      network,
      height
    );
    const result = JSON.parse(resultJson);

    if (result.success && result.result) {
      // Pass wallet's known transparent addresses for filtering
      const knownAddresses = wallet.transparent_addresses || [];
      processScanResult(result.result, knownAddresses);
    } else {
      showScanError(result.error || "Failed to scan transaction.");
    }
  } catch (error) {
    console.error("Scan error:", error);
    showScanError(`Error: ${error.message}`);
  } finally {
    setScanLoading(false);
  }
}

function processScanResult(scanResult, knownTransparentAddresses = []) {
  let notesAdded = 0;
  let notesWithValue = 0;
  let notesSkipped = 0;

  // Create a Set for faster address lookup
  const knownAddressSet = new Set(knownTransparentAddresses);

  // Add notes from scan result
  for (const note of scanResult.notes) {
    // For shielded notes (Orchard/Sapling), only add if decryption succeeded
    // Decryption success is indicated by value > 0 or nullifier being present
    if (note.pool !== "transparent") {
      if (note.value === 0 && !note.nullifier) {
        // Decryption failed - skip this note
        notesSkipped++;
        continue;
      }
    } else {
      // For transparent outputs, only add if address matches one of our known addresses
      if (note.address && !knownAddressSet.has(note.address)) {
        notesSkipped++;
        continue;
      }
      // If no address decoded but we have known addresses, skip it
      // (we can't verify it belongs to us)
      if (!note.address && knownAddressSet.size > 0) {
        notesSkipped++;
        continue;
      }
    }

    if (addNote(note, scanResult.txid)) {
      notesAdded++;
    }
    if (note.value > 0) {
      notesWithValue++;
    }
  }

  // Mark spent shielded notes by nullifiers
  const shieldedSpent = markNotesSpent(
    scanResult.spent_nullifiers,
    scanResult.txid
  );

  // Mark spent transparent outputs by prevout references
  const transparentSpent = markTransparentSpent(
    scanResult.transparent_spends || [],
    scanResult.txid
  );

  const totalSpent = shieldedSpent + transparentSpent;

  // Update displays
  updateBalanceDisplay();
  updateNotesDisplay();

  // Show results
  const resultsDiv = document.getElementById("scanResults");
  const placeholderDiv = document.getElementById("scanPlaceholder");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");

  const summaryDiv = document.getElementById("scanSummary");
  if (summaryDiv) {
    summaryDiv.innerHTML = `
      <div class="alert alert-success mb-3">
        <strong>Scan Complete</strong><br>
        Transaction: <code>${scanResult.txid.slice(0, 16)}...</code><br>
        Notes found: ${scanResult.notes.length} (${notesWithValue} decrypted)<br>
        New notes added: ${notesAdded}${notesSkipped > 0 ? ` (${notesSkipped} skipped - not ours)` : ""}<br>
        Nullifiers found: ${scanResult.spent_nullifiers.length}<br>
        Transparent spends: ${(scanResult.transparent_spends || []).length}<br>
        Notes marked spent: ${totalSpent}
      </div>
    `;
  }
}

function getPoolColorClass(pool) {
  switch (pool) {
    case "orchard":
      return "text-info";
    case "sapling":
      return "text-primary";
    case "transparent":
      return "text-warning";
    default:
      return "text-secondary";
  }
}

function updateBalanceDisplay() {
  const balanceDiv = document.getElementById("balanceDisplay");
  if (!balanceDiv) return;

  const balance = getBalance();
  const poolBalances = getBalanceByPool();

  let html = `
    <div class="card shadow-sm">
      <div class="card-header">
        <h5 class="mb-0 fw-semibold"><i class="bi bi-cash-coin me-1"></i> Total Balance</h5>
      </div>
      <div class="card-body">
        <p class="display-5 mb-3 text-success fw-bold">${formatZatoshi(balance)} ZEC</p>
        <h6 class="text-muted">By Pool</h6>
  `;

  if (Object.keys(poolBalances).length === 0) {
    html += `<p class="text-muted">No notes tracked yet.</p>`;
  } else {
    for (const [pool, amount] of Object.entries(poolBalances)) {
      const poolLabel = pool.charAt(0).toUpperCase() + pool.slice(1);
      const poolClass = getPoolColorClass(pool);
      html += `<p class="mb-1"><span class="${poolClass}">${poolLabel}</span>: <strong>${formatZatoshi(amount)} ZEC</strong></p>`;
    }
  }

  html += `
      </div>
    </div>
  `;

  balanceDiv.innerHTML = html;
}

function updateNotesDisplay() {
  const notesDiv = document.getElementById("notesDisplay");
  if (!notesDiv) return;

  const notes = getAllNotes();

  if (notes.length === 0) {
    notesDiv.innerHTML = `
      <div class="text-muted text-center py-4">
        <i class="bi bi-inbox fs-1"></i>
        <p>No notes tracked yet. Scan a transaction to get started.</p>
      </div>
    `;
    return;
  }

  // Sort notes: unspent first, then by value descending
  notes.sort((a, b) => {
    if (a.spentTxid && !b.spentTxid) return 1;
    if (!a.spentTxid && b.spentTxid) return -1;
    return b.value - a.value;
  });

  let html = `
    <div class="table-responsive">
      <table class="table table-sm">
        <thead>
          <tr>
            <th>Pool</th>
            <th>Value</th>
            <th>Memo</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const note of notes) {
    const poolClass = getPoolColorClass(note.pool);
    const statusBadge = note.spentTxid
      ? '<span class="badge bg-danger">Spent</span>'
      : '<span class="badge bg-success">Unspent</span>';

    html += `
      <tr class="${note.spentTxid ? "text-muted" : ""}">
        <td><span class="${poolClass}">${note.pool}</span></td>
        <td>${note.value > 0 ? formatZatoshi(note.value) + " ZEC" : "-"}</td>
        <td>${note.memo ? escapeHtml(note.memo.slice(0, 30)) + (note.memo.length > 30 ? "..." : "") : "-"}</td>
        <td>${statusBadge}</td>
      </tr>
    `;
  }

  html += `
        </tbody>
      </table>
    </div>
    <p class="small text-muted">Total notes: ${notes.length}</p>
  `;

  notesDiv.innerHTML = html;
}

function setScanLoading(loading) {
  const btn = document.getElementById("scanTxBtn");
  if (!btn) return;

  if (loading) {
    btn.disabled = true;
    btn.innerHTML =
      '<span class="spinner-border spinner-border-sm me-1"></span> Scanning...';
  } else {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-search me-1"></i> Scan Transaction';
  }
}

function showScanError(message) {
  const errorDiv = document.getElementById("scanError");
  if (errorDiv) {
    errorDiv.classList.remove("d-none");
    errorDiv.textContent = message;
  }
}

function hideScanError() {
  const errorDiv = document.getElementById("scanError");
  if (errorDiv) {
    errorDiv.classList.add("d-none");
  }
}

// Populate scanner RPC endpoints from main endpoint list
function populateScannerEndpoints() {
  const scanRpcSelect = document.getElementById("scanRpcEndpoint");
  if (!scanRpcSelect) return;

  const endpoints = loadEndpoints();
  const selectedUrl = getSelectedEndpoint();

  scanRpcSelect.innerHTML =
    '<option value="">-- Select an endpoint --</option>';

  endpoints.forEach((endpoint) => {
    const option = document.createElement("option");
    option.value = endpoint.url;
    option.textContent = `${endpoint.name} (${endpoint.url})`;
    if (endpoint.url === selectedUrl) {
      option.selected = true;
    }
    scanRpcSelect.appendChild(option);
  });
}

// ===========================================================================
// Wallet Generation
// ===========================================================================

let currentWalletData = null;

function initWalletUI() {
  const generateBtn = document.getElementById("generateWalletBtn");
  const restoreBtn = document.getElementById("restoreWalletBtn");
  const downloadBtn = document.getElementById("downloadWalletBtn");
  const saveWalletBtn = document.getElementById("saveWalletBtn");
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
  if (saveWalletBtn) {
    saveWalletBtn.addEventListener("click", saveWalletToBrowser);
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

  // Initial display of saved wallets
  updateSavedWalletsList();
}

async function generateWallet() {
  if (!wasmModule) {
    showWalletError("WASM module not loaded. Please refresh the page.");
    return;
  }

  const btn = document.getElementById("generateWalletBtn");
  const networkSelect = document.getElementById("walletNetwork");
  const network = networkSelect ? networkSelect.value : "testnet";
  const accountInput = document.getElementById("generateAccount");
  const account = parseInt(accountInput?.value || "0", 10);

  setWalletLoading(btn, true);

  try {
    const resultJson = wasmModule.generate_wallet(network, account, 0);
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
  const networkSelect = document.getElementById("restoreNetwork");
  const network = networkSelect ? networkSelect.value : "testnet";
  const accountInput = document.getElementById("restoreAccount");
  const account = parseInt(accountInput?.value || "0", 10);

  setWalletLoading(btn, true);

  try {
    const resultJson = wasmModule.restore_wallet(
      seedPhrase,
      network,
      account,
      0
    );
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
    account_index: currentWalletData.account_index,
    unified_address: currentWalletData.unified_address,
    transparent_address: currentWalletData.transparent_address,
    unified_full_viewing_key: currentWalletData.unified_full_viewing_key,
    generated_at: new Date().toISOString(),
  };

  const network = currentWalletData.network || "testnet";
  const blob = new Blob([JSON.stringify(walletJson, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `zcash-${network}-wallet-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Number of transparent addresses to derive for scanning
const TRANSPARENT_ADDRESS_COUNT = 100;

function saveWalletToBrowser() {
  if (!currentWalletData) {
    showWalletError("No wallet data to save");
    return;
  }

  if (!wasmModule) {
    showWalletError("WASM module not loaded");
    return;
  }

  // Get alias from the appropriate input based on what action was performed
  const generateAlias = document.getElementById("walletAlias")?.value.trim();
  const restoreAlias = document.getElementById("restoreAlias")?.value.trim();
  const alias = currentWalletData._alias || generateAlias || restoreAlias || "";

  // Check for empty alias
  if (!alias) {
    showWalletError("Please enter a wallet name");
    return;
  }

  // Check for duplicate alias (case-insensitive)
  if (walletAliasExists(alias)) {
    showWalletError(
      `A wallet named "${alias}" already exists. Please choose a different name.`
    );
    return;
  }

  // Derive transparent and unified addresses for scanning
  let transparentAddresses = [];
  let unifiedAddresses = [];
  if (currentWalletData.seed_phrase) {
    // Derive transparent addresses (start_index=0, count=100)
    const transparentJson = wasmModule.derive_transparent_addresses(
      currentWalletData.seed_phrase,
      currentWalletData.network || "testnet",
      currentWalletData.account_index || 0,
      0, // start_index
      TRANSPARENT_ADDRESS_COUNT
    );
    try {
      transparentAddresses = JSON.parse(transparentJson);
    } catch {
      console.error("Failed to parse transparent addresses");
    }

    // Derive unified addresses (start_index=0, count=100)
    const unifiedJson = wasmModule.derive_unified_addresses(
      currentWalletData.seed_phrase,
      currentWalletData.network || "testnet",
      currentWalletData.account_index || 0,
      0, // start_index
      TRANSPARENT_ADDRESS_COUNT
    );
    try {
      unifiedAddresses = JSON.parse(unifiedJson);
    } catch {
      console.error("Failed to parse unified addresses");
    }
  }

  const savedWallet = addWallet(
    currentWalletData,
    alias,
    transparentAddresses,
    unifiedAddresses
  );

  // Update UI
  updateSavedWalletsList();
  populateScannerWallets();

  // Show success feedback on save button
  const btn = document.getElementById("saveWalletBtn");
  if (btn) {
    const originalHtml = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check me-1"></i> Saved!';
    btn.classList.remove("btn-primary");
    btn.classList.add("btn-success");
    btn.disabled = true;

    setTimeout(() => {
      btn.innerHTML = originalHtml;
      btn.classList.remove("btn-success");
      btn.classList.add("btn-primary");
      btn.disabled = false;
    }, 2000);
  }
}

function updateSavedWalletsList() {
  const listDiv = document.getElementById("savedWalletsList");
  if (!listDiv) return;

  const wallets = loadWallets();

  if (wallets.length === 0) {
    listDiv.innerHTML = `
      <div class="text-muted text-center py-3">
        <i class="bi bi-wallet2 fs-3"></i>
        <p class="mb-0 mt-2">No wallets saved yet.</p>
      </div>
    `;
    return;
  }

  let html = '<div class="list-group">';

  for (const wallet of wallets) {
    const networkBadge =
      wallet.network === "mainnet"
        ? '<span class="badge bg-success">mainnet</span>'
        : '<span class="badge bg-warning text-dark">testnet</span>';

    html += `
      <div class="list-group-item">
        <div class="d-flex justify-content-between align-items-start">
          <div>
            <h6 class="mb-1">${escapeHtml(wallet.alias)} ${networkBadge}</h6>
            <small class="text-muted mono">${wallet.unified_address ? wallet.unified_address.slice(0, 20) + "..." : "No address"}</small>
          </div>
          <div class="btn-group btn-group-sm">
            <button class="btn btn-outline-secondary" onclick="viewWalletDetails('${wallet.id}')" title="View details">
              <i class="bi bi-eye"></i>
            </button>
            <button class="btn btn-outline-danger" onclick="confirmDeleteWallet('${wallet.id}')" title="Delete">
              <i class="bi bi-trash"></i>
            </button>
          </div>
        </div>
      </div>
    `;
  }

  html += "</div>";
  listDiv.innerHTML = html;
}

function viewWalletDetails(walletId) {
  const wallet = getWallet(walletId);
  if (!wallet) return;

  currentWalletData = wallet;
  displayWalletResult(wallet);
}

function confirmDeleteWallet(walletId) {
  const wallet = getWallet(walletId);
  if (!wallet) return;

  if (
    confirm(
      `Are you sure you want to delete "${wallet.alias}"? This cannot be undone.`
    )
  ) {
    deleteWallet(walletId);
    updateSavedWalletsList();
    populateScannerWallets();
  }
}

// Expose functions to global scope for onclick handlers
window.viewWalletDetails = viewWalletDetails;
window.confirmDeleteWallet = confirmDeleteWallet;

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
  populateScannerEndpoints();
  initWalletUI();
  initScannerUI();
  await initWasm();
});
