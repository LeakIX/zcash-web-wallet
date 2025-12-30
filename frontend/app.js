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
  ledger: "zcash_viewer_ledger",
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

  // Validate txid format using WASM
  const validationResult = JSON.parse(wasmModule.validate_txid(txid));
  if (!validationResult.valid) {
    showError(validationResult.error || "Invalid transaction ID format.");
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
// Note Storage (localStorage) - Uses WASM bindings for type-safe operations
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

function addNote(note, txid, walletId) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return false;
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);

  // Create stored note using WASM binding
  // Parameters: wallet_id, txid, pool, output_index, value, commitment, nullifier, memo, address, created_at
  const createResultJson = wasmModule.create_stored_note(
    walletId,
    txid,
    note.pool || "unknown",
    note.output_index || 0,
    BigInt(note.value || 0),
    note.commitment || null,
    note.nullifier || null,
    note.memo || null,
    note.address || null,
    new Date().toISOString()
  );

  // Unwrap the StorageResult to get the raw StoredNote
  const createResult = JSON.parse(createResultJson);
  if (!createResult.success) {
    console.error("Failed to create stored note:", createResult.error);
    return false;
  }

  if (!createResult.data) {
    console.error("Failed to create stored note: data is undefined");
    return false;
  }

  // add_note_to_list expects raw StoredNote JSON, not wrapped in StorageResult
  const storedNoteJson = JSON.stringify(createResult.data);

  // Add note to list (handles duplicates)
  const resultJson = wasmModule.add_note_to_list(notesJson, storedNoteJson);
  const result = JSON.parse(resultJson);

  if (result.success) {
    saveNotes(result.notes);
    return result.is_new;
  }
  console.error("Failed to add note:", result.error);
  return false;
}

function markNotesSpent(nullifiers, spendingTxid) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return 0;
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);
  const nullifiersJson = JSON.stringify(nullifiers);

  const resultJson = wasmModule.mark_notes_spent(
    notesJson,
    nullifiersJson,
    spendingTxid
  );
  const result = JSON.parse(resultJson);

  if (result.success) {
    saveNotes(result.notes);
    return result.marked_count;
  }
  console.error("Failed to mark notes spent:", result.error);
  return 0;
}

function markTransparentSpent(transparentSpends, spendingTxid) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return 0;
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);
  const spendsJson = JSON.stringify(transparentSpends);

  const resultJson = wasmModule.mark_transparent_spent(
    notesJson,
    spendsJson,
    spendingTxid
  );
  const result = JSON.parse(resultJson);

  if (result.success) {
    saveNotes(result.notes);
    return result.marked_count;
  }
  console.error("Failed to mark transparent spent:", result.error);
  return 0;
}

function getUnspentNotes() {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return [];
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);
  const resultJson = wasmModule.get_unspent_notes(notesJson);
  try {
    return JSON.parse(resultJson);
  } catch {
    return [];
  }
}

function getAllNotes() {
  return loadNotes();
}

function getBalance() {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return 0;
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);
  const resultJson = wasmModule.calculate_balance(notesJson);
  try {
    const result = JSON.parse(resultJson);
    return result.total || 0;
  } catch {
    return 0;
  }
}

function getBalanceByPool() {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return {};
  }

  const notes = loadNotes();
  const notesJson = JSON.stringify(notes);
  const resultJson = wasmModule.calculate_balance(notesJson);
  try {
    const result = JSON.parse(resultJson);
    return result.by_pool || {};
  } catch {
    return {};
  }
}

function clearNotes() {
  localStorage.removeItem(STORAGE_KEYS.notes);
}

// ===========================================================================
// Ledger Storage (localStorage) - Uses WASM bindings for type-safe operations
// ===========================================================================

function loadLedger() {
  const stored = localStorage.getItem(STORAGE_KEYS.ledger);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return { entries: [] };
    }
  }
  return { entries: [] };
}

function saveLedger(ledger) {
  localStorage.setItem(STORAGE_KEYS.ledger, JSON.stringify(ledger));
}

function createLedgerEntry(scanResult, walletId) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return null;
  }

  const scanResultJson = JSON.stringify(scanResult);

  const resultJson = wasmModule.create_ledger_entry(scanResultJson, walletId);

  try {
    const result = JSON.parse(resultJson);
    if (result.success && result.entry) {
      return result.entry;
    }
    console.error("Failed to create ledger entry:", result.error);
    return null;
  } catch (error) {
    console.error("Failed to parse ledger entry result:", error);
    return null;
  }
}

function addLedgerEntry(entry) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return false;
  }

  const ledger = loadLedger();
  const ledgerJson = JSON.stringify(ledger);
  const entryJson = JSON.stringify(entry);

  const resultJson = wasmModule.add_ledger_entry(ledgerJson, entryJson);

  try {
    const result = JSON.parse(resultJson);
    if (result.success && result.ledger) {
      saveLedger(result.ledger);
      return result.is_new;
    }
    console.error("Failed to add ledger entry:", result.error);
    return false;
  } catch (error) {
    console.error("Failed to parse add ledger entry result:", error);
    return false;
  }
}

function getLedgerForWallet(walletId) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return [];
  }

  const ledger = loadLedger();
  const ledgerJson = JSON.stringify(ledger);

  const resultJson = wasmModule.get_ledger_for_wallet(ledgerJson, walletId);

  try {
    const result = JSON.parse(resultJson);
    if (result.success && result.entries) {
      return result.entries;
    }
    return [];
  } catch {
    return [];
  }
}

function getLedgerBalance(walletId) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return 0;
  }

  const ledger = loadLedger();
  const ledgerJson = JSON.stringify(ledger);

  const resultJson = wasmModule.compute_ledger_balance(ledgerJson, walletId);

  try {
    const result = JSON.parse(resultJson);
    if (result.success) {
      return result.balance || 0;
    }
    return 0;
  } catch {
    return 0;
  }
}

function exportLedgerCsv(walletId) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return "";
  }

  const ledger = loadLedger();
  const ledgerJson = JSON.stringify(ledger);

  const resultJson = wasmModule.export_ledger_csv(ledgerJson, walletId);

  try {
    const result = JSON.parse(resultJson);
    if (result.success && result.csv) {
      return result.csv;
    }
    console.error("Failed to export ledger CSV:", result.error);
    return "";
  } catch {
    return "";
  }
}

function clearLedger() {
  localStorage.removeItem(STORAGE_KEYS.ledger);
}

// ===========================================================================
// Wallet Storage (localStorage) - Uses WASM bindings for type-safe operations
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
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return null;
  }

  const wallets = loadWallets();
  const walletsJson = JSON.stringify(wallets);

  // Create stored wallet using WASM binding
  // Parameters: wallet_result_json, alias, timestamp_ms
  const walletResultJson = JSON.stringify(wallet);
  const walletAlias = alias || `Wallet ${wallets.length + 1}`;
  const timestamp = BigInt(Date.now());

  const createResultJson = wasmModule.create_stored_wallet(
    walletResultJson,
    walletAlias,
    timestamp
  );
  const createResult = JSON.parse(createResultJson);

  if (!createResult.success) {
    console.error("Failed to create wallet:", createResult.error);
    return null;
  }

  // Add derived address arrays (not part of core StoredWallet type)
  const storedWallet = createResult.data;
  storedWallet.transparent_addresses = transparentAddresses;
  storedWallet.unified_addresses = unifiedAddresses;

  // Add wallet to list
  const resultJson = wasmModule.add_wallet_to_list(
    walletsJson,
    JSON.stringify(storedWallet)
  );
  const result = JSON.parse(resultJson);

  if (result.success) {
    saveWallets(result.wallets);
    // Return the newly added wallet (last in the list)
    const newWallets = result.wallets;
    return newWallets[newWallets.length - 1];
  }
  console.error("Failed to add wallet:", result.error);
  return null;
}

function getWallet(id) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return null;
  }

  const wallets = loadWallets();
  const walletsJson = JSON.stringify(wallets);
  const resultJson = wasmModule.get_wallet_by_id(walletsJson, id);
  try {
    const result = JSON.parse(resultJson);
    if (result.success && result.wallet) {
      return result.wallet;
    }
    return null;
  } catch {
    return null;
  }
}

function deleteWallet(id) {
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return;
  }

  const wallets = loadWallets();
  const walletsJson = JSON.stringify(wallets);
  const resultJson = wasmModule.delete_wallet_from_list(walletsJson, id);

  try {
    const result = JSON.parse(resultJson);
    if (result.success) {
      saveWallets(result.wallets);
    }
  } catch {
    console.error("Failed to delete wallet");
  }

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

  if (!wasmModule) {
    console.error("WASM module not loaded");
    return false;
  }

  const wallets = loadWallets();
  const walletsJson = JSON.stringify(wallets);
  return wasmModule.wallet_alias_exists(walletsJson, alias);
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
      if (
        confirm(
          "Are you sure you want to clear all tracked notes and transaction history?"
        )
      ) {
        clearNotes();
        clearLedger();
        updateBalanceDisplay();
        updateNotesDisplay();
        updateLedgerDisplay();
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
      // Update ledger display for selected wallet
      updateLedgerDisplay();
    });
  }

  // Populate wallet selector
  populateScannerWallets();

  // Initial display update
  updateBalanceDisplay();
  updateNotesDisplay();
  updateLedgerDisplay();
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

  // Validate txid format using WASM
  const validationResult = JSON.parse(wasmModule.validate_txid(txid));
  if (!validationResult.valid) {
    showScanError(validationResult.error || "Invalid transaction ID format.");
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
      // Note: We get wallet directly from localStorage because getWallet() goes
      // through WASM which strips out transparent_addresses
      const wallets = loadWallets();
      const fullWallet = wallets.find((w) => w.id === walletId);
      const knownAddresses = [
        ...(fullWallet?.transparent_addresses || []),
        ...(fullWallet?.transparent_address
          ? [fullWallet.transparent_address]
          : []),
      ];
      processScanResult(result.result, walletId, knownAddresses);
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

function processScanResult(
  scanResult,
  walletId,
  knownTransparentAddresses = []
) {
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

    if (addNote(note, scanResult.txid, walletId)) {
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

  // Create ledger entry from scan result
  const ledgerEntry = createLedgerEntry(scanResult, walletId);
  let ledgerUpdated = false;
  if (ledgerEntry) {
    ledgerUpdated = addLedgerEntry(ledgerEntry);
  }

  // Update displays
  updateBalanceDisplay();
  updateNotesDisplay();
  updateLedgerDisplay();

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
        Ledger entry: ${ledgerUpdated ? "Created" : ledgerEntry ? "Updated" : "Failed"}<br>
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

function updateLedgerDisplay() {
  const ledgerDiv = document.getElementById("ledgerDisplay");
  if (!ledgerDiv) return;

  // Get selected wallet
  const walletId = getSelectedWalletId();
  let entries = [];

  if (walletId) {
    entries = getLedgerForWallet(walletId);
  } else {
    // Show all entries if no wallet selected
    const ledger = loadLedger();
    entries = ledger.entries || [];
  }

  if (entries.length === 0) {
    ledgerDiv.innerHTML = `
      <div class="text-muted text-center py-4">
        <i class="bi bi-journal-text fs-1"></i>
        <p>No transaction history yet. Scan transactions to build your ledger.</p>
      </div>
    `;
    return;
  }

  // Sort entries by created_at descending (newest first)
  entries.sort((a, b) => {
    if (a.created_at && b.created_at) {
      return b.created_at.localeCompare(a.created_at);
    }
    return 0;
  });

  let html = `
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h6 class="mb-0"><i class="bi bi-journal-text me-1"></i> Transaction History</h6>
      <button class="btn btn-sm btn-outline-secondary" onclick="downloadLedgerCsv()">
        <i class="bi bi-download me-1"></i> Export CSV
      </button>
    </div>
    <div class="table-responsive">
      <table class="table table-sm">
        <thead>
          <tr>
            <th>Date</th>
            <th>TxID</th>
            <th class="text-end">Received</th>
            <th class="text-end">Spent</th>
            <th class="text-end">Net</th>
            <th>Pool</th>
            <th>Memo</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const entry of entries) {
    const date = entry.created_at
      ? new Date(entry.created_at).toLocaleDateString()
      : "-";
    const shortTxid = entry.txid ? entry.txid.slice(0, 10) + "..." : "-";

    // Determine row color based on net change
    let rowClass = "";
    if (entry.net_change > 0) {
      rowClass = "table-success";
    } else if (entry.net_change < 0) {
      rowClass = "table-danger";
    }

    // Format net change with sign
    const netFormatted =
      entry.net_change >= 0
        ? `+${formatZatoshi(entry.net_change)}`
        : formatZatoshi(entry.net_change);

    // Get pool badge
    const poolBadge = getPoolBadge(entry.primary_pool);

    // Get first memo if available
    const memo =
      entry.memos && entry.memos.length > 0
        ? escapeHtml(entry.memos[0].slice(0, 20)) +
          (entry.memos[0].length > 20 ? "..." : "")
        : "-";

    html += `
      <tr class="${rowClass}">
        <td class="small">${date}</td>
        <td class="mono small" title="${escapeHtml(entry.txid || "")}">${shortTxid}</td>
        <td class="text-end text-success">${entry.value_received > 0 ? "+" + formatZatoshi(entry.value_received) : "-"}</td>
        <td class="text-end text-danger">${entry.value_spent > 0 ? "-" + formatZatoshi(entry.value_spent) : "-"}</td>
        <td class="text-end fw-bold">${netFormatted}</td>
        <td>${poolBadge}</td>
        <td class="small">${memo}</td>
      </tr>
    `;
  }

  html += `
        </tbody>
      </table>
    </div>
    <p class="small text-muted">Total transactions: ${entries.length}</p>
  `;

  ledgerDiv.innerHTML = html;
}

function getPoolBadge(pool) {
  switch (pool) {
    case "orchard":
      return '<span class="badge bg-info">Orchard</span>';
    case "sapling":
      return '<span class="badge bg-primary">Sapling</span>';
    case "transparent":
      return '<span class="badge bg-warning text-dark">Transparent</span>';
    case "mixed":
      return '<span class="badge bg-secondary">Mixed</span>';
    default:
      return '<span class="badge bg-secondary">Unknown</span>';
  }
}

function downloadLedgerCsv() {
  const walletId = getSelectedWalletId();
  const csv = exportLedgerCsv(walletId);

  if (!csv) {
    console.error("Failed to generate CSV");
    return;
  }

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `zcash-ledger-${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Expose to global scope for onclick handlers
window.downloadLedgerCsv = downloadLedgerCsv;

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

// ===========================================================================
// Address Viewer
// ===========================================================================

let derivedAddressesData = [];
let derivedAddressesNetwork = "testnet";

function initAddressViewerUI() {
  const deriveBtn = document.getElementById("deriveAddressesBtn");
  const copyAllBtn = document.getElementById("copyAllAddressesBtn");
  const exportCsvBtn = document.getElementById("exportAddressesCsvBtn");
  const saveToWalletBtn = document.getElementById("saveAddressesToWalletBtn");
  const walletSelect = document.getElementById("addressWalletSelect");
  const goToWalletTab = document.getElementById("goToWalletTabFromAddress");

  if (deriveBtn) {
    deriveBtn.addEventListener("click", deriveAddresses);
  }
  if (copyAllBtn) {
    copyAllBtn.addEventListener("click", copyAllAddresses);
  }
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", exportAddressesCsv);
  }
  if (saveToWalletBtn) {
    saveToWalletBtn.addEventListener("click", saveAddressesToWallet);
  }
  if (goToWalletTab) {
    goToWalletTab.addEventListener("click", (e) => {
      e.preventDefault();
      const walletTab = document.getElementById("wallet-tab");
      if (walletTab) {
        walletTab.click();
      }
    });
  }
  if (walletSelect) {
    // Populate wallet selector when tab is shown
    document
      .getElementById("addresses-tab")
      ?.addEventListener("shown.bs.tab", populateAddressViewerWallets);
  }

  // Initial population
  populateAddressViewerWallets();
}

function populateAddressViewerWallets() {
  const walletSelect = document.getElementById("addressWalletSelect");
  const noWalletsWarning = document.getElementById("addressNoWalletsWarning");
  if (!walletSelect) return;

  const wallets = loadWallets();

  walletSelect.innerHTML = '<option value="">-- Select a wallet --</option>';

  for (const wallet of wallets) {
    const option = document.createElement("option");
    option.value = wallet.id;
    option.textContent = `${wallet.alias} (${wallet.network})`;
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

async function deriveAddresses() {
  const walletSelect = document.getElementById("addressWalletSelect");
  const fromInput = document.getElementById("addressFromIndex");
  const toInput = document.getElementById("addressToIndex");

  const walletId = walletSelect?.value;
  const fromIndex = parseInt(fromInput?.value || "0", 10);
  const toIndex = parseInt(toInput?.value || "10", 10);

  if (!walletId) {
    showAddressError("Please select a wallet.");
    return;
  }

  const wallet = getWallet(walletId);
  if (!wallet) {
    showAddressError("Selected wallet not found.");
    return;
  }

  if (!wallet.seed_phrase) {
    showAddressError("Selected wallet has no seed phrase.");
    return;
  }

  if (fromIndex < 0 || toIndex < 0) {
    showAddressError("Indices must be non-negative.");
    return;
  }

  if (fromIndex > toIndex) {
    showAddressError("From index must be less than or equal to To index.");
    return;
  }

  const count = toIndex - fromIndex + 1;
  if (count > 1000) {
    showAddressError("Maximum range is 1000 addresses.");
    return;
  }

  if (!wasmModule) {
    showAddressError("WASM module not loaded. Please refresh the page.");
    return;
  }

  setAddressLoading(true);
  hideAddressError();

  try {
    // Derive transparent addresses
    const transparentJson = wasmModule.derive_transparent_addresses(
      wallet.seed_phrase,
      wallet.network || "testnet",
      wallet.account_index || 0,
      fromIndex,
      count
    );
    const transparentAddresses = JSON.parse(transparentJson);

    // Derive unified addresses
    const unifiedJson = wasmModule.derive_unified_addresses(
      wallet.seed_phrase,
      wallet.network || "testnet",
      wallet.account_index || 0,
      fromIndex,
      count
    );
    const unifiedAddresses = JSON.parse(unifiedJson);

    // Combine into address data
    derivedAddressesData = [];
    derivedAddressesNetwork = wallet.network || "testnet";
    for (let i = 0; i < count; i++) {
      derivedAddressesData.push({
        index: fromIndex + i,
        transparent: transparentAddresses[i] || "",
        unified: unifiedAddresses[i] || "",
      });
    }

    displayDerivedAddresses();
  } catch (error) {
    console.error("Address derivation error:", error);
    showAddressError(`Error: ${error.message}`);
  } finally {
    setAddressLoading(false);
  }
}

function truncateAddress(address, startChars = 12, endChars = 6) {
  if (!address || address.length <= startChars + endChars + 3) {
    return address;
  }
  return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
}

function getExplorerAddressUrl(address, network) {
  const baseUrl =
    network === "mainnet"
      ? "https://zcashexplorer.app"
      : "https://testnet.zcashexplorer.app";
  return `${baseUrl}/address/${address}`;
}

function copyAddress(address, btnId) {
  navigator.clipboard
    .writeText(address)
    .then(() => {
      const btn = document.getElementById(btnId);
      if (btn) {
        const icon = btn.querySelector("i");
        if (icon) {
          icon.className = "bi bi-check";
          setTimeout(() => {
            icon.className = "bi bi-clipboard";
          }, 1500);
        }
      }
    })
    .catch((err) => {
      console.error("Failed to copy:", err);
    });
}

// Expose to global scope for onclick handlers
window.copyAddress = copyAddress;

function displayDerivedAddresses() {
  const displayDiv = document.getElementById("addressesDisplay");
  const copyAllBtn = document.getElementById("copyAllAddressesBtn");
  const exportCsvBtn = document.getElementById("exportAddressesCsvBtn");
  const saveToWalletBtn = document.getElementById("saveAddressesToWalletBtn");

  if (!displayDiv) return;

  if (derivedAddressesData.length === 0) {
    displayDiv.innerHTML = `
      <div class="text-muted text-center py-5">
        <i class="bi bi-card-list fs-1"></i>
        <p class="mt-2 mb-0">No addresses derived yet.</p>
      </div>
    `;
    copyAllBtn?.classList.add("d-none");
    exportCsvBtn?.classList.add("d-none");
    saveToWalletBtn?.classList.add("d-none");
    return;
  }

  // Show export buttons
  copyAllBtn?.classList.remove("d-none");
  exportCsvBtn?.classList.remove("d-none");
  saveToWalletBtn?.classList.remove("d-none");

  // Get saved addresses from the selected wallet
  // Note: We use loadWallets() directly instead of getWallet() because
  // getWallet() goes through WASM which strips out transparent_addresses
  const walletSelect = document.getElementById("addressWalletSelect");
  const walletId = walletSelect?.value;
  const wallets = loadWallets();
  const wallet = walletId ? wallets.find((w) => w.id === walletId) : null;
  const savedTransparent = new Set(wallet?.transparent_addresses || []);
  const savedUnified = new Set(wallet?.unified_addresses || []);

  // Detect duplicate unified addresses (due to Sapling diversifier behavior)
  // Track first occurrence index for each address
  const firstOccurrence = new Map();
  const duplicateIndices = new Set();

  for (const addr of derivedAddressesData) {
    if (firstOccurrence.has(addr.unified)) {
      // This is a duplicate (not the first occurrence)
      duplicateIndices.add(addr.index);
    } else {
      // First occurrence of this address
      firstOccurrence.set(addr.unified, addr.index);
    }
  }

  const duplicateCount = duplicateIndices.size;

  // Count saved addresses
  const savedCount = derivedAddressesData.filter((addr) =>
    savedTransparent.has(addr.transparent)
  ).length;

  let html = "";

  // Show warning if there are duplicates
  if (duplicateCount > 0) {
    html += `
      <div class="alert alert-warning py-2 mb-3 sapling-note">
        <i class="bi bi-exclamation-triangle me-1"></i>
        <strong>Duplicate addresses detected:</strong> ${duplicateCount} indices produce duplicate unified addresses
        due to Sapling diversifier behavior. Avoid reusing these addresses.
      </div>
    `;
  }

  html += `
    <div class="table-responsive">
      <table class="table table-sm">
        <thead>
          <tr>
            <th style="width: 30px" title="Saved to wallet"><i class="bi bi-floppy"></i></th>
            <th style="width: 50px">Index</th>
            <th>Transparent Address</th>
            <th>Unified Address</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const addr of derivedAddressesData) {
    const transparentId = `copy-t-${addr.index}`;
    const unifiedId = `copy-u-${addr.index}`;
    // Only flag as duplicate if this is NOT the first occurrence
    const isDuplicate = duplicateIndices.has(addr.index);
    const duplicateBadge = isDuplicate
      ? `<span class="badge bg-warning text-dark ms-1" title="This address is identical to index ${firstOccurrence.get(addr.unified)} due to Sapling diversifier behavior. Avoid reusing."><i class="bi bi-exclamation-triangle-fill"></i> Duplicate</span>`
      : "";
    const rowClass = isDuplicate ? "table-warning" : "";

    // Check if address is saved
    const isSaved = savedTransparent.has(addr.transparent);
    const savedIcon = isSaved
      ? '<i class="bi bi-check-circle-fill text-success" title="Saved to wallet"></i>'
      : '<i class="bi bi-circle text-muted" title="Not saved"></i>';

    html += `
      <tr class="${rowClass}">
        <td class="align-middle text-center">${savedIcon}</td>
        <td class="text-muted align-middle">${addr.index}</td>
        <td class="align-middle">
          <div class="d-flex align-items-center gap-2">
            <code class="small" title="${escapeHtml(addr.transparent)}">${escapeHtml(truncateAddress(addr.transparent, 10, 8))}</code>
            <button id="${transparentId}" class="btn btn-sm btn-link p-0 text-muted" onclick="copyAddress('${escapeHtml(addr.transparent)}', '${transparentId}')" title="Copy address">
              <i class="bi bi-clipboard"></i>
            </button>
            <a href="${getExplorerAddressUrl(addr.transparent, derivedAddressesNetwork)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-link p-0 text-muted" title="View in explorer">
              <i class="bi bi-box-arrow-up-right"></i>
            </a>
          </div>
        </td>
        <td class="align-middle">
          <div class="d-flex align-items-center gap-2">
            <code class="small" title="${escapeHtml(addr.unified)}">${escapeHtml(truncateAddress(addr.unified, 14, 8))}</code>
            <button id="${unifiedId}" class="btn btn-sm btn-link p-0 text-muted" onclick="copyAddress('${escapeHtml(addr.unified)}', '${unifiedId}')" title="Copy address">
              <i class="bi bi-clipboard"></i>
            </button>
            ${duplicateBadge}
          </div>
        </td>
      </tr>
    `;
  }

  html += `
        </tbody>
      </table>
    </div>
    <p class="small text-muted mb-0">
      Showing ${derivedAddressesData.length} addresses
      ${savedCount > 0 ? `<span class="text-success ms-2"><i class="bi bi-check-circle-fill"></i> ${savedCount} saved</span>` : ""}
      ${savedCount < derivedAddressesData.length ? `<span class="text-muted ms-2"><i class="bi bi-circle"></i> ${derivedAddressesData.length - savedCount} not saved</span>` : ""}
    </p>
  `;

  displayDiv.innerHTML = html;
}

function copyAllAddresses() {
  if (derivedAddressesData.length === 0) return;

  let text = "Index\tTransparent Address\tUnified Address\n";
  for (const addr of derivedAddressesData) {
    text += `${addr.index}\t${addr.transparent}\t${addr.unified}\n`;
  }

  const btn = document.getElementById("copyAllAddressesBtn");
  navigator.clipboard
    .writeText(text)
    .then(() => {
      if (btn) {
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check me-1"></i> Copied!';
        btn.classList.add("btn-success");
        btn.classList.remove("btn-outline-secondary");

        setTimeout(() => {
          btn.innerHTML = originalHtml;
          btn.classList.remove("btn-success");
          btn.classList.add("btn-outline-secondary");
        }, 2000);
      }
    })
    .catch((err) => {
      console.error("Failed to copy:", err);
    });
}

function exportAddressesCsv() {
  if (derivedAddressesData.length === 0) return;

  let csv = "Index,Transparent Address,Unified Address\n";
  for (const addr of derivedAddressesData) {
    // Escape quotes in addresses (unlikely but safe)
    const transparent = addr.transparent.replace(/"/g, '""');
    const unified = addr.unified.replace(/"/g, '""');
    csv += `${addr.index},"${transparent}","${unified}"\n`;
  }

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `zcash-addresses-${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function saveAddressesToWallet() {
  if (derivedAddressesData.length === 0) {
    showAddressError("No addresses to save. Derive addresses first.");
    return;
  }

  const walletSelect = document.getElementById("addressWalletSelect");
  const walletId = walletSelect?.value;

  if (!walletId) {
    showAddressError("Please select a wallet.");
    return;
  }

  // Get the wallet
  const wallets = loadWallets();
  const walletIndex = wallets.findIndex((w) => w.id === walletId);

  if (walletIndex === -1) {
    showAddressError("Wallet not found.");
    return;
  }

  // Extract transparent addresses from derived data
  const transparentAddresses = derivedAddressesData
    .map((addr) => addr.transparent)
    .filter((addr) => addr && addr.length > 0);

  if (transparentAddresses.length === 0) {
    showAddressError("No transparent addresses to save.");
    return;
  }

  // Count existing addresses before merge
  const existingTransparent = new Set(
    wallets[walletIndex].transparent_addresses || []
  );
  const existingUnified = new Set(wallets[walletIndex].unified_addresses || []);

  // Count how many are already saved
  const alreadySavedTransparent = transparentAddresses.filter((addr) =>
    existingTransparent.has(addr)
  ).length;
  const newTransparent = transparentAddresses.length - alreadySavedTransparent;

  // Merge with existing addresses (avoid duplicates)
  const addressSet = new Set([...existingTransparent, ...transparentAddresses]);
  wallets[walletIndex].transparent_addresses = [...addressSet];

  // Also save unified addresses
  const unifiedAddresses = derivedAddressesData
    .map((addr) => addr.unified)
    .filter((addr) => addr && addr.length > 0);

  const alreadySavedUnified = unifiedAddresses.filter((addr) =>
    existingUnified.has(addr)
  ).length;
  const newUnified = unifiedAddresses.length - alreadySavedUnified;

  const unifiedSet = new Set([...existingUnified, ...unifiedAddresses]);
  wallets[walletIndex].unified_addresses = [...unifiedSet];

  // Save updated wallets
  saveWallets(wallets);

  // Refresh display to show updated saved status
  displayDerivedAddresses();

  // Show success feedback
  const saveBtn = document.getElementById("saveAddressesToWalletBtn");
  if (saveBtn) {
    const originalText = saveBtn.innerHTML;
    saveBtn.innerHTML = '<i class="bi bi-check me-1"></i> Saved!';
    saveBtn.classList.remove("btn-outline-primary");
    saveBtn.classList.add("btn-success");
    setTimeout(() => {
      saveBtn.innerHTML = originalText;
      saveBtn.classList.remove("btn-success");
      saveBtn.classList.add("btn-outline-primary");
    }, 2000);
  }

  console.log(
    `Transparent: ${newTransparent} newly saved, ${alreadySavedTransparent} already in wallet. ` +
      `Unified: ${newUnified} newly saved, ${alreadySavedUnified} already in wallet.`
  );
}

function showAddressError(message) {
  const errorDiv = document.getElementById("addressError");
  if (errorDiv) {
    errorDiv.classList.remove("d-none");
    errorDiv.textContent = message;
  }
}

function hideAddressError() {
  const errorDiv = document.getElementById("addressError");
  if (errorDiv) {
    errorDiv.classList.add("d-none");
  }
}

function setAddressLoading(loading) {
  const btn = document.getElementById("deriveAddressesBtn");
  if (!btn) return;

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

// ===========================================================================
// Send Transaction
// ===========================================================================

let currentSendUtxos = [];

function initSendUI() {
  const signBtn = document.getElementById("signTxBtn");
  const walletSelect = document.getElementById("sendWalletSelect");
  const goToWalletTab = document.getElementById("goToWalletTabFromSend");
  const copySendTxidBtn = document.getElementById("copySendTxidBtn");
  const copySendTxHexBtn = document.getElementById("copySendTxHexBtn");

  if (signBtn) {
    signBtn.addEventListener("click", signTransaction);
  }
  if (walletSelect) {
    walletSelect.addEventListener("change", () => {
      updateSendUtxosDisplay();
    });
    // Populate wallet selector when tab is shown
    document
      .getElementById("send-tab")
      ?.addEventListener("shown.bs.tab", populateSendWallets);
  }
  if (goToWalletTab) {
    goToWalletTab.addEventListener("click", (e) => {
      e.preventDefault();
      const walletTab = document.getElementById("wallet-tab");
      if (walletTab) {
        walletTab.click();
      }
    });
  }
  if (copySendTxidBtn) {
    copySendTxidBtn.addEventListener("click", () => {
      copyToClipboard("sendTxid", copySendTxidBtn);
    });
  }
  if (copySendTxHexBtn) {
    copySendTxHexBtn.addEventListener("click", () => {
      const textarea = document.getElementById("sendTxHex");
      if (textarea) {
        navigator.clipboard
          .writeText(textarea.value)
          .then(() => {
            const originalHtml = copySendTxHexBtn.innerHTML;
            copySendTxHexBtn.innerHTML =
              '<i class="bi bi-check me-1"></i> Copied!';
            copySendTxHexBtn.classList.add("btn-success");
            copySendTxHexBtn.classList.remove("btn-outline-secondary");

            setTimeout(() => {
              copySendTxHexBtn.innerHTML = originalHtml;
              copySendTxHexBtn.classList.remove("btn-success");
              copySendTxHexBtn.classList.add("btn-outline-secondary");
            }, 2000);
          })
          .catch((err) => {
            console.error("Failed to copy:", err);
          });
      }
    });
  }

  // Initial population
  populateSendWallets();
}

function populateSendWallets() {
  const walletSelect = document.getElementById("sendWalletSelect");
  const noWalletsWarning = document.getElementById("sendNoWalletsWarning");
  if (!walletSelect) return;

  const wallets = loadWallets();

  walletSelect.innerHTML = '<option value="">-- Select a wallet --</option>';

  for (const wallet of wallets) {
    const option = document.createElement("option");
    option.value = wallet.id;
    option.textContent = `${wallet.alias} (${wallet.network})`;
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

function updateSendUtxosDisplay() {
  const walletSelect = document.getElementById("sendWalletSelect");
  const utxosDiv = document.getElementById("sendUtxosDisplay");

  if (!utxosDiv) return;

  const walletId = walletSelect?.value;

  if (!walletId) {
    currentSendUtxos = [];
    utxosDiv.innerHTML = `
      <div class="text-muted text-center py-4">
        <i class="bi bi-inbox fs-1"></i>
        <p class="mt-2 mb-0">Select a wallet to view available UTXOs.</p>
      </div>
    `;
    return;
  }

  const wallet = getWallet(walletId);
  if (!wallet) {
    currentSendUtxos = [];
    utxosDiv.innerHTML = `
      <div class="text-danger text-center py-4">
        <i class="bi bi-exclamation-triangle fs-1"></i>
        <p class="mt-2 mb-0">Wallet not found.</p>
      </div>
    `;
    return;
  }

  if (!wasmModule) {
    utxosDiv.innerHTML = `
      <div class="text-danger text-center py-4">
        <p class="mb-0">WASM module not loaded.</p>
      </div>
    `;
    return;
  }

  // Get all notes and filter for transparent UTXOs for this wallet
  const notes = getAllNotes();
  const notesJson = JSON.stringify(notes);

  // Use WASM binding to get transparent UTXOs
  const utxosResultJson = wasmModule.get_transparent_utxos(notesJson);
  let utxosResult;
  try {
    utxosResult = JSON.parse(utxosResultJson);
  } catch {
    utxosDiv.innerHTML = `
      <div class="text-danger text-center py-4">
        <p class="mb-0">Failed to parse UTXOs.</p>
      </div>
    `;
    return;
  }

  if (!utxosResult.success) {
    utxosDiv.innerHTML = `
      <div class="text-danger text-center py-4">
        <p class="mb-0">${escapeHtml(utxosResult.error || "Failed to get UTXOs")}</p>
      </div>
    `;
    return;
  }

  // Filter UTXOs to only those belonging to wallet's known addresses
  const knownAddresses = new Set(wallet.transparent_addresses || []);
  const utxos = (utxosResult.utxos || []).filter(
    (utxo) => utxo.address && knownAddresses.has(utxo.address)
  );

  currentSendUtxos = utxos;

  if (utxos.length === 0) {
    utxosDiv.innerHTML = `
      <div class="text-muted text-center py-4">
        <i class="bi bi-inbox fs-1"></i>
        <p class="mt-2 mb-0">No transparent UTXOs found for this wallet.</p>
        <p class="small">Scan transactions in the Scanner tab to track UTXOs.</p>
      </div>
    `;
    return;
  }

  // Calculate total balance
  let totalBalance = 0;
  for (const utxo of utxos) {
    totalBalance += utxo.value || 0;
  }

  let html = `
    <div class="mb-3">
      <strong>Total Available:</strong>
      <span class="text-success">${formatZatoshi(totalBalance)} ZEC</span>
    </div>
    <div class="table-responsive">
      <table class="table table-sm">
        <thead>
          <tr>
            <th>Outpoint</th>
            <th>Value</th>
            <th>Address</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const utxo of utxos) {
    const shortTxid = utxo.txid ? utxo.txid.slice(0, 8) + "..." : "?";
    const shortAddress = utxo.address ? utxo.address.slice(0, 10) + "..." : "-";

    html += `
      <tr>
        <td class="mono small">${escapeHtml(shortTxid)}:${utxo.output_index}</td>
        <td>${formatZatoshi(utxo.value || 0)} ZEC</td>
        <td class="mono small" title="${escapeHtml(utxo.address || "")}">${escapeHtml(shortAddress)}</td>
      </tr>
    `;
  }

  html += `
        </tbody>
      </table>
    </div>
    <p class="small text-muted mb-0">${utxos.length} UTXO(s) available</p>
  `;

  utxosDiv.innerHTML = html;
}

async function signTransaction() {
  const walletSelect = document.getElementById("sendWalletSelect");
  const recipientInput = document.getElementById("sendRecipient");
  const amountInput = document.getElementById("sendAmount");
  const feeInput = document.getElementById("sendFee");
  const expiryInput = document.getElementById("sendExpiryHeight");

  const walletId = walletSelect?.value;
  const recipientAddress = recipientInput?.value.trim();
  const amountZec = parseFloat(amountInput?.value || "0");
  const fee = parseInt(feeInput?.value || "10000", 10);
  const expiryHeight = parseInt(expiryInput?.value || "0", 10);

  // Validate inputs
  if (!walletId) {
    showSendError("Please select a wallet.");
    return;
  }

  const wallet = getWallet(walletId);
  if (!wallet) {
    showSendError("Selected wallet not found.");
    return;
  }

  if (!wallet.seed_phrase) {
    showSendError("Wallet has no seed phrase. Cannot sign transactions.");
    return;
  }

  if (!recipientAddress) {
    showSendError("Please enter a recipient address.");
    return;
  }

  if (amountZec <= 0) {
    showSendError("Please enter a valid amount.");
    return;
  }

  // Convert ZEC to zatoshis
  const amountZatoshi = Math.round(amountZec * 100000000);

  if (fee < 1000) {
    showSendError("Fee must be at least 1000 zatoshis.");
    return;
  }

  if (currentSendUtxos.length === 0) {
    showSendError("No UTXOs available. Scan transactions first.");
    return;
  }

  // Check if we have enough balance
  let totalAvailable = 0;
  for (const utxo of currentSendUtxos) {
    totalAvailable += utxo.value || 0;
  }

  if (totalAvailable < amountZatoshi + fee) {
    showSendError(
      `Insufficient funds. Available: ${formatZatoshi(totalAvailable)} ZEC, ` +
        `Required: ${formatZatoshi(amountZatoshi + fee)} ZEC (including fee).`
    );
    return;
  }

  if (!wasmModule) {
    showSendError("WASM module not loaded. Please refresh the page.");
    return;
  }

  setSendLoading(true);
  hideSendError();

  try {
    // Prepare UTXOs as JSON
    const utxosJson = JSON.stringify(currentSendUtxos);

    // Prepare recipients as JSON
    const recipients = [
      {
        address: recipientAddress,
        amount: amountZatoshi,
      },
    ];
    const recipientsJson = JSON.stringify(recipients);

    // Sign the transaction
    const resultJson = wasmModule.sign_transparent_transaction(
      wallet.seed_phrase,
      wallet.network || "testnet",
      wallet.account_index || 0,
      utxosJson,
      recipientsJson,
      BigInt(fee),
      expiryHeight
    );

    const result = JSON.parse(resultJson);

    if (result.success) {
      displaySendResult(result);
    } else {
      showSendError(result.error || "Failed to sign transaction.");
    }
  } catch (error) {
    console.error("Transaction signing error:", error);
    showSendError(`Error: ${error.message}`);
  } finally {
    setSendLoading(false);
  }
}

function displaySendResult(result) {
  const resultDiv = document.getElementById("sendResult");
  const placeholderDiv = document.getElementById("sendPlaceholder");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultDiv) resultDiv.classList.remove("d-none");

  const txidDisplay = document.getElementById("sendTxid");
  const txHexDisplay = document.getElementById("sendTxHex");

  if (txidDisplay) {
    txidDisplay.textContent = result.txid || "";
  }
  if (txHexDisplay) {
    txHexDisplay.value = result.raw_tx || "";
  }
}

function showSendError(message) {
  const errorDiv = document.getElementById("sendError");
  if (errorDiv) {
    errorDiv.classList.remove("d-none");
    errorDiv.textContent = message;
  }
}

function hideSendError() {
  const errorDiv = document.getElementById("sendError");
  if (errorDiv) {
    errorDiv.classList.add("d-none");
  }
}

function setSendLoading(loading) {
  const btn = document.getElementById("signTxBtn");
  if (!btn) return;

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
  initAddressViewerUI();
  initSendUI();
  const wasmLoaded = await initWasm();

  // Load persisted data after WASM is ready
  if (wasmLoaded) {
    updateBalanceDisplay();
    updateLedgerDisplay();
    updateNotesDisplay();
  }
});
