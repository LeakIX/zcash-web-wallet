// Zcash Web Wallet - Scanner Module

import { getWasm } from "./wasm.js";
import { fetchRawTransaction } from "./rpc.js";
import { formatZatoshi, escapeHtml, renderTxidLink } from "./utils.js";
import {
  loadNotes,
  saveNotes,
  addNote,
  markNotesSpent,
  markTransparentSpent,
  getAllNotes,
  getBalance,
  getBalanceByPool,
  clearNotes,
} from "./storage/notes.js";
import {
  loadLedger,
  createLedgerEntry,
  addLedgerEntry,
  getLedgerForWallet,
  exportLedgerCsv,
  clearLedger,
} from "./storage/ledger.js";
import {
  loadWallets,
  getWallet,
  getSelectedWalletId,
  setSelectedWalletId,
  getSelectedWallet,
} from "./storage/wallets.js";
import { loadEndpoints, getSelectedEndpoint } from "./storage/endpoints.js";

// Initialize scanner UI
export function initScannerUI() {
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
      const walletTab = document.getElementById("wallet-tab");
      if (walletTab) {
        walletTab.click();
      }
    });
  }
  if (walletSelect) {
    walletSelect.addEventListener("change", () => {
      setSelectedWalletId(walletSelect.value);
      const wallet = getSelectedWallet();
      if (wallet) {
        const networkSelect = document.getElementById("scanNetwork");
        if (networkSelect && wallet.network) {
          networkSelect.value = wallet.network;
        }
      }
      updateLedgerDisplay();
    });
  }

  populateScannerWallets();
  updateBalanceDisplay();
  updateNotesDisplay();
  updateLedgerDisplay();
}

// Populate wallet selector
export function populateScannerWallets() {
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

  if (noWalletsWarning) {
    if (wallets.length === 0) {
      noWalletsWarning.classList.remove("d-none");
    } else {
      noWalletsWarning.classList.add("d-none");
    }
  }
}

// Scan transaction
export async function scanTransaction() {
  const txidInput = document.getElementById("scanTxid");
  const walletSelect = document.getElementById("scanWalletSelect");
  const networkSelect = document.getElementById("scanNetwork");
  const heightInput = document.getElementById("scanHeight");
  const rpcSelect = document.getElementById("scanRpcEndpoint");
  const wasmModule = getWasm();

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

  const validationResult = JSON.parse(wasmModule.validate_txid(txid));
  if (!validationResult.valid) {
    showScanError(validationResult.error || "Invalid transaction ID format.");
    return;
  }

  setScanLoading(true);
  hideScanError();

  try {
    const rawTx = await fetchRawTransaction(rpcEndpoint, txid);

    if (!rawTx) {
      showScanError("Failed to fetch transaction.");
      setScanLoading(false);
      return;
    }

    const resultJson = wasmModule.scan_transaction(
      rawTx,
      viewingKey,
      network,
      height
    );
    const result = JSON.parse(resultJson);

    if (result.success && result.result) {
      const wallets = loadWallets();
      const fullWallet = wallets.find((w) => w.id === walletId);
      const knownAddresses = [
        ...(fullWallet?.transparent_addresses || []),
        ...(fullWallet?.transparent_address
          ? [fullWallet.transparent_address]
          : []),
      ];
      processScanResult(result.result, walletId, knownAddresses, height);
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

// Process scan result
export function processScanResult(
  scanResult,
  walletId,
  knownTransparentAddresses = [],
  blockHeight = null
) {
  let notesAdded = 0;
  let notesWithValue = 0;
  let notesSkipped = 0;

  const knownAddressSet = new Set(knownTransparentAddresses);

  for (const note of scanResult.notes) {
    if (note.pool !== "transparent") {
      if (note.value === 0 && !note.nullifier) {
        notesSkipped++;
        continue;
      }
    } else {
      if (note.address && !knownAddressSet.has(note.address)) {
        notesSkipped++;
        continue;
      }
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

  const shieldedResult = markNotesSpent(
    scanResult.spent_nullifiers,
    scanResult.txid,
    blockHeight
  );

  const transparentResult = markTransparentSpent(
    scanResult.transparent_spends || [],
    scanResult.txid,
    blockHeight,
    shieldedResult.notes
  );

  const totalSpent =
    shieldedResult.marked_count + transparentResult.marked_count;

  const resultsDiv = document.getElementById("scanResults");
  const placeholderDiv = document.getElementById("scanPlaceholder");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");

  if (transparentResult.notes) {
    saveNotes(transparentResult.notes);
  }

  const ledgerEntry = createLedgerEntry(scanResult, walletId);
  let ledgerUpdated = false;
  if (ledgerEntry) {
    ledgerUpdated = addLedgerEntry(ledgerEntry);
  }

  updateBalanceDisplay();
  updateNotesDisplay();
  updateLedgerDisplay();

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

// Update balance display
export function updateBalanceDisplay() {
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

// Update notes display
export function updateNotesDisplay() {
  const notesDiv = document.getElementById("notesDisplay");
  if (!notesDiv) return;

  const notes = getAllNotes();

  if (notes.length === 0) {
    notesDiv.innerHTML = getWasm().render_empty_state(
      "No notes tracked yet. Scan a transaction to get started.",
      "bi-inbox"
    );
    return;
  }

  notes.sort((a, b) => {
    if (a.spent_txid && !b.spent_txid) return 1;
    if (!a.spent_txid && b.spent_txid) return -1;
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
    const isSpent = !!note.spent_txid;
    const statusBadge = isSpent
      ? '<span class="badge bg-secondary">Spent</span>'
      : '<span class="badge bg-success">Unspent</span>';
    const rowClass = isSpent ? "text-muted text-decoration-line-through" : "";

    html += `
      <tr class="${rowClass}">
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

// Update ledger display
export function updateLedgerDisplay() {
  const ledgerDiv = document.getElementById("ledgerDisplay");
  if (!ledgerDiv) return;

  const walletId = getSelectedWalletId();
  let entries = [];

  if (walletId) {
    entries = getLedgerForWallet(walletId);
  } else {
    const ledger = loadLedger();
    entries = ledger.entries || [];
  }

  if (entries.length === 0) {
    ledgerDiv.innerHTML = getWasm().render_empty_state(
      "No transaction history yet. Scan transactions to build your ledger.",
      "bi-journal-text"
    );
    return;
  }

  entries.sort((a, b) => {
    if (a.created_at && b.created_at) {
      return b.created_at.localeCompare(a.created_at);
    }
    return 0;
  });

  const wallet = walletId ? getWallet(walletId) : null;
  const network = wallet?.network || "mainnet";

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

    let rowClass = "";
    if (entry.net_change > 0) {
      rowClass = "table-success";
    } else if (entry.net_change < 0) {
      rowClass = "table-danger";
    }

    const netFormatted =
      entry.net_change >= 0
        ? `+${formatZatoshi(entry.net_change)}`
        : formatZatoshi(entry.net_change);

    const poolBadge = getPoolBadge(entry.primary_pool);

    const memo =
      entry.memos && entry.memos.length > 0
        ? escapeHtml(entry.memos[0].slice(0, 20)) +
          (entry.memos[0].length > 20 ? "..." : "")
        : "-";

    html += `
      <tr class="${rowClass}">
        <td class="small">${date}</td>
        <td class="small">${renderTxidLink(entry.txid, network)}</td>
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

// Download ledger CSV
export function downloadLedgerCsv() {
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

// Populate scanner RPC endpoints
export function populateScannerEndpoints() {
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
