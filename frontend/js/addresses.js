// Zcash Web Wallet - Address Viewer Module
// TODO: Full implementation - copied patterns from original app.js

import { getWasm } from "./wasm.js";
import {
  loadWallets,
  saveWallets,
  getSelectedWalletId,
  getSelectedWallet,
} from "./storage/wallets.js";

let derivedAddressesData = [];
let derivedAddressesNetwork = "testnet";
let currentWalletId = null;

export function initAddressViewerUI() {
  const deriveBtn = document.getElementById("deriveAddressesBtn");
  const copyAllBtn = document.getElementById("copyAllAddressesBtn");
  const exportCsvBtn = document.getElementById("exportAddressesCsvBtn");
  const saveToWalletBtn = document.getElementById("saveAddressesToWalletBtn");
  const walletSelect = document.getElementById("addressWalletSelect");

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
  if (walletSelect) {
    walletSelect.addEventListener("change", () => {
      const wallet = getSelectedWallet();
      if (wallet) {
        const networkSelect = document.getElementById("addressNetwork");
        if (networkSelect && wallet.network) {
          networkSelect.value = wallet.network;
        }
      }
    });
  }

  populateAddressViewerWallets();
}

export function populateAddressViewerWallets() {
  const walletSelect = document.getElementById("addressWalletSelect");
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
}

async function deriveAddresses() {
  const wasmModule = getWasm();
  const walletSelect = document.getElementById("addressWalletSelect");
  const fromIndexInput = document.getElementById("addressFromIndex");
  const toIndexInput = document.getElementById("addressToIndex");

  const walletId = walletSelect?.value;
  const fromIndex = parseInt(fromIndexInput?.value || "0", 10);
  const toIndex = parseInt(toIndexInput?.value || "10", 10);
  const count = Math.max(1, toIndex - fromIndex + 1);

  if (!walletId) {
    showAddressError("Please select a wallet.");
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);

  if (!wallet || !wallet.seed_phrase) {
    showAddressError("Selected wallet has no seed phrase.");
    return;
  }

  if (!wasmModule) {
    showAddressError("WASM module not loaded.");
    return;
  }

  setAddressLoading(true);
  hideAddressError();

  try {
    const network = wallet.network || "testnet";
    const accountIndex = wallet.account_index || 0;

    // Get both unified and transparent addresses
    const unifiedResult = wasmModule.derive_unified_addresses(
      wallet.seed_phrase,
      network,
      accountIndex,
      fromIndex,
      count
    );
    const transparentResult = wasmModule.derive_transparent_addresses(
      wallet.seed_phrase,
      network,
      accountIndex,
      fromIndex,
      count
    );

    const unifiedAddresses = JSON.parse(unifiedResult);
    const transparentAddresses = JSON.parse(transparentResult);

    // Get already saved addresses from wallet
    const savedTransparent = new Set(wallet.transparent_addresses || []);
    const savedUnified = new Set(wallet.unified_addresses || []);

    // Combine into objects with index, transparent, unified, and saved status
    derivedAddressesData = unifiedAddresses.map((unified, idx) => ({
      index: fromIndex + idx,
      transparent: transparentAddresses[idx] || "",
      unified: unified,
      isSaved:
        savedTransparent.has(transparentAddresses[idx]) ||
        savedUnified.has(unified),
    }));

    derivedAddressesNetwork = network;
    currentWalletId = walletId;
    displayDerivedAddresses();
  } catch (error) {
    console.error("Address derivation error:", error);
    showAddressError(`Error: ${error.message}`);
  } finally {
    setAddressLoading(false);
  }
}

function displayDerivedAddresses() {
  const displayDiv = document.getElementById("addressesDisplay");
  const wasmModule = getWasm();
  if (!displayDiv || !wasmModule) return;

  displayDiv.innerHTML = wasmModule.render_derived_addresses_table(
    JSON.stringify(derivedAddressesData),
    derivedAddressesNetwork
  );

  // Show the export buttons if we have addresses
  if (derivedAddressesData.length > 0) {
    const copyAllBtn = document.getElementById("copyAllAddressesBtn");
    const exportCsvBtn = document.getElementById("exportAddressesCsvBtn");
    const saveToWalletBtn = document.getElementById("saveAddressesToWalletBtn");
    if (copyAllBtn) copyAllBtn.classList.remove("d-none");
    if (exportCsvBtn) exportCsvBtn.classList.remove("d-none");
    if (saveToWalletBtn) saveToWalletBtn.classList.remove("d-none");
  }
}

function copyAllAddresses() {
  if (derivedAddressesData.length === 0) return;

  const text = derivedAddressesData
    .map((addr) => `${addr.index}\t${addr.transparent}\t${addr.unified}`)
    .join("\n");

  navigator.clipboard.writeText(text);
}

function exportAddressesCsv() {
  if (derivedAddressesData.length === 0) return;

  const csv =
    "Index,Transparent,Unified\n" +
    derivedAddressesData
      .map((addr) => `${addr.index},"${addr.transparent}","${addr.unified}"`)
      .join("\n");

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
  if (derivedAddressesData.length === 0 || !currentWalletId) {
    showAddressError("No addresses to save or no wallet selected.");
    return;
  }

  const wallets = loadWallets();
  const walletIndex = wallets.findIndex((w) => w.id === currentWalletId);

  if (walletIndex === -1) {
    showAddressError("Wallet not found.");
    return;
  }

  const wallet = wallets[walletIndex];

  // Get existing addresses
  const existingTransparent = new Set(wallet.transparent_addresses || []);
  const existingUnified = new Set(wallet.unified_addresses || []);

  // Count new addresses
  let newTransparentCount = 0;
  let newUnifiedCount = 0;
  let duplicateCount = 0;

  for (const addr of derivedAddressesData) {
    if (addr.transparent && !existingTransparent.has(addr.transparent)) {
      existingTransparent.add(addr.transparent);
      newTransparentCount++;
    } else if (addr.transparent) {
      duplicateCount++;
    }

    if (addr.unified && !existingUnified.has(addr.unified)) {
      existingUnified.add(addr.unified);
      newUnifiedCount++;
    }
  }

  // Update wallet
  wallet.transparent_addresses = Array.from(existingTransparent);
  wallet.unified_addresses = Array.from(existingUnified);
  wallets[walletIndex] = wallet;
  saveWallets(wallets);

  // Update display to show saved status
  derivedAddressesData = derivedAddressesData.map((addr) => ({
    ...addr,
    isSaved: true,
  }));
  displayDerivedAddresses();

  // Show result message
  const totalNew = newTransparentCount + newUnifiedCount;
  if (totalNew === 0 && duplicateCount > 0) {
    showAddressInfo(
      `All ${duplicateCount} addresses are already saved to the wallet.`
    );
  } else if (duplicateCount > 0) {
    showAddressInfo(
      `Saved ${totalNew} new addresses. ${duplicateCount} were already saved.`
    );
  } else {
    showAddressSuccess(`Saved ${totalNew} addresses to the wallet.`);
  }
}

function showAddressInfo(message) {
  const displayDiv = document.getElementById("addressesDisplay");
  const wasmModule = getWasm();
  if (!displayDiv || !wasmModule) return;

  // Remove existing alert (but not duplicate warnings)
  const existingAlert = displayDiv.querySelector(
    ".alert-info, .alert-success, .alert-danger"
  );
  if (existingAlert) existingAlert.remove();

  const alertHtml = wasmModule.render_dismissible_alert(
    message,
    "info",
    "bi-info-circle"
  );
  displayDiv.insertAdjacentHTML("afterbegin", alertHtml);
}

function showAddressSuccess(message) {
  const displayDiv = document.getElementById("addressesDisplay");
  const wasmModule = getWasm();
  if (!displayDiv || !wasmModule) return;

  // Remove existing alert (but not duplicate warnings)
  const existingAlert = displayDiv.querySelector(
    ".alert-info, .alert-success, .alert-danger"
  );
  if (existingAlert) existingAlert.remove();

  const alertHtml = wasmModule.render_dismissible_alert(
    message,
    "success",
    "bi-check-circle"
  );
  displayDiv.insertAdjacentHTML("afterbegin", alertHtml);
}

function copyAddress(address, btnId) {
  navigator.clipboard.writeText(address).then(() => {
    const btn = document.getElementById(btnId);
    if (btn) {
      const originalHtml = btn.innerHTML;
      btn.innerHTML = '<i class="bi bi-check"></i>';
      setTimeout(() => {
        btn.innerHTML = originalHtml;
      }, 1500);
    }
  });
}

// Expose to window for onclick handlers
window.copyAddress = copyAddress;

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

  if (loading) {
    btn.disabled = true;
    btn.innerHTML =
      '<span class="spinner-border spinner-border-sm me-1"></span> Deriving...';
  } else {
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-diagram-3 me-1"></i> Derive Addresses';
  }
}
