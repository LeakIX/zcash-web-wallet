// Zcash Web Wallet - Wallet Generation Module

import { TRANSPARENT_ADDRESS_COUNT } from "./constants.js";
import { getWasm } from "./wasm.js";
import {
  loadWallets,
  addWallet,
  getWallet,
  deleteWallet,
  walletAliasExists,
} from "./storage/wallets.js";
import {
  populateScannerWallets,
  updateBalanceDisplay,
  updateNotesDisplay,
  updateLedgerDisplay,
} from "./scanner.js";
import { populateAddressViewerWallets } from "./addresses.js";
import { populateSendWallets } from "./send.js";

let currentWalletData = null;

// Initialize wallet UI
export function initWalletUI() {
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

  updateSavedWalletsList();
}

// Generate new wallet
export async function generateWallet() {
  const wasmModule = getWasm();
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

// Restore wallet from seed
export async function restoreWallet() {
  const seedInput = document.getElementById("restoreSeed");
  const seedPhrase = seedInput?.value.trim();

  if (!seedPhrase) {
    showWalletError("Please enter a seed phrase");
    return;
  }

  const wasmModule = getWasm();
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

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");
  if (errorDiv) errorDiv.classList.add("d-none");
  if (successDiv) successDiv.classList.remove("d-none");

  const seedDisplay = document.getElementById("seedPhraseDisplay");
  const ufvkDisplay = document.getElementById("ufvkDisplay");
  if (seedDisplay) seedDisplay.textContent = wallet.seed_phrase || "";
  if (ufvkDisplay)
    ufvkDisplay.textContent = wallet.unified_full_viewing_key || "";
}

function showWalletError(message) {
  const resultsDiv = document.getElementById("walletResults");
  const placeholderDiv = document.getElementById("walletPlaceholder");
  const errorDiv = document.getElementById("walletError");
  const successDiv = document.getElementById("walletSuccess");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");
  if (errorDiv) errorDiv.classList.remove("d-none");
  if (successDiv) successDiv.classList.add("d-none");

  const errorMsg = document.getElementById("walletErrorMsg");
  if (errorMsg) errorMsg.textContent = message;
}

function setWalletLoading(btn, loading) {
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

function saveWalletToBrowser() {
  if (!currentWalletData) {
    showWalletError("No wallet data to save");
    return;
  }

  const wasmModule = getWasm();
  if (!wasmModule) {
    showWalletError("WASM module not loaded");
    return;
  }

  const generateAlias = document.getElementById("walletAlias")?.value.trim();
  const restoreAlias = document.getElementById("restoreAlias")?.value.trim();
  const alias = currentWalletData._alias || generateAlias || restoreAlias || "";

  if (!alias) {
    showWalletError("Please enter a wallet name");
    return;
  }

  if (walletAliasExists(alias)) {
    showWalletError(
      `A wallet named "${alias}" already exists. Please choose a different name.`
    );
    return;
  }

  let transparentAddresses = [];
  let unifiedAddresses = [];
  if (currentWalletData.seed_phrase) {
    const transparentJson = wasmModule.derive_transparent_addresses(
      currentWalletData.seed_phrase,
      currentWalletData.network || "testnet",
      currentWalletData.account_index || 0,
      0,
      TRANSPARENT_ADDRESS_COUNT
    );
    try {
      transparentAddresses = JSON.parse(transparentJson);
    } catch {
      console.error("Failed to parse transparent addresses");
    }

    const unifiedJson = wasmModule.derive_unified_addresses(
      currentWalletData.seed_phrase,
      currentWalletData.network || "testnet",
      currentWalletData.account_index || 0,
      0,
      TRANSPARENT_ADDRESS_COUNT
    );
    try {
      unifiedAddresses = JSON.parse(unifiedJson);
    } catch {
      console.error("Failed to parse unified addresses");
    }
  }

  addWallet(currentWalletData, alias, transparentAddresses, unifiedAddresses);

  updateSavedWalletsList();
  populateScannerWallets();
  populateAddressViewerWallets();
  populateSendWallets();

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

// Update saved wallets list
export function updateSavedWalletsList() {
  const listDiv = document.getElementById("savedWalletsList");
  const wasmModule = getWasm();
  if (!listDiv || !wasmModule) return;

  const wallets = loadWallets();
  listDiv.innerHTML = wasmModule.render_saved_wallets_list(
    JSON.stringify(wallets)
  );
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
      `Are you sure you want to delete "${wallet.alias}"?\n\nThis will also delete all tracked notes and transaction history for this wallet. This cannot be undone.`
    )
  ) {
    const result = deleteWallet(walletId);
    if (result.success) {
      updateBalanceDisplay();
      updateLedgerDisplay();
      updateNotesDisplay();
    }
    updateSavedWalletsList();
    populateScannerWallets();
  }
}

// Expose to global scope for onclick handlers
window.viewWalletDetails = viewWalletDetails;
window.confirmDeleteWallet = confirmDeleteWallet;

function copyToClipboard(elementId, btn) {
  const element = document.getElementById(elementId);
  if (!element) return;
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
