// Zcash Web Wallet - View Modes Module

import { STORAGE_KEYS, VIEW_MODES } from "./constants.js";
import { loadWallets, getSelectedWallet } from "./storage/wallets.js";
import { loadNotes, getAllNotes } from "./storage/notes.js";
import { loadLedger } from "./storage/ledger.js";
import { loadEndpoints } from "./storage/endpoints.js";
import { getWasm } from "./wasm.js";
import { broadcastTransaction } from "./rpc.js";

// Get current view mode
export function getViewMode() {
  return localStorage.getItem(STORAGE_KEYS.viewMode) || VIEW_MODES.simple;
}

// Set view mode
export function setViewMode(mode) {
  localStorage.setItem(STORAGE_KEYS.viewMode, mode);
  applyViewMode(mode);
}

// Apply view mode to UI
export function applyViewMode(mode) {
  const simpleView = document.getElementById("simpleView");
  const mainTabs = document.getElementById("mainTabs");
  const mainTabContent = document.getElementById("mainTabContent");
  const aboutSection = document.querySelector("section.container.py-4.mt-5");

  const viewerTab = document.getElementById("viewer-tab");
  const scannerTab = document.getElementById("scanner-tab");
  const walletTab = document.getElementById("wallet-tab");
  const addressesTab = document.getElementById("addresses-tab");
  const sendTab = document.getElementById("send-tab");

  // Update radio button state
  const radioButtons = document.querySelectorAll('input[name="viewMode"]');
  radioButtons.forEach((radio) => {
    radio.checked = radio.value === mode;
  });

  const setTabVisible = (tab, visible) => {
    if (tab) {
      tab.parentElement.classList.toggle("d-none", !visible);
    }
  };

  if (mode === VIEW_MODES.simple) {
    if (simpleView) simpleView.classList.remove("d-none");
    if (mainTabs) mainTabs.classList.add("d-none");
    if (mainTabContent) mainTabContent.classList.add("d-none");
    if (aboutSection) aboutSection.classList.add("d-none");
    updateSimpleView();
  } else if (mode === VIEW_MODES.accountant) {
    if (simpleView) simpleView.classList.add("d-none");
    if (mainTabs) mainTabs.classList.remove("d-none");
    if (mainTabContent) mainTabContent.classList.remove("d-none");
    if (aboutSection) aboutSection.classList.remove("d-none");

    setTabVisible(viewerTab, true);
    setTabVisible(scannerTab, true);
    setTabVisible(walletTab, false);
    setTabVisible(addressesTab, true);
    setTabVisible(sendTab, false);

    if (scannerTab) {
      const tab = new bootstrap.Tab(scannerTab);
      tab.show();
    }
  } else {
    if (simpleView) simpleView.classList.add("d-none");
    if (mainTabs) mainTabs.classList.remove("d-none");
    if (mainTabContent) mainTabContent.classList.remove("d-none");
    if (aboutSection) aboutSection.classList.remove("d-none");

    setTabVisible(viewerTab, true);
    setTabVisible(scannerTab, true);
    setTabVisible(walletTab, true);
    setTabVisible(addressesTab, true);
    setTabVisible(sendTab, true);
  }
}

// Update simple view
export function updateSimpleView() {
  const walletSelect = document.getElementById("simpleWalletSelect");
  const noWalletsWarning = document.getElementById("simpleNoWalletsWarning");

  if (!walletSelect) return;

  const wallets = loadWallets();
  walletSelect.innerHTML = '<option value="">Select a wallet...</option>';

  if (wallets.length === 0) {
    if (noWalletsWarning) noWalletsWarning.classList.remove("d-none");
    return;
  }

  if (noWalletsWarning) noWalletsWarning.classList.add("d-none");

  wallets.forEach((wallet) => {
    const option = document.createElement("option");
    option.value = wallet.id;
    option.textContent = wallet.alias || wallet.id;
    walletSelect.appendChild(option);
  });

  const selectedWalletId = localStorage.getItem(STORAGE_KEYS.selectedWallet);
  if (selectedWalletId) {
    walletSelect.value = selectedWalletId;
    updateSimpleBalance(selectedWalletId);
    updateSimpleNetworkBadge(selectedWalletId);
    updateSimpleTransactionList(selectedWalletId);
    updateReceiveAddress(selectedWalletId);
  }
}

function updateSimpleBalance(walletId) {
  const balanceEl = document.getElementById("simpleBalance");
  if (!balanceEl) return;

  if (!walletId) {
    balanceEl.textContent = "0.00";
    return;
  }

  const notes = loadNotes();
  let total = 0;
  notes.forEach((note) => {
    if (note.wallet_id === walletId && !note.spent_txid) {
      total += note.value || 0;
    }
  });

  const zec = total / 100000000;
  balanceEl.textContent = zec.toFixed(8).replace(/\.?0+$/, "") || "0";
}

function updateSimpleNetworkBadge(walletId) {
  const badge = document.getElementById("simpleNetworkBadge");
  if (!badge) return;

  if (!walletId) {
    badge.classList.add("d-none");
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);

  if (!wallet) {
    badge.classList.add("d-none");
    return;
  }

  const network = wallet.network || "testnet";
  badge.classList.remove("d-none", "bg-secondary", "bg-success", "bg-warning");

  if (network === "mainnet") {
    badge.textContent = "Mainnet";
    badge.classList.add("bg-success");
  } else {
    badge.textContent = "Testnet";
    badge.classList.add("bg-warning", "text-dark");
  }
}

function updateSimpleTransactionList(walletId) {
  const listEl = document.getElementById("simpleTransactionList");
  if (!listEl) return;

  if (!walletId) {
    listEl.innerHTML = getWasm().render_empty_state(
      "No transactions yet",
      "bi-clock-history"
    );
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);
  const network = wallet?.network || "mainnet";

  const ledger = loadLedger();
  const walletEntries = (ledger.entries || []).filter(
    (entry) => entry.wallet_id === walletId
  );

  if (walletEntries.length === 0) {
    listEl.innerHTML = getWasm().render_empty_state(
      "No transactions yet",
      "bi-clock-history"
    );
    return;
  }

  listEl.innerHTML = getWasm().render_simple_transaction_list(
    JSON.stringify(walletEntries),
    network
  );
}

export function updateReceiveAddress(walletId) {
  const unifiedDisplay = document.getElementById(
    "receiveUnifiedAddressDisplay"
  );
  const transparentDisplay = document.getElementById(
    "receiveTransparentAddressDisplay"
  );

  if (!unifiedDisplay || !transparentDisplay) return;

  if (!walletId) {
    unifiedDisplay.textContent = "No wallet selected";
    transparentDisplay.textContent = "No wallet selected";
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);

  if (!wallet) {
    unifiedDisplay.textContent = "Wallet not found";
    transparentDisplay.textContent = "Wallet not found";
    return;
  }

  unifiedDisplay.textContent = wallet.unified_address || "No unified address";
  transparentDisplay.textContent =
    wallet.transparent_address || "No transparent address";
}

// Get default RPC endpoint for a network
function getDefaultEndpointForNetwork(network) {
  const endpoints = loadEndpoints();
  // Find the first endpoint matching the network
  const endpoint = endpoints.find((e) => e.network === network);
  return endpoint?.url || null;
}

// Simple Send functionality
async function handleSimpleSend() {
  const wasmModule = getWasm();
  const walletSelect = document.getElementById("simpleWalletSelect");
  const addressInput = document.getElementById("simpleSendAddress");
  const amountInput = document.getElementById("simpleSendAmount");
  const errorDiv = document.getElementById("simpleSendError");
  const confirmBtn = document.getElementById("simpleSendConfirmBtn");

  const walletId = walletSelect?.value;
  const recipient = addressInput?.value.trim();
  const amountZec = parseFloat(amountInput?.value || "0");

  // Hide previous errors
  if (errorDiv) errorDiv.classList.add("d-none");

  // Validation
  if (!walletId) {
    showSimpleSendError("Please select a wallet first.");
    return;
  }

  if (!recipient) {
    showSimpleSendError("Please enter a recipient address.");
    return;
  }

  if (amountZec <= 0) {
    showSimpleSendError("Please enter a valid amount.");
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);

  if (!wallet || !wallet.seed_phrase) {
    showSimpleSendError("Selected wallet has no seed phrase.");
    return;
  }

  if (!wasmModule) {
    showSimpleSendError("WASM module not loaded. Please refresh the page.");
    return;
  }

  // Get UTXOs for this wallet
  const notes = getAllNotes();
  const utxos = notes.filter(
    (note) =>
      note.wallet_id === walletId &&
      note.pool === "transparent" &&
      !note.spent_txid
  );

  if (utxos.length === 0) {
    showSimpleSendError(
      "No transparent UTXOs available. You need transparent funds to send."
    );
    return;
  }

  // Get default RPC endpoint for wallet's network
  const network = wallet.network || "testnet";
  const rpcEndpoint = getDefaultEndpointForNetwork(network);

  if (!rpcEndpoint) {
    showSimpleSendError(
      `No RPC endpoint configured for ${network}. Please add one in Admin view.`
    );
    return;
  }

  const amountZat = Math.floor(amountZec * 100000000);
  const feeZat = 10000; // Default fee: 0.0001 ZEC

  // Set loading state
  setSimpleSendLoading(true);

  try {
    // Transform UTXOs to expected format
    const utxoInputs = utxos.map((u) => ({
      txid: u.txid,
      vout: u.output_index,
      value: u.value,
      address: u.address,
      script_pubkey: u.script_pubkey || null,
    }));

    // Create recipients array
    const recipients = [{ address: recipient, amount: amountZat }];

    // Sign transaction
    const resultJson = wasmModule.sign_transparent_transaction(
      wallet.seed_phrase,
      network,
      wallet.account_index || 0,
      JSON.stringify(utxoInputs),
      JSON.stringify(recipients),
      BigInt(feeZat),
      0 // expiry_height: 0 means no expiry
    );

    const result = JSON.parse(resultJson);

    if (!result.success || !result.tx_hex) {
      showSimpleSendError(result.error || "Failed to sign transaction.");
      return;
    }

    // Broadcast transaction
    const txid = await broadcastTransaction(rpcEndpoint, result.tx_hex);

    // Success - close modal and show result
    const modal = bootstrap.Modal.getInstance(
      document.getElementById("sendModal")
    );
    if (modal) modal.hide();

    // Clear form
    if (addressInput) addressInput.value = "";
    if (amountInput) amountInput.value = "";

    // Show success alert
    showSimpleSendSuccess(txid, network);
  } catch (error) {
    console.error("Simple send error:", error);
    showSimpleSendError(`Error: ${error.message}`);
  } finally {
    setSimpleSendLoading(false);
  }
}

function showSimpleSendError(message) {
  const errorDiv = document.getElementById("simpleSendError");
  if (errorDiv) {
    errorDiv.textContent = message;
    errorDiv.classList.remove("d-none");
  }
}

function showSimpleSendSuccess(txid, network) {
  const alertHtml = getWasm().render_success_alert(txid, network);

  // Insert alert at top of simple view
  const simpleView = document.getElementById("simpleView");
  if (simpleView) {
    const alertContainer = document.createElement("div");
    alertContainer.innerHTML = alertHtml;
    simpleView.insertBefore(
      alertContainer.firstElementChild,
      simpleView.firstChild
    );
  }
}

function setSimpleSendLoading(loading) {
  const btn = document.getElementById("simpleSendConfirmBtn");
  if (!btn) return;

  const btnText = btn.querySelector(".btn-text");
  const spinner = btn.querySelector(".spinner-border");

  if (loading) {
    btn.disabled = true;
    if (btnText) btnText.classList.add("d-none");
    if (spinner) spinner.classList.remove("d-none");
  } else {
    btn.disabled = false;
    if (btnText) btnText.classList.remove("d-none");
    if (spinner) spinner.classList.add("d-none");
  }
}

// Update mobile dropdown to reflect current view mode
function updateMobileDropdown(mode) {
  const dropdownText = document.getElementById("viewModeDropdownText");
  const dropdownIcon = document.getElementById("viewModeDropdownIcon");

  if (!dropdownText || !dropdownIcon) return;

  const modeConfig = {
    simple: { text: "Simple", icon: "bi-phone" },
    accountant: { text: "Accountant", icon: "bi-journal-text" },
    admin: { text: "Admin", icon: "bi-gear" },
  };

  const config = modeConfig[mode] || modeConfig.admin;
  dropdownText.textContent = config.text;
  dropdownIcon.className = `bi ${config.icon} me-1`;
}

// Initialize view mode UI
export function initViewModeUI() {
  // Desktop: Radio buttons
  const viewModeRadios = document.querySelectorAll('input[name="viewMode"]');
  viewModeRadios.forEach((radio) => {
    radio.addEventListener("change", (e) => {
      setViewMode(e.target.value);
      updateMobileDropdown(e.target.value);
    });
  });

  // Mobile: Dropdown items
  const dropdownItems = document.querySelectorAll("[data-view-mode]");
  dropdownItems.forEach((item) => {
    item.addEventListener("click", () => {
      const mode = item.getAttribute("data-view-mode");
      setViewMode(mode);
      updateMobileDropdown(mode);
    });
  });

  const simpleWalletSelect = document.getElementById("simpleWalletSelect");
  if (simpleWalletSelect) {
    simpleWalletSelect.addEventListener("change", (e) => {
      const walletId = e.target.value;
      if (walletId) {
        localStorage.setItem(STORAGE_KEYS.selectedWallet, walletId);
      }
      updateSimpleBalance(walletId);
      updateSimpleNetworkBadge(walletId);
      updateSimpleTransactionList(walletId);
      updateReceiveAddress(walletId);
    });
  }

  const simpleGoToWalletTab = document.getElementById("simpleGoToWalletTab");
  if (simpleGoToWalletTab) {
    simpleGoToWalletTab.addEventListener("click", (e) => {
      e.preventDefault();
      setViewMode(VIEW_MODES.admin);
      const walletTab = document.getElementById("wallet-tab");
      if (walletTab) {
        const tab = new bootstrap.Tab(walletTab);
        tab.show();
      }
    });
  }

  // Copy unified address button
  const copyUnifiedAddressBtn = document.getElementById(
    "copyUnifiedAddressBtn"
  );
  if (copyUnifiedAddressBtn) {
    copyUnifiedAddressBtn.addEventListener("click", () => {
      const addressDisplay = document.getElementById(
        "receiveUnifiedAddressDisplay"
      );
      if (
        addressDisplay &&
        addressDisplay.textContent !== "No wallet selected" &&
        addressDisplay.textContent !== "No unified address"
      ) {
        navigator.clipboard.writeText(addressDisplay.textContent);
        copyUnifiedAddressBtn.innerHTML =
          '<i class="bi bi-check me-1"></i>Copied!';
        setTimeout(() => {
          copyUnifiedAddressBtn.innerHTML =
            '<i class="bi bi-clipboard me-1"></i>Copy Address';
        }, 2000);
      }
    });
  }

  // Copy transparent address button
  const copyTransparentAddressBtn = document.getElementById(
    "copyTransparentAddressBtn"
  );
  if (copyTransparentAddressBtn) {
    copyTransparentAddressBtn.addEventListener("click", () => {
      const addressDisplay = document.getElementById(
        "receiveTransparentAddressDisplay"
      );
      if (
        addressDisplay &&
        addressDisplay.textContent !== "No wallet selected" &&
        addressDisplay.textContent !== "No transparent address"
      ) {
        navigator.clipboard.writeText(addressDisplay.textContent);
        copyTransparentAddressBtn.innerHTML =
          '<i class="bi bi-check me-1"></i>Copied!';
        setTimeout(() => {
          copyTransparentAddressBtn.innerHTML =
            '<i class="bi bi-clipboard me-1"></i>Copy Address';
        }, 2000);
      }
    });
  }

  const receiveModal = document.getElementById("receiveModal");
  if (receiveModal) {
    receiveModal.addEventListener("show.bs.modal", () => {
      const simpleWalletSelect = document.getElementById("simpleWalletSelect");
      const walletId = simpleWalletSelect ? simpleWalletSelect.value : null;
      updateReceiveAddress(walletId);
    });
  }

  // Simple Send button
  const simpleSendConfirmBtn = document.getElementById("simpleSendConfirmBtn");
  if (simpleSendConfirmBtn) {
    simpleSendConfirmBtn.addEventListener("click", handleSimpleSend);
  }

  // Clear send error and set placeholder when modal opens
  const sendModal = document.getElementById("sendModal");
  if (sendModal) {
    sendModal.addEventListener("show.bs.modal", () => {
      const errorDiv = document.getElementById("simpleSendError");
      if (errorDiv) errorDiv.classList.add("d-none");

      // Update placeholder based on wallet network
      const addressInput = document.getElementById("simpleSendAddress");
      if (addressInput) {
        const wallet = getSelectedWallet();
        if (wallet && wallet.network === "mainnet") {
          addressInput.placeholder = "t1... or u1...";
        } else {
          addressInput.placeholder = "tm... or utest1...";
        }
      }
    });
  }

  const currentMode = getViewMode();
  applyViewMode(currentMode);
  updateMobileDropdown(currentMode);
}
