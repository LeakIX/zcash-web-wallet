// Zcash Web Wallet - View Modes Module

import { STORAGE_KEYS, VIEW_MODES } from "./constants.js";
import { loadWallets } from "./storage/wallets.js";
import { loadNotes } from "./storage/notes.js";
import { loadLedger } from "./storage/ledger.js";
import { renderTxidLink } from "./utils.js";

// Get current view mode
export function getViewMode() {
  return localStorage.getItem(STORAGE_KEYS.viewMode) || VIEW_MODES.admin;
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

function updateSimpleTransactionList(walletId) {
  const listEl = document.getElementById("simpleTransactionList");
  if (!listEl) return;

  if (!walletId) {
    listEl.innerHTML = `
      <div class="text-center text-body-secondary py-4">
        <i class="bi bi-clock-history fs-1"></i>
        <p class="mt-2 mb-0">No transactions yet</p>
      </div>
    `;
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
    listEl.innerHTML = `
      <div class="text-center text-body-secondary py-4">
        <i class="bi bi-clock-history fs-1"></i>
        <p class="mt-2 mb-0">No transactions yet</p>
      </div>
    `;
    return;
  }

  const sortedEntries = walletEntries
    .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
    .slice(0, 10);

  listEl.innerHTML = sortedEntries
    .map((entry) => {
      const isIncoming = entry.net_change > 0;
      const icon = isIncoming ? "bi-arrow-down-left" : "bi-arrow-up-right";
      const color = isIncoming ? "text-success" : "text-danger";
      const sign = isIncoming ? "+" : "";
      const zec = (entry.net_change || 0) / 100000000;
      const dateStr = entry.timestamp
        ? new Date(entry.timestamp).toLocaleString()
        : "Unknown";
      const txidLink = entry.txid
        ? renderTxidLink(entry.txid, network, 6, 4)
        : "";

      return `
        <div class="list-group-item d-flex justify-content-between align-items-center">
          <div class="d-flex align-items-center">
            <i class="bi ${icon} ${color} fs-4 me-3"></i>
            <div>
              <div class="fw-semibold">${isIncoming ? "Received" : "Sent"}</div>
              <small class="text-body-secondary">${dateStr}</small>
              ${txidLink ? `<div class="small">${txidLink}</div>` : ""}
            </div>
          </div>
          <div class="text-end">
            <div class="${color} fw-semibold">${sign}${zec.toFixed(8)} ZEC</div>
          </div>
        </div>
      `;
    })
    .join("");
}

export function updateReceiveAddress(walletId) {
  const addressDisplay = document.getElementById("receiveAddressDisplay");
  if (!addressDisplay) return;

  if (!walletId) {
    addressDisplay.textContent = "No wallet selected";
    return;
  }

  const wallets = loadWallets();
  const wallet = wallets.find((w) => w.id === walletId);

  if (!wallet) {
    addressDisplay.textContent = "Wallet not found";
    return;
  }

  const address =
    wallet.unified_address || wallet.transparent_address || "No address";
  addressDisplay.textContent = address;
}

// Initialize view mode UI
export function initViewModeUI() {
  const viewModeRadios = document.querySelectorAll('input[name="viewMode"]');
  viewModeRadios.forEach((radio) => {
    radio.addEventListener("change", (e) => {
      setViewMode(e.target.value);
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

  const copyReceiveAddressBtn = document.getElementById(
    "copyReceiveAddressBtn"
  );
  if (copyReceiveAddressBtn) {
    copyReceiveAddressBtn.addEventListener("click", () => {
      const addressDisplay = document.getElementById("receiveAddressDisplay");
      if (
        addressDisplay &&
        addressDisplay.textContent !== "No wallet selected"
      ) {
        navigator.clipboard.writeText(addressDisplay.textContent);
        copyReceiveAddressBtn.innerHTML =
          '<i class="bi bi-check me-1"></i>Copied!';
        setTimeout(() => {
          copyReceiveAddressBtn.innerHTML =
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

  applyViewMode(getViewMode());
}
