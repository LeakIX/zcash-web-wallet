// Zcash Web Wallet - Main Entry Point
// This file initializes all modules and sets up the application

import { initWasm } from "./wasm.js";
import { setTheme, getPreferredTheme, toggleTheme } from "./theme.js";
import { renderEndpoints } from "./storage/endpoints.js";
import { initDecryptViewerUI } from "./decrypt-viewer.js";
import { initScannerUI, populateScannerEndpoints } from "./scanner.js";
import { initWalletUI } from "./wallet.js";
import { initAddressViewerUI } from "./addresses.js";
import { initSendUI } from "./send.js";
import { initViewModeUI } from "./views.js";

// Initialize application on page load
document.addEventListener("DOMContentLoaded", async () => {
  // Load WASM module first (required for all functionality)
  const wasmLoaded = await initWasm();

  if (!wasmLoaded) {
    // Show error if WASM failed to load
    const errorAlert = document.getElementById("errorAlert");
    const errorMessage = document.getElementById("errorMessage");
    if (errorAlert && errorMessage) {
      errorAlert.classList.remove("d-none");
      errorMessage.textContent =
        "Failed to load decryption module. Please refresh the page.";
    }
    return;
  }

  // Set initial theme
  setTheme(getPreferredTheme());

  // Theme toggle button
  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", toggleTheme);
  }

  // Render RPC endpoints
  renderEndpoints();

  // Populate scanner endpoints
  populateScannerEndpoints();

  // Initialize UI modules
  initDecryptViewerUI();
  initWalletUI();
  initScannerUI();
  initAddressViewerUI();
  initSendUI();
  initViewModeUI();
});
