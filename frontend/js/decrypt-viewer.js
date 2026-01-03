// Zcash Web Wallet - Decrypt/Viewer Module

import { getWasm } from "./wasm.js";
import { fetchRawTransaction } from "./rpc.js";
import { debounce } from "./utils.js";
import {
  setSelectedEndpoint,
  addEndpoint,
  renderEndpoints,
} from "./storage/endpoints.js";
import {
  updateEndpointStatus,
  testEndpoint as testEndpointRpc,
} from "./rpc.js";

// Validate viewing key and update UI
export function validateViewingKey() {
  const keyInput = document.getElementById("viewingKey");
  const keyInfo = document.getElementById("keyInfo");
  const networkSelect = document.getElementById("network");
  const wasmModule = getWasm();

  if (!keyInput || !keyInfo) return;

  const key = keyInput.value.trim();
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
      if (
        networkSelect &&
        (result.network === "mainnet" || result.network === "testnet")
      ) {
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

// Set loading state for decrypt button
function setLoading(loading) {
  const submitBtn = document.getElementById("submitBtn");
  if (!submitBtn) return;

  if (loading) {
    submitBtn.classList.add("loading");
    submitBtn.disabled = true;
  } else {
    submitBtn.classList.remove("loading");
    submitBtn.disabled = false;
  }
}

// Show error message
function showError(message) {
  const placeholderDiv = document.getElementById("placeholder");
  const resultsDiv = document.getElementById("results");
  const errorAlert = document.getElementById("errorAlert");
  const errorMessage = document.getElementById("errorMessage");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");
  if (errorAlert) errorAlert.classList.remove("d-none");
  if (errorMessage) errorMessage.textContent = message;
}

// Hide error message
function hideError() {
  const errorAlert = document.getElementById("errorAlert");
  if (errorAlert) errorAlert.classList.add("d-none");
}

// Decrypt transaction
export async function decryptTransaction() {
  const viewingKeyInput = document.getElementById("viewingKey");
  const txidInput = document.getElementById("txid");
  const networkSelect = document.getElementById("network");
  const rpcEndpointSelect = document.getElementById("rpcEndpoint");
  const wasmModule = getWasm();

  const viewingKey = viewingKeyInput?.value.trim();
  const txid = txidInput?.value.trim();
  const network = networkSelect?.value;
  const rpcEndpoint = rpcEndpointSelect?.value;

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

// Display decryption results
export function displayResults(tx) {
  const wasmModule = getWasm();
  const placeholderDiv = document.getElementById("placeholder");
  const resultsDiv = document.getElementById("results");

  if (placeholderDiv) placeholderDiv.classList.add("d-none");
  if (resultsDiv) resultsDiv.classList.remove("d-none");

  const txidValue = document.getElementById("txidValue");
  if (txidValue) txidValue.textContent = tx.txid;

  // Transparent section
  const transparentSection = document.getElementById("transparentSection");
  const transparentInputs = document.getElementById("transparentInputs");
  const transparentOutputs = document.getElementById("transparentOutputs");

  if (tx.transparent_inputs.length > 0 || tx.transparent_outputs.length > 0) {
    if (transparentSection) transparentSection.classList.remove("d-none");

    if (transparentInputs) {
      transparentInputs.innerHTML = wasmModule.render_transparent_inputs(
        JSON.stringify(tx.transparent_inputs)
      );
    }

    if (transparentOutputs) {
      transparentOutputs.innerHTML = wasmModule.render_transparent_outputs(
        JSON.stringify(tx.transparent_outputs)
      );
    }
  } else {
    if (transparentSection) transparentSection.classList.add("d-none");
  }

  // Sapling section
  const saplingSection = document.getElementById("saplingSection");
  const saplingOutputs = document.getElementById("saplingOutputs");

  if (tx.sapling_outputs.length > 0) {
    if (saplingSection) saplingSection.classList.remove("d-none");
    if (saplingOutputs) {
      saplingOutputs.innerHTML = wasmModule.render_sapling_outputs(
        JSON.stringify(tx.sapling_outputs)
      );
    }
  } else {
    if (saplingSection) saplingSection.classList.add("d-none");
  }

  // Orchard section
  const orchardSection = document.getElementById("orchardSection");
  const orchardActions = document.getElementById("orchardActions");

  if (tx.orchard_actions.length > 0) {
    if (orchardSection) orchardSection.classList.remove("d-none");
    if (orchardActions) {
      orchardActions.innerHTML = wasmModule.render_orchard_actions(
        JSON.stringify(tx.orchard_actions)
      );
    }
  } else {
    if (orchardSection) orchardSection.classList.add("d-none");
  }

  // No shielded data message
  const noShieldedData = document.getElementById("noShieldedData");
  if (noShieldedData) {
    if (tx.sapling_outputs.length === 0 && tx.orchard_actions.length === 0) {
      noShieldedData.classList.remove("d-none");
    } else {
      noShieldedData.classList.add("d-none");
    }
  }
}

// Initialize decrypt viewer UI
export function initDecryptViewerUI() {
  const form = document.getElementById("decryptForm");
  const viewingKeyInput = document.getElementById("viewingKey");
  const rpcEndpointSelect = document.getElementById("rpcEndpoint");
  const newEndpointInput = document.getElementById("newEndpoint");
  const addEndpointBtn = document.getElementById("addEndpointBtn");
  const testEndpointBtn = document.getElementById("testEndpointBtn");
  const endpointStatus = document.getElementById("endpointStatus");

  // Form submission
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      await decryptTransaction();
    });
  }

  // Validate viewing key on input
  if (viewingKeyInput) {
    viewingKeyInput.addEventListener(
      "input",
      debounce(validateViewingKey, 300)
    );
  }

  // RPC endpoint selection
  if (rpcEndpointSelect) {
    rpcEndpointSelect.addEventListener("change", () => {
      setSelectedEndpoint(rpcEndpointSelect.value);
      if (endpointStatus) endpointStatus.innerHTML = "";
    });
  }

  // Add endpoint button
  if (addEndpointBtn && newEndpointInput) {
    addEndpointBtn.addEventListener("click", () => {
      const url = newEndpointInput.value;
      if (addEndpoint(url)) {
        newEndpointInput.value = "";
        updateEndpointStatus(
          endpointStatus,
          "Endpoint added successfully",
          "success"
        );
      } else {
        updateEndpointStatus(
          endpointStatus,
          "Invalid URL or endpoint already exists",
          "danger"
        );
      }
    });
  }

  // Test endpoint button
  if (testEndpointBtn && rpcEndpointSelect) {
    testEndpointBtn.addEventListener("click", async () => {
      const rpcEndpoint = rpcEndpointSelect.value;

      if (!rpcEndpoint) {
        updateEndpointStatus(
          endpointStatus,
          "Please select an endpoint first",
          "warning"
        );
        return;
      }

      // Show testing status
      testEndpointBtn.disabled = true;
      const originalContent = testEndpointBtn.innerHTML;
      testEndpointBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm" role="status"></span>';
      updateEndpointStatus(endpointStatus, "Testing connection...", "info", 0);

      try {
        const result = await testEndpointRpc(rpcEndpoint);
        updateEndpointStatus(
          endpointStatus,
          `Connected: ${result.chain} network, block height ${result.blocks.toLocaleString()}`,
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
        updateEndpointStatus(endpointStatus, `Error: ${errorMsg}`, "danger");
      } finally {
        testEndpointBtn.disabled = false;
        testEndpointBtn.innerHTML = originalContent;
      }
    });
  }
}
