// Zcash Web Wallet - Contacts Module

import { getWasm } from "./wasm.js";
import {
  loadContacts,
  addContact,
  updateContact,
  deleteContact,
  getContact,
  exportContactsJson,
  exportContactsCsv,
  importContactsJson,
} from "./storage/contacts.js";

let editingContactId = null;

export function initContactsUI() {
  const addBtn = document.getElementById("addContactBtn");
  const saveBtn = document.getElementById("saveContactBtn");
  const exportJsonBtn = document.getElementById("exportContactsJsonBtn");
  const exportCsvBtn = document.getElementById("exportContactsCsvBtn");
  const importBtn = document.getElementById("importContactsBtn");
  const importFileInput = document.getElementById("importContactsFile");

  if (addBtn) {
    addBtn.addEventListener("click", showAddContactForm);
  }
  if (saveBtn) {
    saveBtn.addEventListener("click", saveContact);
  }
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", handleExportJson);
  }
  if (exportCsvBtn) {
    exportCsvBtn.addEventListener("click", handleExportCsv);
  }
  if (importBtn) {
    importBtn.addEventListener("click", () => importFileInput?.click());
  }
  if (importFileInput) {
    importFileInput.addEventListener("change", handleImportFile);
  }

  updateContactsList();
  initContactsSearch();
}

export function updateContactsList() {
  const listDiv = document.getElementById("contactsList");
  const wasmModule = getWasm();
  if (!listDiv || !wasmModule) return;

  const contacts = loadContacts();
  listDiv.innerHTML = wasmModule.render_contacts_list(JSON.stringify(contacts));

  // Also update the autocomplete datalists
  populateContactsDatalist();
}

function showAddContactForm() {
  editingContactId = null;
  clearContactForm();

  const formTitle = document.getElementById("contactFormTitle");
  const form = document.getElementById("contactForm");

  if (formTitle) formTitle.textContent = "Add New Contact";
  if (form) form.classList.remove("d-none");

  document.getElementById("contactName")?.focus();
}

function showEditContactForm(contactId) {
  const contact = getContact(contactId);
  if (!contact) return;

  editingContactId = contactId;

  const formTitle = document.getElementById("contactFormTitle");
  const form = document.getElementById("contactForm");
  const nameInput = document.getElementById("contactName");
  const addressInput = document.getElementById("contactAddress");
  const networkSelect = document.getElementById("contactNetwork");
  const notesInput = document.getElementById("contactNotes");

  if (formTitle) formTitle.textContent = "Edit Contact";
  if (form) form.classList.remove("d-none");
  if (nameInput) nameInput.value = contact.name;
  if (addressInput) addressInput.value = contact.address;
  if (networkSelect) networkSelect.value = contact.network;
  if (notesInput) notesInput.value = contact.notes || "";

  nameInput?.focus();
}

function clearContactForm() {
  const nameInput = document.getElementById("contactName");
  const addressInput = document.getElementById("contactAddress");
  const networkSelect = document.getElementById("contactNetwork");
  const notesInput = document.getElementById("contactNotes");

  if (nameInput) nameInput.value = "";
  if (addressInput) addressInput.value = "";
  if (networkSelect) networkSelect.value = "mainnet";
  if (notesInput) notesInput.value = "";
}

function saveContact() {
  const wasmModule = getWasm();
  const nameInput = document.getElementById("contactName");
  const addressInput = document.getElementById("contactAddress");
  const networkSelect = document.getElementById("contactNetwork");
  const notesInput = document.getElementById("contactNotes");

  const name = nameInput?.value.trim();
  const address = addressInput?.value.trim();
  const network = networkSelect?.value || "mainnet";
  const notes = notesInput?.value.trim() || "";

  if (!name) {
    showContactError("Please enter a contact name.");
    return;
  }

  if (!address) {
    showContactError("Please enter an address.");
    return;
  }

  // Validate address format using WASM
  if (wasmModule) {
    try {
      const validationResult = JSON.parse(
        wasmModule.validate_address(address, network)
      );
      if (!validationResult.valid) {
        showContactError(
          validationResult.error || "Invalid address format for this network."
        );
        return;
      }
    } catch (e) {
      showContactError("Failed to validate address.");
      return;
    }
  }

  let result;
  if (editingContactId) {
    result = updateContact(editingContactId, { name, address, network, notes });
  } else {
    result = addContact(name, address, network, notes);
  }

  if (result.success) {
    const wasEditing = editingContactId !== null;
    // Reset form to "Add Contact" mode instead of hiding
    editingContactId = null;
    clearContactForm();
    hideContactError();
    const formTitle = document.getElementById("contactFormTitle");
    if (formTitle) formTitle.textContent = "Add New Contact";
    updateContactsList();
    showContactSuccess(wasEditing ? "Contact updated!" : "Contact saved!");
  } else {
    showContactError(result.error);
  }
}

function confirmDelete(contactId) {
  const contact = getContact(contactId);
  if (!contact) return;

  if (confirm(`Are you sure you want to delete "${contact.name}"?`)) {
    const result = deleteContact(contactId);
    if (result.success) {
      updateContactsList();
    }
  }
}

function showContactError(message) {
  const errorDiv = document.getElementById("contactError");
  if (errorDiv) {
    errorDiv.classList.remove("d-none");
    errorDiv.textContent = message;
  }
}

function hideContactError() {
  const errorDiv = document.getElementById("contactError");
  if (errorDiv) {
    errorDiv.classList.add("d-none");
  }
}

function showContactSuccess(message) {
  const successDiv = document.getElementById("contactSuccess");
  if (successDiv) {
    successDiv.classList.remove("d-none");
    successDiv.textContent = message;
    setTimeout(() => {
      successDiv.classList.add("d-none");
    }, 2000);
  }
}

function handleExportJson() {
  const json = exportContactsJson();
  downloadFile(json, "zcash-contacts.json", "application/json");
}

function handleExportCsv() {
  const csv = exportContactsCsv();
  downloadFile(csv, "zcash-contacts.csv", "text/csv");
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function handleImportFile(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target?.result;
    if (typeof content !== "string") return;

    const result = importContactsJson(content);
    if (result.success) {
      updateContactsList();
      showContactSuccess(
        `Imported ${result.added} contacts (${result.skipped} skipped)`
      );
    } else {
      showContactError(result.error);
    }
  };
  reader.readAsText(file);

  // Reset file input
  event.target.value = "";
}

// Setup autocomplete dropdowns for address inputs
export function setupContactsAutocomplete() {
  const inputs = [
    {
      inputId: "simpleSendAddress",
      dropdownId: "simpleSendContactsDropdown",
    },
    {
      inputId: "sendRecipient",
      dropdownId: "sendRecipientContactsDropdown",
    },
  ];

  for (const { inputId, dropdownId } of inputs) {
    const input = document.getElementById(inputId);
    const dropdown = document.getElementById(dropdownId);

    if (input && dropdown) {
      setupAutocompleteInput(input, dropdown);
    }
  }
}

function setupAutocompleteInput(input, dropdown) {
  let selectedIndex = -1;

  // Show dropdown on focus if there are contacts
  input.addEventListener("focus", () => {
    updateAutocompleteDropdown(input, dropdown);
  });

  // Filter on input
  input.addEventListener("input", () => {
    selectedIndex = -1;
    updateAutocompleteDropdown(input, dropdown);
  });

  // Keyboard navigation
  input.addEventListener("keydown", (e) => {
    const items = dropdown.querySelectorAll(".dropdown-item");
    if (items.length === 0) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, items.length - 1);
      updateSelection(items, selectedIndex);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      updateSelection(items, selectedIndex);
    } else if (e.key === "Enter" && selectedIndex >= 0) {
      e.preventDefault();
      const address = items[selectedIndex].dataset.address;
      if (address) {
        input.value = address;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        hideDropdown(dropdown);
      }
    } else if (e.key === "Escape") {
      hideDropdown(dropdown);
    }
  });

  // Hide on blur (with delay to allow click)
  input.addEventListener("blur", () => {
    setTimeout(() => hideDropdown(dropdown), 200);
  });
}

function updateSelection(items, index) {
  items.forEach((item, i) => {
    item.classList.toggle("active", i === index);
  });
}

function updateAutocompleteDropdown(input, dropdown) {
  const contacts = loadContacts();
  const query = input.value.toLowerCase().trim();

  // Filter contacts by name or address
  const filtered = contacts.filter(
    (c) =>
      c.name.toLowerCase().includes(query) ||
      c.address.toLowerCase().includes(query)
  );

  if (filtered.length === 0) {
    hideDropdown(dropdown);
    return;
  }

  // Render dropdown items
  dropdown.innerHTML = filtered
    .map((c) => {
      const addressShort =
        c.address.length > 24
          ? `${c.address.slice(0, 12)}...${c.address.slice(-8)}`
          : c.address;
      const networkBadge =
        c.network === "mainnet"
          ? '<span class="badge bg-success ms-2">mainnet</span>'
          : '<span class="badge bg-info ms-2">testnet</span>';
      return `
        <button type="button" class="dropdown-item" data-address="${c.address}">
          <div class="d-flex justify-content-between align-items-center">
            <div>
              <strong>${escapeHtml(c.name)}</strong>${networkBadge}
              <div class="text-muted small mono">${escapeHtml(addressShort)}</div>
            </div>
          </div>
        </button>
      `;
    })
    .join("");

  // Add click handlers
  dropdown.querySelectorAll(".dropdown-item").forEach((item) => {
    item.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const address = item.dataset.address;
      if (address) {
        input.value = address;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        hideDropdown(dropdown);
      }
    });
  });

  showDropdown(dropdown);
}

function showDropdown(dropdown) {
  dropdown.classList.add("show");
  dropdown.style.display = "block";
}

function hideDropdown(dropdown) {
  dropdown.classList.remove("show");
  dropdown.style.display = "none";
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// Legacy function for backward compatibility - now uses custom dropdown
export function populateContactsDatalist() {
  // Call setupContactsAutocomplete instead
  setupContactsAutocomplete();
}

// Copy contact address to clipboard
function copyContactAddress(address) {
  navigator.clipboard
    .writeText(address)
    .then(() => {
      showContactSuccess("Address copied to clipboard!");
    })
    .catch(() => {
      showContactError("Failed to copy address");
    });
}

// Filter contacts in the list based on search input
function filterContacts(query) {
  const items = document.querySelectorAll("#contactsList .contact-item");
  const lowerQuery = query.toLowerCase().trim();

  items.forEach((item) => {
    const name = item.dataset.name || "";
    const address = item.dataset.address || "";
    const matches =
      name.includes(lowerQuery) || address.includes(lowerQuery) || !lowerQuery;
    item.style.display = matches ? "" : "none";
  });
}

// Setup search input listener
function initContactsSearch() {
  const searchInput = document.getElementById("contactsSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      filterContacts(e.target.value);
    });
  }
}

// Expose functions to global scope for onclick handlers
window.editContact = showEditContactForm;
window.confirmDeleteContact = confirmDelete;
window.copyContactAddress = copyContactAddress;
