// Zcash Web Wallet - Contacts Storage

import { STORAGE_KEYS } from "../constants.js";

// Generate a unique ID for contacts
function generateId() {
  return `contact_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Load contacts from localStorage
export function loadContacts() {
  const stored = localStorage.getItem(STORAGE_KEYS.contacts);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }
  return [];
}

// Save contacts to localStorage
export function saveContacts(contacts) {
  localStorage.setItem(STORAGE_KEYS.contacts, JSON.stringify(contacts));
}

// Add a new contact
export function addContact(name, address, network = "mainnet", notes = "") {
  if (!name || !address) {
    return { success: false, error: "Name and address are required" };
  }

  const contacts = loadContacts();

  // Check for duplicate address
  const existingByAddress = contacts.find(
    (c) => c.address.toLowerCase() === address.toLowerCase()
  );
  if (existingByAddress) {
    return {
      success: false,
      error: `Address already exists as "${existingByAddress.name}"`,
    };
  }

  const contact = {
    id: generateId(),
    name: name.trim(),
    address: address.trim(),
    network,
    notes: notes.trim(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  contacts.push(contact);
  saveContacts(contacts);

  return { success: true, contact };
}

// Update an existing contact
export function updateContact(id, updates) {
  const contacts = loadContacts();
  const index = contacts.findIndex((c) => c.id === id);

  if (index === -1) {
    return { success: false, error: "Contact not found" };
  }

  // Check for duplicate address (excluding current contact)
  if (updates.address) {
    const existingByAddress = contacts.find(
      (c) =>
        c.id !== id && c.address.toLowerCase() === updates.address.toLowerCase()
    );
    if (existingByAddress) {
      return {
        success: false,
        error: `Address already exists as "${existingByAddress.name}"`,
      };
    }
  }

  contacts[index] = {
    ...contacts[index],
    ...updates,
    updated_at: new Date().toISOString(),
  };

  saveContacts(contacts);
  return { success: true, contact: contacts[index] };
}

// Delete a contact
export function deleteContact(id) {
  const contacts = loadContacts();
  const index = contacts.findIndex((c) => c.id === id);

  if (index === -1) {
    return { success: false, error: "Contact not found" };
  }

  const deleted = contacts.splice(index, 1)[0];
  saveContacts(contacts);

  return { success: true, contact: deleted };
}

// Get a contact by ID
export function getContact(id) {
  const contacts = loadContacts();
  return contacts.find((c) => c.id === id) || null;
}

// Get contacts by network
export function getContactsByNetwork(network) {
  const contacts = loadContacts();
  return contacts.filter((c) => c.network === network);
}

// Search contacts by name or address
export function searchContacts(query) {
  if (!query) return loadContacts();

  const lowerQuery = query.toLowerCase();
  const contacts = loadContacts();

  return contacts.filter(
    (c) =>
      c.name.toLowerCase().includes(lowerQuery) ||
      c.address.toLowerCase().includes(lowerQuery)
  );
}

// Export contacts to JSON
export function exportContactsJson() {
  const contacts = loadContacts();
  return JSON.stringify(contacts, null, 2);
}

// Export contacts to CSV
export function exportContactsCsv() {
  const contacts = loadContacts();
  const header = "Name,Address,Network,Notes,Created,Updated";
  const rows = contacts.map(
    (c) =>
      `"${c.name}","${c.address}","${c.network}","${c.notes || ""}","${c.created_at}","${c.updated_at}"`
  );
  return [header, ...rows].join("\n");
}

// Import contacts from JSON
export function importContactsJson(jsonString) {
  try {
    const imported = JSON.parse(jsonString);
    if (!Array.isArray(imported)) {
      return { success: false, error: "Invalid JSON format: expected array" };
    }

    const contacts = loadContacts();
    let added = 0;
    let skipped = 0;

    for (const item of imported) {
      if (!item.name || !item.address) {
        skipped++;
        continue;
      }

      // Check for duplicate address
      const exists = contacts.find(
        (c) => c.address.toLowerCase() === item.address.toLowerCase()
      );
      if (exists) {
        skipped++;
        continue;
      }

      contacts.push({
        id: generateId(),
        name: item.name.trim(),
        address: item.address.trim(),
        network: item.network || "mainnet",
        notes: (item.notes || "").trim(),
        created_at: item.created_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      added++;
    }

    saveContacts(contacts);
    return { success: true, added, skipped };
  } catch (e) {
    return { success: false, error: `Failed to parse JSON: ${e.message}` };
  }
}
