// Zcash Web Wallet - Messages Storage (Encrypted Messaging)

import { STORAGE_KEYS } from "../constants.js";

/**
 * Message schema:
 * {
 *   id: string,              // txid + output_index (unique identifier)
 *   conversation: string,    // recipient z-addr (normalized)
 *   direction: 'sent' | 'received',
 *   content: string,         // message text
 *   timestamp: number,       // unix timestamp from memo
 *   nonce: u32,              // nonce from memo (for dedup)
 *   blockHeight: number | null,  // block height when confirmed
 *   status: 'pending' | 'confirmed',
 *   fragmentGroup: string | null,  // group ID for fragmented messages
 *   txid: string,            // transaction ID
 *   outputIndex: number,     // output index in transaction
 * }
 */

// Load messages from localStorage
export function loadMessages() {
  const stored = localStorage.getItem(STORAGE_KEYS.messages);
  if (stored) {
    try {
      return JSON.parse(stored);
    } catch {
      return [];
    }
  }
  return [];
}

// Save messages to localStorage
export function saveMessages(messages) {
  localStorage.setItem(STORAGE_KEYS.messages, JSON.stringify(messages));
}

// Add a message to storage
export function addMessage(message) {
  const messages = loadMessages();

  // Check for duplicates based on ID (txid + output_index)
  const existingIndex = messages.findIndex((m) => m.id === message.id);

  if (existingIndex >= 0) {
    // Update existing message
    messages[existingIndex] = { ...messages[existingIndex], ...message };
  } else {
    // Add new message
    messages.push(message);
  }

  saveMessages(messages);
  return existingIndex < 0; // Return true if new message was added
}

// Update message status
export function updateMessageStatus(messageId, status, blockHeight = null) {
  const messages = loadMessages();
  const messageIndex = messages.findIndex((m) => m.id === messageId);

  if (messageIndex >= 0) {
    messages[messageIndex].status = status;
    if (blockHeight !== null) {
      messages[messageIndex].blockHeight = blockHeight;
    }
    saveMessages(messages);
    return true;
  }

  return false;
}

// Get messages for a specific conversation
export function getConversationMessages(address) {
  const messages = loadMessages();
  return messages
    .filter((m) => m.conversation === address)
    .sort((a, b) => a.timestamp - b.timestamp); // Sort by timestamp ascending
}

// Get all conversations (grouped by address)
export function getConversations() {
  const messages = loadMessages();
  const conversations = new Map();

  for (const message of messages) {
    const existing = conversations.get(message.conversation);

    if (!existing || message.timestamp > existing.lastMessage.timestamp) {
      conversations.set(message.conversation, {
        address: message.conversation,
        lastMessage: message,
        unreadCount: 0, // TODO: implement unread tracking
      });
    }
  }

  // Convert to array and sort by most recent message
  return Array.from(conversations.values()).sort(
    (a, b) => b.lastMessage.timestamp - a.lastMessage.timestamp
  );
}

// Get pending messages (waiting for confirmation)
export function getPendingMessages() {
  const messages = loadMessages();
  return messages.filter((m) => m.status === "pending");
}

// Check if a message with this nonce already exists
export function messageExistsByNonce(nonce, conversation) {
  const messages = loadMessages();
  return messages.some(
    (m) => m.nonce === nonce && m.conversation === conversation
  );
}

// Delete a message by ID
export function deleteMessage(messageId) {
  const messages = loadMessages();
  const filtered = messages.filter((m) => m.id !== messageId);

  if (filtered.length !== messages.length) {
    saveMessages(filtered);
    return true;
  }

  return false;
}

// Delete all messages for a conversation
export function deleteConversation(address) {
  const messages = loadMessages();
  const filtered = messages.filter((m) => m.conversation !== address);

  if (filtered.length !== messages.length) {
    saveMessages(filtered);
    return true;
  }

  return false;
}

// Get message fragments that need reassembly
export function getFragmentsByGroup(fragmentGroup) {
  const messages = loadMessages();
  return messages.filter((m) => m.fragmentGroup === fragmentGroup);
}

// Mark fragments as reassembled
export function markFragmentsReassembled(fragmentGroup, reassembledMessageId) {
  const messages = loadMessages();
  let updated = false;

  for (const message of messages) {
    if (message.fragmentGroup === fragmentGroup) {
      message.reassembledTo = reassembledMessageId;
      updated = true;
    }
  }

  if (updated) {
    saveMessages(messages);
  }

  return updated;
}

// Clear all messages (for testing/debugging)
export function clearAllMessages() {
  localStorage.removeItem(STORAGE_KEYS.messages);
}

// Get messages count
export function getMessagesCount() {
  const messages = loadMessages();
  return messages.length;
}

// Get conversation count
export function getConversationsCount() {
  const conversations = getConversations();
  return conversations.length;
}
