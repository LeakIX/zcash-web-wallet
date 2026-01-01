// Zcash Web Wallet - Message Sync Service

import { getWasm } from "../wasm.js";
import {
  addMessage,
  messageExistsByNonce,
  getFragmentsByGroup,
  markFragmentsReassembled,
} from "../storage/messages.js";

/**
 * Extract and parse messages from notes with memos.
 *
 * This service scans notes for memo fields, decodes them as messages,
 * and stores them in the messages database.
 *
 * @param {Array} notes - Array of StoredNote objects
 * @param {string} walletAddress - The wallet's unified address
 * @returns {number} Number of new messages extracted
 */
export function extractMessagesFromNotes(notes, walletAddress) {
  const wasmModule = getWasm();
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return 0;
  }

  let newMessagesCount = 0;
  const fragmentGroups = new Map(); // Map of fragmentGroup -> fragments[]

  for (const note of notes) {
    // Skip notes without memos
    if (!note.memo) {
      continue;
    }

    // Skip encrypted memos (they haven't been decrypted yet)
    if (note.memo === "(encrypted)") {
      continue;
    }

    // Try to decode as a message memo
    // For now, we'll assume memos are already hex-encoded
    // In a real implementation, memos would come from transaction scanning
    const memoHex = note.memo;

    try {
      const decodeResultJson = wasmModule.decode_message_memo(memoHex);
      const decodeResult = JSON.parse(decodeResultJson);

      if (!decodeResult.success) {
        // Not a valid message memo, skip
        continue;
      }

      const decodedMessage = decodeResult.message;

      // Skip non-text and non-fragment messages (e.g., acks)
      if (
        decodedMessage.type !== "Text" &&
        decodedMessage.type !== "Fragment"
      ) {
        continue;
      }

      // Check for duplicates based on nonce
      // The conversation is the address we're communicating with
      // For received messages, this would be the sender's address
      // For sent messages, this would be the recipient's address
      // For now, we'll use a placeholder since we don't have sender info yet
      const conversation = note.address || "unknown";

      if (messageExistsByNonce(decodedMessage.nonce, conversation)) {
        // Message already exists, skip
        continue;
      }

      // Determine message direction
      // If the note belongs to our wallet, it's received
      const direction = note.wallet_id ? "received" : "sent";

      // Create message object
      const message = {
        id: `${note.txid}:${note.output_index}`,
        conversation: conversation,
        direction: direction,
        content: decodedMessage.content,
        timestamp: decodedMessage.timestamp,
        nonce: decodedMessage.nonce,
        blockHeight: null, // Will be set when we have block info
        status: note.spent_txid ? "confirmed" : "pending",
        fragmentGroup: null,
        txid: note.txid,
        outputIndex: note.output_index,
      };

      // Handle fragments
      if (decodedMessage.type === "Fragment") {
        const fragmentInfo = decodedMessage.fragment_info;
        // Create a unique fragment group ID based on timestamp and nonce
        const fragmentGroup = `${decodedMessage.timestamp}-${decodedMessage.nonce}`;
        message.fragmentGroup = fragmentGroup;

        // Track fragments for reassembly
        if (!fragmentGroups.has(fragmentGroup)) {
          fragmentGroups.set(fragmentGroup, []);
        }
        fragmentGroups.get(fragmentGroup).push({
          message: decodedMessage,
          storedMessage: message,
        });
      }

      // Add message to storage
      const isNew = addMessage(message);
      if (isNew) {
        newMessagesCount++;
      }
    } catch (error) {
      console.error("Error decoding memo as message:", error);
      continue;
    }
  }

  // Reassemble fragmented messages
  for (const [fragmentGroup, fragments] of fragmentGroups.entries()) {
    try {
      reassembleFragmentedMessage(fragmentGroup, fragments);
    } catch (error) {
      console.error(
        `Error reassembling fragment group ${fragmentGroup}:`,
        error
      );
    }
  }

  return newMessagesCount;
}

/**
 * Reassemble a fragmented message from its fragments.
 *
 * @param {string} fragmentGroup - The fragment group ID
 * @param {Array} fragments - Array of {message, storedMessage} objects
 */
function reassembleFragmentedMessage(fragmentGroup, fragments) {
  const wasmModule = getWasm();
  if (!wasmModule) {
    console.error("WASM module not loaded");
    return;
  }

  // Check if we have all fragments
  const firstFragment = fragments[0].message;
  const expectedFragments = firstFragment.fragment_info.total_fragments;

  if (fragments.length !== expectedFragments) {
    console.log(
      `Fragment group ${fragmentGroup}: have ${fragments.length}/${expectedFragments} fragments, waiting for more`
    );
    return;
  }

  // Sort fragments by index
  fragments.sort(
    (a, b) => a.message.fragment_info.index - b.message.fragment_info.index
  );

  // Reassemble the message
  const messages = fragments.map((f) => f.message);
  const reassembleResultJson = wasmModule.reassemble_message_fragments(
    JSON.stringify(messages)
  );
  const reassembleResult = JSON.parse(reassembleResultJson);

  if (!reassembleResult.success) {
    console.error("Failed to reassemble fragments:", reassembleResult.error);
    return;
  }

  // Create a single message with the reassembled content
  const firstStoredMessage = fragments[0].storedMessage;
  const reassembledMessage = {
    ...firstStoredMessage,
    id: `${fragmentGroup}-reassembled`,
    content: reassembleResult.content,
    fragmentGroup: fragmentGroup,
  };

  // Add the reassembled message
  addMessage(reassembledMessage);

  // Mark fragments as reassembled
  markFragmentsReassembled(fragmentGroup, reassembledMessage.id);

  console.log(
    `Successfully reassembled message from ${fragments.length} fragments`
  );
}

/**
 * Sync messages for the current wallet.
 *
 * This should be called after wallet sync to extract any new messages.
 *
 * @param {Array} notes - All notes for the wallet
 * @param {string} walletAddress - The wallet's unified address
 * @returns {number} Number of new messages extracted
 */
export function syncMessages(notes, walletAddress) {
  console.log("Syncing messages from notes...");
  const newMessages = extractMessagesFromNotes(notes, walletAddress);
  if (newMessages > 0) {
    console.log(`Found ${newMessages} new message(s)`);
  }
  return newMessages;
}

/**
 * Update pending messages to confirmed when their transactions are confirmed.
 *
 * @param {Array} messages - Pending messages to check
 * @param {Array} ledger - Transaction ledger
 * @returns {number} Number of messages updated
 */
export function updatePendingMessages(messages, ledger) {
  // TODO: Implement once we have better transaction confirmation tracking
  return 0;
}
