let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    }
}

let WASM_VECTOR_LEN = 0;

/**
 * Add or update a ledger entry in a collection.
 *
 * If an entry with the same wallet_id and txid exists, it will be updated.
 * Otherwise, a new entry will be added.
 *
 * # Arguments
 *
 * * `ledger_json` - JSON of the ledger collection (array of entries)
 * * `entry_json` - JSON of the LedgerEntry to add
 *
 * # Returns
 *
 * JSON containing the updated ledger and whether the entry was new.
 * @param {string} ledger_json
 * @param {string} entry_json
 * @returns {string}
 */
export function add_ledger_entry(ledger_json, entry_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ledger_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(entry_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.add_ledger_entry(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Add or update a note in the notes list.
 *
 * If a note with the same ID already exists, it will be updated.
 * Otherwise, the note will be added.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of existing StoredNotes
 * * `note_json` - JSON of the StoredNote to add/update
 *
 * # Returns
 *
 * JSON containing the updated notes array and whether a new note was added.
 * @param {string} notes_json
 * @param {string} note_json
 * @returns {string}
 */
export function add_note_to_list(notes_json, note_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(note_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.add_note_to_list(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Add a wallet to the wallets list.
 *
 * Checks for duplicate aliases (case-insensitive) before adding.
 *
 * # Arguments
 *
 * * `wallets_json` - JSON array of existing StoredWallets
 * * `wallet_json` - JSON of the StoredWallet to add
 *
 * # Returns
 *
 * JSON containing the updated wallets array or an error if alias exists.
 * @param {string} wallets_json
 * @param {string} wallet_json
 * @returns {string}
 */
export function add_wallet_to_list(wallets_json, wallet_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wallets_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.add_wallet_to_list(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Calculate the balance from a list of notes.
 *
 * Returns the total balance and balance broken down by pool.
 * Only counts unspent notes with positive value.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 *
 * # Returns
 *
 * JSON containing total balance and balance by pool.
 * @param {string} notes_json
 * @returns {string}
 */
export function calculate_balance(notes_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.calculate_balance(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Compute balance from ledger entries.
 *
 * Sums the net_change of all entries for the wallet.
 *
 * # Arguments
 *
 * * `ledger_json` - JSON of the ledger collection
 * * `wallet_id` - The wallet ID to compute balance for
 *
 * # Returns
 *
 * JSON containing the balance (can be negative if outgoing exceeds incoming).
 * @param {string} ledger_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function compute_ledger_balance(ledger_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ledger_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.compute_ledger_balance(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Create a ledger entry from a scan result.
 *
 * Takes the scan result, wallet ID, and information about which notes were
 * received and spent, and creates a LedgerEntry for the transaction.
 *
 * # Arguments
 *
 * * `scan_result_json` - JSON of ScanResult from scanning a transaction
 * * `wallet_id` - The wallet ID this entry belongs to
 * * `received_note_ids_json` - JSON array of note IDs that were received
 * * `spent_note_ids_json` - JSON array of note IDs that were spent
 * * `spent_values_json` - JSON array of values (u64) for spent notes
 * * `timestamp` - ISO 8601 timestamp for created_at/updated_at
 *
 * # Returns
 *
 * JSON containing the created LedgerEntry or an error.
 * @param {string} scan_result_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function create_ledger_entry(scan_result_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(scan_result_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.create_ledger_entry(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Create a new stored note from individual parameters.
 *
 * This is useful when converting scan results to stored notes.
 *
 * # Arguments
 *
 * * `wallet_id` - The wallet ID this note belongs to
 * * `txid` - Transaction ID where the note was received
 * * `pool` - Pool type ("orchard", "sapling", or "transparent")
 * * `output_index` - Output index within the transaction
 * * `value` - Value in zatoshis
 * * `commitment` - Note commitment (optional, for shielded notes)
 * * `nullifier` - Nullifier (optional, for shielded notes)
 * * `memo` - Memo field (optional)
 * * `address` - Recipient address (optional)
 * * `created_at` - ISO 8601 timestamp
 *
 * # Returns
 *
 * JSON string containing the StoredNote or an error.
 * @param {string} wallet_id
 * @param {string} txid
 * @param {string} pool
 * @param {number} output_index
 * @param {bigint} value
 * @param {string | null | undefined} commitment
 * @param {string | null | undefined} nullifier
 * @param {string | null | undefined} memo
 * @param {string | null | undefined} address
 * @param {string} created_at
 * @returns {string}
 */
export function create_stored_note(wallet_id, txid, pool, output_index, value, commitment, nullifier, memo, address, created_at) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(pool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        var ptr3 = isLikeNone(commitment) ? 0 : passStringToWasm0(commitment, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(nullifier) ? 0 : passStringToWasm0(nullifier, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len4 = WASM_VECTOR_LEN;
        var ptr5 = isLikeNone(memo) ? 0 : passStringToWasm0(memo, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len5 = WASM_VECTOR_LEN;
        var ptr6 = isLikeNone(address) ? 0 : passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(created_at, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.create_stored_note(ptr0, len0, ptr1, len1, ptr2, len2, output_index, value, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7);
        deferred9_0 = ret[0];
        deferred9_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

/**
 * Create a new stored wallet from a WalletResult.
 *
 * Generates a unique ID and timestamp, and creates a StoredWallet
 * ready for persistence.
 *
 * # Arguments
 *
 * * `wallet_result_json` - JSON of WalletResult from generate/restore
 * * `alias` - User-friendly name for the wallet
 * * `timestamp_ms` - Current timestamp in milliseconds (from JavaScript Date.now())
 *
 * # Returns
 *
 * JSON string containing the StoredWallet or an error.
 * @param {string} wallet_result_json
 * @param {string} alias
 * @param {bigint} timestamp_ms
 * @returns {string}
 */
export function create_stored_wallet(wallet_result_json, alias, timestamp_ms) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wallet_result_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(alias, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.create_stored_wallet(ptr0, len0, ptr1, len1, timestamp_ms);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Decrypt a transaction using the provided viewing key
 * @param {string} raw_tx_hex
 * @param {string} viewing_key
 * @param {string} network
 * @returns {string}
 */
export function decrypt_transaction(raw_tx_hex, viewing_key, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(raw_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(viewing_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.decrypt_transaction(ptr0, len0, ptr1, len1, ptr2, len2);
        deferred4_0 = ret[0];
        deferred4_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Delete a wallet from the wallets list by ID.
 *
 * # Arguments
 *
 * * `wallets_json` - JSON array of StoredWallets
 * * `wallet_id` - The ID of the wallet to delete
 *
 * # Returns
 *
 * JSON containing the updated wallets array.
 * @param {string} wallets_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function delete_wallet_from_list(wallets_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wallets_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.delete_wallet_from_list(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive multiple transparent addresses from a seed phrase.
 *
 * This is useful for scanning transactions - we need to check if transparent
 * outputs belong to any of our derived addresses.
 *
 * # Arguments
 *
 * * `seed_phrase` - A valid 24-word BIP39 mnemonic
 * * `network` - The network ("mainnet" or "testnet")
 * * `account_index` - The account index (BIP32 level 3)
 * * `start_index` - The starting address index
 * * `count` - Number of addresses to derive
 *
 * # Returns
 *
 * JSON string containing an array of transparent addresses.
 * @param {string} seed_phrase
 * @param {string} network_str
 * @param {number} account_index
 * @param {number} start_index
 * @param {number} count
 * @returns {string}
 */
export function derive_transparent_addresses(seed_phrase, network_str, account_index, start_index, count) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.derive_transparent_addresses(ptr0, len0, ptr1, len1, account_index, start_index, count);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive multiple unified addresses from a seed phrase.
 *
 * This is useful for scanning transactions and verifying receiving addresses.
 *
 * # Arguments
 *
 * * `seed_phrase` - A valid 24-word BIP39 mnemonic
 * * `network` - The network ("mainnet" or "testnet")
 * * `account_index` - The account index (BIP32 level 3)
 * * `start_index` - The starting address/diversifier index
 * * `count` - Number of addresses to derive
 *
 * # Returns
 *
 * JSON string containing an array of unified addresses.
 * @param {string} seed_phrase
 * @param {string} network_str
 * @param {number} account_index
 * @param {number} start_index
 * @param {number} count
 * @returns {string}
 */
export function derive_unified_addresses(seed_phrase, network_str, account_index, start_index, count) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.derive_unified_addresses(ptr0, len0, ptr1, len1, account_index, start_index, count);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Export ledger entries as CSV for tax reporting.
 *
 * # Arguments
 *
 * * `ledger_json` - JSON of the ledger collection
 * * `wallet_id` - The wallet ID to export
 *
 * # Returns
 *
 * JSON containing the CSV string or an error.
 * @param {string} ledger_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function export_ledger_csv(ledger_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ledger_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.export_ledger_csv(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate a new wallet with a random seed phrase
 * @param {string} network_str
 * @param {number} account_index
 * @param {number} address_index
 * @returns {string}
 */
export function generate_wallet(network_str, account_index, address_index) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(network_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.generate_wallet(ptr0, len0, account_index, address_index);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Get all wallets from the collection.
 *
 * Useful for listing wallets in the UI.
 *
 * # Arguments
 *
 * * `wallets_json` - JSON array of StoredWallets
 *
 * # Returns
 *
 * JSON containing the wallets array.
 * @param {string} wallets_json
 * @returns {string}
 */
export function get_all_wallets(wallets_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(wallets_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.get_all_wallets(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Get ledger entries for a specific wallet.
 *
 * Returns entries sorted by block_height descending (newest first).
 *
 * # Arguments
 *
 * * `ledger_json` - JSON of the ledger collection
 * * `wallet_id` - The wallet ID to filter by
 *
 * # Returns
 *
 * JSON containing the filtered entries.
 * @param {string} ledger_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function get_ledger_for_wallet(ledger_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(ledger_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.get_ledger_for_wallet(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get notes for a specific wallet.
 *
 * Filters the notes list to only include notes belonging to the specified wallet.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 * * `wallet_id` - The wallet ID to filter by
 *
 * # Returns
 *
 * JSON array of StoredNotes belonging to the wallet.
 * @param {string} notes_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function get_notes_for_wallet(notes_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.get_notes_for_wallet(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get unspent transparent UTXOs from stored notes.
 *
 * Filters stored notes to find transparent outputs that haven't been spent
 * and can be used as transaction inputs.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 *
 * # Returns
 *
 * JSON array of UTXOs suitable for `sign_transparent_transaction`
 * @param {string} notes_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function get_transparent_utxos(notes_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.get_transparent_utxos(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get all unspent notes with positive value.
 *
 * Filters the notes list to only include notes that haven't been spent
 * and have a value greater than zero.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 *
 * # Returns
 *
 * JSON array of unspent StoredNotes.
 * @param {string} notes_json
 * @returns {string}
 */
export function get_unspent_notes(notes_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.get_unspent_notes(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Get version information
 * @returns {string}
 */
export function get_version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.get_version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Get a wallet by ID.
 *
 * # Arguments
 *
 * * `wallets_json` - JSON array of StoredWallets
 * * `wallet_id` - The ID of the wallet to find
 *
 * # Returns
 *
 * JSON containing the wallet if found, or an error.
 * @param {string} wallets_json
 * @param {string} wallet_id
 * @returns {string}
 */
export function get_wallet_by_id(wallets_json, wallet_id) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(wallets_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(wallet_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.get_wallet_by_id(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Mark notes as spent by matching nullifiers.
 *
 * Finds notes with matching nullifiers and sets their spent_txid.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 * * `nullifiers_json` - JSON array of SpentNullifier objects
 * * `spending_txid` - Transaction ID where the notes were spent
 * * `spent_at_height` - Optional block height where the spend occurred
 *
 * # Returns
 *
 * JSON containing the updated notes array and count of marked notes.
 * @param {string} notes_json
 * @param {string} nullifiers_json
 * @param {string} spending_txid
 * @param {number | null} [spent_at_height]
 * @returns {string}
 */
export function mark_notes_spent(notes_json, nullifiers_json, spending_txid, spent_at_height) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nullifiers_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(spending_txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.mark_notes_spent(ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(spent_at_height) ? 0x100000001 : (spent_at_height) >>> 0);
        deferred4_0 = ret[0];
        deferred4_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Mark transparent notes as spent by matching prevout references.
 *
 * Finds transparent notes matching txid:output_index and sets their spent_txid.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNotes
 * * `spends_json` - JSON array of TransparentSpend objects
 * * `spending_txid` - Transaction ID where the notes were spent
 * * `spent_at_height` - Optional block height where the spend occurred
 *
 * # Returns
 *
 * JSON containing the updated notes array and count of marked notes.
 * @param {string} notes_json
 * @param {string} spends_json
 * @param {string} spending_txid
 * @param {number | null} [spent_at_height]
 * @returns {string}
 */
export function mark_transparent_spent(notes_json, spends_json, spending_txid, spent_at_height) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(spends_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(spending_txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.mark_transparent_spent(ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(spent_at_height) ? 0x100000001 : (spent_at_height) >>> 0);
        deferred4_0 = ret[0];
        deferred4_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Parse and validate a viewing key
 * @param {string} key
 * @returns {string}
 */
export function parse_viewing_key(key) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.parse_viewing_key(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for a balance display card.
 *
 * Creates a Bootstrap card component showing the wallet balance.
 *
 * # Arguments
 *
 * * `balance_zatoshis` - The balance in zatoshis (1 ZEC = 100,000,000 zatoshis)
 * * `wallet_alias` - Optional wallet name to display
 *
 * # Returns
 *
 * HTML string for the balance card.
 * @param {bigint} balance_zatoshis
 * @param {string | null} [wallet_alias]
 * @returns {string}
 */
export function render_balance_card(balance_zatoshis, wallet_alias) {
    let deferred2_0;
    let deferred2_1;
    try {
        var ptr0 = isLikeNone(wallet_alias) ? 0 : passStringToWasm0(wallet_alias, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_balance_card(balance_zatoshis, ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for a broadcast result alert.
 *
 * Creates a Bootstrap alert for displaying broadcast results.
 *
 * # Arguments
 *
 * * `message` - The message to display
 * * `alert_type` - Bootstrap alert type ("success", "danger", "warning", "info")
 *
 * # Returns
 *
 * HTML string for the alert.
 * @param {string} message
 * @param {string} alert_type
 * @returns {string}
 */
export function render_broadcast_result(message, alert_type) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(alert_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_broadcast_result(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for an empty state message.
 *
 * Creates a centered message for empty lists.
 *
 * # Arguments
 *
 * * `message` - The message to display
 * * `icon_class` - Bootstrap icon class (e.g., "bi-inbox")
 *
 * # Returns
 *
 * HTML string for the empty state.
 * @param {string} message
 * @param {string} icon_class
 * @returns {string}
 */
export function render_empty_state(message, icon_class) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(icon_class, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_empty_state(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for the ledger/transaction history table in the scanner view.
 *
 * Creates a responsive table showing transaction history with date, txid, amounts, and pool.
 *
 * # Arguments
 *
 * * `entries_json` - JSON array of LedgerEntry objects
 * * `network` - Network name ("mainnet" or "testnet") for explorer links
 *
 * # Returns
 *
 * HTML string for the complete ledger table.
 * @param {string} entries_json
 * @param {string} network
 * @returns {string}
 */
export function render_ledger_table(entries_json, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(entries_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_ledger_table(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for a note/UTXO list item.
 *
 * Creates a list group item showing note details.
 *
 * # Arguments
 *
 * * `note_json` - JSON of StoredNote
 *
 * # Returns
 *
 * HTML string for the note list item.
 * @param {string} note_json
 * @returns {string}
 */
export function render_note_item(note_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(note_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_note_item(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for the notes table in the scanner view.
 *
 * Creates a responsive table showing all tracked notes with pool, value, memo, and status.
 *
 * # Arguments
 *
 * * `notes_json` - JSON array of StoredNote objects
 *
 * # Returns
 *
 * HTML string for the complete notes table.
 * @param {string} notes_json
 * @returns {string}
 */
export function render_notes_table(notes_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(notes_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_notes_table(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for Orchard actions in the decrypt viewer.
 *
 * # Arguments
 *
 * * `actions_json` - JSON array of DecryptedOrchardAction objects
 *
 * # Returns
 *
 * HTML string for the Orchard actions section.
 * @param {string} actions_json
 * @returns {string}
 */
export function render_orchard_actions(actions_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(actions_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_orchard_actions(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for Sapling outputs in the decrypt viewer.
 *
 * # Arguments
 *
 * * `outputs_json` - JSON array of DecryptedSaplingOutput objects
 *
 * # Returns
 *
 * HTML string for the Sapling outputs section.
 * @param {string} outputs_json
 * @returns {string}
 */
export function render_sapling_outputs(outputs_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(outputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_sapling_outputs(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for the scanner balance card with pool breakdown.
 *
 * Creates a card showing total balance and breakdown by pool (Orchard, Sapling, Transparent).
 *
 * # Arguments
 *
 * * `balance_zatoshis` - The total balance in zatoshis
 * * `pool_balances_json` - JSON object with pool balances: {"orchard": u64, "sapling": u64, "transparent": u64}
 *
 * # Returns
 *
 * HTML string for the balance card with pool breakdown.
 * @param {bigint} balance_zatoshis
 * @param {string} pool_balances_json
 * @returns {string}
 */
export function render_scanner_balance_card(balance_zatoshis, pool_balances_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(pool_balances_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_scanner_balance_card(balance_zatoshis, ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for the send UTXOs table.
 *
 * Creates a table displaying available transparent UTXOs for sending.
 *
 * # Arguments
 *
 * * `utxos_json` - JSON array of StoredNote objects (filtered to transparent)
 * * `network` - Network name ("mainnet" or "testnet") for explorer links
 *
 * # Returns
 *
 * HTML string for the UTXOs table.
 * @param {string} utxos_json
 * @param {string} network
 * @returns {string}
 */
export function render_send_utxos_table(utxos_json, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_send_utxos_table(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for the simple view transaction list.
 *
 * Creates a list of transaction items for the Simple view with icons, dates,
 * explorer links, and amounts.
 *
 * # Arguments
 *
 * * `entries_json` - JSON array of LedgerEntry objects
 * * `network` - Network name ("mainnet" or "testnet") for explorer links
 *
 * # Returns
 *
 * HTML string for the transaction list items.
 * @param {string} entries_json
 * @param {string} network
 * @returns {string}
 */
export function render_simple_transaction_list(entries_json, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(entries_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_simple_transaction_list(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for a success alert with explorer link.
 *
 * Creates a dismissible Bootstrap alert for successful transactions.
 *
 * # Arguments
 *
 * * `txid` - The transaction ID
 * * `network` - Network name ("mainnet" or "testnet") for explorer links
 *
 * # Returns
 *
 * HTML string for the success alert.
 * @param {string} txid
 * @param {string} network
 * @returns {string}
 */
export function render_success_alert(txid, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.render_success_alert(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate HTML for a transaction list item.
 *
 * Creates a list group item showing transaction details from a ledger entry.
 *
 * # Arguments
 *
 * * `entry_json` - JSON of LedgerEntry
 *
 * # Returns
 *
 * HTML string for the transaction list item.
 * @param {string} entry_json
 * @returns {string}
 */
export function render_transaction_item(entry_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(entry_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_transaction_item(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for transparent inputs in the decrypt viewer.
 *
 * # Arguments
 *
 * * `inputs_json` - JSON array of TransparentInput objects
 *
 * # Returns
 *
 * HTML string for the inputs section, or empty string if no inputs.
 * @param {string} inputs_json
 * @returns {string}
 */
export function render_transparent_inputs(inputs_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(inputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_transparent_inputs(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate HTML for transparent outputs in the decrypt viewer.
 *
 * # Arguments
 *
 * * `outputs_json` - JSON array of TransparentOutput objects
 *
 * # Returns
 *
 * HTML string for the outputs section, or empty string if no outputs.
 * @param {string} outputs_json
 * @returns {string}
 */
export function render_transparent_outputs(outputs_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(outputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.render_transparent_outputs(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Restore a wallet from an existing seed phrase
 * @param {string} seed_phrase
 * @param {string} network_str
 * @param {number} account_index
 * @param {number} address_index
 * @returns {string}
 */
export function restore_wallet(seed_phrase, network_str, account_index, address_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.restore_wallet(ptr0, len0, ptr1, len1, account_index, address_index);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Scan a transaction for notes belonging to a viewing key.
 *
 * Performs trial decryption on all shielded outputs to find notes
 * addressed to the viewing key. Also extracts nullifiers to track
 * spent notes.
 *
 * # Arguments
 *
 * * `raw_tx_hex` - The raw transaction as a hexadecimal string
 * * `viewing_key` - The viewing key (UFVK, UIVK, or legacy Sapling)
 * * `network` - The network ("mainnet" or "testnet")
 * * `height` - Optional block height (needed for full Sapling decryption)
 *
 * # Returns
 *
 * JSON string containing a `ScanTransactionResult` with found notes,
 * spent nullifiers, and transparent outputs.
 * @param {string} raw_tx_hex
 * @param {string} viewing_key
 * @param {string} network
 * @param {number | null} [height]
 * @returns {string}
 */
export function scan_transaction(raw_tx_hex, viewing_key, network, height) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(raw_tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(viewing_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.scan_transaction(ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(height) ? 0x100000001 : (height) >>> 0);
        deferred4_0 = ret[0];
        deferred4_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Sign a transparent transaction.
 *
 * Builds and signs a v5 transaction spending transparent UTXOs. The transaction
 * can be broadcast via any Zcash node RPC.
 *
 * # Arguments
 *
 * * `seed_phrase` - The wallet's 24-word BIP39 seed phrase
 * * `network` - The network ("mainnet" or "testnet")
 * * `account_index` - The account index (BIP32 level 3)
 * * `utxos_json` - JSON array of UTXOs to spend: `[{txid, vout, value, address}]`
 * * `recipients_json` - JSON array of recipients: `[{address, amount}]`
 * * `fee` - Transaction fee in zatoshis
 * * `expiry_height` - Block height after which tx expires (0 for no expiry)
 *
 * # Returns
 *
 * JSON with `{success, tx_hex, txid, total_input, total_output, fee, error}`
 *
 * # Example
 *
 * ```javascript
 * const utxos = JSON.stringify([{
 *   txid: "abc123...",
 *   vout: 0,
 *   value: 100000,
 *   address: "t1..."
 * }]);
 * const recipients = JSON.stringify([{
 *   address: "t1...",
 *   amount: 50000
 * }]);
 * const result = JSON.parse(sign_transparent_transaction(
 *   seedPhrase, "testnet", 0, utxos, recipients, 1000, 0
 * ));
 * if (result.success) {
 *   console.log("Signed tx:", result.tx_hex);
 * }
 * ```
 * @param {string} seed_phrase
 * @param {string} network_str
 * @param {number} account_index
 * @param {string} utxos_json
 * @param {string} recipients_json
 * @param {bigint} fee
 * @param {number} expiry_height
 * @returns {string}
 */
export function sign_transparent_transaction(seed_phrase, network_str, account_index, utxos_json, recipients_json, fee, expiry_height) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(utxos_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(recipients_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.sign_transparent_transaction(ptr0, len0, ptr1, len1, account_index, ptr2, len2, ptr3, len3, fee, expiry_height);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Validate an account index.
 *
 * Account indices must be less than 2^31 (hardened derivation limit).
 *
 * # Arguments
 *
 * * `index` - The account index to validate
 *
 * # Returns
 *
 * JSON with `{valid: bool, error?: string}`
 * @param {number} index
 * @returns {string}
 */
export function validate_account_index(index) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.validate_account_index(index);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Validate a Zcash address.
 *
 * Supports transparent (t-addr), Sapling (zs), and unified addresses (u).
 *
 * # Arguments
 *
 * * `address` - The address to validate
 * * `network` - The network ("mainnet" or "testnet")
 *
 * # Returns
 *
 * JSON with `{valid: bool, address_type?: string, error?: string}`
 * @param {string} address
 * @param {string} network
 * @returns {string}
 */
export function validate_address(address, network) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.validate_address(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Validate an address derivation range.
 *
 * Checks that from <= to and the count doesn't exceed the maximum.
 *
 * # Arguments
 *
 * * `from_index` - Starting index
 * * `to_index` - Ending index (inclusive)
 * * `max_count` - Maximum allowed count
 *
 * # Returns
 *
 * JSON with `{valid: bool, count?: u32, error?: string}`
 * @param {number} from_index
 * @param {number} to_index
 * @param {number} max_count
 * @returns {string}
 */
export function validate_address_range(from_index, to_index, max_count) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.validate_address_range(from_index, to_index, max_count);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Validate a BIP39 seed phrase.
 *
 * Checks word count and basic format. Valid phrases have 12, 15, 18, 21, or 24 words.
 *
 * # Arguments
 *
 * * `seed_phrase` - The seed phrase to validate
 *
 * # Returns
 *
 * JSON with `{valid: bool, word_count?: u8, error?: string}`
 * @param {string} seed_phrase
 * @returns {string}
 */
export function validate_seed_phrase(seed_phrase) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(seed_phrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validate_seed_phrase(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Validate a transaction ID (txid).
 *
 * A valid txid is a 64-character hexadecimal string.
 *
 * # Arguments
 *
 * * `txid` - The transaction ID to validate
 *
 * # Returns
 *
 * JSON with `{valid: bool, error?: string}`
 * @param {string} txid
 * @returns {string}
 */
export function validate_txid(txid) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.validate_txid(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Check if a wallet alias already exists (case-insensitive).
 *
 * # Arguments
 *
 * * `wallets_json` - JSON array of StoredWallets
 * * `alias` - The alias to check
 *
 * # Returns
 *
 * `true` if the alias exists, `false` otherwise.
 * @param {string} wallets_json
 * @param {string} alias
 * @returns {boolean}
 */
export function wallet_alias_exists(wallets_json, alias) {
    const ptr0 = passStringToWasm0(wallets_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(alias, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.wallet_alias_exists(ptr0, len0, ptr1, len1);
    return ret !== 0;
}

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg___wbindgen_is_function_8d400b8b1af978cd = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbg___wbindgen_is_object_ce774f3490692386 = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg___wbindgen_is_string_704ef9c8fc131030 = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbg___wbindgen_is_undefined_f6b95eab589e0269 = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbg___wbindgen_string_get_a2a31e16edf96e42 = function(arg0, arg1) {
        const obj = arg1;
        const ret = typeof(obj) === 'string' ? obj : undefined;
        var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg___wbindgen_throw_dd24417ed36fc46e = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbg_call_3020136f7a2d6e44 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_abb4ff46ce38be40 = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_length_22ac23eaec9d8053 = function(arg0) {
        const ret = arg0.length;
        return ret;
    };
    imports.wbg.__wbg_log_1d990106d99dacb7 = function(arg0) {
        console.log(arg0);
    };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new_0_23cedd11d9b40c9d = function() {
        const ret = new Date();
        return ret;
    };
    imports.wbg.__wbg_new_no_args_cb138f77cf6151ee = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_new_with_length_aa5eaf41d35235e5 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_prototypesetcall_dfe9b766cdc1f1fd = function(arg0, arg1, arg2) {
        Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_static_accessor_GLOBAL_769e6b65d6557335 = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_60cf02db4de8e1c1 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_08f5a74c69739274 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_a8924b26aa92d024 = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_subarray_845f2f5bce7d061a = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_toISOString_eca15cbe422eeea5 = function(arg0) {
        const ret = arg0.toISOString();
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
        // Cast intrinsic for `Ref(String) -> Externref`.
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_cast_cb9088102bce6b30 = function(arg0, arg1) {
        // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
        const ret = getArrayU8FromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_externrefs;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
    };

    return imports;
}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('zcash_tx_viewer_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
