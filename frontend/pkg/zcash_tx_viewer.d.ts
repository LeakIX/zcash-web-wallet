/* tslint:disable */
/* eslint-disable */

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
 */
export function add_ledger_entry(ledger_json: string, entry_json: string): string;

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
 */
export function add_note_to_list(notes_json: string, note_json: string): string;

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
 */
export function add_wallet_to_list(wallets_json: string, wallet_json: string): string;

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
 */
export function calculate_balance(notes_json: string): string;

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
 */
export function compute_ledger_balance(ledger_json: string, wallet_id: string): string;

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
 */
export function create_ledger_entry(scan_result_json: string, wallet_id: string): string;

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
 */
export function create_stored_note(wallet_id: string, txid: string, pool: string, output_index: number, value: bigint, commitment: string | null | undefined, nullifier: string | null | undefined, memo: string | null | undefined, address: string | null | undefined, created_at: string): string;

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
 */
export function create_stored_wallet(wallet_result_json: string, alias: string, timestamp_ms: bigint): string;

/**
 * Decrypt a transaction using the provided viewing key
 */
export function decrypt_transaction(raw_tx_hex: string, viewing_key: string, network: string): string;

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
 */
export function delete_wallet_from_list(wallets_json: string, wallet_id: string): string;

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
 */
export function derive_transparent_addresses(seed_phrase: string, network_str: string, account_index: number, start_index: number, count: number): string;

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
 */
export function derive_unified_addresses(seed_phrase: string, network_str: string, account_index: number, start_index: number, count: number): string;

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
 */
export function export_ledger_csv(ledger_json: string, wallet_id: string): string;

/**
 * Generate a new wallet with a random seed phrase
 */
export function generate_wallet(network_str: string, account_index: number, address_index: number): string;

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
 */
export function get_all_wallets(wallets_json: string): string;

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
 */
export function get_ledger_for_wallet(ledger_json: string, wallet_id: string): string;

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
 */
export function get_notes_for_wallet(notes_json: string, wallet_id: string): string;

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
 */
export function get_transparent_utxos(notes_json: string, wallet_id: string): string;

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
 */
export function get_unspent_notes(notes_json: string): string;

/**
 * Get version information
 */
export function get_version(): string;

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
 */
export function get_wallet_by_id(wallets_json: string, wallet_id: string): string;

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
 */
export function mark_notes_spent(notes_json: string, nullifiers_json: string, spending_txid: string, spent_at_height?: number | null): string;

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
 */
export function mark_transparent_spent(notes_json: string, spends_json: string, spending_txid: string, spent_at_height?: number | null): string;

/**
 * Parse and validate a viewing key
 */
export function parse_viewing_key(key: string): string;

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
 */
export function render_balance_card(balance_zatoshis: bigint, wallet_alias?: string | null): string;

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
 */
export function render_empty_state(message: string, icon_class: string): string;

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
 */
export function render_ledger_table(entries_json: string, network: string): string;

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
 */
export function render_note_item(note_json: string): string;

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
 */
export function render_notes_table(notes_json: string): string;

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
 */
export function render_scanner_balance_card(balance_zatoshis: bigint, pool_balances_json: string): string;

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
 */
export function render_transaction_item(entry_json: string): string;

/**
 * Restore a wallet from an existing seed phrase
 */
export function restore_wallet(seed_phrase: string, network_str: string, account_index: number, address_index: number): string;

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
 */
export function scan_transaction(raw_tx_hex: string, viewing_key: string, network: string, height?: number | null): string;

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
 */
export function sign_transparent_transaction(seed_phrase: string, network_str: string, account_index: number, utxos_json: string, recipients_json: string, fee: bigint, expiry_height: number): string;

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
 */
export function validate_account_index(index: number): string;

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
 */
export function validate_address(address: string, network: string): string;

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
 */
export function validate_address_range(from_index: number, to_index: number, max_count: number): string;

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
 */
export function validate_seed_phrase(seed_phrase: string): string;

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
 */
export function validate_txid(txid: string): string;

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
 */
export function wallet_alias_exists(wallets_json: string, alias: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly add_ledger_entry: (a: number, b: number, c: number, d: number) => [number, number];
  readonly add_note_to_list: (a: number, b: number, c: number, d: number) => [number, number];
  readonly add_wallet_to_list: (a: number, b: number, c: number, d: number) => [number, number];
  readonly calculate_balance: (a: number, b: number) => [number, number];
  readonly compute_ledger_balance: (a: number, b: number, c: number, d: number) => [number, number];
  readonly create_ledger_entry: (a: number, b: number, c: number, d: number) => [number, number];
  readonly create_stored_note: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => [number, number];
  readonly create_stored_wallet: (a: number, b: number, c: number, d: number, e: bigint) => [number, number];
  readonly decrypt_transaction: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
  readonly delete_wallet_from_list: (a: number, b: number, c: number, d: number) => [number, number];
  readonly derive_transparent_addresses: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly derive_unified_addresses: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly export_ledger_csv: (a: number, b: number, c: number, d: number) => [number, number];
  readonly generate_wallet: (a: number, b: number, c: number, d: number) => [number, number];
  readonly get_all_wallets: (a: number, b: number) => [number, number];
  readonly get_ledger_for_wallet: (a: number, b: number, c: number, d: number) => [number, number];
  readonly get_notes_for_wallet: (a: number, b: number, c: number, d: number) => [number, number];
  readonly get_transparent_utxos: (a: number, b: number, c: number, d: number) => [number, number];
  readonly get_unspent_notes: (a: number, b: number) => [number, number];
  readonly get_version: () => [number, number];
  readonly get_wallet_by_id: (a: number, b: number, c: number, d: number) => [number, number];
  readonly mark_notes_spent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly mark_transparent_spent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly parse_viewing_key: (a: number, b: number) => [number, number];
  readonly render_balance_card: (a: bigint, b: number, c: number) => [number, number];
  readonly render_empty_state: (a: number, b: number, c: number, d: number) => [number, number];
  readonly render_ledger_table: (a: number, b: number, c: number, d: number) => [number, number];
  readonly render_note_item: (a: number, b: number) => [number, number];
  readonly render_notes_table: (a: number, b: number) => [number, number];
  readonly render_scanner_balance_card: (a: bigint, b: number, c: number) => [number, number];
  readonly render_transaction_item: (a: number, b: number) => [number, number];
  readonly restore_wallet: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
  readonly scan_transaction: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly sign_transparent_transaction: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: bigint, k: number) => [number, number];
  readonly validate_account_index: (a: number) => [number, number];
  readonly validate_address: (a: number, b: number, c: number, d: number) => [number, number];
  readonly validate_address_range: (a: number, b: number, c: number) => [number, number];
  readonly validate_seed_phrase: (a: number, b: number) => [number, number];
  readonly validate_txid: (a: number, b: number) => [number, number];
  readonly wallet_alias_exists: (a: number, b: number, c: number, d: number) => number;
  readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
