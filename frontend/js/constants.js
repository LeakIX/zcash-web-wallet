// Zcash Web Wallet - Constants

// LocalStorage keys
export const STORAGE_KEYS = {
  endpoints: "zcash_viewer_endpoints",
  selectedEndpoint: "zcash_viewer_selected_endpoint",
  notes: "zcash_viewer_notes",
  scanViewingKey: "zcash_viewer_scan_viewing_key",
  wallets: "zcash_viewer_wallets",
  selectedWallet: "zcash_viewer_selected_wallet",
  ledger: "zcash_viewer_ledger",
  viewMode: "zcash_viewer_view_mode",
  theme: "zcash_viewer_theme",
  contacts: "zcash_viewer_contacts",
};

// View modes: simple, accountant, admin
export const VIEW_MODES = {
  simple: "simple",
  accountant: "accountant",
  admin: "admin",
};

// Default RPC endpoints (users can add their own)
export const DEFAULT_ENDPOINTS = [
  {
    name: "Tatum - mainnet (rate limited)",
    url: "https://zcash-mainnet.gateway.tatum.io/",
    network: "mainnet",
  },
  {
    name: "Tatum - testnet (rate limited)",
    url: "https://zcash-testnet.gateway.tatum.io/",
    network: "testnet",
  },
  {
    name: "Local Node (mainnet)",
    url: "http://127.0.0.1:8232",
    network: "mainnet",
  },
  {
    name: "Local Node (testnet)",
    url: "http://127.0.0.1:18232",
    network: "testnet",
  },
];

// Number of transparent addresses to derive
export const TRANSPARENT_ADDRESS_COUNT = 100;
