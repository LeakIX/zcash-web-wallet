# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## CHANGELOG

## [0.3.0]

### Added

- Add Playwright E2E tests for frontend with CI integration on ubuntu and macOS
- Integrate external html-builder library for type-safe HTML generation in Rust
  ([#162](https://github.com/LeakIX/zcash-web-wallet/pull/162))
  - Add render functions for balance cards, notes, transactions, and empty
    states
  - First step toward moving DOM manipulation from JavaScript to Rust/WASM
- Add mobile responsive testing with Playwright
  ([#176](https://github.com/LeakIX/zcash-web-wallet/issues/176),
  [#179](https://github.com/LeakIX/zcash-web-wallet/pull/179))
  - Add mobile device profiles (Pixel 5, iPhone 12)
  - Run E2E tests on desktop, mobile Chrome, and mobile Safari in CI
- Add MIT LICENSE file
  ([#181](https://github.com/LeakIX/zcash-web-wallet/issues/181),
  [#183](https://github.com/LeakIX/zcash-web-wallet/pull/183))
- Add repository field to Cargo.toml
  ([#182](https://github.com/LeakIX/zcash-web-wallet/issues/182),
  [#185](https://github.com/LeakIX/zcash-web-wallet/pull/185))
- Add transaction scanning E2E tests with real transaction fixtures
  ([#178](https://github.com/LeakIX/zcash-web-wallet/issues/178),
  [#186](https://github.com/LeakIX/zcash-web-wallet/pull/186))
- Add contact address book for managing frequently used addresses
  ([#195](https://github.com/LeakIX/zcash-web-wallet/issues/195))
  - Save contacts with name, address, network, and notes
  - Address validation when adding/editing contacts
  - Autocomplete in send address fields (simple and admin views)
  - Import/export contacts as JSON or CSV
  - Add render_contacts_list(), render_contacts_dropdown() WASM functions

### Changed

- Optimize CI: E2E tests use committed artifacts instead of rebuilding
  ([#180](https://github.com/LeakIX/zcash-web-wallet/issues/180),
  [#184](https://github.com/LeakIX/zcash-web-wallet/pull/184))
- Migrate scanner.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#187](https://github.com/LeakIX/zcash-web-wallet/pull/187))
  - Add render_scanner_balance_card(), render_notes_table(),
    render_ledger_table() WASM functions
  - Reduce scanner.js by ~180 lines
- Migrate views.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#188](https://github.com/LeakIX/zcash-web-wallet/pull/188))
  - Add render_simple_transaction_list(), render_success_alert() WASM functions
  - Reduce views.js by ~50 lines
- Migrate decrypt-viewer.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#189](https://github.com/LeakIX/zcash-web-wallet/pull/189))
  - Add render_transparent_inputs(), render_transparent_outputs(),
    render_sapling_outputs(), render_orchard_actions() WASM functions
  - Reduce decrypt-viewer.js by ~75 lines
- Migrate send.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#191](https://github.com/LeakIX/zcash-web-wallet/pull/191))
  - Add render_send_utxos_table(), render_broadcast_result() WASM functions
  - Reduce send.js by ~45 lines
- Migrate addresses.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#192](https://github.com/LeakIX/zcash-web-wallet/pull/192))
  - Add render_derived_addresses_table(), render_dismissible_alert() WASM
    functions
  - Reduce addresses.js by ~95 lines
- Migrate wallet.js DOM manipulation to Rust/WASM
  ([#163](https://github.com/LeakIX/zcash-web-wallet/issues/163),
  [#193](https://github.com/LeakIX/zcash-web-wallet/pull/193))
  - Add render_saved_wallets_list() WASM function
  - Reduce wallet.js by ~40 lines
- Remove unused utility functions from utils.js
  ([#164](https://github.com/LeakIX/zcash-web-wallet/issues/164))
  - Functions now handled by WASM: formatZatoshi, escapeHtml, truncateAddress,
    truncateMiddle, renderTxidLink, renderAddressLink, explorer URL helpers
  - Reduce utils.js by ~80 lines
- Skip E2E tests when on WebKit as it requires permissions
  ([#203](https://github.com/LeakIX/zcash-web-wallet/pull/203/))

## 0.2.0 - 20260101

### Added

- Show both unified and transparent addresses in Simple view Receive dialog
  ([#113](https://github.com/LeakIX/zcash-web-wallet/issues/113),
  [#114](https://github.com/LeakIX/zcash-web-wallet/pull/114))
- Add code coverage with cargo-llvm-cov and Codecov integration
  ([#22](https://github.com/LeakIX/zcash-web-wallet/issues/22),
  [#116](https://github.com/LeakIX/zcash-web-wallet/pull/116))
- Pin Rust nightly version for reproducible builds with weekly auto-update CI
  ([#129](https://github.com/LeakIX/zcash-web-wallet/issues/129))
- Add integrity verification status indicator in footer
  ([#127](https://github.com/LeakIX/zcash-web-wallet/pull/127))
- Integrity verification modal now allows verifying against a specific commit,
  branch, or tag ([#144](https://github.com/LeakIX/zcash-web-wallet/pull/144))
- Add release process documentation
  ([#158](https://github.com/LeakIX/zcash-web-wallet/pull/158))

### Changed

- Consolidate `pages-build` CI job into deploy workflow
  ([#152](https://github.com/LeakIX/zcash-web-wallet/pull/152))
- Update Rust nightly to `nightly-2025-12-31`
  ([#138](https://github.com/LeakIX/zcash-web-wallet/pull/138))
- Require GNU sed on macOS for Makefile targets (`brew install gnu-sed`)
- CI now uses git-based check to verify generated files are committed separately
  ([#130](https://github.com/LeakIX/zcash-web-wallet/pull/130))
- WASM and CSS artifacts are now tracked in git; CI/deploy uses committed files
  instead of rebuilding
  ([#144](https://github.com/LeakIX/zcash-web-wallet/pull/144))
- Split generated files CI check into separate jobs for WASM, CSS, checksums,
  and changelog ([#144](https://github.com/LeakIX/zcash-web-wallet/pull/144))
- Commit hash must be injected with `make inject-commit` before merging to main
  ([#146](https://github.com/LeakIX/zcash-web-wallet/pull/146))
- CI enforces `__COMMIT_HASH__` placeholder on develop, injection on main PRs
  ([#148](https://github.com/LeakIX/zcash-web-wallet/pull/148))
- CI should not run code coverage on main
  ([#150](https://github.com/LeakIX/zcash-web-wallet/pull/150))
- Deploy workflow verifies checksums before publishing to GitHub Pages
  ([#151](https://github.com/LeakIX/zcash-web-wallet/pull/151))
- Makefile: remove inject-commit target
  ([#157](https://github.com/LeakIX/zcash-web-wallet/pull/157))

## [0.1.0] - 2025-12-30

### Added

- **Simple View**: New default view with clean interface for everyday users
  - Balance display with Mainnet/Testnet indicator
  - Receive functionality with address copy
  - Send transparent transactions
  - Recent transactions with timestamps and explorer links
- **Wallet Management**
  - Generate new wallets (24-word BIP39 seed phrases)
  - Restore existing wallets from seed phrase
  - Support for both Mainnet and Testnet
  - Multiple wallet support
- **Transaction Scanning**
  - Scan transactions using viewing keys
  - Decrypt shielded outputs (Sapling & Orchard)
  - Track notes with spent/unspent status
  - Balance breakdown by pool (Transparent, Sapling, Orchard)
- **Address Derivation**
  - Derive transparent addresses (t1/tm)
  - Derive unified addresses (u1/utest1)
  - Duplicate address detection (Sapling diversifier behavior)
  - Save addresses to wallet for scanning
  - Export as CSV
- **Accountant View**
  - Transaction ledger with running balance
  - Export to CSV for tax reporting
- **Admin View**: Full-featured interface for power users
- **Dark/Light mode** with system preference detection
- **Mobile-friendly interface** with responsive design
- **Multiple RPC endpoint support**
- **Transaction broadcast capability**
- **Disclaimer modal** in footer

### Technical

- 100% client-side - no backend server
- Official Zcash Rust libraries compiled to WebAssembly
- Modular ES6 JavaScript architecture
- Bootstrap 5 + Sass styling
- GitHub Pages deployment

[0.1.0]: https://github.com/LeakIX/zcash-web-wallet/releases/tag/v0.1.0
