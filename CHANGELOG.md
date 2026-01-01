# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed

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

## [Unreleased]

### Added

- Show both unified and transparent addresses in Simple view Receive dialog
  ([#113](https://github.com/LeakIX/zcash-web-wallet/issues/113),
  [#114](https://github.com/LeakIX/zcash-web-wallet/pull/114))

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
