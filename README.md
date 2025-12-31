# Zcash Web Wallet

[![CI](https://github.com/LeakIX/zcash-web-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/LeakIX/zcash-web-wallet/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/LeakIX/zcash-web-wallet/graph/badge.svg)](https://codecov.io/gh/LeakIX/zcash-web-wallet)

A privacy-preserving Zcash wallet toolkit that runs entirely in your browser. Generate wallets, view shielded transactions, and track balances - all client-side with no server dependencies.

## Features

- **Wallet Generation**: Create and restore Zcash testnet wallets with BIP39 seed phrases
- **Transaction Viewer**: Decode shielded transaction details using viewing keys
- **CLI Tool**: Command-line wallet generation and note/balance tracking
- **Privacy First**: All cryptographic operations happen locally - keys never leave your device
- **Orchard Support**: Full support for the latest Orchard shielded pool
- **Code Integrity Verification**: Automatic verification that served code matches the repository

## Security

### Code Integrity Verification

This application includes a client-side integrity verification system that protects against compromised servers:

**How It Works:**

1. **Checksums from GitHub**: The application fetches expected file hashes directly from `raw.githubusercontent.com`, which is controlled by the repository, not the hosting server
2. **Local Verification**: Each critical file is hashed in your browser and compared against expected values
3. **Visual Transparency**: A progress indicator shows each file being verified with a 200ms delay for transparency
4. **Version Tracking**: The application remembers which version you've verified and warns you if the code changes

**First Visit:**

- A modal displays security information and verification instructions
- You must acknowledge the warning before the application loads
- Links are provided to manually inspect the code and compare with the repository

**Subsequent Visits:**

- A discrete "✓ Verified" button appears in the footer
- Clicking it shows verification details and allows re-verification
- The verified version is stored in localStorage

**Version Changes:**

- If the code changes, a prominent warning appears
- Shows the old and new version hashes
- Provides links to view the diff on GitHub
- You must explicitly accept the update before proceeding

**Manual Verification:**

To maximize security, you should:

1. View the [bootstrap code](frontend/integrity-check.js) (under 500 lines) and verify it's not malicious
2. Compare critical files with the [repository](https://github.com/LeakIX/zcash-web-wallet/tree/main/frontend)
3. Check the [CHECKSUMS.json](CHECKSUMS.json) file matches what's served from `raw.githubusercontent.com`
4. Clone and build the application yourself for complete control

**Limitations:**

- Users must trust the bootstrap code on first visit (but it's small and auditable)
- Checksums are fetched from GitHub, not cryptographically signed
- This is a detection mechanism, not a cryptographic guarantee
- A sophisticated attacker could modify the bootstrap code itself

Despite these limitations, this system provides strong protection against:

- Compromised hosting infrastructure
- Man-in-the-middle attacks at the CDN level
- Silent malicious updates

## Quick Start

### Web Interface

```bash
make install    # Install dependencies
make build      # Build WASM module and Sass
make serve      # Serve on http://localhost:3000
```

### CLI Tool

```bash
make build-cli  # Build the CLI

# Generate a new testnet wallet
./target/release/zcash-wallet generate --output wallet.json

# Restore from seed phrase
./target/release/zcash-wallet restore --seed "your 24 words here" --output wallet.json

# Get testnet faucet instructions
./target/release/zcash-wallet faucet
```

## Development

```bash
make test       # Run all tests (Rust + e2e)
make lint       # Lint all code (clippy, prettier, shellcheck)
make format     # Format all code
make help       # Show all available commands
```

## Architecture

```
Browser                              Zcash Node
   |                                     |
   |  1. User enters txid + viewing key  |
   |  2. Fetch raw tx via RPC            |
   |------------------------------------>|
   |  3. Raw transaction hex             |
   |<------------------------------------|
   |  4. WASM decrypts locally           |
   |     (keys never leave browser)      |
```

## Project Structure

- `core/` - Shared Rust library for wallet derivation
- `wasm-module/` - Rust WASM library for browser-based operations
- `cli/` - Command-line wallet and note tracking tool
- `frontend/` - Web interface (Bootstrap + vanilla JS)

## License

MIT
