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
