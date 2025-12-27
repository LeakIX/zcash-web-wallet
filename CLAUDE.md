# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zcash Shielded Transaction Viewer - a web application for viewing shielded transaction details using viewing keys. Decryption happens entirely client-side using official Zcash Rust libraries compiled to WebAssembly.

## Build Commands

All commands are in the Makefile. Run `make help` for full list.

```bash
make install          # Install all dependencies (wasm-pack, poetry, prettier)
make build            # Build WASM module to frontend/pkg/
make test             # Run all tests (Rust + Python)
make lint             # Lint all code (clippy, ruff, prettier)
make format           # Format all code
```

### Component-specific commands

```bash
# Rust WASM module
cd wasm-module && cargo +nightly test              # Run single test
cd wasm-module && cargo +nightly clippy            # Lint
cd wasm-module && cargo +nightly fmt               # Format

# Python backend
cd backend && poetry run pytest                    # Run tests
cd backend && poetry run ruff check .              # Lint
cd backend && poetry run ruff format .             # Format

# Frontend
npx prettier --check "frontend/**/*.{js,html}"    # Check formatting
```

### Development servers

```bash
make dev-backend      # FastAPI on port 8000 (hot reload)
make dev-frontend     # Static server on port 3000
```

## Architecture

```
Browser                         Backend                    Zcash Node
   │                               │                           │
   │  1. Submit txid               │                           │
   ├──────────────────────────────►│  2. getrawtransaction     │
   │                               ├──────────────────────────►│
   │  3. raw tx hex                │◄──────────────────────────┤
   │◄──────────────────────────────┤                           │
   │                               │                           │
   │  4. WASM decrypts locally     │                           │
   │     (viewing key stays        │                           │
   │      in browser)              │                           │
```

**Key security property**: Viewing keys never leave the browser. The backend only fetches raw transaction data from zcashd.

## Code Structure

- `wasm-module/` - Rust WASM library using zcash_primitives, orchard, sapling-crypto
  - Exposes `parse_viewing_key()` and `decrypt_transaction()` to JavaScript
  - Uses Rust nightly (edition 2024) with wasm-pack
- `backend/` - FastAPI server (Poetry + Ruff)
  - Proxies `getrawtransaction` RPC calls to zcashd
- `frontend/` - Bootstrap 5 + vanilla JS
  - Loads WASM module from `pkg/` subdirectory

## Configuration

Backend uses environment variables:
- `ZCASH_RPC_HOST`, `ZCASH_RPC_PORT`, `ZCASH_RPC_USER`, `ZCASH_RPC_PASSWORD` (mainnet)
- `ZCASH_TESTNET_RPC_*` variants for testnet

## Conventions

- Makefile targets have `.PHONY` declaration immediately before each target
- Makefile uses self-documenting help (`## comment` after target)
- Rust uses nightly toolchain (specified in `rust-toolchain.toml`)
