# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zcash Web Wallet - a privacy-preserving Zcash wallet toolkit that runs entirely in your browser. Features include wallet generation, transaction viewing, and balance tracking. All cryptographic operations happen client-side using official Zcash Rust libraries compiled to WebAssembly.

## Build Commands

All commands are in the Makefile. Run `make help` for full list.

```bash
make install          # Install all dependencies (wasm-pack, npm)
make build            # Build WASM module and compile Sass
make test             # Run all tests (Rust)
make lint             # Lint all code (clippy, prettier)
make format           # Format all code
make serve            # Build and serve frontend on port 3000
```

### Component-specific commands

```bash
# Rust WASM module
cd wasm-module && cargo +nightly test              # Run single test
cd wasm-module && cargo +nightly clippy            # Lint
cd wasm-module && cargo +nightly fmt               # Format

# Frontend
make format-check-js                               # Check JS/HTML formatting
make format-check-sass                             # Check Sass formatting
make build-sass                                    # Compile Sass to CSS
make watch-sass                                    # Watch and recompile Sass
```

### Development server

```bash
make serve            # Build and serve frontend on port 3000
```

## Architecture

```
Browser                                        Zcash Node
   |                                               |
   |  1. User selects RPC endpoint                 |
   |  2. Submit txid + viewing key                 |
   |                                               |
   |  3. JavaScript fetches raw tx via RPC         |
   |----------------------------------------------►|
   |  4. Raw tx hex                                |
   |◄----------------------------------------------|
   |                                               |
   |  5. WASM decrypts locally                     |
   |     (viewing key stays in browser)            |
```

**Key security property**: Viewing keys never leave the browser. Transaction data is fetched directly from the RPC endpoint the user selects.

## Code Structure

- `core/` - Shared Rust library for wallet derivation (used by both CLI and WASM)
- `wasm-module/` - Rust WASM library using zcash_primitives, orchard, sapling-crypto
  - Exposes `parse_viewing_key()`, `decrypt_transaction()`, `generate_wallet()`, `restore_wallet()` to JavaScript
  - Uses Rust nightly (edition 2024) with wasm-pack
- `cli/` - Command-line tool for wallet generation and note tracking
  - SQLite database for note/nullifier storage
  - RPC client for fetching transactions
- `frontend/` - Bootstrap 5 + vanilla JS + Sass
  - Loads WASM module from `pkg/` subdirectory
  - Queries RPC endpoints directly via JavaScript fetch
  - Stores user preferences (endpoints, theme) in localStorage
  - `sass/` - Sass source files (indented syntax)
  - `css/` - Compiled CSS output

## Conventions

- Makefile targets have `.PHONY` declaration immediately before each target
- Makefile uses self-documenting help (`## comment` after target)
- Rust uses nightly toolchain (specified in `rust-toolchain.toml`)
- Never use `scripts` field in package.json - use only Makefile targets
- Never use UTF-8 emoji/special characters in code - use icon classes from CSS library (Bootstrap Icons) instead

## Development Guidelines

### Formatting

- Run `make format` before committing
- Rust: `cargo +nightly fmt`
- JS/HTML: `prettier --write`
- Sass: indented syntax has strict formatting rules (no automated formatter)

### Pre-Commit Checklist

Before committing and pushing changes:

1. Run `make test` and ensure all tests pass (includes unit tests and CLI e2e tests)
2. Run `make format` to format all code
3. Run `make lint` to check for linting issues

Note: `make test` runs both `make test-rust` (unit tests for core, wasm, cli) and `make test-e2e` (CLI end-to-end tests).

### Commit Standards

- No emojis in commit messages
- Do not add Claude as co-author
- Wrap commit message titles at 72 characters
- Wrap commit message body at 80 characters
- Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`

### Code Style

- Rust: follow clippy lints with `-D warnings`
- Keep functions focused and small
- Prefer explicit error handling over panics in library code
- Use Bootstrap Icons for all icons (no UTF-8 emoji characters)

### Deployment

The app is deployed to GitHub Pages automatically on push to main. See `.github/workflows/deploy.yml`.
