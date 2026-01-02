# Frontend E2E Tests

This directory contains end-to-end (E2E) tests for the Zcash Web Wallet frontend using [Playwright](https://playwright.dev/).

## Overview

The E2E tests validate frontend functionality including:
- Application loading and WASM module initialization  
- Wallet generation and restoration
- Address derivation and display
- Transaction scanning and note tracking
- Theme switching and localStorage persistence
- RPC endpoint management
- Send transaction flow

## Running Tests

### Prerequisites

```bash
# Install dependencies
make install-npm

# Build WASM and CSS
make build

# Install Playwright browsers (one-time setup)
npx playwright install chromium
```

### Run All Tests

```bash
# Run all E2E tests
make test-e2e-frontend

# Or directly with Playwright
npx playwright test
```

### Run Specific Tests

```bash
# Run a single test file
npx playwright test frontend/e2e/basic.spec.js

# Run tests with UI mode (interactive)
make test-e2e-frontend-ui

# Run tests in headed mode (see browser)
make test-e2e-frontend-headed
```

### Debugging

```bash
# Run with Playwright Inspector
npx playwright test --debug

# View test trace
npx playwright show-trace test-results/<test-name>/trace.zip
```

## Test Structure

- `helpers.js` - Shared test utilities and constants
- `basic.spec.js` - Basic application loading and navigation
- `wallet.spec.js` - Wallet generation and restoration
- `addresses.spec.js` - Address derivation and display
- `theme.spec.js` - Theme switching and settings
- `rpc.spec.js` - RPC endpoint management
- `scanner.spec.js` - Transaction scanning and notes
- `send.spec.js` - Send transaction flow
- `simple-view.spec.js` - Simple view functionality

## CI Integration

E2E tests run automatically on pull requests and pushes to main/develop branches via GitHub Actions.

## Notes

- Tests use a known BIP39 test seed for deterministic results
- All tests run with localStorage cleared to ensure clean state
- Tests use testnet network and do not interact with real funds
- WASM module loading can take several seconds - tests have appropriate timeouts
