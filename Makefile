# Zcash Web Wallet - Makefile

# =============================================================================
# Configuration
# =============================================================================

WASM_PACK_VERSION := 0.13.1
# When updating RUST_NIGHTLY, also update rust-toolchain.toml and
# .github/workflows/ci.yml
RUST_NIGHTLY := nightly-2025-12-31
CARGO := rustup run $(RUST_NIGHTLY) cargo

# Use GNU sed on macOS (install with: brew install gnu-sed)
ifeq ($(shell uname),Darwin)
    ifeq ($(shell which gsed 2>/dev/null),)
        $(error GNU sed not found. Install with: brew install gnu-sed)
    endif
    SED := gsed
else
    SED := sed
endif

# =============================================================================
# Default target
# =============================================================================

.PHONY: all
all: build ## Build the entire project

# =============================================================================
# Installation
# =============================================================================

.PHONY: install
install: install-wasm-pack install-npm ## Install all dependencies
	@echo "All dependencies installed"

.PHONY: install-wasm-pack
install-wasm-pack: ## Install wasm-pack and Rust toolchain
	@echo "Installing wasm-pack v$(WASM_PACK_VERSION)..."
	cargo install wasm-pack --version $(WASM_PACK_VERSION)
	@echo "Installing Rust toolchain $(RUST_NIGHTLY)..."
	@rustup install $(RUST_NIGHTLY)
	@rustup target add wasm32-unknown-unknown --toolchain $(RUST_NIGHTLY)

.PHONY: install-npm
install-npm: ## Install npm dependencies (Prettier, Sass)
	@echo "Installing npm dependencies..."
	npm install

# =============================================================================
# Building
# =============================================================================

.PHONY: build
build: build-wasm build-cli build-sass ## Build WASM module, CLI, and CSS
	@echo "Build complete"

.PHONY: build-wasm
build-wasm: ## Build WASM module with wasm-pack
	@echo "Building WASM module..."
ifeq ($(shell uname),Darwin)
	@if [ -d "$$(brew --prefix llvm 2>/dev/null)" ]; then \
		LLVM_PREFIX=$$(brew --prefix llvm); \
		CC="$$LLVM_PREFIX/bin/clang" AR="$$LLVM_PREFIX/bin/llvm-ar" \
		sh -c 'cd wasm-module && \
			wasm-pack build --target web --release --out-dir ../frontend/pkg'; \
	else \
		echo "Error: Homebrew LLVM not found. Install with: brew install llvm"; \
		exit 1; \
	fi
else
	cd wasm-module && \
		wasm-pack build --target web --release --out-dir ../frontend/pkg
endif
	@rm -f frontend/pkg/.gitignore

.PHONY: build-cli
build-cli: ## Build CLI tool
	@echo "Building CLI tool..."
	$(CARGO) build --release -p zcash-wallet-cli

.PHONY: build-sass
build-sass: ## Compile Sass to CSS
	@echo "Compiling Sass..."
	npx sass frontend/sass/style.sass frontend/css/style.css --style=compressed

.PHONY: generate-checksums
generate-checksums: ## Generate checksums for frontend files
	@echo "Generating checksums..."
	node scripts/generate-checksums.js

.PHONY: verify-checksums
verify-checksums: ## Verify CHECKSUMS.json is up to date
	@echo "Verifying checksums..."
	node scripts/verify-checksums.js

# =============================================================================
# Development
# =============================================================================

.PHONY: serve
serve: build ## Build and serve frontend on port 3000
	@echo "Serving frontend on http://localhost:3000"
	cd frontend && python3 -m http.server 3000

.PHONY: watch-sass
watch-sass: ## Watch Sass files and recompile on changes
	@echo "Watching Sass files..."
	npx sass --watch frontend/sass/style.sass:frontend/css/style.css

# =============================================================================
# Formatting
# =============================================================================

.PHONY: format
format: format-rust format-toml format-js ## Format all code
	@echo "Formatting complete"

.PHONY: format-rust
format-rust: ## Format Rust code with cargo fmt
	@echo "Formatting Rust code..."
	$(CARGO) fmt --all

.PHONY: format-toml
format-toml: ## Format TOML files with taplo
	@echo "Formatting TOML files..."
	taplo format

.PHONY: format-js
format-js: ## Format JavaScript/HTML/Markdown with Prettier
	@echo "Formatting JavaScript/HTML/Markdown files..."
	npx prettier --write "frontend/**/*.{js,html,json}" "*.md"

# =============================================================================
# Format Checking (for CI)
# =============================================================================

.PHONY: format-check
format-check: format-check-rust format-check-toml format-check-js
format-check: ## Check formatting without modifying files
	@echo "Format check complete"

.PHONY: format-check-rust
format-check-rust: ## Check Rust formatting
	@echo "Checking Rust formatting..."
	$(CARGO) fmt --all --check

.PHONY: format-check-cli
format-check-cli: ## Check CLI Rust formatting
	@echo "Checking CLI formatting..."
	$(CARGO) fmt -p zcash-wallet-cli --check

.PHONY: format-check-toml
format-check-toml: ## Check TOML formatting with taplo
	@echo "Checking TOML formatting..."
	taplo format --check

.PHONY: format-check-js
format-check-js: ## Check JavaScript/HTML/Markdown formatting with Prettier
	@echo "Checking JavaScript/HTML/Markdown formatting..."
	npx prettier --check "frontend/**/*.{js,html,json}" "*.md"

# =============================================================================
# Linting
# =============================================================================

.PHONY: lint
lint: lint-rust lint-js lint-shell ## Lint all code
	@echo "Linting complete"

.PHONY: lint-rust
lint-rust: lint-wasm lint-cli ## Lint all Rust code with clippy
	@echo "Rust linting complete"

.PHONY: lint-wasm
lint-wasm: ## Lint WASM module with clippy
	@echo "Linting WASM module..."
	cd wasm-module && $(CARGO) clippy -- -D warnings

.PHONY: lint-cli
lint-cli: ## Lint CLI tool with clippy
	@echo "Linting CLI tool..."
	$(CARGO) clippy -p zcash-wallet-cli -- -D warnings

.PHONY: lint-js
lint-js: ## Alias for format-check-js
	@$(MAKE) format-check-js

.PHONY: lint-shell
lint-shell: ## Lint shell scripts with shellcheck
	@echo "Linting shell scripts..."
	shellcheck cli/e2e/*.sh .github/scripts/*.sh

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test: test-rust test-e2e test-e2e-frontend ## Run all tests
	@echo "All tests passed"

.PHONY: test-rust
test-rust: test-core test-wasm-unit test-cli ## Run all Rust unit tests
	@echo "Rust tests complete"

.PHONY: test-core
test-core: ## Run core library unit tests
	@echo "Running core library tests..."
	$(CARGO) test -p zcash-wallet-core

.PHONY: test-wasm-unit
test-wasm-unit: ## Run WASM module unit tests
	@echo "Running WASM module tests..."
	cd wasm-module && $(CARGO) test

.PHONY: test-cli
test-cli: ## Run CLI unit tests
	@echo "Running CLI tests..."
	$(CARGO) test -p zcash-wallet-cli

.PHONY: test-e2e
test-e2e: build-cli ## Run CLI end-to-end tests
	@echo "Running CLI e2e tests..."
	cli/e2e/test_cli.sh

.PHONY: test-e2e-frontend
test-e2e-frontend: build ## Run frontend end-to-end tests
	@echo "Running frontend e2e tests..."
	npx playwright test

.PHONY: test-e2e-frontend-ui
test-e2e-frontend-ui: build ## Run frontend e2e tests in UI mode
	@echo "Running frontend e2e tests in UI mode..."
	npx playwright test --ui

.PHONY: test-e2e-frontend-headed
test-e2e-frontend-headed: build ## Run frontend e2e tests in headed mode
	@echo "Running frontend e2e tests in headed mode..."
	npx playwright test --headed

# =============================================================================
# Code Coverage
# =============================================================================

.PHONY: install-coverage
install-coverage: ## Install cargo-llvm-cov for code coverage
	@echo "Installing cargo-llvm-cov..."
	$(CARGO) install cargo-llvm-cov

.PHONY: coverage
coverage: ## Run tests with coverage for core library
	@echo "Running tests with coverage..."
	$(CARGO) llvm-cov --package zcash-wallet-core

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report for core library
	@echo "Generating HTML coverage report..."
	$(CARGO) llvm-cov --package zcash-wallet-core --html --output-dir coverage
	@echo "Coverage report generated at coverage/html/index.html"

.PHONY: coverage-lcov
coverage-lcov: ## Generate LCOV coverage report for CI
	@echo "Generating LCOV coverage report..."
	$(CARGO) llvm-cov --package zcash-wallet-core \
		--lcov --output-path coverage.lcov

.PHONY: coverage-all
coverage-all: ## Run tests with coverage for all Rust packages
	@echo "Running tests with coverage for all packages..."
	$(CARGO) llvm-cov --workspace --exclude html-builder

# =============================================================================
# Cleaning
# =============================================================================

.PHONY: clean
clean: clean-rust clean-node clean-css ## Clean all build artifacts
	@echo "Clean complete"

.PHONY: clean-rust
clean-rust: ## Clean Rust build artifacts (workspace target dir)
	@echo "Cleaning Rust build artifacts..."
	rm -rf target

.PHONY: clean-wasm
clean-wasm: ## Clean WASM pkg output
	@echo "Cleaning WASM pkg output..."
	rm -rf frontend/pkg

.PHONY: clean-node
clean-node: ## Clean node_modules
	@echo "Cleaning Node modules..."
	rm -rf node_modules

.PHONY: clean-css
clean-css: ## Clean compiled CSS
	@echo "Cleaning compiled CSS..."
	rm -f frontend/css/style.css frontend/css/style.css.map

# =============================================================================
# Production
# =============================================================================

.PHONY: prod-build
prod-build: build ## Build for production
	@echo "Production build complete"

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
