# Zcash Web Wallet - Makefile

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
install-wasm-pack: ## Install wasm-pack and Rust nightly toolchain
	@echo "Installing wasm-pack..."
	@which wasm-pack > /dev/null || cargo install wasm-pack
	@echo "Installing Rust nightly toolchain..."
	@rustup install nightly
	@rustup target add wasm32-unknown-unknown --toolchain nightly

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
	cd wasm-module && wasm-pack build --target web --release --out-dir ../frontend/pkg

.PHONY: build-cli
build-cli: ## Build CLI tool
	@echo "Building CLI tool..."
	cargo +nightly build --release -p zcash-wallet-cli

.PHONY: build-sass
build-sass: ## Compile Sass to CSS
	@echo "Compiling Sass..."
	npx sass frontend/sass/style.sass frontend/css/style.css --style=compressed

# =============================================================================
# Development
# =============================================================================

.PHONY: serve
serve: build inject-version ## Build and serve frontend on port 3000
	@echo "Serving frontend on http://localhost:3000"
	cd frontend && python -m http.server 3000

.PHONY: inject-version
inject-version: ## Inject git commit hash into frontend
	@echo "Injecting version info..."
	@COMMIT_HASH=$$(git rev-parse HEAD); \
	COMMIT_SHORT=$$(git rev-parse --short HEAD); \
	sed -i "s/__COMMIT_HASH__/$${COMMIT_HASH}/g" frontend/index.html; \
	sed -i "s/__COMMIT_SHORT__/$${COMMIT_SHORT}/g" frontend/index.html
	@echo "Version: $$(git rev-parse --short HEAD)"

.PHONY: restore-version
restore-version: ## Restore version placeholders in frontend
	@echo "Restoring version placeholders..."
	@COMMIT_HASH=$$(git rev-parse HEAD); \
	COMMIT_SHORT=$$(git rev-parse --short HEAD); \
	sed -i "s/$${COMMIT_HASH}/__COMMIT_HASH__/g" frontend/index.html; \
	sed -i "s/$${COMMIT_SHORT}/__COMMIT_SHORT__/g" frontend/index.html

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
	cargo +nightly fmt --all

.PHONY: format-toml
format-toml: ## Format TOML files with taplo
	@echo "Formatting TOML files..."
	taplo format

.PHONY: format-js
format-js: ## Format JavaScript/HTML with Prettier
	@echo "Formatting JavaScript/HTML files..."
	npx prettier --write "frontend/**/*.{js,html,json}"

# =============================================================================
# Format Checking (for CI)
# =============================================================================

.PHONY: format-check
format-check: format-check-rust format-check-toml format-check-js ## Check formatting without modifying files
	@echo "Format check complete"

.PHONY: format-check-rust
format-check-rust: ## Check Rust formatting
	@echo "Checking Rust formatting..."
	cargo +nightly fmt --all --check

.PHONY: format-check-toml
format-check-toml: ## Check TOML formatting with taplo
	@echo "Checking TOML formatting..."
	taplo format --check

.PHONY: format-check-js
format-check-js: ## Check JavaScript/HTML formatting with Prettier
	@echo "Checking JavaScript/HTML formatting..."
	npx prettier --check "frontend/**/*.{js,html,json}"

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
	cd wasm-module && cargo +nightly clippy -- -D warnings

.PHONY: lint-cli
lint-cli: ## Lint CLI tool with clippy
	@echo "Linting CLI tool..."
	cargo +nightly clippy -p zcash-wallet-cli -- -D warnings

.PHONY: lint-js
lint-js: ## Alias for format-check-js
	@$(MAKE) format-check-js

.PHONY: lint-shell
lint-shell: ## Lint shell scripts with shellcheck
	@echo "Linting shell scripts..."
	shellcheck cli/e2e/*.sh

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test: test-rust test-e2e ## Run all tests
	@echo "All tests passed"

.PHONY: test-rust
test-rust: test-core test-wasm test-cli ## Run all Rust unit tests
	@echo "Rust tests complete"

.PHONY: test-core
test-core: ## Run core library unit tests
	@echo "Running core library tests..."
	cargo +nightly test -p zcash-wallet-core

.PHONY: test-wasm
test-wasm: ## Run WASM module unit tests
	@echo "Running WASM module tests..."
	cd wasm-module && cargo +nightly test

.PHONY: test-cli
test-cli: ## Run CLI unit tests
	@echo "Running CLI tests..."
	cargo +nightly test -p zcash-wallet-cli

.PHONY: test-e2e
test-e2e: build-cli ## Run CLI end-to-end tests
	@echo "Running CLI e2e tests..."
	cli/e2e/test_cli.sh

.PHONY: test-wasm-browser
test-wasm-browser: ## Run WASM tests in headless browser
	@echo "Running WASM browser tests..."
	cd wasm-module && wasm-pack test --headless --firefox

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
