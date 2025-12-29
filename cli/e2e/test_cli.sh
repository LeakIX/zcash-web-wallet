#!/usr/bin/env bash
#
# End-to-end tests for zcash-wallet CLI
#
# Usage: ./test_cli.sh [path-to-binary]
#
# If no path is provided, uses ../target/release/zcash-wallet

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Binary path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_BIN="${1:-${SCRIPT_DIR}/../../target/release/zcash-wallet}"

# Temp directory for test artifacts
TEST_DIR=""

# Known test seed phrase (BIP39 test vector)
TEST_SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

# Expected values for the test seed
EXPECTED_TRANSPARENT_ADDR="tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd"
EXPECTED_UFVK_PREFIX="uviewtest1w4wqdd4qw09p5hwll0u5wgl9m359nzn0z5hevyllf9ymg7a2ep7ndk5rhh4gut0gaanep78eylutxdua5unlpcpj8gvh9tjwf7r20de8074g7g6ywvawjuhuxc0hlsxezvn64cdsr49pcyzncjx5q084fcnk9qwa2hj5ae3dplstlg9yv950hgs9jjfnxvtcvu79mdrq66ajh62t5zrvp8tqkqsgh8r4xa6dr2v0mdruac46qk4hlddm58h3khmrrn8awwdm20vfxsr9n6a94vkdf3dzyfpdul558zgxg80kkgth4ghzudd7nx5gvry49sxs78l9xft0lme0llmc5pkh0a4dv4ju6xv4a2y7xh6ekrnehnyrhwcfnpsqw4qwwm3q6c8r02fnqxt9adqwuj5hyzedt9ms9sk0j35ku7j6sm6z0m2x4cesch6nhe9ln44wpw8e7nnyak0up92d6mm6dwdx4r60pyaq7k8vj0r2neqxtqmsgcrd"

#
# Helper functions
#

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

run_test() {
    local test_name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    log_info "Running: ${test_name}"
}

setup() {
    TEST_DIR="$(mktemp -d)"
    log_info "Test directory: ${TEST_DIR}"
}

# shellcheck disable=SC2317
cleanup() {
    if [[ -n "${TEST_DIR}" && -d "${TEST_DIR}" ]]; then
        rm -rf "${TEST_DIR}"
    fi
}

trap cleanup EXIT

#
# Test cases
#

test_binary_exists() {
    run_test "Binary exists and is executable"

    if [[ -x "${CLI_BIN}" ]]; then
        log_pass "Binary found at ${CLI_BIN}"
    else
        log_fail "Binary not found or not executable at ${CLI_BIN}"
        echo "Please build with: cargo +nightly build -p zcash-wallet-cli --release"
        exit 1
    fi
}

test_help() {
    run_test "Help command works"

    if "${CLI_BIN}" --help | grep -q "Zcash testnet wallet CLI tool"; then
        log_pass "Help output is correct"
    else
        log_fail "Help output unexpected"
    fi
}

test_generate_creates_file() {
    run_test "Generate creates wallet file"

    local wallet_file="${TEST_DIR}/generated_wallet.json"

    if "${CLI_BIN}" generate --output "${wallet_file}" > /dev/null 2>&1; then
        if [[ -f "${wallet_file}" ]]; then
            log_pass "Wallet file created"
        else
            log_fail "Wallet file not created"
        fi
    else
        log_fail "Generate command failed"
    fi
}

test_generate_file_has_required_fields() {
    run_test "Generated wallet has required JSON fields"

    local wallet_file="${TEST_DIR}/wallet_fields.json"
    "${CLI_BIN}" generate --output "${wallet_file}" > /dev/null 2>&1

    local required_fields=("seed_phrase" "network" "unified_address" "unified_full_viewing_key" "transparent_address")
    local all_present=true

    for field in "${required_fields[@]}"; do
        if ! grep -q "\"${field}\"" "${wallet_file}"; then
            log_fail "Missing field: ${field}"
            all_present=false
        fi
    done

    if [[ "${all_present}" == "true" ]]; then
        log_pass "All required fields present"
    fi
}

test_generate_file_exists_error() {
    run_test "Generate fails if file already exists"

    local wallet_file="${TEST_DIR}/existing_wallet.json"
    echo "{}" > "${wallet_file}"

    local output
    output=$("${CLI_BIN}" generate --output "${wallet_file}" 2>&1 || true)

    if echo "${output}" | grep -q "already exists"; then
        log_pass "Correctly refused to overwrite existing file"
    else
        log_fail "Should have refused to overwrite existing file"
    fi
}

test_restore_outputs_correct_addresses() {
    run_test "Restore produces correct addresses from known seed"

    local output
    output=$("${CLI_BIN}" restore --seed "${TEST_SEED}" 2>&1)

    if echo "${output}" | grep -q "${EXPECTED_TRANSPARENT_ADDR}"; then
        log_pass "Transparent address matches expected value"
    else
        log_fail "Transparent address mismatch"
        echo "Expected: ${EXPECTED_TRANSPARENT_ADDR}"
    fi
}

test_restore_outputs_correct_ufvk() {
    run_test "Restore produces correct UFVK from known seed"

    local output
    output=$("${CLI_BIN}" restore --seed "${TEST_SEED}" 2>&1)

    if echo "${output}" | grep -q "${EXPECTED_UFVK_PREFIX}"; then
        log_pass "UFVK matches expected value"
    else
        log_fail "UFVK mismatch"
    fi
}

test_restore_with_output_creates_file() {
    run_test "Restore with --output creates wallet file"

    local wallet_file="${TEST_DIR}/restored_wallet.json"

    if "${CLI_BIN}" restore --seed "${TEST_SEED}" --output "${wallet_file}" > /dev/null 2>&1; then
        if [[ -f "${wallet_file}" ]]; then
            log_pass "Restored wallet file created"
        else
            log_fail "Restored wallet file not created"
        fi
    else
        log_fail "Restore command failed"
    fi
}

test_restore_file_contains_seed() {
    run_test "Restored wallet file contains seed phrase"

    local wallet_file="${TEST_DIR}/restored_with_seed.json"
    "${CLI_BIN}" restore --seed "${TEST_SEED}" --output "${wallet_file}" > /dev/null 2>&1

    if grep -q "abandon abandon abandon" "${wallet_file}"; then
        log_pass "Wallet file contains seed phrase"
    else
        log_fail "Wallet file missing seed phrase"
    fi
}

test_restore_file_exists_error() {
    run_test "Restore fails if output file already exists"

    local wallet_file="${TEST_DIR}/existing_restored.json"
    echo "{}" > "${wallet_file}"

    local output
    output=$("${CLI_BIN}" restore --seed "${TEST_SEED}" --output "${wallet_file}" 2>&1 || true)

    if echo "${output}" | grep -q "already exists"; then
        log_pass "Correctly refused to overwrite existing file"
    else
        log_fail "Should have refused to overwrite existing file"
    fi
}

test_restore_invalid_seed() {
    run_test "Restore fails with invalid seed phrase"

    local output
    output=$("${CLI_BIN}" restore --seed "invalid seed phrase" 2>&1 || true)

    if echo "${output}" | grep -iq "invalid\|error"; then
        log_pass "Correctly rejected invalid seed phrase"
    else
        log_fail "Should have rejected invalid seed phrase"
    fi
}

test_faucet_shows_instructions() {
    run_test "Faucet command shows instructions"

    local output
    output=$("${CLI_BIN}" faucet 2>&1)

    if echo "${output}" | grep -q "testnet.zecfaucet.com"; then
        log_pass "Faucet shows correct URL"
    else
        log_fail "Faucet missing expected URL"
    fi
}

test_config_creates_database() {
    run_test "Config command creates database"

    local db_file="${TEST_DIR}/test_notes.db"

    "${CLI_BIN}" config --db "${db_file}" > /dev/null 2>&1

    if [[ -f "${db_file}" ]]; then
        log_pass "Database file created"
    else
        log_fail "Database file not created"
    fi
}

test_config_sets_rpc_url() {
    run_test "Config command sets RPC URL"

    local db_file="${TEST_DIR}/config_test.db"
    local test_url="http://localhost:18232"

    "${CLI_BIN}" config --db "${db_file}" --rpc-url "${test_url}" > /dev/null 2>&1

    local output
    output=$("${CLI_BIN}" config --db "${db_file}" 2>&1)

    if echo "${output}" | grep -q "${test_url}"; then
        log_pass "RPC URL correctly stored and retrieved"
    else
        log_fail "RPC URL not stored correctly"
    fi
}

test_balance_shows_zero_initially() {
    run_test "Balance command shows zero for empty database"

    local db_file="${TEST_DIR}/balance_test.db"
    "${CLI_BIN}" config --db "${db_file}" > /dev/null 2>&1

    local output
    output=$("${CLI_BIN}" balance --db "${db_file}" 2>&1)

    if echo "${output}" | grep -q "0.00000000"; then
        log_pass "Balance shows zero for empty database"
    else
        log_fail "Balance should show zero"
    fi
}

test_notes_empty_initially() {
    run_test "Notes command shows no notes for empty database"

    local db_file="${TEST_DIR}/notes_test.db"
    "${CLI_BIN}" config --db "${db_file}" > /dev/null 2>&1

    local output
    output=$("${CLI_BIN}" notes --db "${db_file}" 2>&1)

    if echo "${output}" | grep -q "No notes found"; then
        log_pass "Notes correctly shows empty state"
    else
        log_fail "Notes should show empty state"
    fi
}

#
# Main
#

main() {
    echo "============================================================"
    echo "       ZCASH-WALLET CLI END-TO-END TESTS"
    echo "============================================================"

    setup

    # Run all tests
    test_binary_exists
    test_help
    test_generate_creates_file
    test_generate_file_has_required_fields
    test_generate_file_exists_error
    test_restore_outputs_correct_addresses
    test_restore_outputs_correct_ufvk
    test_restore_with_output_creates_file
    test_restore_file_contains_seed
    test_restore_file_exists_error
    test_restore_invalid_seed
    test_faucet_shows_instructions
    test_config_creates_database
    test_config_sets_rpc_url
    test_balance_shows_zero_initially
    test_notes_empty_initially

    # Summary
    echo ""
    echo "============================================================"
    echo "                    TEST SUMMARY"
    echo "============================================================"
    echo ""
    echo "Tests run:    ${TESTS_RUN}"
    echo -e "Tests passed: ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Tests failed: ${RED}${TESTS_FAILED}${NC}"
    echo ""

    if [[ ${TESTS_FAILED} -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

main "$@"
