#!/bin/bash
# shellcheck disable=SC2001  # sed is clearer for adding prefixes to multi-line output
# Verify that generated files are updated in dedicated commits
# Usage: verify-checksum-commit.sh <check_type> <base_ref> <head_ref>
#
# Check types:
#   wasm      - Check WASM files (frontend/pkg/*)
#   css       - Check CSS files (frontend/css/*)
#   checksums - Check CHECKSUMS.json
#   all       - Run all checks (default)
#
# Rules:
# 1. If WASM source files are modified, WASM output files must be updated
# 2. WASM files (frontend/pkg/*) must be in their own commit (no other files)
# 3. If Sass source files are modified, CSS output files must be updated
# 4. CSS files (frontend/css/*) must be in their own commit (no other files)
# 5. If checksummed files are modified, CHECKSUMS.json must be updated
# 6. CHECKSUMS.json must be in its own commit (no other files)
#
# This ensures auditors can easily review:
# - Code changes
# - Generated WASM files (separate commit)
# - Generated CSS files (separate commit)
# - Checksum updates (separate commit)

set -e

CHECK_TYPE="${1:-all}"
BASE_REF="${2:-origin/develop}"
HEAD_REF="${3:-HEAD}"

echo "Verifying generated files are in dedicated commits..."
echo "Check type: $CHECK_TYPE"
echo "Base: $BASE_REF"
echo "Head: $HEAD_REF"
echo ""

ERROR_COUNT=0

# =============================================================================
# Check WASM files
# =============================================================================

check_wasm() {
    echo "=== Checking WASM files ==="

    # Get all commits that modify WASM output files
    WASM_COMMITS=$(git log --format="%H" "$BASE_REF..$HEAD_REF" -- 'frontend/pkg/*')

    if [ -z "$WASM_COMMITS" ]; then
        echo "No commits modify WASM files"
        # Check if WASM source files were modified without updating WASM output
        WASM_SOURCE_MODIFIED=$(git diff --name-only "$BASE_REF..$HEAD_REF" -- \
            'wasm-module/*.rs' 'wasm-module/Cargo.toml' 'wasm-module/Cargo.lock' \
            'core/*.rs' 'core/Cargo.toml')
        if [ -n "$WASM_SOURCE_MODIFIED" ]; then
            echo "ERROR: WASM source files were modified but frontend/pkg/* was not updated"
            echo "Modified source files:"
            echo "$WASM_SOURCE_MODIFIED" | sed 's/^/  /'
            echo ""
            echo "Run 'make build-wasm' and commit the generated files separately."
            ERROR_COUNT=$((ERROR_COUNT + 1))
        fi
    else
        # For each commit that modifies WASM files, verify it only contains WASM files
        for COMMIT in $WASM_COMMITS; do
            SHORT_HASH=$(echo "$COMMIT" | cut -c1-7)
            FILES=$(git diff-tree --no-commit-id --name-only -r "$COMMIT")

            echo "Commit $SHORT_HASH modifies WASM files"

            # Check if all files are in frontend/pkg/
            NON_WASM_FILES=$(echo "$FILES" | grep -v '^frontend/pkg/' || true)
            if [ -n "$NON_WASM_FILES" ]; then
                echo "  ERROR: WASM files must be in their own dedicated commit"
                echo "  This commit also contains:"
                echo "$NON_WASM_FILES" | sed 's/^/    /'
                ERROR_COUNT=$((ERROR_COUNT + 1))
            else
                echo "  OK: Dedicated WASM commit"
            fi
        done
    fi

    echo ""
}

# =============================================================================
# Check CSS files
# =============================================================================

check_css() {
    echo "=== Checking CSS files ==="

    # Get all commits that modify CSS output files
    CSS_COMMITS=$(git log --format="%H" "$BASE_REF..$HEAD_REF" -- 'frontend/css/*')

    if [ -z "$CSS_COMMITS" ]; then
        echo "No commits modify CSS files"
        # Check if Sass source files were modified without updating CSS output
        SASS_SOURCE_MODIFIED=$(git diff --name-only "$BASE_REF..$HEAD_REF" -- \
            'frontend/sass/*.sass' 'frontend/sass/**/*.sass')
        if [ -n "$SASS_SOURCE_MODIFIED" ]; then
            echo "ERROR: Sass source files were modified but frontend/css/* was not updated"
            echo "Modified source files:"
            echo "$SASS_SOURCE_MODIFIED" | sed 's/^/  /'
            echo ""
            echo "Run 'make build-sass' and commit the generated files separately."
            ERROR_COUNT=$((ERROR_COUNT + 1))
        fi
    else
        # For each commit that modifies CSS files, verify it only contains CSS files
        for COMMIT in $CSS_COMMITS; do
            SHORT_HASH=$(echo "$COMMIT" | cut -c1-7)
            FILES=$(git diff-tree --no-commit-id --name-only -r "$COMMIT")

            echo "Commit $SHORT_HASH modifies CSS files"

            # Check if all files are in frontend/css/
            NON_CSS_FILES=$(echo "$FILES" | grep -v '^frontend/css/' || true)
            if [ -n "$NON_CSS_FILES" ]; then
                echo "  ERROR: CSS files must be in their own dedicated commit"
                echo "  This commit also contains:"
                echo "$NON_CSS_FILES" | sed 's/^/    /'
                ERROR_COUNT=$((ERROR_COUNT + 1))
            else
                echo "  OK: Dedicated CSS commit"
            fi
        done
    fi

    echo ""
}

# =============================================================================
# Check CHECKSUMS.json
# =============================================================================

check_checksums() {
    echo "=== Checking CHECKSUMS.json ==="

    # Get all commits that modify CHECKSUMS.json
    CHECKSUM_COMMITS=$(git log --format="%H" "$BASE_REF..$HEAD_REF" -- CHECKSUMS.json)

    if [ -z "$CHECKSUM_COMMITS" ]; then
        echo "No commits modify CHECKSUMS.json"
        # Check if any checksummed files were modified without updating CHECKSUMS.json
        CHECKSUMMED_MODIFIED=$(git diff --name-only "$BASE_REF..$HEAD_REF" -- \
            'frontend/js/*.js' 'frontend/js/**/*.js' 'frontend/css/*.css' \
            'frontend/index.html' 'frontend/pkg/*')
        if [ -n "$CHECKSUMMED_MODIFIED" ]; then
            echo "ERROR: Checksummed files were modified but CHECKSUMS.json was not updated"
            echo "Modified files:"
            echo "$CHECKSUMMED_MODIFIED" | sed 's/^/  /'
            echo ""
            echo "Run 'make generate-checksums' and commit CHECKSUMS.json separately."
            ERROR_COUNT=$((ERROR_COUNT + 1))
        fi
    else
        # For each commit that modifies CHECKSUMS.json, verify it only contains CHECKSUMS.json
        for COMMIT in $CHECKSUM_COMMITS; do
            SHORT_HASH=$(echo "$COMMIT" | cut -c1-7)
            FILES=$(git diff-tree --no-commit-id --name-only -r "$COMMIT")
            FILE_COUNT=$(echo "$FILES" | wc -l | tr -d ' ')

            echo "Commit $SHORT_HASH modifies CHECKSUMS.json"

            if [ "$FILE_COUNT" -ne 1 ] || [ "$FILES" != "CHECKSUMS.json" ]; then
                echo "  ERROR: CHECKSUMS.json must be in its own dedicated commit"
                echo "  This commit also contains:"
                echo "$FILES" | grep -v "CHECKSUMS.json" | sed 's/^/    /'
                ERROR_COUNT=$((ERROR_COUNT + 1))
            else
                echo "  OK: Dedicated checksum commit"
            fi
        done
    fi

    echo ""
}

# =============================================================================
# Run checks based on type
# =============================================================================

case "$CHECK_TYPE" in
    wasm)
        check_wasm
        ;;
    css)
        check_css
        ;;
    checksums)
        check_checksums
        ;;
    all)
        check_wasm
        check_css
        check_checksums
        ;;
    *)
        echo "Unknown check type: $CHECK_TYPE"
        echo "Valid types: wasm, css, checksums, all"
        exit 1
        ;;
esac

# =============================================================================
# Summary
# =============================================================================

if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "=== FAILED: $ERROR_COUNT error(s) found ==="
    exit 1
fi

echo "=== All checks passed ==="
