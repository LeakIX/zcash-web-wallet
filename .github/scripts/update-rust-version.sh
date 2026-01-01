#!/bin/bash
# Update Rust nightly version in all project files
#
# Usage: ./update-rust-version.sh <new-version>
# Example: ./update-rust-version.sh nightly-2025-12-31

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <new-version>"
    echo "Example: $0 nightly-2025-12-31"
    exit 1
fi

NEW_VERSION="$1"

# Validate format
if ! echo "$NEW_VERSION" | grep -qE '^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    echo "Error: Version must be in format nightly-YYYY-MM-DD"
    exit 1
fi

# Get current version from rust-toolchain.toml
OLD_VERSION=$(grep -oE 'nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}' \
    rust-toolchain.toml | head -1)

if [ -z "$OLD_VERSION" ]; then
    echo "Error: Could not find current version in rust-toolchain.toml"
    exit 1
fi

if [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
    echo "Already at $NEW_VERSION"
    exit 0
fi

echo "Updating from $OLD_VERSION to $NEW_VERSION"

# Detect sed in-place flag (GNU vs BSD)
if sed --version >/dev/null 2>&1; then
    SED_INPLACE="sed -i"
else
    SED_INPLACE="sed -i ''"
fi

# Update rust-toolchain.toml
$SED_INPLACE "s/$OLD_VERSION/$NEW_VERSION/g" rust-toolchain.toml
echo "Updated rust-toolchain.toml"

# Update Makefile
$SED_INPLACE "s/$OLD_VERSION/$NEW_VERSION/g" Makefile
echo "Updated Makefile"

# Update CI workflow
$SED_INPLACE "s/$OLD_VERSION/$NEW_VERSION/g" .github/workflows/ci.yml
echo "Updated .github/workflows/ci.yml"

echo "Done. Run 'git diff' to review changes."
