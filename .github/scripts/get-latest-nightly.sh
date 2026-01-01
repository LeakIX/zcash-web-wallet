#!/bin/bash
# Get the latest available Rust nightly version
#
# Usage: ./get-latest-nightly.sh
# Output: nightly-YYYY-MM-DD

set -euo pipefail

# Get the latest available nightly version from rustup
LATEST=$(rustup check 2>/dev/null | grep nightly | head -1 | \
    grep -oE 'nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)

if [ -z "$LATEST" ]; then
    # Fallback: use yesterday's date as nightly
    # (nightly builds are typically available the day after)
    if date --version >/dev/null 2>&1; then
        # GNU date
        LATEST="nightly-$(date -d 'yesterday' '+%Y-%m-%d')"
    else
        # BSD date (macOS)
        LATEST="nightly-$(date -v-1d '+%Y-%m-%d')"
    fi
fi

echo "$LATEST"
