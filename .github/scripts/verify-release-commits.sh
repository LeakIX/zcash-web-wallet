#!/bin/bash
# Verify that a PR targeting main has exactly 3 commits on top of develop:
# 1. A merge commit (merging main into the branch)
# 2. A commit updating only index.html (commit hash injection)
# 3. A commit updating only CHECKSUMS.json

set -e

BASE_REF="${1:-origin/develop}"
HEAD_SHA="${2:-HEAD}"

echo "Verifying release branch structure..."
echo "Base: $BASE_REF"
echo "Head: $HEAD_SHA"
echo ""

# Get the list of commits between develop and HEAD
COMMITS=$(git rev-list --reverse "$BASE_REF".."$HEAD_SHA")
COMMIT_COUNT=$(echo "$COMMITS" | grep -c . || true)

echo "Found $COMMIT_COUNT commit(s) on top of develop"
echo ""

if [ "$COMMIT_COUNT" -ne 3 ]; then
    echo "ERROR: Expected exactly 3 commits, found $COMMIT_COUNT"
    echo ""
    echo "Release branches must have exactly 3 commits on top of develop:"
    echo "  1. Merge main into the release branch"
    echo "  2. Inject commit hash (make inject-commit)"
    echo "  3. Update checksums (make generate-checksums)"
    exit 1
fi

# Convert to array
readarray -t COMMIT_ARRAY <<< "$COMMITS"

# Check commit 1: Must be a merge commit
COMMIT1="${COMMIT_ARRAY[0]}"
PARENT_COUNT=$(git rev-list --parents -n 1 "$COMMIT1" | wc -w)
# Parent count includes the commit itself, so merge commits have 3+ words
if [ "$PARENT_COUNT" -lt 3 ]; then
    echo "ERROR: First commit ($COMMIT1) is not a merge commit"
    echo ""
    echo "The first commit must merge main into the release branch."
    echo "Run: git merge origin/main"
    exit 1
fi
echo "✓ Commit 1: Merge commit"
git log --oneline -1 "$COMMIT1"
echo ""

# Check commit 2: Must only modify index.html
COMMIT2="${COMMIT_ARRAY[1]}"
FILES_CHANGED2=$(git diff-tree --no-commit-id --name-only -r "$COMMIT2")
if [ "$FILES_CHANGED2" != "frontend/index.html" ]; then
    echo "ERROR: Second commit ($COMMIT2) must only modify frontend/index.html"
    echo ""
    echo "Files changed:"
    echo "$FILES_CHANGED2"
    echo ""
    echo "Run: make inject-commit"
    exit 1
fi
echo "✓ Commit 2: index.html update (commit hash injection)"
git log --oneline -1 "$COMMIT2"
echo ""

# Check commit 3: Must only modify CHECKSUMS.json
COMMIT3="${COMMIT_ARRAY[2]}"
FILES_CHANGED3=$(git diff-tree --no-commit-id --name-only -r "$COMMIT3")
if [ "$FILES_CHANGED3" != "CHECKSUMS.json" ]; then
    echo "ERROR: Third commit ($COMMIT3) must only modify CHECKSUMS.json"
    echo ""
    echo "Files changed:"
    echo "$FILES_CHANGED3"
    echo ""
    echo "Run: make generate-checksums"
    exit 1
fi
echo "✓ Commit 3: CHECKSUMS.json update"
git log --oneline -1 "$COMMIT3"
echo ""

echo "OK: Release branch structure is valid"
