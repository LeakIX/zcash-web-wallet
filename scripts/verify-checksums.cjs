#!/usr/bin/env node
// Verify that CHECKSUMS.json is up to date with the source files
// Returns exit code 0 if up to date, 1 if outdated

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// Files to checksum (must match generate-checksums.js)
const FILES_TO_CHECKSUM = [
  "js/app.js",
  "js/wasm.js",
  "js/decrypt-viewer.js",
  "js/scanner.js",
  "js/wallet.js",
  "js/addresses.js",
  "js/send.js",
  "js/views.js",
  "js/theme.js",
  "js/utils.js",
  "js/rpc.js",
  "js/constants.js",
  "js/contacts.js",
  "js/storage/endpoints.js",
  "js/storage/notes.js",
  "js/storage/wallets.js",
  "js/storage/ledger.js",
  "js/storage/contacts.js",
  "css/style.css",
  "index.html",
  "pkg/zcash_tx_viewer.js",
  "pkg/zcash_tx_viewer_bg.wasm",
];

function sha256File(filePath) {
  const isBinary = filePath.endsWith(".wasm");
  const content = fs.readFileSync(filePath, isBinary ? null : "utf8");
  return crypto.createHash("sha256").update(content).digest("hex");
}

function verifyChecksums() {
  const frontendDir = path.join(__dirname, "..", "frontend");
  const checksumsPath = path.join(__dirname, "..", "CHECKSUMS.json");

  // Check if CHECKSUMS.json exists
  if (!fs.existsSync(checksumsPath)) {
    console.error("ERROR: CHECKSUMS.json not found");
    console.error("Run 'make generate-checksums' to generate it");
    return { success: false, mismatches: [], missing: ["CHECKSUMS.json"] };
  }

  const checksums = JSON.parse(fs.readFileSync(checksumsPath, "utf8"));
  const mismatches = [];
  const missing = [];

  console.log("Verifying checksums...");
  console.log(`Version in CHECKSUMS.json: ${checksums.version}`);
  console.log("");

  for (const file of FILES_TO_CHECKSUM) {
    const filePath = path.join(frontendDir, file);

    if (!fs.existsSync(filePath)) {
      console.log(`  SKIP ${file} (file not found)`);
      missing.push(file);
      continue;
    }

    const actualHash = sha256File(filePath);
    const expectedHash = checksums.files[file];

    if (!expectedHash) {
      console.log(`  MISSING ${file} (not in CHECKSUMS.json)`);
      mismatches.push({ file, expected: null, actual: actualHash });
    } else if (actualHash !== expectedHash) {
      console.log(`  MISMATCH ${file}`);
      console.log(`    Expected: ${expectedHash.substring(0, 32)}...`);
      console.log(`    Actual:   ${actualHash.substring(0, 32)}...`);
      mismatches.push({ file, expected: expectedHash, actual: actualHash });
    } else {
      console.log(`  OK ${file}`);
    }
  }

  console.log("");

  if (mismatches.length > 0) {
    console.error(
      `ERROR: ${mismatches.length} file(s) have mismatched checksums`
    );
    console.error("Run 'make generate-checksums' to update CHECKSUMS.json");
    return { success: false, mismatches, missing };
  }

  if (missing.length > 0) {
    console.warn(
      `WARNING: ${missing.length} file(s) not found (may need to build first)`
    );
  }

  console.log("All checksums verified successfully");
  return { success: true, mismatches, missing };
}

// Run if called directly
if (require.main === module) {
  const result = verifyChecksums();
  process.exit(result.success ? 0 : 1);
}

module.exports = { verifyChecksums };
