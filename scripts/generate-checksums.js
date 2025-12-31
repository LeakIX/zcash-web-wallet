#!/usr/bin/env node
// Generate checksums for frontend files
// This script is run during the build process to create CHECKSUMS.json

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// Files to checksum (relative to frontend/)
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
  "js/storage/endpoints.js",
  "js/storage/notes.js",
  "js/storage/wallets.js",
  "js/storage/ledger.js",
  "css/style.css",
  "index.html",
];

function sha256File(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  return crypto.createHash("sha256").update(content).digest("hex");
}

function getGitCommitHash() {
  try {
    const { execSync } = require("child_process");
    return execSync("git rev-parse HEAD").toString().trim();
  } catch (error) {
    console.error("Warning: Could not get git commit hash:", error.message);
    return "unknown";
  }
}

function generateChecksums() {
  const frontendDir = path.join(__dirname, "..", "frontend");
  const checksums = {
    version: getGitCommitHash(),
    timestamp: new Date().toISOString(),
    files: {},
  };

  console.log("Generating checksums...");
  console.log(`Version: ${checksums.version}`);
  console.log(`Timestamp: ${checksums.timestamp}`);
  console.log("");

  for (const file of FILES_TO_CHECKSUM) {
    const filePath = path.join(frontendDir, file);

    if (!fs.existsSync(filePath)) {
      console.error(`ERROR: File not found: ${file}`);
      process.exit(1);
    }

    const hash = sha256File(filePath);
    checksums.files[file] = hash;
    console.log(`  ${file}: ${hash.substring(0, 16)}...`);
  }

  // Write to root directory
  const outputPath = path.join(__dirname, "..", "CHECKSUMS.json");
  fs.writeFileSync(outputPath, JSON.stringify(checksums, null, 2));

  console.log("");
  console.log(`Checksums written to: ${outputPath}`);
  console.log(`Total files: ${Object.keys(checksums.files).length}`);
}

// Run if called directly
if (require.main === module) {
  generateChecksums();
}

module.exports = { generateChecksums };
