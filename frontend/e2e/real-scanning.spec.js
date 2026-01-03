import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  restoreTestWallet,
  restoreWalletWithSeed,
  saveWalletToBrowser,
} from "./helpers.js";

// =============================================================================
// Test fixtures from Rust codebase
// =============================================================================

// Seed phrase for the test wallet (from core/src/scanner.rs tests)
const SCANNER_TEST_SEED =
  "ahead pupil festival wife avoid yellow noodle puzzle pact alone ginger judge safe era spread lawn goat potato punch physical lamp oyster crisp attract";

// Transaction IDs
const RECEIVING_TXID =
  "0411ffa70699e3fdd5bfe30573d8d49c26939bc9598c3c44f4c07cf44f24f141";
const SPENDING_TXID =
  "5aa23ef474d119dc0262b1a350b00cf4d806ee72036c460f6bcf8252da96695f";

// Transaction hex data loaded inline
// These are from core/src/testdata/tx_*.hex fixtures

// Helper to load fixture files
async function loadFixtures() {
  const fs = await import("node:fs");
  const path = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  const receivingTxHex = fs
    .readFileSync(path.join(__dirname, "fixtures/tx_0411ffa7.hex"), "utf-8")
    .trim();
  const spendingTxHex = fs
    .readFileSync(path.join(__dirname, "fixtures/tx_5aa23ef4.hex"), "utf-8")
    .trim();

  return { receivingTxHex, spendingTxHex };
}

// =============================================================================
// Basic scanning tests with mocked RPC
// =============================================================================

test.describe("Transaction Scanning - Basic Flow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
    await waitForWasmLoad(page);
  });

  test("should show error for invalid transaction ID", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", "invalid-txid-format");
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible({ timeout: 5000 });
    const errorText = await page.locator("#scanError").textContent();
    expect(errorText).toMatch(/invalid|must be 64 characters/i);
  });

  test("should show error when RPC returns error", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          result: null,
          error: {
            code: -5,
            message: "No such mempool or blockchain transaction",
          },
          id: "zcash-viewer",
        }),
      });
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill(
      "#scanTxid",
      "0000000000000000000000000000000000000000000000000000000000000001"
    );
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible({ timeout: 5000 });
  });

  test("should handle network errors gracefully", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      await route.abort("failed");
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill(
      "#scanTxid",
      "0000000000000000000000000000000000000000000000000000000000000001"
    );
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible({ timeout: 5000 });
    const errorText = await page.locator("#scanError").textContent();
    expect(errorText.toLowerCase()).toMatch(/error|network|failed/);
  });

  test("should handle rate limiting", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      await route.fulfill({
        status: 429,
        contentType: "application/json",
        body: JSON.stringify({ error: "Rate limited" }),
      });
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill(
      "#scanTxid",
      "0000000000000000000000000000000000000000000000000000000000000001"
    );
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible({ timeout: 5000 });
    const errorText = await page.locator("#scanError").textContent();
    expect(errorText.toLowerCase()).toContain("rate");
  });

  test("should require wallet selection before scanning", async ({ page }) => {
    // Navigate directly to scanner tab without wallet
    await navigateToTab(page, "scanner");

    // Select network and RPC but NOT wallet
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill(
      "#scanTxid",
      "0000000000000000000000000000000000000000000000000000000000000001"
    );
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible();
    const errorText = await page.locator("#scanError").textContent();
    expect(errorText.toLowerCase()).toContain("wallet");
  });

  test("should require RPC endpoint selection", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");

    await page.fill(
      "#scanTxid",
      "0000000000000000000000000000000000000000000000000000000000000001"
    );
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible();
  });
});

// =============================================================================
// Real transaction scanning tests with fixtures from Rust codebase
// =============================================================================

test.describe("Transaction Scanning - Real Transactions", () => {
  let RECEIVING_TX_HEX;
  let SPENDING_TX_HEX;

  test.beforeAll(async () => {
    const fixtures = await loadFixtures();
    RECEIVING_TX_HEX = fixtures.receivingTxHex;
    SPENDING_TX_HEX = fixtures.spendingTxHex;
  });

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
    await waitForWasmLoad(page);
  });

  test("should scan receiving transaction and update storage", async ({
    page,
  }) => {
    // Restore wallet with the scanner test seed
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC to return the receiving transaction
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (
        postData?.method === "getrawtransaction" &&
        postData?.params?.[0] === RECEIVING_TXID
      ) {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    // Select wallet and network
    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    // Enter the receiving transaction ID
    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");

    // Wait for scan to complete
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify scan summary shows notes found
    const summaryText = await page.locator("#scanSummary").textContent();
    expect(summaryText).toContain("Scan Complete");

    // Verify notes are stored in localStorage
    const storedNotes = await page.evaluate(() => {
      return localStorage.getItem("zcash_viewer_notes");
    });
    expect(storedNotes).not.toBeNull();
    const notes = JSON.parse(storedNotes);
    expect(Object.keys(notes).length).toBeGreaterThan(0);

    // Verify ledger is updated
    const storedLedger = await page.evaluate(() => {
      return localStorage.getItem("zcash_viewer_ledger");
    });
    expect(storedLedger).not.toBeNull();
  });

  test("should display tracked notes after scanning", async ({ page }) => {
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify notes display is updated (should no longer show "No notes tracked")
    const notesDisplay = await page.locator("#notesDisplay").textContent();
    expect(notesDisplay).not.toContain("No notes tracked");
  });

  test("should update balance after scanning receiving transaction", async ({
    page,
  }) => {
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Get initial balance text
    const initialBalance = await page.locator("#balanceDisplay").textContent();
    expect(initialBalance).toContain("0.00000000");

    // Mock RPC
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");

    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify balance is updated (should show transparent balance)
    const updatedBalance = await page.locator("#balanceDisplay").textContent();
    // The receiving transaction has a transparent output, balance should be > 0
    expect(updatedBalance).toContain("Transparent");
  });

  test("should scan multiple transactions sequentially", async ({ page }) => {
    // This test verifies that multiple transactions can be scanned
    // The spending tx is transparent-only, so it won't mark shielded notes as spent
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC to return both transactions
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        const txid = postData?.params?.[0];
        if (txid === RECEIVING_TXID) {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              result: RECEIVING_TX_HEX,
              error: null,
              id: "zcash-viewer",
            }),
          });
        } else if (txid === SPENDING_TXID) {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              result: SPENDING_TX_HEX,
              error: null,
              id: "zcash-viewer",
            }),
          });
        } else {
          await route.continue();
        }
      } else {
        await route.continue();
      }
    });

    // Step 1: Scan receiving transaction (contains shielded outputs)
    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Get notes count after receiving
    const notesAfterReceive = await page.evaluate(() => {
      const notes = JSON.parse(
        localStorage.getItem("zcash_viewer_notes") || "{}"
      );
      return Object.keys(notes).length;
    });
    expect(notesAfterReceive).toBeGreaterThan(0);

    // Step 2: Scan second transaction (transparent-only)
    await page.fill("#scanTxid", SPENDING_TXID);
    await page.click("#scanTxBtn");
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify scan completed without error
    const summaryText = await page.locator("#scanSummary").textContent();
    expect(summaryText).toContain("Scan Complete");

    // Verify first transaction created a ledger entry
    // (The transparent-only spending tx may not create an entry since it's unrelated to wallet)
    const ledger = await page.evaluate(() => {
      return JSON.parse(localStorage.getItem("zcash_viewer_ledger") || "{}");
    });
    expect(ledger.entries).toBeDefined();
    expect(ledger.entries.length).toBeGreaterThanOrEqual(1);

    // Verify the receiving tx is in the ledger
    const hasReceivingTx = ledger.entries.some(
      (e) =>
        e.txid ===
        "0411ffa70699e3fdd5bfe30573d8d49c26939bc9598c3c44f4c07cf44f24f141"
    );
    expect(hasReceivingTx).toBe(true);
  });

  test("should persist notes across page reload", async ({ page }) => {
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Get notes count before reload
    const notesBeforeReload = await page.evaluate(() => {
      const notes = JSON.parse(
        localStorage.getItem("zcash_viewer_notes") || "{}"
      );
      return Object.keys(notes).length;
    });
    expect(notesBeforeReload).toBeGreaterThan(0);

    // Reload page
    await page.reload();
    await waitForWasmLoad(page);

    // Verify notes persisted
    const notesAfterReload = await page.evaluate(() => {
      const notes = JSON.parse(
        localStorage.getItem("zcash_viewer_notes") || "{}"
      );
      return Object.keys(notes).length;
    });
    expect(notesAfterReload).toBe(notesBeforeReload);

    // Verify notes display shows the tracked notes
    await navigateToTab(page, "scanner");
    const notesDisplay = await page.locator("#notesDisplay").textContent();
    expect(notesDisplay).not.toContain("No notes tracked");
  });

  test("should create ledger entries for transactions", async ({ page }) => {
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify ledger entry created
    const ledger = await page.evaluate(() => {
      return JSON.parse(localStorage.getItem("zcash_viewer_ledger") || "{}");
    });
    expect(ledger.entries).toBeDefined();
    expect(ledger.entries.length).toBeGreaterThan(0);

    // Verify ledger entry has correct txid
    const entry = ledger.entries.find((e) => e.txid === RECEIVING_TXID);
    expect(entry).toBeDefined();
    expect(entry.value_received).toBeGreaterThan(0);
  });

  test("should display ledger history after scanning", async ({ page }) => {
    await restoreWalletWithSeed(page, SCANNER_TEST_SEED, "Scanner Test Wallet");
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    // Mock RPC
    await page.route("**/zcash-testnet.gateway.tatum.io/**", async (route) => {
      const request = route.request();
      const postData = request.postDataJSON();

      if (postData?.method === "getrawtransaction") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            result: RECEIVING_TX_HEX,
            error: null,
            id: "zcash-viewer",
          }),
        });
      } else {
        await route.continue();
      }
    });

    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.selectOption("#scanNetwork", "testnet");
    await page.selectOption("#scanRpcEndpoint", { index: 2 });

    await page.fill("#scanTxid", RECEIVING_TXID);
    await page.click("#scanTxBtn");
    await expect(page.locator("#scanSummary")).toBeVisible({ timeout: 15000 });

    // Verify ledger display is updated
    const ledgerDisplay = await page.locator("#ledgerDisplay").textContent();
    expect(ledgerDisplay).not.toContain("No transaction history");
    expect(ledgerDisplay).toContain("Transaction History");
  });
});

// =============================================================================
// Optional: Real RPC tests (skipped by default)
// =============================================================================

test.describe("Transaction Scanning with Real RPC", () => {
  test.skip(
    () => !process.env.REAL_RPC,
    "Set REAL_RPC=true to run real network tests"
  );

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
    await waitForWasmLoad(page);
  });

  test("should connect to testnet RPC", async ({ page }) => {
    await navigateToTab(page, "viewer");

    await page.selectOption("#rpcEndpoint", { index: 2 });

    const selectedValue = await page.locator("#rpcEndpoint").inputValue();
    expect(selectedValue).toContain("tatum");
  });
});
