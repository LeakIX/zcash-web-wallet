import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  restoreTestWallet,
  saveWalletToBrowser,
} from "./helpers.js";

test.describe("Scanner and Notes", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should display warning when no wallets are saved", async ({ page }) => {
    await navigateToTab(page, "scanner");

    await expect(page.locator("#noWalletsWarning")).toBeVisible();
  });

  test("should populate wallet selector when wallet exists", async ({
    page,
  }) => {
    await restoreTestWallet(page, "Scanner Test");
    await saveWalletToBrowser(page);

    await navigateToTab(page, "scanner");

    const options = page.locator("#scanWalletSelect option");
    const count = await options.count();
    expect(count).toBeGreaterThan(1);

    const optionsText = await options.allTextContents();
    expect(optionsText.some((text) => text.includes("Scanner Test"))).toBe(
      true
    );
  });

  test("should require all fields before scanning", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.selectOption("#scanWalletSelect", { index: 1 });

    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible();
  });

  test("should show error for invalid transaction ID format", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "scanner");

    await page.selectOption("#scanRpcEndpoint", { index: 1 });
    await page.selectOption("#scanWalletSelect", { index: 1 });
    await page.fill("#scanTxid", "invalid-txid");

    await page.click("#scanTxBtn");

    await expect(page.locator("#scanError")).toBeVisible({ timeout: 5000 });
  });

  test("should display notes placeholder when no notes exist", async ({
    page,
  }) => {
    await navigateToTab(page, "scanner");

    await expect(page.locator("#notesDisplay")).toContainText(
      "No notes tracked yet"
    );
  });

  test("should display ledger placeholder when no transactions exist", async ({
    page,
  }) => {
    await navigateToTab(page, "scanner");

    await expect(page.locator("#ledgerDisplay")).toContainText(
      "No transaction history yet"
    );
  });

  test("should show clear notes button", async ({ page }) => {
    await navigateToTab(page, "scanner");

    await expect(page.locator("#clearNotesBtn")).toBeVisible();
  });

  test("should clear notes when button clicked", async ({ page }) => {
    await navigateToTab(page, "scanner");

    const mockNotes = {
      testNote1: {
        value: 1000000,
        spent: false,
        pool: "sapling",
      },
    };

    await page.evaluate((notes) => {
      localStorage.setItem("zcash_viewer_notes", JSON.stringify(notes));
    }, mockNotes);

    await page.reload();
    await waitForWasmLoad(page);
    await navigateToTab(page, "scanner");

    page.on("dialog", (dialog) => dialog.accept());
    await page.click("#clearNotesBtn");

    await page.waitForTimeout(500);

    const storedNotes = await page.evaluate(() => {
      return localStorage.getItem("zcash_viewer_notes");
    });
    expect(storedNotes).toBeNull();
  });

  test("should persist notes in localStorage", async ({ page }) => {
    const testNotes = {
      note1: {
        value: 5000000,
        spent: false,
        pool: "sapling",
        txid: "abc123",
      },
    };

    await page.evaluate((notes) => {
      localStorage.setItem("zcash_viewer_notes", JSON.stringify(notes));
    }, testNotes);

    await page.reload();
    await waitForWasmLoad(page);

    const storedNotes = await page.evaluate(() => {
      return JSON.parse(localStorage.getItem("zcash_viewer_notes"));
    });

    expect(storedNotes).toEqual(testNotes);
  });

  test("should display balance card", async ({ page }) => {
    await navigateToTab(page, "scanner");

    await expect(page.locator("#balanceDisplay")).toBeVisible();
  });

  test("should select network for scanning", async ({ page }) => {
    await navigateToTab(page, "scanner");

    await page.selectOption("#scanNetwork", "mainnet");
    const selectedValue = await page.locator("#scanNetwork").inputValue();
    expect(selectedValue).toBe("mainnet");

    await page.selectOption("#scanNetwork", "testnet");
    const testnetValue = await page.locator("#scanNetwork").inputValue();
    expect(testnetValue).toBe("testnet");
  });
});
