import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  generateTestWallet,
  restoreTestWallet,
  saveWalletToBrowser,
  TEST_SEED,
  EXPECTED_TRANSPARENT_ADDR,
  EXPECTED_UFVK_PREFIX,
} from "./helpers.js";

test.describe("Wallet Generation and Restoration", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should generate a new wallet", async ({ page }) => {
    await navigateToTab(page, "wallet");

    const walletName = "My Test Wallet";
    await page.fill("#walletAlias", walletName);
    await page.selectOption("#walletNetwork", "testnet");
    await page.fill("#generateAccount", "0");

    await page.click("#generateWalletBtn");

    await expect(page.locator("#walletSuccess")).toBeVisible({
      timeout: 10000,
    });
    await expect(page.locator("#seedPhraseDisplay")).not.toBeEmpty();
    await expect(page.locator("#ufvkDisplay")).not.toBeEmpty();
  });

  test("should generate a 24-word seed phrase", async ({ page }) => {
    await generateTestWallet(page, "Word Count Test");

    const seedPhrase = await page
      .locator("#seedPhraseDisplay")
      .textContent();
    const words = seedPhrase.trim().split(/\s+/);
    expect(words.length).toBe(24);
  });

  test("should allow copying seed phrase", async ({ page }) => {
    await generateTestWallet(page);

    await page.click("#copySeedBtn");

    await page.waitForTimeout(500);
  });

  test("should restore wallet from seed phrase", async ({ page }) => {
    await navigateToTab(page, "wallet");

    const walletName = "Restored Test Wallet";
    await page.fill("#restoreAlias", walletName);
    await page.selectOption("#restoreNetwork", "testnet");
    await page.fill("#restoreAccount", "0");
    await page.fill("#restoreSeed", TEST_SEED);

    await page.click("#restoreWalletBtn");

    await expect(page.locator("#walletSuccess")).toBeVisible({
      timeout: 10000,
    });
  });

  test("should restore wallet with correct transparent address", async ({
    page,
  }) => {
    await restoreTestWallet(page);

    const transparentAddr = await page
      .evaluate(() => {
        const wallets = JSON.parse(localStorage.getItem("zcash_wallets"));
        return wallets[Object.keys(wallets)[0]].transparent_address;
      })
      .catch(() => null);

    expect(transparentAddr).toBe(EXPECTED_TRANSPARENT_ADDR);
  });

  test("should restore wallet with correct UFVK", async ({ page }) => {
    await restoreTestWallet(page);

    const ufvk = await page.locator("#ufvkDisplay").textContent();
    expect(ufvk).toContain(EXPECTED_UFVK_PREFIX);
  });

  test("should save wallet to browser localStorage", async ({ page }) => {
    await generateTestWallet(page, "Saved Wallet");
    await saveWalletToBrowser(page);

    const walletsInStorage = await page.evaluate(() => {
      return localStorage.getItem("zcash_wallets");
    });

    expect(walletsInStorage).not.toBeNull();
    const wallets = JSON.parse(walletsInStorage);
    expect(Object.keys(wallets).length).toBe(1);
    expect(wallets[Object.keys(wallets)[0]].alias).toBe("Saved Wallet");
  });

  test("should allow downloading wallet JSON", async ({ page }) => {
    await generateTestWallet(page);

    const downloadPromise = page.waitForEvent("download");
    await page.click("#downloadWalletBtn");
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toMatch(/zcash-wallet.*\.json/);
  });

  test("should display saved wallets list", async ({ page }) => {
    await generateTestWallet(page, "First Wallet");
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);
    await navigateToTab(page, "wallet");

    await expect(page.locator("#savedWalletsList")).toContainText(
      "First Wallet",
    );
  });

  test("should generate different addresses for different account indices", async ({
    page,
  }) => {
    await navigateToTab(page, "wallet");

    await page.fill("#restoreAlias", "Account 0");
    await page.selectOption("#restoreNetwork", "testnet");
    await page.fill("#restoreAccount", "0");
    await page.fill("#restoreSeed", TEST_SEED);
    await page.click("#restoreWalletBtn");
    await expect(page.locator("#walletSuccess")).toBeVisible({
      timeout: 10000,
    });

    const addr0 = await page.evaluate(() => {
      const wallets = JSON.parse(localStorage.getItem("zcash_wallets"));
      return wallets[Object.keys(wallets)[0]].transparent_address;
    });

    await page.goto("/");
    await clearLocalStorage(page);
    await page.reload();
    await waitForWasmLoad(page);
    await navigateToTab(page, "wallet");

    await page.fill("#restoreAlias", "Account 1");
    await page.selectOption("#restoreNetwork", "testnet");
    await page.fill("#restoreAccount", "1");
    await page.fill("#restoreSeed", TEST_SEED);
    await page.click("#restoreWalletBtn");
    await expect(page.locator("#walletSuccess")).toBeVisible({
      timeout: 10000,
    });

    const addr1 = await page.evaluate(() => {
      const wallets = JSON.parse(localStorage.getItem("zcash_wallets"));
      return wallets[Object.keys(wallets)[0]].transparent_address;
    });

    expect(addr0).not.toBe(addr1);
  });
});
