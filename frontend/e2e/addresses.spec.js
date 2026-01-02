import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  restoreTestWallet,
  saveWalletToBrowser,
} from "./helpers.js";

test.describe("Address Display and Management", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should display warning when no wallets are saved", async ({ page }) => {
    await navigateToTab(page, "addresses");
    // When no wallet is selected, the placeholder shows "Select a wallet"
    await expect(page.locator("#addressesDisplay")).toContainText(
      "Select a wallet"
    );
  });

  test("should derive transparent and unified addresses", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await navigateToTab(page, "addresses");

    const walletOptions = page.locator("#addressWalletSelect option");
    const count = await walletOptions.count();
    expect(count).toBeGreaterThan(1);

    await page.selectOption("#addressWalletSelect", { index: 1 });
    await page.fill("#addressFromIndex", "0");
    await page.fill("#addressToIndex", "5");

    await page.click("#deriveAddressesBtn");

    await expect(page.locator("#addressesDisplay")).not.toContainText(
      "Select a wallet"
    );
    // Check for "Index" in the table header (no colon)
    await expect(page.locator("#addressesDisplay")).toContainText("Index");
  });

  test("should display both transparent and unified addresses", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "addresses");

    await page.selectOption("#addressWalletSelect", { index: 1 });
    await page.fill("#addressFromIndex", "0");
    await page.fill("#addressToIndex", "2");
    await page.click("#deriveAddressesBtn");

    await page.waitForTimeout(1000);

    await expect(page.locator("#addressesDisplay")).toContainText("tm");
    await expect(page.locator("#addressesDisplay")).toContainText("utest1");
  });

  test("should allow copying individual addresses", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "addresses");

    await page.selectOption("#addressWalletSelect", { index: 1 });
    await page.fill("#addressFromIndex", "0");
    await page.fill("#addressToIndex", "1");
    await page.click("#deriveAddressesBtn");

    await page.waitForTimeout(1000);

    const copyButtons = page.locator('button:has-text("Copy")');
    const buttonCount = await copyButtons.count();
    expect(buttonCount).toBeGreaterThan(0);
  });

  test("should show export buttons after deriving addresses", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "addresses");

    await page.selectOption("#addressWalletSelect", { index: 1 });
    await page.fill("#addressFromIndex", "0");
    await page.fill("#addressToIndex", "5");
    await page.click("#deriveAddressesBtn");

    await page.waitForTimeout(1000);

    await expect(page.locator("#copyAllAddressesBtn")).toBeVisible();
    await expect(page.locator("#exportAddressesCsvBtn")).toBeVisible();
  });

  test("should validate address index inputs accept numbers", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "addresses");

    await page.selectOption("#addressWalletSelect", { index: 1 });

    // Test that number inputs accept valid values
    await page.fill("#addressFromIndex", "0");
    await page.fill("#addressToIndex", "5");

    const fromValue = await page.locator("#addressFromIndex").inputValue();
    const toValue = await page.locator("#addressToIndex").inputValue();

    expect(fromValue).toBe("0");
    expect(toValue).toBe("5");
  });
});
