import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  restoreTestWallet,
  saveWalletToBrowser,
  switchToSimpleView,
  switchToAdminView,
} from "./helpers.js";

test.describe("Simple View", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should display simple view when selected", async ({ page }) => {
    // App starts in simple view by default, verify it
    await expect(page.locator("#simpleView")).toBeVisible();
    await expect(page.locator("#mainTabs")).not.toBeVisible();
  });

  test("should display wallet selector in simple view", async ({ page }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleWalletSelect")).toBeVisible();
  });

  test("should show no wallets warning when no wallets exist", async ({
    page,
  }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleNoWalletsWarning")).toBeVisible();
  });

  test("should populate wallet selector when wallet exists", async ({
    page,
  }) => {
    await restoreTestWallet(page, "Simple View Test");
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    // restoreTestWallet switches to admin view, need to switch back
    await switchToSimpleView(page);

    const options = page.locator("#simpleWalletSelect option");
    const count = await options.count();
    expect(count).toBeGreaterThan(1);

    const optionsText = await options.allTextContents();
    expect(optionsText.some((text) => text.includes("Simple View Test"))).toBe(
      true
    );
  });

  test("should display balance card", async ({ page }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleBalance")).toBeVisible();
    const balance = await page.locator("#simpleBalance").textContent();
    expect(balance).toContain("0.00");
  });

  test("should display receive button", async ({ page }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleReceiveBtn")).toBeVisible();
  });

  test("should display send button", async ({ page }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleSendBtn")).toBeVisible();
  });

  test("should display transaction list", async ({ page }) => {
    // App starts in simple view by default
    await expect(page.locator("#simpleTransactionList")).toBeVisible();
    await expect(page.locator("#simpleTransactionList")).toContainText(
      "No transactions yet"
    );
  });

  test("should open receive modal when receive button clicked", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    // restoreTestWallet switches to admin view, need to switch back
    await switchToSimpleView(page);
    await page.selectOption("#simpleWalletSelect", { index: 1 });

    await page.click("#simpleReceiveBtn");

    await expect(page.locator("#receiveModal")).toBeVisible();
  });

  test("should show unified and transparent address tabs in receive modal", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    // restoreTestWallet switches to admin view, need to switch back
    await switchToSimpleView(page);
    await page.selectOption("#simpleWalletSelect", { index: 1 });

    await page.click("#simpleReceiveBtn");

    await expect(page.locator("#unified-tab")).toBeVisible();
    await expect(page.locator("#transparent-tab")).toBeVisible();
  });

  test("should display addresses in receive modal", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    // restoreTestWallet switches to admin view, need to switch back
    await switchToSimpleView(page);
    await page.selectOption("#simpleWalletSelect", { index: 1 });

    await page.click("#simpleReceiveBtn");

    await page.waitForTimeout(500);

    const unifiedAddr = await page
      .locator("#receiveUnifiedAddressDisplay")
      .textContent();
    expect(unifiedAddr).not.toContain("No wallet selected");

    await page.click("#transparent-tab");
    await page.waitForTimeout(200);

    const transparentAddr = await page
      .locator("#receiveTransparentAddressDisplay")
      .textContent();
    expect(transparentAddr).not.toContain("No wallet selected");
  });

  test("should have copy buttons in receive modal", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    // restoreTestWallet switches to admin view, need to switch back
    await switchToSimpleView(page);
    await page.selectOption("#simpleWalletSelect", { index: 1 });

    await page.click("#simpleReceiveBtn");

    await expect(page.locator("#copyUnifiedAddressBtn")).toBeVisible();

    await page.click("#transparent-tab");
    await expect(page.locator("#copyTransparentAddressBtn")).toBeVisible();
  });

  test("should link to wallet tab from no wallets warning", async ({
    page,
  }) => {
    // App starts in simple view by default
    const link = page.locator("#simpleGoToWalletTab");
    await expect(link).toBeVisible();

    await link.click();

    await expect(page.locator("#viewAdmin")).toBeChecked();
    await expect(page.locator("#wallet-pane")).toHaveClass(/active/);
  });
});
