import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  switchToAdminView,
} from "./helpers.js";

test.describe("Basic Application", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
  });

  test("should load the page and display title", async ({ page }) => {
    await expect(page).toHaveTitle("Zcash Web Wallet");
    await expect(page.locator("h1.display-5")).toContainText(
      "Zcash Web Wallet"
    );
  });

  test("should load WASM module successfully", async ({ page }) => {
    await waitForWasmLoad(page);
  });

  test("should have all main tabs visible in admin view", async ({ page }) => {
    await switchToAdminView(page);
    await expect(page.locator("#viewer-tab")).toBeVisible();
    await expect(page.locator("#scanner-tab")).toBeVisible();
    await expect(page.locator("#wallet-tab")).toBeVisible();
    await expect(page.locator("#addresses-tab")).toBeVisible();
    await expect(page.locator("#send-tab")).toBeVisible();
  });

  test("should start in simple view mode by default", async ({ page }) => {
    await expect(page.locator("#viewSimple")).toBeChecked();
    await expect(page.locator("#simpleView")).toBeVisible();
  });

  test("should show admin tabs when switching to admin view", async ({
    page,
  }) => {
    await switchToAdminView(page);
    await expect(page.locator("#mainTabs")).toBeVisible();
    await expect(page.locator("#simpleView")).not.toBeVisible();
  });
});
