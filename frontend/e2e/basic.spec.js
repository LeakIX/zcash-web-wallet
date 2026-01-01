import { test, expect } from "@playwright/test";
import { clearLocalStorage, waitForWasmLoad } from "./helpers.js";

test.describe("Basic Application", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
  });

  test("should load the page and display title", async ({ page }) => {
    await expect(page).toHaveTitle("Zcash Web Wallet");
    await expect(page.locator("h1")).toContainText("Zcash Web Wallet");
  });

  test("should load WASM module successfully", async ({ page }) => {
    await waitForWasmLoad(page);
    const wasmLoaded = await page.evaluate(() => {
      return typeof window.wasmModule !== "undefined";
    });
    expect(wasmLoaded).toBe(true);
  });

  test("should have all main tabs visible", async ({ page }) => {
    await expect(page.locator("#viewer-tab")).toBeVisible();
    await expect(page.locator("#scanner-tab")).toBeVisible();
    await expect(page.locator("#wallet-tab")).toBeVisible();
    await expect(page.locator("#addresses-tab")).toBeVisible();
    await expect(page.locator("#send-tab")).toBeVisible();
  });

  test("should start in admin view mode", async ({ page }) => {
    await expect(page.locator("#viewAdmin")).toBeChecked();
    await expect(page.locator("#mainTabs")).toBeVisible();
  });

  test("should hide admin tabs in simple view", async ({ page }) => {
    await page.click("#viewSimple");
    await expect(page.locator("#mainTabs")).not.toBeVisible();
    await expect(page.locator("#simpleView")).toBeVisible();
  });
});
