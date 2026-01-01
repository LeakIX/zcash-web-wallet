import { expect } from "@playwright/test";

export const TEST_SEED =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

export const EXPECTED_TRANSPARENT_ADDR = "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd";
export const EXPECTED_UFVK_PREFIX = "uviewtest1";

export async function clearLocalStorage(page) {
  await page.evaluate(() => {
    localStorage.clear();
  });
}

export async function waitForWasmLoad(page) {
  await page.waitForFunction(
    () => {
      return typeof window.wasmModule !== "undefined";
    },
    { timeout: 30000 },
  );
}

export async function switchToAdminView(page) {
  const viewModeRadio = page.locator("#viewAdmin");
  if (!(await viewModeRadio.isChecked())) {
    await viewModeRadio.click();
  }
}

export async function switchToSimpleView(page) {
  const viewModeRadio = page.locator("#viewSimple");
  if (!(await viewModeRadio.isChecked())) {
    await viewModeRadio.click();
  }
}

export async function navigateToTab(page, tabId) {
  await page.click(`#${tabId}-tab`);
  await page.waitForSelector(`#${tabId}-pane.active`, { state: "visible" });
}

export async function generateTestWallet(page, walletName = "Test Wallet") {
  await navigateToTab(page, "wallet");
  await page.fill("#walletAlias", walletName);
  await page.selectOption("#walletNetwork", "testnet");
  await page.fill("#generateAccount", "0");
  await page.click("#generateWalletBtn");

  await expect(page.locator("#walletSuccess")).toBeVisible({ timeout: 15000 });
}

export async function restoreTestWallet(page, walletName = "Restored Wallet") {
  await navigateToTab(page, "wallet");
  await page.fill("#restoreAlias", walletName);
  await page.selectOption("#restoreNetwork", "testnet");
  await page.fill("#restoreAccount", "0");
  await page.fill("#restoreSeed", TEST_SEED);
  await page.click("#restoreWalletBtn");

  await expect(page.locator("#walletSuccess")).toBeVisible({ timeout: 15000 });
}

export async function saveWalletToBrowser(page) {
  await page.click("#saveWalletBtn");
  await page.waitForTimeout(500);
}
