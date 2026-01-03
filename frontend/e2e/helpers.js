import { expect } from "@playwright/test";

export const TEST_SEED =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

export const EXPECTED_TRANSPARENT_ADDR = "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd";
export const EXPECTED_UFVK_PREFIX = "uviewtest1";

export async function clearLocalStorage(page) {
  await page.evaluate(() => {
    localStorage.clear();
  });
  await page.reload();
}

export async function waitForWasmLoad(page) {
  // Wait for WASM to load by checking that the error alert is not shown
  // If WASM fails to load, the app shows #errorAlert (removes d-none class)
  // If WASM loads successfully, #errorAlert keeps the d-none class
  await page.waitForFunction(
    () => {
      const errorAlert = document.querySelector("#errorAlert");
      // WASM loaded if error alert exists and is hidden (has d-none class)
      // This means the app initialized without showing an error
      if (errorAlert && errorAlert.classList.contains("d-none")) {
        return true;
      }
      // Also check if error alert is visible (WASM failed)
      if (errorAlert && !errorAlert.classList.contains("d-none")) {
        throw new Error("WASM module failed to load");
      }
      // Still waiting for DOM to be ready
      return false;
    },
    { timeout: 30000 }
  );
}

async function switchViewMode(page, mode) {
  // Check if mobile dropdown is visible
  const mobileDropdown = page.locator("#viewModeDropdown");
  const isMobile = await mobileDropdown.isVisible();

  if (isMobile) {
    // Mobile: Use dropdown
    await mobileDropdown.click();
    await page.locator(`button[data-view-mode="${mode}"]`).click();
  } else {
    // Desktop: Use radio button labels
    const viewModeRadio = page.locator(
      `#view${mode.charAt(0).toUpperCase() + mode.slice(1)}`
    );
    if (!(await viewModeRadio.isChecked())) {
      await page
        .locator(
          `label[for="view${mode.charAt(0).toUpperCase() + mode.slice(1)}"]`
        )
        .click();
    }
  }
}

export async function switchToAdminView(page) {
  await switchViewMode(page, "admin");
}

export async function switchToSimpleView(page) {
  await switchViewMode(page, "simple");
}

export async function switchToAccountantView(page) {
  await switchViewMode(page, "accountant");
}

export async function navigateToTab(page, tabId) {
  // Admin tabs require switching to admin view first
  await switchToAdminView(page);
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
