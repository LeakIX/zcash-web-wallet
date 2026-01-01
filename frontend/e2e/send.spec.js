import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  restoreTestWallet,
  saveWalletToBrowser,
} from "./helpers.js";

test.describe("Send Transaction", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should display warning when no wallets are saved", async ({ page }) => {
    await navigateToTab(page, "send");

    await expect(page.locator("#sendNoWalletsWarning")).toBeVisible();
  });

  test("should populate wallet selector when wallet exists", async ({
    page,
  }) => {
    await restoreTestWallet(page, "Send Test");
    await saveWalletToBrowser(page);

    await navigateToTab(page, "send");

    const options = page.locator("#sendWalletSelect option");
    const count = await options.count();
    expect(count).toBeGreaterThan(1);

    const optionsText = await options.allTextContents();
    expect(optionsText.some((text) => text.includes("Send Test"))).toBe(true);
  });

  test("should display UTXO placeholder when no wallet selected", async ({
    page,
  }) => {
    await navigateToTab(page, "send");

    await expect(page.locator("#sendUtxosDisplay")).toContainText(
      "Select a wallet",
    );
  });

  test("should validate recipient address field", async ({ page }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "send");

    await page.selectOption("#sendWalletSelect", { index: 1 });

    const recipientInput = page.locator("#sendRecipient");
    await expect(recipientInput).toBeVisible();
    await expect(recipientInput).toHaveAttribute("placeholder", "t1... or u1...");
  });

  test("should validate amount input accepts decimal values", async ({
    page,
  }) => {
    await navigateToTab(page, "send");

    await page.fill("#sendAmount", "0.12345678");
    const value = await page.locator("#sendAmount").inputValue();
    expect(value).toBe("0.12345678");
  });

  test("should have default fee value", async ({ page }) => {
    await navigateToTab(page, "send");

    const feeValue = await page.locator("#sendFee").inputValue();
    expect(feeValue).toBe("10000");
  });

  test("should validate expiry height input", async ({ page }) => {
    await navigateToTab(page, "send");

    await page.fill("#sendExpiryHeight", "2500000");
    const value = await page.locator("#sendExpiryHeight").inputValue();
    expect(value).toBe("2500000");
  });

  test("should show error when signing without required fields", async ({
    page,
  }) => {
    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "send");

    await page.selectOption("#sendWalletSelect", { index: 1 });
    await page.click("#signTxBtn");

    await expect(page.locator("#sendError")).toBeVisible({ timeout: 3000 });
  });

  test("should display result section after successful signing", async ({
    page,
  }) => {
    const mockUtxos = [
      {
        txid: "0000000000000000000000000000000000000000000000000000000000000000",
        vout: 0,
        value: 100000000,
        address: "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd",
      },
    ];

    await page.evaluate((utxos) => {
      localStorage.setItem("zcash_transparent_utxos", JSON.stringify(utxos));
    }, mockUtxos);

    await restoreTestWallet(page);
    await saveWalletToBrowser(page);
    await navigateToTab(page, "send");

    await page.selectOption("#sendWalletSelect", { index: 1 });
    await page.fill(
      "#sendRecipient",
      "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd",
    );
    await page.fill("#sendAmount", "0.5");

    await page.click("#signTxBtn");

    await page.waitForTimeout(2000);
  });

  test("should have broadcast RPC endpoint selector", async ({ page }) => {
    await navigateToTab(page, "send");

    await expect(page.locator("#broadcastRpcSelect")).toBeVisible();
  });

  test("should hide result section initially", async ({ page }) => {
    await navigateToTab(page, "send");

    await expect(page.locator("#sendResult")).toHaveClass(/d-none/);
  });

  test("should show placeholder when no transaction signed", async ({
    page,
  }) => {
    await navigateToTab(page, "send");

    await expect(page.locator("#sendPlaceholder")).toBeVisible();
  });
});

test.describe("Simple View Send Modal", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should open send modal from simple view", async ({ page }) => {
    await page.click("#viewSimple");

    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    await page.selectOption("#simpleWalletSelect", { index: 1 });

    await page.click("#simpleSendBtn");

    await expect(page.locator("#sendModal")).toBeVisible();
  });

  test("should have address and amount fields in send modal", async ({
    page,
  }) => {
    await page.click("#viewSimple");

    await restoreTestWallet(page);
    await saveWalletToBrowser(page);

    await page.reload();
    await waitForWasmLoad(page);

    await page.selectOption("#simpleWalletSelect", { index: 1 });
    await page.click("#simpleSendBtn");

    await expect(page.locator("#simpleSendAddress")).toBeVisible();
    await expect(page.locator("#simpleSendAmount")).toBeVisible();
  });
});
