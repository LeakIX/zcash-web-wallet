import { test, expect } from "@playwright/test";
import { clearLocalStorage, navigateToTab } from "./helpers.js";

test.describe("RPC Endpoint Management", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

  });

  test("should display default RPC endpoints", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const options = page.locator("#rpcEndpoint option");
    const count = await options.count();
    expect(count).toBeGreaterThan(1);
  });

  test("should add a custom RPC endpoint", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const customEndpoint = "http://localhost:18232";
    await page.fill("#newEndpoint", customEndpoint);
    await page.click("#addEndpointBtn");

    await page.waitForTimeout(500);

    const options = page.locator("#rpcEndpoint option");
    const optionsText = await options.allTextContents();
    expect(optionsText.some((text) => text.includes(customEndpoint))).toBe(
      true,
    );
  });

  test("should persist custom endpoints in localStorage", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const customEndpoint = "http://localhost:18232";
    await page.fill("#newEndpoint", customEndpoint);
    await page.click("#addEndpointBtn");

    const storedEndpoints = await page.evaluate(() => {
      return localStorage.getItem("rpc_endpoints");
    });

    expect(storedEndpoints).toContain(customEndpoint);
  });

  test("should restore custom endpoints on page reload", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const customEndpoint = "http://localhost:18232";
    await page.fill("#newEndpoint", customEndpoint);
    await page.click("#addEndpointBtn");

    await page.reload();
    await navigateToTab(page, "viewer");

    const options = page.locator("#rpcEndpoint option");
    const optionsText = await options.allTextContents();
    expect(optionsText.some((text) => text.includes(customEndpoint))).toBe(
      true,
    );
  });

  test("should select an RPC endpoint", async ({ page }) => {
    await navigateToTab(page, "viewer");

    await page.selectOption("#rpcEndpoint", { index: 1 });

    const selectedValue = await page.locator("#rpcEndpoint").inputValue();
    expect(selectedValue).not.toBe("");
  });

  test("should clear endpoint input after adding", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const customEndpoint = "http://localhost:18232";
    await page.fill("#newEndpoint", customEndpoint);
    await page.click("#addEndpointBtn");

    const inputValue = await page.locator("#newEndpoint").inputValue();
    expect(inputValue).toBe("");
  });

  test("should not add empty endpoint", async ({ page }) => {
    await navigateToTab(page, "viewer");

    const initialOptionsCount = await page
      .locator("#rpcEndpoint option")
      .count();

    await page.fill("#newEndpoint", "");
    await page.click("#addEndpointBtn");

    const finalOptionsCount = await page
      .locator("#rpcEndpoint option")
      .count();
    expect(finalOptionsCount).toBe(initialOptionsCount);
  });

  test("should populate scanner RPC endpoint dropdown", async ({ page }) => {
    await navigateToTab(page, "scanner");

    const options = page.locator("#scanRpcEndpoint option");
    const count = await options.count();
    expect(count).toBeGreaterThan(1);
  });

  test("should sync custom endpoints across all dropdowns", async ({
    page,
  }) => {
    await navigateToTab(page, "viewer");

    const customEndpoint = "http://localhost:18232";
    await page.fill("#newEndpoint", customEndpoint);
    await page.click("#addEndpointBtn");

    await navigateToTab(page, "scanner");

    const scannerOptions = page.locator("#scanRpcEndpoint option");
    const scannerOptionsText = await scannerOptions.allTextContents();
    expect(
      scannerOptionsText.some((text) => text.includes(customEndpoint)),
    ).toBe(true);
  });
});
