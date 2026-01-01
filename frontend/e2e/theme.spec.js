import { test, expect } from "@playwright/test";
import { clearLocalStorage } from "./helpers.js";

test.describe("Theme and Settings", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

  });

  test("should start with light theme by default", async ({ page }) => {
    const theme = await page.evaluate(() => {
      return document.documentElement.getAttribute("data-bs-theme");
    });
    expect(theme).toBeNull();
  });

  test("should toggle to dark theme", async ({ page }) => {
    await page.click("#themeToggle");

    const theme = await page.evaluate(() => {
      return document.documentElement.getAttribute("data-bs-theme");
    });
    expect(theme).toBe("dark");
  });

  test("should toggle back to light theme", async ({ page }) => {
    await page.click("#themeToggle");
    await page.click("#themeToggle");

    const theme = await page.evaluate(() => {
      return document.documentElement.getAttribute("data-bs-theme");
    });
    expect(theme).toBeNull();
  });

  test("should persist theme preference in localStorage", async ({ page }) => {
    await page.click("#themeToggle");

    const storedTheme = await page.evaluate(() => {
      return localStorage.getItem("theme");
    });
    expect(storedTheme).toBe("dark");
  });

  test("should load theme from localStorage on page reload", async ({
    page,
  }) => {
    await page.click("#themeToggle");
    await page.reload();

    const theme = await page.evaluate(() => {
      return document.documentElement.getAttribute("data-bs-theme");
    });
    expect(theme).toBe("dark");
  });

  test("should update theme icon when toggling", async ({ page }) => {
    const initialIcon = await page.locator("#themeIcon").getAttribute("class");

    await page.click("#themeToggle");

    const updatedIcon = await page.locator("#themeIcon").getAttribute("class");
    expect(updatedIcon).not.toBe(initialIcon);
  });
});

test.describe("View Mode", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

  });

  test("should switch to simple view", async ({ page }) => {
    await page.click("#viewSimple");

    await expect(page.locator("#simpleView")).toBeVisible();
    await expect(page.locator("#mainTabs")).not.toBeVisible();
  });

  test("should switch to accountant view", async ({ page }) => {
    await page.click("#viewAccountant");

    await expect(page.locator("#viewAccountant")).toBeChecked();
  });

  test("should persist view mode in localStorage", async ({ page }) => {
    await page.click("#viewSimple");

    const storedViewMode = await page.evaluate(() => {
      return localStorage.getItem("viewMode");
    });
    expect(storedViewMode).toBe("simple");
  });

  test("should restore view mode from localStorage", async ({ page }) => {
    await page.click("#viewSimple");
    await page.reload();

    await expect(page.locator("#viewSimple")).toBeChecked();
    await expect(page.locator("#simpleView")).toBeVisible();
  });
});
