import { test, expect } from "@playwright/test";
import {
  clearLocalStorage,
  waitForWasmLoad,
  navigateToTab,
  restoreTestWallet,
  saveWalletToBrowser,
  switchToSimpleView,
  EXPECTED_TRANSPARENT_ADDR,
} from "./helpers.js";

// Valid testnet transparent address
const VALID_TESTNET_ADDRESS = EXPECTED_TRANSPARENT_ADDR;
// Valid testnet unified address prefix
const VALID_TESTNET_UNIFIED =
  "utest1ql2ys5g5xed4v7x7gk89zwpwjgatj9hgv3fn7w2nv3fynk8fz7rqsmqjlqq6kh4wfwwnrz2k29w5k7a82q5zzg2qhg4z8f8n6q3j8f2c6q";

test.describe("Contact Address Book", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should display empty contacts list initially", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await expect(page.locator("#contactsList")).toContainText(
      "No contacts yet"
    );
  });

  test("should add a new contact with valid address", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await page.fill("#contactName", "Test Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.fill("#contactNotes", "Test notes");

    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();
    await expect(page.locator("#contactsList")).toContainText("Test Contact");
    await expect(page.locator("#contactsList")).toContainText("testnet");
  });

  test("should reject invalid address", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await page.fill("#contactName", "Invalid Contact");
    await page.fill("#contactAddress", "invalid-address-12345");
    await page.selectOption("#contactNetwork", "testnet");

    await page.click("#saveContactBtn");

    await expect(page.locator("#contactError")).toBeVisible();
    await expect(page.locator("#contactError")).toContainText("Unrecognized");
  });

  test("should require name field", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactError")).toContainText("name");
  });

  test("should require address field", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await page.fill("#contactName", "Test Contact");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactError")).toContainText("address");
  });

  test("should edit an existing contact", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // First add a contact
    await page.fill("#contactName", "Original Name");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactsList")).toContainText("Original Name");

    // Click edit button (secondary, with pencil icon)
    await page.click("#contactsList button.btn-outline-secondary");

    // Form should show "Edit Contact"
    await expect(page.locator("#contactFormTitle")).toContainText(
      "Edit Contact"
    );

    // Update the name
    await page.fill("#contactName", "Updated Name");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toContainText("updated");
    await expect(page.locator("#contactsList")).toContainText("Updated Name");
  });

  test("should delete a contact", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // First add a contact
    await page.fill("#contactName", "Contact To Delete");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactsList")).toContainText(
      "Contact To Delete"
    );

    // Accept the confirmation dialog
    page.on("dialog", (dialog) => dialog.accept());

    // Click delete button (the danger button)
    await page.click("#contactsList button.btn-outline-danger");

    await expect(page.locator("#contactsList")).toContainText(
      "No contacts yet"
    );
  });

  test("should prevent duplicate addresses", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // Add first contact
    await page.fill("#contactName", "First Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();

    // Wait for success message to disappear
    await page.waitForTimeout(2500);

    // Try to add another contact with same address
    await page.fill("#contactName", "Second Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactError")).toContainText("already exists");
  });

  test("should reset form after saving contact", async ({ page }) => {
    await navigateToTab(page, "contacts");

    await page.fill("#contactName", "Test Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.fill("#contactNotes", "Test notes");

    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();

    // Form should be cleared and title reset
    await expect(page.locator("#contactFormTitle")).toContainText(
      "Add New Contact"
    );
    await expect(page.locator("#contactName")).toHaveValue("");
    await expect(page.locator("#contactAddress")).toHaveValue("");
    await expect(page.locator("#contactNotes")).toHaveValue("");
  });

  test("should export contacts as JSON", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // Add a contact first
    await page.fill("#contactName", "Export Test");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    const downloadPromise = page.waitForEvent("download");
    await page.click("#exportContactsJsonBtn");
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toBe("zcash-contacts.json");
  });

  test("should export contacts as CSV", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // Add a contact first
    await page.fill("#contactName", "CSV Export Test");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    const downloadPromise = page.waitForEvent("download");
    await page.click("#exportContactsCsvBtn");
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toBe("zcash-contacts.csv");
  });

  test("should filter contacts with search input", async ({ page }) => {
    await navigateToTab(page, "contacts");

    // Add two contacts
    await page.fill("#contactName", "Alice");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");
    await expect(page.locator("#contactSuccess")).toBeVisible();

    await page.waitForTimeout(500);

    await page.fill("#contactName", "Bob");
    await page.fill("#contactAddress", "tmJY1xDisVrPwfBfAzBwRoPqDsTizyJJJJT");
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");
    await expect(page.locator("#contactSuccess")).toBeVisible();

    // Both contacts should be visible
    await expect(page.locator("#contactsList")).toContainText("Alice");
    await expect(page.locator("#contactsList")).toContainText("Bob");

    // Search for "Alice"
    await page.fill("#contactsSearchInput", "Alice");

    // Alice should be visible, Bob should be hidden
    const aliceItem = page
      .locator(".contact-item")
      .filter({ hasText: "Alice" });
    const bobItem = page.locator(".contact-item").filter({ hasText: "Bob" });

    await expect(aliceItem).toBeVisible();
    await expect(bobItem).toBeHidden();

    // Clear search
    await page.fill("#contactsSearchInput", "");

    // Both should be visible again
    await expect(aliceItem).toBeVisible();
    await expect(bobItem).toBeVisible();
  });
});

test.describe("Contact Autocomplete in Send Views", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);

    await waitForWasmLoad(page);
  });

  test("should show autocomplete dropdown for simple view send", async ({
    page,
  }) => {
    // First add a contact
    await navigateToTab(page, "contacts");
    await page.fill("#contactName", "Autocomplete Test");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();

    // Check that the autocomplete dropdown element exists
    const dropdown = page.locator("#simpleSendContactsDropdown");
    await expect(dropdown).toHaveCount(1);
  });

  test("should show autocomplete dropdown for admin send view", async ({
    page,
  }) => {
    // First add a contact
    await navigateToTab(page, "contacts");
    await page.fill("#contactName", "Admin View Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();

    // Wait for contact to be added to list
    await expect(page.locator("#contactsList")).toContainText(
      "Admin View Contact"
    );

    // Navigate to send tab and verify dropdown exists
    await navigateToTab(page, "send");
    const dropdown = page.locator("#sendRecipientContactsDropdown");
    await expect(dropdown).toHaveCount(1);
  });

  test("should copy address when using copy button", async ({
    page,
    browserName,
  }) => {
    // Skip on WebKit as clipboard permissions are not supported
    test.skip(
      browserName === "webkit",
      "Clipboard permissions not supported in WebKit"
    );

    // Add a contact
    await navigateToTab(page, "contacts");
    await page.fill("#contactName", "Copy Test");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactSuccess")).toBeVisible();
    await expect(page.locator("#contactsList")).toContainText("Copy Test");

    // Grant clipboard permissions for the test
    await page
      .context()
      .grantPermissions(["clipboard-read", "clipboard-write"]);

    // Click the copy button (primary variant with clipboard icon)
    await page.click("#contactsList button.btn-outline-primary");

    // Verify success message
    await expect(page.locator("#contactSuccess")).toContainText("copied");
  });
});

test.describe("Contact Persistence", () => {
  test("should persist contacts across page reloads", async ({ page }) => {
    await page.goto("/");
    await clearLocalStorage(page);
    await waitForWasmLoad(page);

    // Add a contact
    await navigateToTab(page, "contacts");
    await page.fill("#contactName", "Persistent Contact");
    await page.fill("#contactAddress", VALID_TESTNET_ADDRESS);
    await page.selectOption("#contactNetwork", "testnet");
    await page.click("#saveContactBtn");

    await expect(page.locator("#contactsList")).toContainText(
      "Persistent Contact"
    );

    // Reload the page
    await page.reload();
    await waitForWasmLoad(page);
    await navigateToTab(page, "contacts");

    // Contact should still be there
    await expect(page.locator("#contactsList")).toContainText(
      "Persistent Contact"
    );
  });
});
