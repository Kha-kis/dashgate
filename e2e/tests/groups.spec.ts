import { test, expect } from "@playwright/test";
import { login } from "../helpers/auth";

test.describe("Group Management", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="users"]').click();
    // Wait for admin data to load and groups to render
    await expect(page.locator("#localGroupsSection")).toBeVisible({
      timeout: 8000,
    });

    // Wait for at least the built-in groups (admin, admins, users) to appear
    await expect(
      page.locator("#localGroupsList .admin-item").first(),
    ).toBeVisible({ timeout: 8000 });
  });

  test("creates and shows a new managed group", async ({ page }) => {
    await page.locator("#newLocalGroupInput").fill("testgroup-e2e");
    await page
      .locator("#localGroupsSection button")
      .filter({ hasText: "Add" })
      .click();
    await page.waitForTimeout(500);

    const items = page.locator("#localGroupsList .admin-item-name");
    const names = await items.allTextContents();
    expect(names.some((n) => n.includes("testgroup-e2e"))).toBeTruthy();
  });

  test("deletes a managed group", async ({ page }) => {
    // Create first
    await page.locator("#newLocalGroupInput").fill("delete-me-group");
    await page
      .locator("#localGroupsSection button")
      .filter({ hasText: "Add" })
      .click();
    await page.waitForTimeout(500);

    // Ensure it was created
    const items = page.locator("#localGroupsList .admin-item-name");
    let names = await items.allTextContents();
    expect(names.some((n) => n.includes("delete-me-group"))).toBeTruthy();

    // Delete
    const groupRow = page
      .locator("#localGroupsList .admin-item")
      .filter({ hasText: "delete-me-group" });
    const deleteBtn = groupRow.locator(".admin-action-btn.danger");
    if ((await deleteBtn.count()) > 0) {
      await deleteBtn.click();
      await page.waitForTimeout(500);
    }

    // Verify it's gone
    names = await items.allTextContents();
    expect(names.some((n) => n.includes("delete-me-group"))).toBeFalsy();
  });

  test("prevents duplicate group creation", async ({ page }) => {
    // Create once
    await page.locator("#newLocalGroupInput").fill("unique-group");
    await page
      .locator("#localGroupsSection button")
      .filter({ hasText: "Add" })
      .click();
    await page.waitForTimeout(500);

    // Try duplicate
    await page.locator("#newLocalGroupInput").fill("unique-group");
    await page
      .locator("#localGroupsSection button")
      .filter({ hasText: "Add" })
      .click();
    await page.waitForTimeout(500);

    const toast = page.locator(".toast");
    await expect(toast).not.toBeEmpty({ timeout: 3000 });
    const toastText = await toast.textContent();
    expect(toastText).toContain("already exists");
  });
});
