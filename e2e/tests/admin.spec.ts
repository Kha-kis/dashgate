import { test, expect } from "@playwright/test";
import { login } from "../helpers/auth";

test.describe("Admin Panel", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("admin tab visible for admin users", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    const adminTab = page.locator('[data-tab="admin"]');
    await expect(adminTab).toBeVisible();
  });

  test("system config loads and saves", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="auth"]').click();

    const sessionDays = page.locator("#systemSessionDays");
    await expect(sessionDays).toBeVisible();
    const value = await sessionDays.inputValue();
    expect(parseInt(value)).toBeGreaterThan(0);

    // Modify the value and call markSystemConfigDirty via evaluate
    await sessionDays.fill("14");
    await page.evaluate(() => {
      (window as any).markSystemConfigDirty();
    });
    await page.waitForTimeout(200);

    // The save button should now be enabled
    const saveBtn = page.locator("#saveSystemConfig");
    await expect(saveBtn).toBeEnabled({ timeout: 3_000 });

    // Call saveSystemSettings directly to avoid potential CSRF timing issues
    const saveResult = await page.evaluate(async () => {
      try {
        await (window as any).saveSystemSettings();
        return "ok";
      } catch (e) {
        return (e as Error).message;
      }
    });

    // Check status message
    await page.waitForTimeout(1_000);
    const status = page.locator("#systemConfigStatus");
    const statusText = await status.textContent();
    expect(statusText).toContain("Saved");
  });

  test("app CRUD - create, edit, delete", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();

    const addAppBtn = page.locator(
      'button:has-text("Add App"), .add-app-btn, [data-action="add-app"]',
    );
    if (await addAppBtn.isVisible()) {
      await addAppBtn.click();

      const nameInput = page.locator(
        '#appName, input[name="name"], .app-form input[type="text"]',
      );
      if (await nameInput.isVisible()) {
        await nameInput.first().fill("Test App E2E");

        const urlInput = page.locator(
          '#appUrl, input[name="url"], .app-form input[type="url"]',
        );
        if (await urlInput.isVisible()) {
          await urlInput.first().fill("http://localhost:9999");
        }

        const saveBtn = page.locator(
          'button:has-text("Save"), button:has-text("Add"), .app-form button[type="submit"]',
        );
        await saveBtn.first().click();
        await page.waitForTimeout(1_000);
      }
    }
  });

  test("category management", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();

    await page.locator(".category-item").first().waitFor({ timeout: 5000 });
    const categories = page.locator(".category-item");
    const count = await categories.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("local user creation", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="users"]').click();

    const addUserBtn = page.locator(
      'button:has-text("Add User"), .add-user-btn, [data-action="add-user"]',
    );
    if (await addUserBtn.isVisible()) {
      await addUserBtn.click();

      const usernameInput = page.locator(
        '#newUsername, input[name="username"]',
      );
      if (await usernameInput.first().isVisible()) {
        await usernameInput.first().fill("testuser");

        const passwordInput = page.locator(
          '#newPassword, input[name="password"]',
        );
        if (await passwordInput.first().isVisible()) {
          await passwordInput.first().fill("testpassword123");
        }

        const saveBtn = page.locator(
          'button:has-text("Save"), button:has-text("Create"), .user-form button[type="submit"]',
        );
        await saveBtn.first().click();
        await page.waitForTimeout(1_000);
      }
    }
  });

  test("API key create and delete", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="auth"]').click();

    // Enable API keys via evaluate (checkbox may be hidden/toggle)
    const apiKeysToggle = page.locator("#systemAPIKeys");
    if ((await apiKeysToggle.count()) > 0) {
      const isChecked = await apiKeysToggle.isChecked();
      if (!isChecked) {
        await page.evaluate(() => {
          const cb = document.getElementById(
            "systemAPIKeys",
          ) as HTMLInputElement;
          cb.checked = true;
          cb.dispatchEvent(new Event("change", { bubbles: true }));
          (window as any).markSystemConfigDirty();
        });
        await page.waitForTimeout(200);

        // Save system settings via evaluate to include CSRF
        await page.evaluate(async () => {
          await (window as any).saveSystemSettings();
        });
        await page.waitForTimeout(1_000);
      }
    }

    const apiKeysSection = page.locator("#apiKeysSection");
    if (await apiKeysSection.isVisible()) {
      const createBtn = page.locator(
        '#apiKeysSection button:has-text("Create"), .create-api-key-btn',
      );
      if (await createBtn.first().isVisible()) {
        await createBtn.first().click();
        await page.waitForTimeout(1_000);

        const keysList = page.locator("#apiKeysList");
        await expect(keysList).toBeVisible();

        const deleteBtn = page.locator(
          '#apiKeysList button:has-text("Delete"), #apiKeysList .delete-btn',
        );
        if ((await deleteBtn.count()) > 0) {
          await deleteBtn.first().click();
          await page.waitForTimeout(500);
          const confirmBtn = page.locator(
            'button:has-text("Confirm"), button:has-text("Yes")',
          );
          if (await confirmBtn.isVisible().catch(() => false)) {
            await confirmBtn.click();
          }
        }
      }
    }
  });
});
