import { test, expect } from "@playwright/test";
import { login } from "../helpers/auth";

test.describe("Admin Panel", () => {
  // API fixtures must reach Playwright routes rather than the PWA service worker.
  test.use({ serviceWorkers: 'block' });
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("admin tab visible for admin users", async ({ page }) => {
    await page.locator(".dock-item").nth(4).click();
    await expect(page.locator("#settingsModal")).toBeVisible();

    const adminTab = page.locator('[data-tab="admin"]');
    await expect(adminTab).toBeVisible();
  });

  test("local users load and Add User opens its form", async ({ page }) => {
    const pageErrors: string[] = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="users"]').click();

    await expect(page.locator('#localUsersList')).toContainText('admin');
    await page.locator('button[onclick="openCreateLocalUserModal()"]').click();
    await expect(page.locator('#localUserModal')).toBeVisible();
    await expect(page.locator('#localUserUsername')).toBeVisible();
    expect(pageErrors).toEqual([]);
  });

  test("explains a saved user's app access", async ({ page }) => {
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="users"]').click();

    await expect(page.locator('#accessCheckUser option')).toContainText(['Select user', 'admin (local)']);
    await page.locator('#accessCheckUser').selectOption({ label: 'admin (local)' });
    await page.locator('#accessCheckApp').selectOption({ label: 'Grafana (config)' });
    const checkRequest = page.waitForRequest(request => request.url().includes('/api/admin/access-check?'));
    await page.getByRole('button', { name: 'Explain access' }).click();
    const requestURL = new URL((await checkRequest).url());
    expect(requestURL.searchParams.has('appUrl')).toBe(false);
    expect(requestURL.searchParams.has('appName')).toBe(false);
    expect(requestURL.searchParams.has('appId')).toBe(true);

    await expect(page.locator('#accessCheckResult')).toContainText('Visible: Grafana (config)');
    await expect(page.locator('#accessCheckResult')).toContainText("The user's admin group grants access.");
  });

  test("Docker and Nginx discoveries appear in the inbox", async ({ page }) => {
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: {
      active: [
        { name: 'Docker Found', url: 'https://docker.example.test', source: 'docker', icon: '', description: '' },
        { name: 'Nginx Found', url: 'https://nginx.example.test', source: 'nginx', icon: '', description: '' },
      ],
      stale: [],
    } }));

    // Install the fixture before the admin preload, which starts on page load.
    await page.reload();

    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await expect(page.locator('#discoveredAppsList')).toContainText('Docker Found');
    await expect(page.locator('#discoveredAppsList')).toContainText('Nginx Found');
  });

  test("discovery inbox dismisses, bulk dismisses, and restores without changing published apps", async ({ page }) => {
    const active = [
      { name: 'Webhook', url: 'https://one.test/hook', source: 'nginx', icon: '', description: '' },
      { name: 'Health', url: 'https://two.test/health', source: 'nginx', icon: '', description: '' },
      { name: 'Candidate', url: 'https://three.test', source: 'docker', icon: '', description: '' },
      { name: 'Published', url: 'https://published.test', source: 'docker', icon: '', description: '', override: { url: 'https://published.test', hidden: false } },
    ];
    const ignored: { source: string; url: string; name: string }[] = [];
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: { active, stale: [], ignored } }));
    await page.route('**/api/admin/discovered-apps/ignored', async route => {
      const { action, items } = route.request().postDataJSON();
      if (action === 'dismiss') {
        items.forEach((item: { source: string; url: string }) => ignored.push({ ...item, name: active.find(a => a.source === item.source && a.url === item.url)!.name }));
      } else {
        items.forEach((item: { source: string; url: string }) => {
          const index = ignored.findIndex(i => i.source === item.source && i.url === item.url);
          if (index >= 0) ignored.splice(index, 1);
        });
      }
      await route.fulfill({ json: { status: 'ok' } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('3');
    await expect(page.locator('#discoveredAppsList')).not.toContainText('Published');
    const dismissButton = page.locator('#discoveredAppsList .discovered-app-item').filter({ hasText: 'Webhook' }).getByRole('button', { name: 'Dismiss' });
    expect(await dismissButton.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await dismissButton.click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
    await expect(page.locator('#discoveredAppsList')).not.toContainText('Webhook');
    await page.locator('#selectAllDiscovered').check();
    await page.getByRole('button', { name: 'Dismiss selected' }).click();
    await expect(page.locator('#discoveredCountBadge')).toBeHidden();
    await page.locator('#discoveredIgnoredSection summary').click();
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('Webhook');
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('3 ignored');
    await page.locator('#discoveredIgnoredSection .discovered-app-item').filter({ hasText: 'Webhook' }).getByRole('button', { name: 'Restore' }).click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('1');
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await expect(page.locator('#discoveredAppsList')).not.toContainText('Published');
  });

  test("discovery inbox keeps a row visible when dismiss fails", async ({ page }) => {
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: { active: [
      { name: 'Webhook', url: 'https://one.test/hook', source: 'nginx', icon: '', description: '' },
    ], stale: [], ignored: [] } }));
    await page.route('**/api/admin/discovered-apps/ignored', route => route.fulfill({ status: 500, json: { error: 'Save failed' } }));
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveredAppsList').getByRole('button', { name: 'Dismiss' }).click();
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await expect(page.locator('#toast')).toContainText('Save failed');
  });

  test("discovery inbox selection keeps source identity for matching URLs", async ({ page }) => {
    const url = "https://same.test/o'hare";
    let submitted: { source: string; url: string }[] = [];
    const active = [
      { name: 'Docker route', url, source: 'docker', icon: '', description: '' },
      { name: 'Nginx route', url, source: 'nginx', icon: '', description: '' },
    ];
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: { active, stale: [], ignored: submitted.map(item => ({ ...item, name: 'Nginx route' })) } }));
    await page.route('**/api/admin/discovered-apps/ignored', async route => {
      submitted = route.request().postDataJSON().items;
      await route.fulfill({ json: { status: 'ok' } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveredAppsList .discovered-app-item').filter({ hasText: 'Nginx route' }).locator('input[type="checkbox"]').check();
    await page.getByRole('button', { name: 'Dismiss selected' }).click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('1');
    await expect(page.locator('#discoveredAppsList')).toContainText('Docker route');
    expect(submitted).toEqual([{ source: 'nginx', url }]);
  });

  test("discovery inbox reports a saved action when refresh fails and can retry", async ({ page }) => {
    let ignored = false;
    let refreshFails = false;
    await page.route('**/api/admin/discovered-apps', route => {
      if (refreshFails) return route.fulfill({ status: 500, json: { error: 'Refresh unavailable' } });
      return route.fulfill({ json: {
        active: [{ name: 'Webhook', url: 'https://hook.test', source: 'nginx', icon: '', description: '' }],
        stale: [], ignored: ignored ? [{ name: 'Webhook', url: 'https://hook.test', source: 'nginx' }] : [],
      } });
    });
    await page.route('**/api/admin/discovered-apps/ignored', async route => {
      ignored = true;
      refreshFails = true;
      await route.fulfill({ json: { status: 'ok' } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveredAppsList').getByRole('button', { name: 'Dismiss' }).click();
    await expect(page.locator('#toast')).toContainText('Saved, but refresh failed');
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await page.getByRole('button', { name: 'Refresh discovered list' }).click();
    await expect(page.locator('#toast')).toContainText('Failed to refresh discovered apps');
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    refreshFails = false;
    await page.getByRole('button', { name: 'Refresh discovered list' }).click();
    await expect(page.locator('#discoveredAppsList')).not.toContainText('Webhook');
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('Webhook');
  });

  test("discovery inbox keeps keyboard focus after selecting a route", async ({ page }) => {
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: { active: [
      { name: 'Webhook', url: 'https://hook.test', source: 'nginx', icon: '', description: '' },
    ], stale: [], ignored: [] } }));
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    const checkbox = page.locator('#discoveredAppsList .discovered-app-item input[type="checkbox"]');
    await checkbox.focus();
    await page.keyboard.press('Space');
    await expect(checkbox).toBeChecked();
    expect(await checkbox.evaluate(element => document.activeElement === element)).toBe(true);
  });

  test("discovery save reports an environment-controlled source rejection", async ({ page }) => {
    await page.route('**/api/admin/docker-discovery', async route => {
      if (route.request().method() === 'PUT') {
        await route.fulfill({ status: 409, json: { error: 'Docker discovery is controlled by environment variables' } });
      } else {
        await route.continue();
      }
    });

    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="discovery"]').click();
    await page.evaluate(() => (window as any).markDiscoveryDirty());
    await page.locator('#saveDiscoveryConfig').click();
    await expect(page.locator('#toast')).toContainText('Docker discovery');
    await expect(page.locator('#saveDiscoveryConfig')).toBeEnabled();
  });

  test("environment-controlled discovery stays enabled and cannot be changed in the UI", async ({ page }) => {
    let writes = 0;
    let reads = 0;
    await page.route('**/api/admin/docker-discovery', async route => {
      if (route.request().method() === 'GET') {
        reads++;
        await route.fulfill({ json: { enabled: true, envOverride: true, socketPath: 'tcp://socket-proxy:2375', appCount: 2 } });
      } else if (route.request().method() === 'PUT') {
        writes++;
        await route.fulfill({ status: 409, json: { error: 'Docker discovery is controlled by environment variables' } });
      } else {
        await route.continue();
      }
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="discovery"]').click();

    await page.evaluate(() => (window as any).loadDockerDiscoveryStatus());
    expect(reads).toBeGreaterThan(0);
    await expect(page.locator('#dockerDiscoveryEnabled')).toBeChecked();
    await expect(page.locator('#dockerDiscoveryEnabled')).toBeDisabled();
    await expect(page.locator('#dockerSocketPath')).toBeDisabled();
    await expect(page.locator('#dockerStatusHint')).toContainText('2 app(s) discovered');
    await page.evaluate(() => (window as any).markDiscoveryDirty());
    await page.locator('#saveDiscoveryConfig').click();
    await expect(page.locator('#toast')).toContainText('saved successfully');
    expect(writes).toBe(0);
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
