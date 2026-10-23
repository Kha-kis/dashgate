import { test, expect } from '@playwright/test';
import { login } from '../helpers/auth';

test.describe('DashGate UI', () => {
  // Preference fixtures must reach Playwright routes rather than the PWA service worker.
  test.use({ serviceWorkers: 'block' });
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('app categories and apps render', async ({ page }) => {
    // Categories from test-config.yaml: Monitoring, Development
    await expect(page.locator('.category-section')).toHaveCount(2, {
      timeout: 5_000,
    });

    const categoryNames = page.locator('.category-name');
    await expect(categoryNames.nth(0)).toHaveText('Monitoring');
    await expect(categoryNames.nth(1)).toHaveText('Development');

    // Admin user should see all 3 apps
    const appItems = page.locator('.app-item');
    await expect(appItems).toHaveCount(3, { timeout: 5_000 });
  });

  test('personal app renders before categories and syncs to a second browser', async ({ page, browser }) => {
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await page.locator('button[onclick="openMyAppModal()"]').click();
    await page.locator('#myAppName').fill('Personal E2E');
    await page.locator('#myAppUrl').fill('https://personal.example.test');
    await page.locator('#myAppModal .admin-btn-primary').click();

    const section = page.locator('#myAppsSection');
    await expect(section.getByRole('link', { name: 'Personal E2E' })).toBeVisible();
    await expect(page.locator('#totalCount')).toHaveText('3');
    expect(await section.locator('.app-grid').evaluate(el => getComputedStyle(el).display)).toBe('grid');
    await expect.poll(async () => page.locator('#myAppsSection').evaluate(el =>
      el.nextElementSibling?.classList.contains('category-section')
    )).toBe(true);

    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.[0]?.name;
    }).toBe('Personal E2E');

    const other = await browser.newContext();
    try {
      await other.addCookies(await page.context().cookies());
      const secondPage = await other.newPage();
      await secondPage.goto('/');
      await expect(secondPage.locator('#myAppsSection').getByRole('link', { name: 'Personal E2E' })).toBeVisible();
      expect(await secondPage.evaluate(() => localStorage.getItem('dashgate-my-apps'))).toContain('Personal E2E');
    } finally {
      await other.close();
    }

    await page.evaluate(() => (window as any).closeSettings());
    page.once('dialog', dialog => dialog.accept());
    await page.evaluate(() => (window as any).deleteMyApp(0));
    await expect(section).toHaveCount(0);
    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.length;
    }).toBe(0);
  });

  test('empty server apps remove stale local dashboard section', async ({ page }) => {
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ json: { myApps: [] } });
      } else {
        await route.continue();
      }
    });
    await page.evaluate(() => localStorage.setItem('dashgate-my-apps', JSON.stringify([
      { name: 'Stale App', url: 'https://stale.example.test' },
    ])));
    await page.reload();
    await expect(page.locator('#myAppsSection')).toHaveCount(0);
    expect(await page.evaluate(() => JSON.parse(localStorage.getItem('dashgate-my-apps') || '[]'))).toEqual([]);
  });

  test('missing server apps never expose another account cached links', async ({ page }) => {
    await page.route('**/api/user/preferences', route => route.fulfill({ json: {} }));
    await page.evaluate(() => localStorage.setItem('dashgate-my-apps', JSON.stringify([
      { name: 'Previous User Secret', url: 'https://private.example.test' },
    ])));
    await page.reload();
    await expect(page.locator('#myAppsSection')).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => (window as any).eval('prefsSyncEnabled'))).toBe(true);
    expect(await page.evaluate(() => (window as any).eval('myApps'))).toEqual([]);
  });

  test('legacy browser apps are preserved for explicit restoration', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    let fixtureUsed = false;
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET' && !fixtureUsed) {
        fixtureUsed = true;
        await route.fulfill({ json: {} });
      } else await route.continue();
    });
    await page.evaluate(() => {
      localStorage.removeItem('dashgate-my-apps-migration-checked');
      localStorage.removeItem('dashgate-my-apps-legacy-backup');
      localStorage.setItem('dashgate-my-apps', JSON.stringify([
        { name: 'Legacy Link', url: 'https://legacy.example.test' },
      ]));
    });
    await page.reload();
    await expect(page.locator('#myAppsSection')).toHaveCount(0);
    expect(await page.evaluate(() => localStorage.getItem('dashgate-my-apps-legacy-backup'))).toContain('Legacy Link');
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await expect(page.locator('#myAppsMigrationNotice')).toBeVisible();
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain('Legacy Link: https://legacy.example.test');
      await dialog.accept();
    });
    await page.locator('#restoreLegacyMyApps').click();
    await expect(page.locator('#myAppsSection')).toContainText('Legacy Link');
    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.[0]?.name;
    }).toBe('Legacy Link');
    await expect.poll(() => page.evaluate(() => localStorage.getItem('dashgate-my-apps-legacy-backup'))).toBeNull();
  });

  test('already synced browser apps do not trigger migration', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    const saved = [{ name: 'Already Synced', url: 'https://synced.example.test' }];
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET') await route.fulfill({ json: { myApps: saved } });
      else await route.continue();
    });
    await page.evaluate(value => {
      localStorage.removeItem('dashgate-my-apps-migration-checked');
      localStorage.removeItem('dashgate-my-apps-legacy-backup');
      localStorage.setItem('dashgate-my-apps', JSON.stringify(value));
    }, saved);
    await page.reload();
    await expect(page.locator('#myAppsSection')).toContainText('Already Synced');
    expect(await page.evaluate(() => localStorage.getItem('dashgate-my-apps-legacy-backup'))).toBeNull();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await expect(page.locator('#myAppsMigrationNotice')).toBeHidden();
  });

  test('unsynced edits to a known URL can be restored', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    const serverApp = { name: 'Old Name', url: 'https://same.example.test', description: '', icon: '' };
    const localApp = { ...serverApp, name: 'New Name', description: 'Unsynced edit' };
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET') await route.fulfill({ json: { myApps: [serverApp] } });
      else await route.continue();
    });
    await page.evaluate(value => {
      localStorage.removeItem('dashgate-my-apps-migration-checked');
      localStorage.removeItem('dashgate-my-apps-legacy-backup');
      localStorage.setItem('dashgate-my-apps', JSON.stringify([value]));
    }, localApp);
    await page.reload();
    await expect.poll(() => page.evaluate(() => localStorage.getItem('dashgate-my-apps-legacy-backup'))).toContain('New Name');
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    page.once('dialog', dialog => dialog.accept());
    await page.locator('#restoreLegacyMyApps').click();
    await page.unroute('**/api/user/preferences');
    await expect(page.locator('#myAppsSection')).toContainText('New Name');
    await expect(page.locator('#myAppsSection .app-item')).toHaveCount(1);
    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.[0]?.description;
    }).toBe('Unsynced edit');
  });

  test('older browser list can restore an unsynced deletion', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    const keep = { name: 'Keep', url: 'https://keep.example.test' };
    const deleted = { name: 'Deleted Locally', url: 'https://deleted.example.test' };
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET') await route.fulfill({ json: { myApps: [keep, deleted] } });
      else await route.continue();
    });
    await page.evaluate(value => {
      localStorage.removeItem('dashgate-my-apps-migration-checked');
      localStorage.removeItem('dashgate-my-apps-legacy-backup');
      localStorage.setItem('dashgate-my-apps', JSON.stringify(value));
    }, [keep]);
    await page.reload();
    await expect.poll(() => page.evaluate(() => localStorage.getItem('dashgate-my-apps-legacy-backup'))).toContain('Keep');
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain('Deleted Locally');
      await dialog.accept();
    });
    await page.locator('#restoreLegacyMyApps').click();
    await page.unroute('**/api/user/preferences');
    await expect(page.locator('#myAppsSection .app-item')).toHaveCount(1);
    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.map((app: any) => app.name);
    }).toEqual(['Keep']);
  });

  test('failed personal app sync remains recoverable for the same account', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    const rejectWrite = (route: any) => route.request().method() === 'PUT'
      ? route.fulfill({ status: 500, json: { error: 'temporary failure' } }) : route.continue();
    await page.route('**/api/user/preferences', rejectWrite);
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await page.locator('button[onclick="openMyAppModal()"]').click();
    await page.locator('#myAppName').fill('Pending App');
    await page.locator('#myAppUrl').fill('https://pending.example.test');
    await page.locator('#myAppModal .admin-btn-primary').click();
    await expect.poll(() => page.evaluate(() => {
      const key = (window as any).eval('myAppsPendingKey()');
      return JSON.parse(localStorage.getItem(key) || '[]').some((app: any) => app.name === 'Pending App');
    })).toBe(true);
    await page.reload();
    await expect(page.locator('#myAppsSection').getByText('Pending App')).toHaveCount(0);
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await expect(page.locator('#myAppsPendingNotice')).toBeVisible();
    await page.unroute('**/api/user/preferences', rejectWrite);
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain('Pending App');
      await dialog.accept();
    });
    await page.locator('#retryMyAppsSync').click();
    await expect(page.locator('#myAppsSection')).toContainText('Pending App');
    await expect(page.locator('#myAppsPendingNotice')).toBeHidden();
    await expect.poll(async () => {
      const response = await page.request.get('/api/user/preferences');
      return (await response.json()).myApps?.some((app: any) => app.name === 'Pending App');
    }).toBe(true);
  });

  test('pending sync previews newer account apps before replacement', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    await page.evaluate(() => {
      const key = (window as any).eval('myAppsPendingKey()');
      localStorage.setItem(key, JSON.stringify([{ name: 'Pending Local', url: 'https://local.example.test' }]));
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await expect(page.locator('#myAppsPendingNotice')).toBeVisible();
    let writes = 0;
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ json: { myApps: [{ name: 'Newer Remote', url: 'https://remote.example.test' }] } });
      } else if (route.request().method() === 'PUT') {
        writes++;
        await route.continue();
      } else await route.continue();
    });
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain('Newer Remote');
      expect(dialog.message()).toContain('Pending Local');
      await dialog.dismiss();
    });
    await page.locator('#retryMyAppsSync').click();
    expect(writes).toBe(0);
    await expect(page.locator('#myAppsPendingNotice')).toBeVisible();
  });

  test('discarding unsynced browser apps keeps account apps editable', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    await page.evaluate(() => {
      const key = (window as any).eval('myAppsPendingKey()');
      localStorage.setItem(key, JSON.stringify([{ name: 'Old Pending', url: 'https://old.example.test' }]));
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await expect(page.locator('#myAppsPendingNotice')).toBeVisible();
    page.once('dialog', async dialog => {
      expect(dialog.message()).toContain('Old Pending');
      await dialog.accept();
    });
    await page.locator('#discardPendingMyApps').click();
    await expect(page.locator('#myAppsPendingNotice')).toBeHidden();
    expect(await page.evaluate(() => localStorage.getItem((window as any).eval('myAppsPendingKey()')))).toBeNull();
    await page.locator('button[onclick="openMyAppModal()"]').click();
    await page.locator('#myAppName').fill('Editable Again');
    await page.locator('#myAppUrl').fill('https://editable.example.test');
    await page.locator('#myAppModal .admin-btn-primary').click();
    await expect(page.locator('#myAppsSection')).toContainText('Editable Again');
  });

  test('invalid personal app import does not create a pending copy', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="favorites"]').click();
    await page.locator('#myAppsImportInput').setInputFiles({
      name: 'invalid-apps.json',
      mimeType: 'application/json',
      buffer: Buffer.from('{"myApps":[null]}'),
    });
    await expect(page.locator('#myAppsPendingNotice')).toBeHidden();
    expect(await page.evaluate(() => localStorage.getItem((window as any).eval('myAppsPendingKey()')))).toBeNull();
  });

  test('preference sync stops if the signed-in account changes before writing', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    let writes = 0;
    await page.route('**/api/auth/me', route => route.fulfill({ json: { username: 'different-user', source: 'local' } }));
    await page.route('**/api/user/preferences', route => {
      if (route.request().method() === 'PUT') writes++;
      return route.continue();
    });
    const result = await page.evaluate(() => (window as any).syncPreferencesToServer());
    expect(result).toBe(false);
    expect(writes).toBe(0);
  });

  test('an older preference write cannot clear a newer pending edit', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    let writes = 0;
    let releaseFirst: (() => void) | undefined;
    await page.route('**/api/user/preferences', async route => {
      if (route.request().method() !== 'PUT') return route.continue();
      writes++;
      if (writes === 1) {
        await new Promise<void>(resolve => { releaseFirst = resolve; });
        await route.fulfill({ json: {} });
      } else {
        await route.fulfill({ status: 500, json: { error: 'temporary failure' } });
      }
    });
    const result = page.evaluate(async () => {
      (window as any).eval(`myApps = [{ name: 'First', url: 'https://first.example.test' }]; markMyAppsPending()`);
      const first = (window as any).syncPreferencesToServer();
      (window as any).eval(`myApps = [{ name: 'Second', url: 'https://second.example.test' }]; markMyAppsPending()`);
      const second = (window as any).syncPreferencesToServer();
      return Promise.all([first, second]);
    });
    await expect.poll(() => writes).toBe(1);
    releaseFirst!();
    expect(await result).toEqual([true, false]);
    expect(writes).toBe(2);
    expect(await page.evaluate(() => {
      const key = (window as any).eval('myAppsPendingKey()');
      return JSON.parse(localStorage.getItem(key) || '[]')[0]?.name;
    })).toBe('Second');
  });

  test('personal apps cannot be saved before account identity loads', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    const result = await page.evaluate(() => {
      localStorage.removeItem('dashgate-my-apps-legacy-backup');
      (window as any).eval('currentUser = null; prefsSyncEnabled = false');
      (document.getElementById('myAppName') as HTMLInputElement).value = 'Preauth App';
      (document.getElementById('myAppUrl') as HTMLInputElement).value = 'https://preauth.example.test';
      (window as any).saveMyApp();
      return { backup: localStorage.getItem('dashgate-my-apps-legacy-backup'), apps: (window as any).eval('myApps') };
    });
    expect(result.backup).toBeNull();
    expect(result.apps.some((app: any) => app.name === 'Preauth App')).toBe(false);
  });

  test('personal app fields cannot inject event handlers', async ({ page }) => {
    await page.route('**/api/user/preferences', route => route.fulfill({ json: {
      myApps: [{ name: 'Safe Name', url: 'https://example.test/" onclick="window.__injected=true', icon: 'https://missing.example.test/" onerror="window.__injected=true' }],
    } }));
    await page.reload();
    await expect(page.locator('#myAppsSection .app-item')).toHaveCount(1);
    await page.waitForTimeout(500);
    expect(await page.evaluate(() => (window as any).__injected || false)).toBe(false);
    await expect(page.locator('#myAppsSection .app-item')).not.toHaveAttribute('onclick');
  });

  test('personal apps appear in search immediately after sync', async ({ page }) => {
    await page.route('**/api/user/preferences', route => route.fulfill({ json: {
      myApps: [{ name: 'My Search App', url: 'https://search.example.test' }],
    } }));
    await page.reload();
    await expect(page.locator('#myAppsSection .app-item')).toBeVisible();
    await page.keyboard.press('Control+k');
    await page.locator('#searchInput').fill('My Search App');
    await expect(page.locator('#searchResults .search-result')).toContainText('My Search App');
  });

  test('health refresh updates shared card when personal URL matches', async ({ page }) => {
    await page.waitForLoadState('networkidle');
    await expect.poll(() => page.evaluate(() => (window as any).eval('prefsSyncEnabled'))).toBe(true);
    const sharedUrl = await page.locator('.category-section:not(#myAppsSection) .app-item').first().getAttribute('data-url');
    await page.evaluate(url => {
      (window as any).eval(`myApps = [{ name: "Duplicate", url: ${JSON.stringify(url)} }]; renderMyAppsOnDashboard()`);
    }, sharedUrl);
    let healthRequests = 0;
    await page.route('**/api/health', route => {
      healthRequests++;
      return route.fulfill({ json: [
        { apps: [{ url: sharedUrl, status: 'online' }] },
      ] });
    });
    await page.evaluate(() => (window as any).refreshHealth());
    expect(healthRequests).toBeGreaterThan(0);
    await expect(page.locator('.category-section:not(#myAppsSection) .app-item').first()).toHaveAttribute('data-status', 'online');
    await expect(page.locator('#onlineCount')).toHaveText('1');
  });

  test('personal apps render when there are no configured categories', async ({ page }) => {
    await expect.poll(() => page.evaluate(() => (window as any).eval('prefsSyncEnabled'))).toBe(true);
    await page.evaluate(() => {
      document.querySelectorAll('.category-section').forEach(el => el.remove());
      (window as any).eval('myApps = [{ name: "Only App", url: "https://only.example.test" }]; renderMyAppsOnDashboard()');
    });
    await expect(page.locator('.main-content #myAppsSection').getByRole('link', { name: 'Only App' })).toBeVisible();
  });

  test('unsafe personal app URLs from preferences are not linked on the dashboard', async ({ page }) => {
    await page.route('**/api/user/preferences', route => route.fulfill({ json: {
      myApps: [{ name: 'Unsafe', url: 'javascript:alert(1)' }],
    } }));
    await page.reload();
    await expect.poll(() => page.evaluate(() => (window as any).eval('prefsSyncEnabled'))).toBe(true);
    await expect(page.locator('#myAppsSection')).toHaveCount(0);
  });

  test('search modal opens with Ctrl+K', async ({ page }) => {
    await page.keyboard.press('Control+k');

    const searchModal = page.locator('#searchModal');
    await expect(searchModal).toBeVisible({ timeout: 3_000 });

    const searchInput = page.locator('#searchInput');
    await expect(searchInput).toBeFocused();
  });

  test('search filters results', async ({ page }) => {
    await page.keyboard.press('Control+k');
    await expect(page.locator('#searchModal')).toBeVisible();

    await page.fill('#searchInput', 'Grafana');

    const results = page.locator('#searchResults .search-result');
    await expect(results).toHaveCount(1, { timeout: 3_000 });
    await expect(results.first()).toContainText('Grafana');
  });

  test('search navigates with arrow keys', async ({ page }) => {
    await page.keyboard.press('Control+k');
    await expect(page.locator('#searchModal')).toBeVisible();

    // Clear and wait for all results
    await page.fill('#searchInput', '');

    const results = page.locator('#searchResults .search-result');
    await expect(results.first()).toBeVisible({ timeout: 3_000 });

    await page.keyboard.press('ArrowDown');
    const activeResult = page.locator(
      '#searchResults .search-result.selected'
    );
    await expect(activeResult).toHaveCount(1, { timeout: 2_000 });
  });

  test('search modal closes with Escape', async ({ page }) => {
    await page.keyboard.press('Control+k');
    await expect(page.locator('#searchModal')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(page.locator('#searchModal')).not.toBeVisible();
  });

  test('right-click context menu appears', async ({ page }) => {
    const firstApp = page.locator('.app-item').first();
    await firstApp.click({ button: 'right' });

    const contextMenu = page.locator('#contextMenu');
    await expect(contextMenu).toBeVisible({ timeout: 3_000 });

    await expect(page.locator('#contextMenu [data-action="open"]')).toBeVisible();
    await expect(page.locator('#contextMenu [data-action="copy"]')).toBeVisible();
    await expect(page.locator('#contextMenu [data-action="favorite"]')).toBeVisible();
  });

  test('context menu closes on click elsewhere', async ({ page }) => {
    const firstApp = page.locator('.app-item').first();
    await firstApp.click({ button: 'right' });
    await expect(page.locator('#contextMenu')).toBeVisible();

    await page.locator('body').click();
    await expect(page.locator('#contextMenu')).not.toBeVisible();
  });

  test('welcome greeting shows username', async ({ page }) => {
    const greeting = page.locator('.greeting');
    await expect(greeting).toBeVisible();
    const text = await greeting.textContent();
    expect(text).toBeTruthy();
    expect(text!.length).toBeGreaterThan(0);
  });

  test('unauthenticated access redirects to /login', async ({ page }) => {
    await page.context().clearCookies();
    await page.goto('/');

    await page.waitForURL('**/login', { timeout: 5_000 });
    expect(page.url()).toContain('/login');
  });
});
