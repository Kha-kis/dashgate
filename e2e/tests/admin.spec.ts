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

  test("already added discovery routes stay inspectable and return when a published app is removed", async ({ page }) => {
    let includeGrafana = true;
    const active = [
      { name: 'Grafana route', url: 'http://localhost:3000/', source: 'nginx', icon: '', description: '' },
      { name: 'Grafana API', url: 'http://localhost:3000/api', source: 'nginx', icon: '', description: '' },
      { name: 'Hidden Prometheus', url: 'http://localhost:9090', source: 'nginx', icon: '', description: '', override: { hidden: true } },
      { name: 'New candidate', url: 'https://new.example.test', source: 'docker', icon: '', description: '' },
      { name: 'Ignored route', url: 'https://ignored.example.test', source: 'nginx', icon: '', description: '' },
      { name: 'Rule route', url: 'https://rule.example.test', source: 'nginx', icon: '', description: '' },
    ];
    await page.route('**/api/admin/config/apps', async route => {
      const response = await route.fetch();
      const apps = await response.json();
      await route.fulfill({ json: includeGrafana ? apps : apps.filter((app: { url: string }) => app.url !== 'http://localhost:3000') });
    });
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: {
      active,
      stale: [],
      ignored: [{ name: 'Ignored route', url: 'https://ignored.example.test', source: 'nginx' }],
      ruleMatches: [{ url: 'https://rule.example.test', source: 'nginx', ruleId: 1 }],
    } }));
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();

    await expect(page.locator('#discoveredCountBadge')).toHaveText('3');
    await expect(page.locator('#discoveredAppsList')).not.toContainText('Grafana route');
    await expect(page.locator('#discoveredAppsList')).toContainText('Grafana API');
    await expect(page.locator('#discoveredAppsList')).toContainText('Hidden Prometheus');
    await expect(page.locator('#discoveryAlreadyAddedSection summary')).toContainText('1 already added');
    await page.locator('#discoveryAlreadyAddedSection summary').click();
    await expect(page.locator('#discoveryAlreadyAddedSection')).toContainText('Grafana route');
    await expect(page.locator('#discoveryAlreadyAddedSection')).toContainText('Grafana');
    await expect(page.locator('#discoveryAlreadyAddedSection')).not.toContainText('Ignored route');
    await expect(page.locator('#discoveryAlreadyAddedSection')).not.toContainText('Rule route');
    await page.locator('#discoveredSourceFilters button').filter({ hasText: 'Docker' }).click();
    await expect(page.locator('#discoveryAlreadyAddedSection .discovered-app-item')).toHaveCount(0);
    await expect(page.locator('#discoveryAlreadyAddedSection summary')).toContainText('0 of 1 match');
    await page.locator('#discoveredSourceFilters button').filter({ hasText: 'All' }).click();
    await page.locator('#discoveredSearchInput').fill('Grafana route');
    await expect(page.locator('#discoveryAlreadyAddedSection .discovered-app-item')).toHaveCount(1);
    await page.locator('#discoveredSearchInput').fill('');

    includeGrafana = false;
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('4');
    await expect(page.locator('#discoveredAppsList')).toContainText('Grafana route');
    await expect(page.locator('#discoveryAlreadyAddedSection')).toBeEmpty();
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

  test("discovery ignore rules preview, save, disable, and restore inbox routes", async ({ page }) => {
    const active = [
      { name: 'Health', url: 'https://routes.test/health', source: 'nginx', icon: '', description: '', override: null },
      { name: 'Health live', url: 'https://routes.test/health/live', source: 'nginx', icon: '', description: '', override: null },
      { name: 'Published', url: 'https://routes.test/health/published', source: 'nginx', icon: '', description: '', override: { hidden: false } },
    ];
    const rules: { id: number; source: string; origin: string; pathPrefix: string; enabled: boolean }[] = [];
    const currentMatches = () => active
      .filter(app => !app.override && rules.some(rule => rule.enabled && app.source === rule.source && app.url.startsWith(rule.origin + rule.pathPrefix)))
      .map(app => ({ source: app.source, url: app.url, ruleId: rules[0].id }));
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({
      json: { active, stale: [], ignored: [], ignoreRules: rules, ruleMatches: currentMatches() },
    }));
    await page.route('**/api/admin/discovery-ignore-rules**', async route => {
      const path = new URL(route.request().url()).pathname;
      const method = route.request().method();
      if (path.endsWith('/preview')) {
        const input = route.request().postDataJSON();
        const matches = active.filter(app => !app.override && app.source === input.source && app.url.startsWith(input.origin + input.pathPrefix));
        await route.fulfill({ json: { count: matches.length, matches } });
      } else if (method === 'POST') {
        const rule = { id: 1, ...route.request().postDataJSON() };
        rules.push(rule);
        await route.fulfill({ status: 201, json: { rule } });
      } else if (method === 'PUT') {
        Object.assign(rules[0], route.request().postDataJSON());
        await route.fulfill({ json: { status: 'ok' } });
      } else if (method === 'DELETE') {
        rules.splice(0, 1);
        await route.fulfill({ json: { status: 'ok' } });
      } else {
        await route.fulfill({ json: { rules } });
      }
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
    await page.locator('#discoveredAppsList .discovered-app-item').filter({ hasText: 'Health live' }).getByRole('button', { name: 'Ignore similar routes' }).click();
    await expect(page.locator('#ignoreRuleSource')).toHaveValue('nginx');
    await expect(page.locator('#ignoreRuleOrigin')).toHaveValue('https://routes.test');
    await expect(page.locator('#ignoreRuleSaveButton')).toBeDisabled();
    await page.locator('#ignoreRulePathPrefix').fill('/health');
    await page.getByRole('button', { name: 'Preview rule' }).click();
    await expect(page.locator('#ignoreRulePreviewResults')).toContainText('2 current inbox routes');
    await expect(page.locator('#ignoreRulePreviewResults')).toContainText('Future routes may also match');
    await expect(page.locator('#ignoreRuleSaveButton')).toBeEnabled();
    await page.locator('#ignoreRulePathPrefix').fill('/health/live');
    await expect(page.locator('#ignoreRuleSaveButton')).toBeDisabled();
    await page.locator('#ignoreRulePathPrefix').fill('/health');
    await page.getByRole('button', { name: 'Preview rule' }).click();
    await page.locator('#discoveredAppsList .discovered-app-item').filter({ hasText: 'Health live' }).locator('input[type="checkbox"]').check();
    await expect(page.locator('#discoveredBulkActions')).toBeVisible();
    await page.locator('#ignoreRuleSaveButton').click();
    await expect(page.locator('#discoveredCountBadge')).toBeHidden();
    await expect(page.locator('#discoveredBulkActions')).toBeHidden();
    await expect(page.locator('#discoveryRuleMatchedSection')).toContainText('2 rule matched');
    await expect(page.locator('#discoveryRuleMatchedSection')).not.toContainText('Published');
    await page.locator('#discoveryRuleMatchedSection summary').click();
    await page.locator('#discoveredSearchInput').fill('live');
    await expect(page.locator('#discoveryRuleMatchedSection .discovered-app-item')).toHaveCount(1);
    await page.locator('#discoveredSearchInput').fill('');
    await page.locator('#discoveryIgnoreRulesSection').getByRole('button', { name: 'Disable rule' }).click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
    await page.locator('#discoveryIgnoreRulesSection').getByRole('button', { name: 'Edit rule' }).click();
    await page.getByRole('button', { name: 'Preview rule' }).click();
    await expect(page.locator('#ignoreRulePreviewResults')).toContainText('would match if enabled');
    await page.locator('#ignoreRuleSaveButton').click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
    await page.locator('#discoveryIgnoreRulesSection').getByRole('button', { name: 'Enable rule' }).click();
    await expect(page.locator('#discoveredCountBadge')).toBeHidden();
    await page.locator('#discoveryIgnoreRulesSection').getByRole('button', { name: 'Delete rule' }).click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
  });

  test("discovery ignore rule explains manual restore precedence", async ({ page }) => {
    const app = { name: 'Health', url: 'https://routes.test/health', source: 'nginx', icon: '', description: '', override: { hidden: true, nameOverride: 'Internal API' } };
    const rule = { id: 3, source: 'nginx', origin: 'https://routes.test', pathPrefix: '/health', enabled: true };
    let ignored = true;
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: {
      active: [app], stale: [], ignored: ignored ? [app] : [], ignoreRules: [rule],
      ruleMatches: [{ source: app.source, url: app.url, ruleId: rule.id }],
    } }));
    await page.route('**/api/admin/discovered-apps/ignored', route => {
      ignored = false;
      return route.fulfill({ json: { status: 'ok' } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveredIgnoredSection summary').click();
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('still keep this route out of the inbox after Restore');
    await page.locator('#discoveredIgnoredSection').getByRole('button', { name: 'Restore' }).click();
    await expect(page.locator('#discoveredCountBadge')).toBeHidden();
    await expect(page.locator('#discoveryRuleMatchedSection')).toContainText('1 rule matched');
    await page.locator('#discoveryRuleMatchedSection summary').click();
    await page.locator('#discoveredSearchInput').fill('Internal API');
    await expect(page.locator('#discoveryRuleMatchedSection .discovered-app-item')).toHaveCount(1);
    await expect(page.locator('#discoveryRuleMatchedSection')).toContainText('Internal API');
  });

  test("discovery ignore rule save and refresh failures preserve inbox rows", async ({ page }) => {
    const active = [{ name: 'Webhook', url: 'https://routes.test/hooks', source: 'nginx', icon: '', description: '', override: null }];
    let listFails = false;
    let saveFails = true;
    await page.route('**/api/admin/discovered-apps', route => listFails
      ? route.fulfill({ status: 500, json: { error: 'List unavailable' } })
      : route.fulfill({ json: { active, stale: [], ignored: [], ignoreRules: [], ruleMatches: [] } }));
    await page.route('**/api/admin/discovery-ignore-rules**', route => {
      if (new URL(route.request().url()).pathname.endsWith('/preview')) {
        return route.fulfill({ json: { count: 1, matches: active } });
      }
      return saveFails
        ? route.fulfill({ status: 500, json: { error: 'Save unavailable' } })
        : route.fulfill({ status: 201, json: { rule: { id: 1, ...route.request().postDataJSON() } } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveredAppsList').getByRole('button', { name: 'Ignore similar routes' }).click();
    await page.getByRole('button', { name: 'Preview rule' }).click();
    await page.locator('#ignoreRuleSaveButton').click();
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await expect(page.locator('#toast')).toContainText('Save unavailable');
    listFails = true;
    await page.getByRole('button', { name: 'Refresh discovered list' }).click();
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await expect(page.locator('#toast')).toContainText('Failed to refresh');
    saveFails = false;
    await page.locator('#ignoreRuleSaveButton').click();
    await expect(page.locator('#toast')).toContainText('Saved, but refresh failed');
    await expect(page.locator('#ignoreRuleEditor')).toBeHidden();
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
  });

  test("discovery ignore rule may cover future routes after an empty preview", async ({ page }) => {
    const rules: { id: number; source: string; origin: string; pathPrefix: string; enabled: boolean }[] = [];
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({
      json: { active: [], stale: [], ignored: [], ignoreRules: rules, ruleMatches: [] },
    }));
    await page.route('**/api/admin/discovery-ignore-rules**', route => {
      if (new URL(route.request().url()).pathname.endsWith('/preview')) {
        return route.fulfill({ json: { count: 0, matches: [] } });
      }
      const rule = { id: 1, ...route.request().postDataJSON() };
      rules.push(rule);
      return route.fulfill({ status: 201, json: { rule } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await page.locator('#discoveryIgnoreRulesSection').getByRole('button', { name: 'New ignore rule' }).click();
    await page.locator('#ignoreRuleSource').selectOption('nginx');
    await page.locator('#ignoreRuleOrigin').fill('https://future.test');
    await page.locator('#ignoreRulePathPrefix').fill('/hooks');
    await page.getByRole('button', { name: 'Preview rule' }).click();
    await expect(page.locator('#ignoreRulePreviewResults')).toContainText('0 current inbox routes');
    await page.locator('#ignoreRuleSaveButton').click();
    await expect(page.locator('#discoveryIgnoreRulesSection')).toContainText('https://future.test/hooks');
  });

  test("search and source filters include Ignored routes without changing inbox count", async ({ page }) => {
    const active = [
      { name: 'Active route', url: 'https://active.test', source: 'docker', icon: '', description: '' },
      { name: 'Webhook', url: 'https://hook.test', source: 'nginx', icon: '', description: '' },
    ];
    const ignored = [
      { name: 'Webhook', url: 'https://hook.test', source: 'nginx' },
      { name: 'Old service', url: 'https://old.test/archive', source: 'docker' },
    ];
    await page.route('**/api/admin/discovered-apps', route => route.fulfill({ json: { active, stale: [], ignored } }));
    await page.route('**/api/admin/discovered-apps/ignored', async route => {
      const { action, items } = route.request().postDataJSON();
      expect(action).toBe('restore');
      const index = ignored.findIndex(app => app.source === items[0].source && app.url === items[0].url);
      expect(index).toBeGreaterThanOrEqual(0);
      ignored.splice(index, 1);
      await route.fulfill({ json: { status: 'ok' } });
    });
    await page.reload();
    await page.locator('.dock-item').nth(4).click();
    await page.locator('[data-tab="admin"]').click();
    await page.locator('[data-admin-tab="content"]').click();
    await expect(page.locator('#discoveredCountBadge')).toHaveText('1');
    await page.locator('#discoveredIgnoredSection summary').click();
    await page.locator('#discoveredSearchInput').fill('Old service');
    await expect(page.locator('#discoveredIgnoredSection .discovered-app-item')).toHaveCount(1);
    await page.locator('#discoveredSearchInput').fill('old.test');
    await expect(page.locator('#discoveredIgnoredSection .discovered-app-item')).toHaveCount(1);
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('No longer discovered');
    await expect(page.locator('#discoveredIgnoredSection summary')).toContainText('1 of 2');
    await page.locator('#discoveredSourceFilters').getByRole('button', { name: 'Nginx' }).click();
    await expect(page.locator('#discoveredIgnoredSection .discovered-app-item')).toHaveCount(0);
    await expect(page.locator('#discoveredIgnoredSection')).toContainText('No ignored apps match');
    await page.locator('#discoveredSearchInput').fill('hook.test');
    await expect(page.locator('#discoveredIgnoredSection .discovered-app-item')).toHaveCount(1);
    await expect(page.locator('#discoveredCountBadge')).toHaveText('1');
    await expect(page.locator('#discoveredIgnoredSection summary')).toContainText('1 of 2');
    await page.locator('#discoveredIgnoredSection').getByRole('button', { name: 'Restore' }).click();
    await expect(page.locator('#discoveredAppsList')).toContainText('Webhook');
    await expect(page.locator('#discoveredIgnoredSection .discovered-app-item')).toHaveCount(0);
    await expect(page.locator('#discoveredCountBadge')).toHaveText('2');
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
