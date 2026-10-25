        // admin-discovery.js - Discovery config and discovered apps management

        // Discovery dirty state tracking
        let discoveryConfigDirty = false;

        function markDiscoveryDirty() {
            discoveryConfigDirty = true;
            const btn = document.getElementById('saveDiscoveryConfig');
            if (btn) btn.disabled = false;
        }

        function clearDiscoveryDirty() {
            discoveryConfigDirty = false;
            const btn = document.getElementById('saveDiscoveryConfig');
            if (btn) btn.disabled = true;
        }

        function setDiscoveryFormLocked(configSection, envOverride, locked) {
            configSection.querySelectorAll('input, select, textarea, button').forEach(control => {
                control.disabled = !!locked;
            });
            envOverride.style.display = locked ? 'flex' : 'none';
        }

        // Toggle functions for collapsible sections
        function toggleDockerSection() {
            const enabled = document.getElementById('dockerDiscoveryEnabled').checked;
            document.getElementById('dockerConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleTraefikSection() {
            const enabled = document.getElementById('traefikDiscoveryEnabled').checked;
            document.getElementById('traefikConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleNginxSection() {
            const enabled = document.getElementById('nginxDiscoveryEnabled').checked;
            document.getElementById('nginxConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleNPMSection() {
            const enabled = document.getElementById('npmDiscoveryEnabled').checked;
            document.getElementById('npmConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleCaddySection() {
            const enabled = document.getElementById('caddyDiscoveryEnabled').checked;
            document.getElementById('caddyConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleUnraidSection() {
            const enabled = document.getElementById('unraidDiscoveryEnabled').checked;
            document.getElementById('unraidConfigSection').style.display = enabled ? 'block' : 'none';
        }

        // Docker Discovery
        async function loadDockerDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/docker-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('dockerStatusHint');
                    const refreshBtn = document.getElementById('dockerRefreshBtn');
                    const enabledChk = document.getElementById('dockerDiscoveryEnabled');
                    const socketPath = document.getElementById('dockerSocketPath');
                    const envOverride = document.getElementById('dockerEnvOverride');
                    const configSection = document.getElementById('dockerConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.socketPath) socketPath.value = status.socketPath;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load Docker discovery status:', e);
            }
        }

        async function refreshDockerDiscovery() {
            try {
                const resp = await fetch('/api/admin/docker-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing Docker discovery...');
                    setTimeout(loadDockerDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        // Traefik Discovery
        async function loadTraefikDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/traefik-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('traefikStatusHint');
                    const refreshBtn = document.getElementById('traefikRefreshBtn');
                    const enabledChk = document.getElementById('traefikDiscoveryEnabled');
                    const urlInput = document.getElementById('traefikUrl');
                    const usernameInput = document.getElementById('traefikUsername');
                    const envOverride = document.getElementById('traefikEnvOverride');
                    const configSection = document.getElementById('traefikConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.url) urlInput.value = status.url;
                    if (status.username) usernameInput.value = status.username;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load Traefik discovery status:', e);
            }
        }

        async function refreshTraefikDiscovery() {
            try {
                const resp = await fetch('/api/admin/traefik-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing Traefik discovery...');
                    setTimeout(loadTraefikDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        async function testTraefikConnection() {
            const url = document.getElementById('traefikUrl').value;
            const username = document.getElementById('traefikUsername').value;
            const password = document.getElementById('traefikPassword').value;
            const result = document.getElementById('traefikTestResult');
            if (!url) {
                result.textContent = 'Please enter a URL first';
                result.style.color = 'var(--orange)';
                return;
            }
            result.textContent = 'Testing...';
            result.style.color = 'var(--text-secondary)';
            try {
                const resp = await fetch('/api/admin/traefik-discovery/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password }),
                    credentials: 'include'
                });
                const data = await resp.json();
                if (data.success) {
                    result.textContent = data.message;
                    result.style.color = 'var(--green)';
                } else {
                    result.textContent = data.error || 'Connection failed';
                    result.style.color = 'var(--red)';
                }
            } catch (e) {
                result.textContent = 'Test failed: ' + e.message;
                result.style.color = 'var(--red)';
            }
        }

        // Nginx Config Discovery
        async function loadNginxDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/nginx-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('nginxStatusHint');
                    const refreshBtn = document.getElementById('nginxRefreshBtn');
                    const enabledChk = document.getElementById('nginxDiscoveryEnabled');
                    const pathInput = document.getElementById('nginxConfigPath');
                    const envOverride = document.getElementById('nginxEnvOverride');
                    const configSection = document.getElementById('nginxConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.configPath) pathInput.value = status.configPath;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load Nginx discovery status:', e);
            }
        }

        async function refreshNginxDiscovery() {
            try {
                const resp = await fetch('/api/admin/nginx-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing Nginx discovery...');
                    setTimeout(loadNginxDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        // NPM Discovery
        async function loadNPMDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/npm-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('npmStatusHint');
                    const refreshBtn = document.getElementById('npmRefreshBtn');
                    const enabledChk = document.getElementById('npmDiscoveryEnabled');
                    const urlInput = document.getElementById('npmUrl');
                    const emailInput = document.getElementById('npmEmail');
                    const envOverride = document.getElementById('npmEnvOverride');
                    const configSection = document.getElementById('npmConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.url) urlInput.value = status.url;
                    if (status.email) emailInput.value = status.email;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load NPM discovery status:', e);
            }
        }

        async function refreshNPMDiscovery() {
            try {
                const resp = await fetch('/api/admin/npm-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing NPM discovery...');
                    setTimeout(loadNPMDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        async function testNPMConnection() {
            const url = document.getElementById('npmUrl').value;
            const email = document.getElementById('npmEmail').value;
            const password = document.getElementById('npmPassword').value;
            const result = document.getElementById('npmTestResult');

            if (!url || !email || !password) {
                result.textContent = 'Please fill in URL, email, and password';
                result.style.color = 'var(--orange)';
                return;
            }
            result.textContent = 'Testing...';
            result.style.color = 'var(--text-secondary)';
            try {
                const resp = await fetch('/api/admin/npm-discovery/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, email, password }),
                    credentials: 'include'
                });
                const data = await resp.json();
                if (data.success) {
                    result.textContent = data.message;
                    result.style.color = 'var(--green)';
                } else {
                    result.textContent = data.error || 'Connection failed';
                    result.style.color = 'var(--red)';
                }
            } catch (e) {
                result.textContent = 'Test failed: ' + e.message;
                result.style.color = 'var(--red)';
            }
        }

        // Caddy Discovery
        async function loadCaddyDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/caddy-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('caddyStatusHint');
                    const refreshBtn = document.getElementById('caddyRefreshBtn');
                    const enabledChk = document.getElementById('caddyDiscoveryEnabled');
                    const urlInput = document.getElementById('caddyAdminUrl');
                    const usernameInput = document.getElementById('caddyUsername');
                    const envOverride = document.getElementById('caddyEnvOverride');
                    const configSection = document.getElementById('caddyConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.url) urlInput.value = status.url;
                    if (status.username) usernameInput.value = status.username;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load Caddy discovery status:', e);
            }
        }

        async function refreshCaddyDiscovery() {
            try {
                const resp = await fetch('/api/admin/caddy-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing Caddy discovery...');
                    setTimeout(loadCaddyDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        async function testCaddyConnection() {
            const url = document.getElementById('caddyAdminUrl').value;
            const username = document.getElementById('caddyUsername').value;
            const password = document.getElementById('caddyPassword').value;
            const result = document.getElementById('caddyTestResult');
            if (!url) {
                result.textContent = 'Please enter a URL first';
                result.style.color = 'var(--orange)';
                return;
            }
            result.textContent = 'Testing...';
            result.style.color = 'var(--text-secondary)';
            try {
                const resp = await fetch('/api/admin/caddy-discovery/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, username, password }),
                    credentials: 'include'
                });
                const data = await resp.json();
                if (data.success) {
                    result.textContent = data.message;
                    result.style.color = 'var(--green)';
                } else {
                    result.textContent = data.error || 'Connection failed';
                    result.style.color = 'var(--red)';
                }
            } catch (e) {
                result.textContent = 'Test failed: ' + e.message;
                result.style.color = 'var(--red)';
            }
        }

        // Unraid Discovery
        async function loadUnraidDiscoveryStatus() {
            try {
                const resp = await fetch('/api/admin/unraid-discovery', { credentials: 'include' });
                if (resp.ok) {
                    const status = await resp.json();
                    const hint = document.getElementById('unraidStatusHint');
                    const refreshBtn = document.getElementById('unraidRefreshBtn');
                    const enabledChk = document.getElementById('unraidDiscoveryEnabled');
                    const urlInput = document.getElementById('unraidUrl');
                    const envOverride = document.getElementById('unraidEnvOverride');
                    const configSection = document.getElementById('unraidConfigSection');

                    // Populate fields
                    enabledChk.checked = status.enabled;
                    enabledChk.disabled = !!status.envOverride;
                    setDiscoveryFormLocked(configSection, envOverride, status.envOverride);
                    if (status.url) urlInput.value = status.url;

                    // Show env override warning if applicable
                    if (status.envOverride) {
                        envOverride.style.display = 'flex';
                    }

                    // Update hint
                    if (status.enabled) {
                        hint.textContent = `${status.appCount} app(s) discovered`;
                        hint.style.color = 'var(--green)';
                        refreshBtn.style.display = 'flex';
                        configSection.style.display = 'block';
                    } else {
                        hint.textContent = 'Not enabled';
                        hint.style.color = 'var(--text-muted)';
                        refreshBtn.style.display = 'none';
                    }
                }
            } catch (e) {
                console.error('Failed to load Unraid discovery status:', e);
            }
        }

        async function refreshUnraidDiscovery() {
            try {
                const resp = await fetch('/api/admin/unraid-discovery', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (resp.ok) {
                    showToast('Refreshing Unraid discovery...');
                    setTimeout(loadUnraidDiscoveryStatus, 2000);
                }
            } catch (e) {
                showToast('Failed to refresh');
            }
        }

        async function testUnraidConnection() {
            const url = document.getElementById('unraidUrl').value;
            const apiKey = document.getElementById('unraidApiKey').value;
            const result = document.getElementById('unraidTestResult');

            if (!url || !apiKey) {
                result.textContent = 'Please fill in URL and API key';
                result.style.color = 'var(--orange)';
                return;
            }
            result.textContent = 'Testing...';
            result.style.color = 'var(--text-secondary)';
            try {
                const resp = await fetch('/api/admin/unraid-discovery/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, apiKey }),
                    credentials: 'include'
                });
                const data = await resp.json();
                if (data.success) {
                    result.textContent = data.message;
                    result.style.color = 'var(--green)';
                } else {
                    result.textContent = data.error || 'Connection failed';
                    result.style.color = 'var(--red)';
                }
            } catch (e) {
                result.textContent = 'Test failed: ' + e.message;
                result.style.color = 'var(--red)';
            }
        }

        // Save all discovery settings
        async function saveDiscoverySource(name, checkboxId, path, body) {
            // Environment-controlled sources cannot be edited from the UI.
            if (document.getElementById(checkboxId).disabled) return;

            const resp = await fetch(path, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
                credentials: 'include'
            });
            if (!resp.ok) {
                let detail = await resp.text();
                try { detail = JSON.parse(detail).error || detail; } catch (_) { /* Plain-text response */ }
                throw new Error(`${name}: ${detail || `HTTP ${resp.status}`}`);
            }
        }

        async function saveDiscoverySettings() {
            const btn = document.getElementById('saveDiscoveryConfig');
            btn.disabled = true;
            btn.textContent = 'Saving...';
            const errors = [];

            try {
                // Save Docker settings
                await saveDiscoverySource('Docker discovery', 'dockerDiscoveryEnabled', '/api/admin/docker-discovery', {
                        enabled: document.getElementById('dockerDiscoveryEnabled').checked,
                        socketPath: document.getElementById('dockerSocketPath').value
                }).catch(error => errors.push(error.message));

                // Save Traefik settings
                await saveDiscoverySource('Traefik discovery', 'traefikDiscoveryEnabled', '/api/admin/traefik-discovery', {
                        enabled: document.getElementById('traefikDiscoveryEnabled').checked,
                        url: document.getElementById('traefikUrl').value,
                        username: document.getElementById('traefikUsername').value,
                        password: document.getElementById('traefikPassword').value
                }).catch(error => errors.push(error.message));

                // Save Nginx settings
                await saveDiscoverySource('Nginx discovery', 'nginxDiscoveryEnabled', '/api/admin/nginx-discovery', {
                        enabled: document.getElementById('nginxDiscoveryEnabled').checked,
                        configPath: document.getElementById('nginxConfigPath').value
                }).catch(error => errors.push(error.message));

                // Save NPM settings
                await saveDiscoverySource('NPM discovery', 'npmDiscoveryEnabled', '/api/admin/npm-discovery', {
                        enabled: document.getElementById('npmDiscoveryEnabled').checked,
                        url: document.getElementById('npmUrl').value,
                        email: document.getElementById('npmEmail').value,
                        password: document.getElementById('npmPassword').value
                }).catch(error => errors.push(error.message));

                // Save Caddy settings
                await saveDiscoverySource('Caddy discovery', 'caddyDiscoveryEnabled', '/api/admin/caddy-discovery', {
                        enabled: document.getElementById('caddyDiscoveryEnabled').checked,
                        url: document.getElementById('caddyAdminUrl').value,
                        username: document.getElementById('caddyUsername').value,
                        password: document.getElementById('caddyPassword').value
                }).catch(error => errors.push(error.message));

                // Save Unraid settings
                await saveDiscoverySource('Unraid discovery', 'unraidDiscoveryEnabled', '/api/admin/unraid-discovery', {
                        enabled: document.getElementById('unraidDiscoveryEnabled').checked,
                        url: document.getElementById('unraidUrl').value,
                        apiKey: document.getElementById('unraidApiKey').value
                }).catch(error => errors.push(error.message));

                if (errors.length) throw new Error(errors.join('; '));

                showToast('Discovery settings saved successfully');
                clearDiscoveryDirty();

                // Reload all statuses
                await loadDockerDiscoveryStatus();
                await loadTraefikDiscoveryStatus();
                await loadNginxDiscoveryStatus();
                await loadNPMDiscoveryStatus();
                await loadCaddyDiscoveryStatus();
                await loadUnraidDiscoveryStatus();
                await loadDiscoveredAppsData();

            } catch (e) {
                showToast('Error saving settings: ' + e.message);
                btn.disabled = false;
            } finally {
                btn.textContent = 'Save Discovery Settings';
            }
        }

        // Discovered Apps Management
        async function loadDiscoveredAppsData(throwOnError = false) {
            try {
                const resp = await fetch('/api/admin/discovered-apps', { credentials: 'include' });
                if (!resp.ok) throw new Error(`List refresh failed (${resp.status})`);
                const data = await resp.json();
                adminState.discoveredApps = data.active || [];
                adminState.staleOverrides = data.stale || [];
                adminState.ignoredDiscoveredApps = data.ignored || [];
                adminState.discoveryIgnoreRules = data.ignoreRules || [];
                adminState.discoveryRuleMatches = data.ruleMatches || [];
                renderDiscoveredAppsList();
                renderAppsList();
            } catch (e) {
                console.error('Failed to load discovered apps:', e);
                if (throwOnError) throw e;
            }
            await loadAccessUsers();
        }

        async function refreshDiscoveredAppsData() {
            try {
                await loadDiscoveredAppsData(true);
            } catch (e) {
                showToast('Failed to refresh discovered apps. Try again.');
            }
        }

        function renderDiscoveredAppsList() {
            const container = document.getElementById('discoveredAppsList');
            const badge = document.getElementById('discoveredCountBadge');
            const searchTerm = (document.getElementById('discoveredSearchInput')?.value || '').toLowerCase();
            const sourceFilter = adminState.discoveredSourceFilter || 'all';

            const allDiscovered = adminState.discoveredApps || [];
            const ignored = adminState.ignoredDiscoveredApps || [];
            const ignoredKeys = new Set(ignored.map(a => discoveredAppKey(a)));
            const ruleKeys = new Set((adminState.discoveryRuleMatches || []).map(a => discoveredAppKey(a)));

            // Inbox: only unconfigured apps OR hidden apps
            let apps = allDiscovered.filter(a => (!a.override || a.override.hidden) && !ignoredKeys.has(discoveredAppKey(a)) && !ruleKeys.has(discoveredAppKey(a)));
            const actionableKeys = new Set(apps.map(discoveredAppKey));
            for (const key of adminState.selectedDiscoveredApps) {
                if (!actionableKeys.has(key)) adminState.selectedDiscoveredApps.delete(key);
            }

            if (allDiscovered.length === 0) {
                container.innerHTML = '<div class="admin-empty">No discovered apps. Enable a discovery source in the Discovery settings.</div>';
                badge.style.display = 'none';
                adminState.filteredDiscoveredApps = [];
                renderIgnoredDiscoveredApps();
                renderDiscoveryIgnoreRules();
                renderRuleMatchedDiscoveredApps();
                renderStaleOverrides();
                updateBulkActionBar();
                return;
            }

            // Badge shows inbox count
            if (apps.length > 0) {
                badge.textContent = apps.length;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }

            // Filter by source
            if (sourceFilter !== 'all') {
                apps = apps.filter(a => a.source === sourceFilter);
            }

            // Filter by search
            if (searchTerm) {
                apps = apps.filter(a =>
                    a.name.toLowerCase().includes(searchTerm) ||
                    a.url.toLowerCase().includes(searchTerm) ||
                    (a.override?.nameOverride || '').toLowerCase().includes(searchTerm)
                );
            }

            if (apps.length === 0) {
                container.innerHTML = '<div class="admin-empty">No actionable discovered apps.</div>';
                adminState.filteredDiscoveredApps = [];
                renderIgnoredDiscoveredApps();
                renderDiscoveryIgnoreRules();
                renderRuleMatchedDiscoveredApps();
                renderStaleOverrides();
                updateBulkActionBar();
                return;
            }

            // Store filtered apps for select-all functionality
            adminState.filteredDiscoveredApps = apps;

            container.innerHTML = apps.map(app => {
                const override = app.override;
                const displayName = override?.nameOverride || app.name;
                const icon = override?.iconOverride || app.icon;
                const key = discoveredAppKey(app);
                const isSelected = adminState.selectedDiscoveredApps?.has(key);

                const iconHtml = icon
                    ? `<img src="/static/icons/${escapeHtml(icon)}" alt="" onerror="this.parentElement.innerHTML='<span style=\\'color:var(--text-tertiary);font-size:14px;\\'>${escapeHtml(displayName.charAt(0).toUpperCase())}</span>'">`
                    : `<span style="color:var(--text-tertiary);font-size:14px;">${escapeHtml(displayName.charAt(0).toUpperCase())}</span>`;

                const hiddenBadge = (override && override.hidden)
                    ? `<span class="discovered-status-badge hidden">Hidden</span>`
                    : '';

                const resetBtn = override
                    ? `<button class="admin-action-btn danger" onclick="confirmResetDiscoveredApp('${encodeURIComponent(app.url)}', '${escapeHtml(displayName).replace(/'/g, "\\'")}')" title="Reset">
                        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                        </svg>
                       </button>`
                    : '';

                return `
                    <div class="discovered-app-item${isSelected ? ' selected' : ''}" data-url="${escapeHtml(app.url)}" data-discovery-key="${escapeHtml(key)}">
                        <label class="discovered-app-checkbox" onclick="event.stopPropagation()">
                            <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="toggleDiscoveredAppSelection('${encodeURIComponent(key).replace(/'/g, '%27')}')">
                        </label>
                        <div class="discovered-app-icon">${iconHtml}</div>
                        <div class="discovered-app-info">
                            <div class="discovered-app-name">${escapeHtml(displayName)}</div>
                            <div class="discovered-app-url">${escapeHtml(app.url)}</div>
                            <div class="discovered-app-badges">
                                <span class="discovered-source-badge ${escapeHtml(app.source)}">${escapeHtml(app.source)}</span>
                                ${hiddenBadge}
                            </div>
                        </div>
                        <div class="admin-item-actions">
                            <button class="admin-action-btn discovery-text-action" onclick="dismissDiscoveredApp('${encodeURIComponent(app.source).replace(/'/g, '%27')}', '${encodeURIComponent(app.url).replace(/'/g, '%27')}')" title="Dismiss" aria-label="Dismiss">Dismiss</button>
                            <button type="button" class="admin-action-btn discovery-text-action ignore-rule-from-route" aria-label="Ignore similar routes">Rule</button>
                            <button class="admin-action-btn" onclick="openDiscoveredAppModal('${encodeURIComponent(app.url)}')" title="Configure">
                                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                    <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                            </button>
                            ${resetBtn}
                        </div>
                    </div>
                `;
            }).join('');

            updateBulkActionBar();

            renderIgnoredDiscoveredApps();
            renderDiscoveryIgnoreRules();
            renderRuleMatchedDiscoveredApps();
            renderStaleOverrides();
        }

        function discoveredAppKey(app) {
            return JSON.stringify([app.source, app.url]);
        }

        function renderIgnoredDiscoveredApps() {
            const section = document.getElementById('discoveredIgnoredSection');
            if (!section) return;
            const ignored = adminState.ignoredDiscoveredApps || [];
            if (ignored.length === 0) {
                section.innerHTML = '';
                return;
            }
            const searchTerm = (document.getElementById('discoveredSearchInput')?.value || '').toLowerCase();
            const sourceFilter = adminState.discoveredSourceFilter || 'all';
            const visible = ignored.filter(app =>
                (sourceFilter === 'all' || app.source === sourceFilter) &&
                (!searchTerm || (app.name || '').toLowerCase().includes(searchTerm) || app.url.toLowerCase().includes(searchTerm))
            );
            const activeKeys = new Set((adminState.discoveredApps || []).map(a => discoveredAppKey(a)));
            const ruleKeys = new Set((adminState.discoveryRuleMatches || []).map(a => discoveredAppKey(a)));
            const wasOpen = section.querySelector('details')?.open || false;
            section.innerHTML = `<details ${wasOpen ? 'open' : ''}>
                <summary>Ignored (${visible.length === ignored.length ? `${ignored.length} ignored` : `${visible.length} of ${ignored.length} match`})</summary>
                <p class="settings-desc">Dismissed routes stay here until restored.</p>
                ${visible.length === 0 ? '<div class="admin-empty">No ignored apps match the current search or source filter.</div>' : visible.map(app => `<div class="discovered-app-item">
                    <div class="discovered-app-info">
                        <div class="discovered-app-name">${escapeHtml(app.name || app.url)}</div>
                        <div class="discovered-app-url">${escapeHtml(app.url)}</div>
                        <div class="discovered-app-badges"><span class="discovered-source-badge">${escapeHtml(app.source)}</span>
                            ${activeKeys.has(discoveredAppKey(app)) ? '' : '<span class="discovered-status-badge">No longer discovered</span>'}</div>
                        ${ruleKeys.has(discoveredAppKey(app)) ? '<p class="settings-desc">An active ignore rule will still keep this route out of the inbox after Restore.</p>' : ''}
                    </div>
                    <div class="admin-item-actions"><button class="admin-action-btn discovery-text-action" onclick="restoreDiscoveredApp('${encodeURIComponent(app.source).replace(/'/g, '%27')}', '${encodeURIComponent(app.url).replace(/'/g, '%27')}')">Restore</button></div>
                </div>`).join('')}
            </details>`;
        }

        let ignoreRuleEditingID = null;
        let ignoreRulePreviewSignature = null;

        function ignoreRuleFormValue() {
            return {
                source: document.getElementById('ignoreRuleSource').value,
                origin: document.getElementById('ignoreRuleOrigin').value.trim(),
                pathPrefix: document.getElementById('ignoreRulePathPrefix').value.trim(),
                enabled: ignoreRuleEditingID ? adminState.discoveryIgnoreRules.find(rule => rule.id === ignoreRuleEditingID)?.enabled ?? true : true
            };
        }

        function invalidateIgnoreRulePreview() {
            ignoreRulePreviewSignature = null;
            document.getElementById('ignoreRuleSaveButton').disabled = true;
            document.getElementById('ignoreRulePreviewResults').textContent = 'Preview this rule before saving.';
        }

        function openIgnoreRuleEditor(rule = null, route = null) {
            ignoreRuleEditingID = rule?.id || null;
            document.getElementById('ignoreRuleEditorTitle').textContent = rule ? 'Edit ignore rule' : 'New ignore rule';
            document.getElementById('ignoreRuleSource').value = rule?.source || route?.source || 'docker';
            document.getElementById('ignoreRuleOrigin').value = rule?.origin || route?.origin || '';
            document.getElementById('ignoreRulePathPrefix').value = rule?.pathPrefix || route?.pathPrefix || '';
            document.getElementById('ignoreRuleEditor').hidden = false;
            invalidateIgnoreRulePreview();
            document.getElementById('ignoreRulePathPrefix').focus();
        }

        function renderDiscoveryIgnoreRules() {
            const section = document.getElementById('discoveryIgnoreRulesSection');
            if (!section) return;
            const rules = adminState.discoveryIgnoreRules || [];
            const matches = adminState.discoveryRuleMatches || [];
            section.innerHTML = `<div class="admin-section-header"><h4>Ignore rules (${rules.length})</h4><button type="button" class="bulk-action-btn secondary" data-ignore-rule-action="new">New ignore rule</button></div>
                <p class="settings-desc">Enabled rules remove matching discovered routes from the inbox. Published apps are unaffected.</p>
                ${rules.map(rule => `<div class="discovered-app-item ignore-rule-row" data-rule-id="${Number(rule.id)}">
                    <div class="discovered-app-info"><div class="discovered-app-name">${escapeHtml(rule.origin + rule.pathPrefix)}</div>
                    <div class="discovered-app-badges"><span class="discovered-source-badge">${escapeHtml(rule.source)}</span><span class="discovered-status-badge">${rule.enabled ? 'Enabled' : 'Disabled'}</span><span>${matches.filter(match => match.ruleId === rule.id).length} current matches</span></div></div>
                    <div class="admin-item-actions"><button type="button" class="admin-action-btn discovery-text-action" data-ignore-rule-action="edit" aria-label="Edit rule">Edit</button>
                    <button type="button" class="admin-action-btn discovery-text-action" data-ignore-rule-action="toggle" aria-label="${rule.enabled ? 'Disable rule' : 'Enable rule'}">${rule.enabled ? 'Disable' : 'Enable'}</button>
                    <button type="button" class="admin-action-btn discovery-text-action danger" data-ignore-rule-action="delete" aria-label="Delete rule">Delete</button></div></div>`).join('')}`;
        }

        function renderRuleMatchedDiscoveredApps() {
            const section = document.getElementById('discoveryRuleMatchedSection');
            if (!section) return;
            const matches = adminState.discoveryRuleMatches || [];
            if (!matches.length) { section.innerHTML = ''; return; }
            const activeByKey = new Map((adminState.discoveredApps || []).map(app => [discoveredAppKey(app), app]));
            const ignoredKeys = new Set((adminState.ignoredDiscoveredApps || []).map(discoveredAppKey));
            const searchTerm = (document.getElementById('discoveredSearchInput')?.value || '').toLowerCase();
            const sourceFilter = adminState.discoveredSourceFilter || 'all';
            const visible = matches.map(match => ({ match, app: activeByKey.get(discoveredAppKey(match)) }))
                .filter(({ match, app }) => app && !ignoredKeys.has(discoveredAppKey(match)) &&
                    (sourceFilter === 'all' || match.source === sourceFilter) &&
                    (!searchTerm || (app.name || '').toLowerCase().includes(searchTerm) || (app.override?.nameOverride || '').toLowerCase().includes(searchTerm) || app.url.toLowerCase().includes(searchTerm)));
            const wasOpen = section.querySelector('details')?.open || false;
            section.innerHTML = `<details ${wasOpen ? 'open' : ''}><summary>Rule matched (${visible.length === matches.length ? `${matches.length} rule matched` : `${visible.length} of ${matches.length} match`})</summary>
                <p class="settings-desc">These routes remain discovered. Edit or disable a rule to return them to the inbox.</p>
                ${visible.length ? visible.map(({ match, app }) => `<div class="discovered-app-item"><div class="discovered-app-info">
                    <div class="discovered-app-name">${escapeHtml(app.override?.nameOverride || app.name || app.url)}</div><div class="discovered-app-url">${escapeHtml(app.url)}</div>
                    <div class="discovered-app-badges"><span class="discovered-source-badge">${escapeHtml(app.source)}</span></div></div>
                    <div class="admin-item-actions"><button type="button" class="admin-action-btn discovery-text-action" data-edit-matched-rule="${Number(match.ruleId)}">Edit rule</button></div></div>`).join('') : '<div class="admin-empty">No rule-matched apps match the current search or source filter.</div>'}</details>`;
        }

        async function previewIgnoreRule() {
            const input = ignoreRuleFormValue();
            invalidateIgnoreRulePreview();
            try {
                const resp = await fetch('/api/admin/discovery-ignore-rules/preview', {
                    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input)
                });
                if (!resp.ok) {
                    const body = await resp.json().catch(() => ({}));
                    throw new Error(body.error || `Preview failed (${resp.status})`);
                }
                const data = await resp.json();
                if (JSON.stringify(input) !== JSON.stringify(ignoreRuleFormValue())) return;
                const results = document.getElementById('ignoreRulePreviewResults');
                results.innerHTML = `<p>${Number(data.count)} current inbox routes${input.enabled ? '' : ' would match if enabled'}. Future routes may also match.</p>
                    ${(data.matches || []).map(app => `<div class="ignore-rule-preview-row"><strong>${escapeHtml(app.override?.nameOverride || app.name || app.url)}</strong> <span>${escapeHtml(app.source)}</span><div>${escapeHtml(app.url)}</div></div>`).join('')}
                    ${data.count > (data.matches || []).length ? `<p>Showing first ${(data.matches || []).length} matches.</p>` : ''}`;
                ignoreRulePreviewSignature = JSON.stringify(input);
                document.getElementById('ignoreRuleSaveButton').disabled = false;
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        async function writeIgnoreRule(method, path, input, successMessage) {
            try {
                const resp = await fetch(path, { method, credentials: 'include', headers: { 'Content-Type': 'application/json' }, ...(input ? { body: JSON.stringify(input) } : {}) });
                if (!resp.ok) {
                    const body = await resp.json().catch(() => ({}));
                    throw new Error(body.error || `Rule request failed (${resp.status})`);
                }
                try {
                    await loadDiscoveredAppsData(true);
                } catch (_) {
                    showToast('Saved, but refresh failed. Use Refresh discovered list to retry.');
                    return true;
                }
                showToast(successMessage);
                return true;
            } catch (e) {
                showToast('Error: ' + e.message);
                return false;
            }
        }

        async function saveIgnoreRule() {
            const input = ignoreRuleFormValue();
            if (JSON.stringify(input) !== ignoreRulePreviewSignature) { invalidateIgnoreRulePreview(); return; }
            const id = ignoreRuleEditingID;
            if (await writeIgnoreRule(id ? 'PUT' : 'POST', id ? `/api/admin/discovery-ignore-rules/${id}` : '/api/admin/discovery-ignore-rules', input, 'Ignore rule saved')) {
                document.getElementById('ignoreRuleEditor').hidden = true;
                invalidateIgnoreRulePreview();
            }
        }

        document.getElementById('discoveredAppsList')?.addEventListener('click', event => {
            if (!event.target.closest('.ignore-rule-from-route')) return;
            const key = event.target.closest('.discovered-app-item')?.dataset.discoveryKey;
            if (!key) return;
            const [source, url] = JSON.parse(key);
            try {
                const parsed = new URL(url);
                openIgnoreRuleEditor(null, { source, origin: parsed.origin, pathPrefix: parsed.pathname === '/' ? '' : parsed.pathname });
            } catch (_) { showToast('Cannot create a rule for this URL'); }
        });
        document.getElementById('discoveryIgnoreRulesSection')?.addEventListener('click', event => {
            const action = event.target.closest('[data-ignore-rule-action]')?.dataset.ignoreRuleAction;
            if (!action) return;
            if (action === 'new') { openIgnoreRuleEditor(); return; }
            const id = Number(event.target.closest('.ignore-rule-row')?.dataset.ruleId);
            const rule = adminState.discoveryIgnoreRules.find(item => item.id === id);
            if (!rule) return;
            if (action === 'edit') { openIgnoreRuleEditor(rule); return; }
            if (action === 'toggle') writeIgnoreRule('PUT', `/api/admin/discovery-ignore-rules/${id}`, { source: rule.source, origin: rule.origin, pathPrefix: rule.pathPrefix, enabled: !rule.enabled }, rule.enabled ? 'Ignore rule disabled' : 'Ignore rule enabled');
            if (action === 'delete') writeIgnoreRule('DELETE', `/api/admin/discovery-ignore-rules/${id}`, null, 'Ignore rule deleted');
        });
        document.getElementById('discoveryRuleMatchedSection')?.addEventListener('click', event => {
            const id = Number(event.target.closest('[data-edit-matched-rule]')?.dataset.editMatchedRule);
            const rule = adminState.discoveryIgnoreRules.find(item => item.id === id);
            if (rule) openIgnoreRuleEditor(rule);
        });
        ['ignoreRuleSource', 'ignoreRuleOrigin', 'ignoreRulePathPrefix'].forEach(id => {
            const field = document.getElementById(id);
            field?.addEventListener('input', invalidateIgnoreRulePreview);
            field?.addEventListener('change', invalidateIgnoreRulePreview);
        });
        document.getElementById('ignoreRulePreviewButton')?.addEventListener('click', previewIgnoreRule);
        document.getElementById('ignoreRuleSaveButton')?.addEventListener('click', saveIgnoreRule);
        document.getElementById('ignoreRuleCancelButton')?.addEventListener('click', () => {
            document.getElementById('ignoreRuleEditor').hidden = true;
            invalidateIgnoreRulePreview();
        });

        async function changeIgnoredDiscoveredApps(action, items) {
            try {
                const resp = await fetch('/api/admin/discovered-apps/ignored', {
                    method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action, items })
                });
                if (!resp.ok) {
                    const body = await resp.json().catch(() => ({}));
                    throw new Error(body.error || `Request failed (${resp.status})`);
                }
                if (action === 'dismiss') clearDiscoveredSelection();
                try {
                    await loadDiscoveredAppsData(true);
                } catch (e) {
                    showToast('Saved, but refresh failed. Use Refresh discovered list to retry.');
                    return;
                }
                showToast(action === 'dismiss' ? `${items.length} app(s) dismissed` : 'App restored');
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        window.dismissDiscoveredApp = (source, url) => changeIgnoredDiscoveredApps('dismiss', [{ source: decodeURIComponent(source), url: decodeURIComponent(url) }]);
        window.restoreDiscoveredApp = (source, url) => changeIgnoredDiscoveredApps('restore', [{ source: decodeURIComponent(source), url: decodeURIComponent(url) }]);
        window.dismissSelectedDiscoveredApps = function() {
            const items = Array.from(adminState.selectedDiscoveredApps || [], key => {
                const [source, url] = JSON.parse(key);
                return { source, url };
            });
            if (items.length === 0) return;
            if (items.length > 100) { showToast('Select at most 100 apps'); return; }
            return changeIgnoredDiscoveredApps('dismiss', items);
        }

        function renderStaleOverrides() {
            const section = document.getElementById('discoveredStaleSection');
            const stale = adminState.staleOverrides;

            if (!stale || stale.length === 0) {
                section.style.display = 'none';
                return;
            }

            section.style.display = 'block';
            section.innerHTML = `
                <div class="discovered-stale-section">
                    <div class="discovered-stale-title">Stale Overrides (${stale.length})</div>
                    <p class="settings-desc" style="margin-bottom: 8px; font-size: 11px;">These apps were configured but are no longer being discovered. They may reappear if the source is restarted.</p>
                    ${stale.map(o => `
                        <div class="discovered-app-item" style="margin-top: 6px;">
                            <div class="discovered-app-info">
                                <div class="discovered-app-name">${escapeHtml(o.nameOverride || o.url)}</div>
                                <div class="discovered-app-url">${escapeHtml(o.url)}</div>
                                <div class="discovered-app-badges">
                                    <span class="discovered-source-badge ${escapeHtml(o.source || '')}">${escapeHtml(o.source || 'unknown')}</span>
                                    <span class="discovered-category-badge">${escapeHtml(o.category || 'none')}</span>
                                </div>
                            </div>
                            <div class="admin-item-actions">
                                <button class="admin-action-btn danger" onclick="confirmDeleteStaleOverride('${encodeURIComponent(o.url)}', '${escapeHtml(o.nameOverride || o.url).replace(/'/g, "\\'")}')" title="Remove">
                                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                        <polyline points="3 6 5 6 21 6"/>
                                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        function filterDiscoveredApps() {
            renderDiscoveredAppsList();
        }

        function filterDiscoveredBySource(source) {
            adminState.discoveredSourceFilter = source;
            // Update active filter button
            document.querySelectorAll('.discovered-source-filter').forEach(btn => {
                btn.classList.toggle('active', btn.textContent.trim().toLowerCase() === source || (source === 'all' && btn.textContent.trim() === 'All'));
            });
            renderDiscoveredAppsList();
        }

        function openDiscoveredAppModal(encodedUrl) {
            const url = decodeURIComponent(encodedUrl);
            const app = adminState.discoveredApps.find(a => a.url === url);
            if (!app) return;

            window._discoveredIconMode = false;

            document.getElementById('discoveredAppUrl').value = app.url;
            document.getElementById('discoveredAppSource').value = app.source;
            document.getElementById('discoveredAppOrigName').textContent = app.name;
            document.getElementById('discoveredAppOrigUrl').textContent = app.url;
            document.getElementById('discoveredAppOrigSource').textContent = app.source;

            const override = app.override;
            document.getElementById('discoveredAppHidden').checked = override?.hidden || false;
            document.getElementById('discoveredAppNameOverride').value = override?.nameOverride || '';
            document.getElementById('discoveredAppUrlOverride').value = override?.urlOverride || '';
            document.getElementById('discoveredAppDescOverride').value = override?.descriptionOverride || '';
            document.getElementById('discoveredAppIconOverride').value = override?.iconOverride || '';
            updateDiscoveredIconPreview(override?.iconOverride || '');

            // Populate category dropdown
            const catSelect = document.getElementById('discoveredAppCategory');
            catSelect.innerHTML = '<option value="">-- Select Category --</option>';
            adminState.categories.forEach(cat => {
                const opt = document.createElement('option');
                opt.value = cat.name;
                opt.textContent = cat.name;
                catSelect.appendChild(opt);
            });
            const newOpt = document.createElement('option');
            newOpt.value = '__new__';
            newOpt.textContent = 'New Category...';
            catSelect.appendChild(newOpt);
            catSelect.value = override?.category || '';

            // Populate groups
            const groupContainer = document.getElementById('discoveredAppGroups');
            const selectedGroups = override?.groups || [];
            const allGroups = getAvailableGroups();

            if (allGroups.length === 0) {
                groupContainer.innerHTML = '<div class="admin-empty">No groups available</div>';
            } else {
                const adminGroups = getAdminGroupNames();
                groupContainer.innerHTML = allGroups.map(g => {
                    const isAdminGroup = adminGroups.includes(g);
                    const isChecked = isAdminGroup || selectedGroups.includes(g);
                    return `
                    <label class="admin-group-checkbox">
                        <input type="checkbox" value="${escapeHtml(g)}" ${isChecked ? 'checked' : ''} ${isAdminGroup ? 'disabled' : ''}>
                        <span class="admin-group-checkbox-label">${escapeHtml(g)}${isAdminGroup ? ' (required)' : ''}</span>
                    </label>`;
                }).join('');
            }

            toggleDiscoveredConfigFields();
            document.getElementById('discoveredAppModal').classList.add('open');
        }

        function getAvailableGroups() {
            // Combine LLDAP groups and local user groups
            const groups = new Set();
            if (adminState.groups && adminState.groups.length > 0) {
                adminState.groups.forEach(g => groups.add(g.displayName));
            }
            // Also add common local groups
            if (adminState.localUsers && adminState.localUsers.length > 0) {
                adminState.localUsers.forEach(u => {
                    (u.groups || []).forEach(g => groups.add(g));
                });
            }
            // Always include common groups
            ['admin', 'lldap_admin', 'users'].forEach(g => groups.add(g));
            return Array.from(groups).sort();
        }

        function closeDiscoveredAppModal() {
            document.getElementById('discoveredAppModal').classList.remove('open');
            window._discoveredIconMode = false;
        }

        function toggleDiscoveredConfigFields() {
            const hidden = document.getElementById('discoveredAppHidden').checked;
            const fields = document.getElementById('discoveredConfigFields');
            fields.style.opacity = hidden ? '0.4' : '1';
            fields.style.pointerEvents = hidden ? 'none' : 'auto';
        }

        function updateDiscoveredIconPreview(iconName) {
            const preview = document.getElementById('discoveredIconPreview');
            if (iconName) {
                preview.innerHTML = `<img src="/static/icons/${escapeHtml(iconName)}" alt="${escapeHtml(iconName)}">`;
            } else {
                preview.innerHTML = '<span>No icon override</span>';
            }
        }

        function openDiscoveredIconSelector() {
            window._discoveredIconMode = true;
            renderIconGrid();
            document.getElementById('iconSelectorModal').classList.add('open');
        }

        function clearDiscoveredIcon() {
            document.getElementById('discoveredAppIconOverride').value = '';
            updateDiscoveredIconPreview('');
        }

        async function saveDiscoveredAppConfig() {
            const url = document.getElementById('discoveredAppUrl').value;
            const source = document.getElementById('discoveredAppSource').value;
            const hidden = document.getElementById('discoveredAppHidden').checked;
            const nameOverride = document.getElementById('discoveredAppNameOverride').value.trim();
            const urlOverride = document.getElementById('discoveredAppUrlOverride').value.trim();
            const descOverride = document.getElementById('discoveredAppDescOverride').value.trim();
            const iconOverride = document.getElementById('discoveredAppIconOverride').value;
            let category = document.getElementById('discoveredAppCategory').value;
            const checkboxes = document.querySelectorAll('#discoveredAppGroups input[type="checkbox"]:checked');
            const groups = Array.from(checkboxes).map(cb => cb.value);
            // Always include admin groups (disabled checkboxes don't appear in :checked)
            getAdminGroupNames().forEach(g => {
                if (!groups.includes(g)) groups.push(g);
            });

            if (!hidden) {
                if (category === '__new__') {
                    const newCat = prompt('Enter new category name:');
                    if (!newCat || !newCat.trim()) return;
                    category = newCat.trim();
                }
                if (!category) {
                    showToast('Category is required');
                    return;
                }
                if (groups.length === 0) {
                    showToast('At least one group is required');
                    return;
                }
            }

            try {
                const resp = await fetch('/api/admin/discovered-apps', {
                    method: 'PUT',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url,
                        source,
                        nameOverride,
                        urlOverride: hidden ? '' : urlOverride,
                        iconOverride,
                        descriptionOverride: descOverride,
                        category: hidden ? '' : category,
                        groups: hidden ? [] : groups,
                        hidden
                    })
                });
                if (!resp.ok) throw new Error(await resp.text());
                showToast('Discovered app configured');
                closeDiscoveredAppModal();
                await loadDiscoveredAppsData();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        function confirmResetDiscoveredApp(encodedUrl, name) {
            document.getElementById('confirmDeleteMessage').textContent = `Reset "${name}" to unconfigured? It will be hidden from DashGate.`;
            adminState.deleteCallback = async () => {
                try {
                    const resp = await fetch(`/api/admin/discovered-apps?url=${encodedUrl}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    showToast('Override removed');
                    closeConfirmDelete();
                    await loadDiscoveredAppsData();
                } catch (e) {
                    showToast('Error: ' + e.message);
                }
            };
            document.getElementById('confirmDeleteModal').classList.add('open');
        }

        function confirmDeleteStaleOverride(encodedUrl, name) {
            document.getElementById('confirmDeleteMessage').textContent = `Remove stale override for "${name}"?`;
            adminState.deleteCallback = async () => {
                try {
                    const resp = await fetch(`/api/admin/discovered-apps?url=${encodedUrl}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    showToast('Stale override removed');
                    closeConfirmDelete();
                    await loadDiscoveredAppsData();
                } catch (e) {
                    showToast('Error: ' + e.message);
                }
            };
            document.getElementById('confirmDeleteModal').classList.add('open');
        }

        // Legacy App Access Modal (for quick group editing)
        function openEditAppModal(encodedUrl) {
            const url = decodeURIComponent(encodedUrl);
            const app = adminState.apps.find(a => a.url === url);
            if (!app) return;

            adminState.editingApp = app;
            document.getElementById('editAppTitle').textContent = `Edit Access: ${app.name}`;
            document.getElementById('editAppUrl').value = url;

            const container = document.getElementById('appGroupCheckboxes');
            const appGroups = app.groups || [];

            if (adminState.groups.length === 0) {
                container.innerHTML = '<div class="admin-empty">No groups available</div>';
                return;
            }

            const adminGroups = getAdminGroupNames();
            container.innerHTML = adminState.groups.map(group => {
                const isAdminGroup = adminGroups.includes(group.displayName);
                const isChecked = isAdminGroup || appGroups.includes(group.displayName);
                return `
                <label class="admin-group-checkbox">
                    <input type="checkbox" value="${escapeHtml(group.displayName)}" ${isChecked ? 'checked' : ''} ${isAdminGroup ? 'disabled' : ''}>
                    <span class="admin-group-checkbox-label">${escapeHtml(group.displayName)}${isAdminGroup ? ' (required)' : ''}</span>
                    <span class="admin-group-checkbox-count">${group.users ? group.users.length : 0} members</span>
                </label>`;
            }).join('');

            document.getElementById('editAppModal').classList.add('open');
        }

        function closeEditAppModal() {
            document.getElementById('editAppModal').classList.remove('open');
            adminState.editingApp = null;
        }

        async function saveAppAccess() {
            const appUrl = document.getElementById('editAppUrl').value;
            const checkboxes = document.querySelectorAll('#appGroupCheckboxes input[type="checkbox"]:checked');
            const selectedGroups = Array.from(checkboxes).map(cb => cb.value);
            // Always include admin groups (disabled checkboxes don't appear in :checked)
            getAdminGroupNames().forEach(g => {
                if (!selectedGroups.includes(g)) selectedGroups.push(g);
            });

            try {
                const resp = await fetch('/api/admin/apps/mapping', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ appUrl, groups: selectedGroups })
                });

                if (!resp.ok) throw new Error(await resp.text());

                showToast('App access updated');
                closeEditAppModal();
                await reloadApps();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        // Bulk selection functions (exposed globally for onclick handlers)
        window.toggleDiscoveredAppSelection = function(encodedUrl) {
            const key = decodeURIComponent(encodedUrl);
            if (!adminState.selectedDiscoveredApps) {
                adminState.selectedDiscoveredApps = new Set();
            }

            if (adminState.selectedDiscoveredApps.has(key)) {
                adminState.selectedDiscoveredApps.delete(key);
            } else {
                adminState.selectedDiscoveredApps.add(key);
            }
            renderDiscoveredAppsList();
            const replacement = Array.from(document.querySelectorAll('#discoveredAppsList .discovered-app-item'))
                .find(item => item.dataset.discoveryKey === key);
            replacement?.querySelector('input[type="checkbox"]')?.focus();
            updateSelectAllCheckbox();
        }

        window.toggleSelectAllDiscovered = function() {
            const selectAllCb = document.getElementById('selectAllDiscovered');
            const filtered = adminState.filteredDiscoveredApps || [];

            if (!adminState.selectedDiscoveredApps) {
                adminState.selectedDiscoveredApps = new Set();
            }

            const isChecked = selectAllCb.checked;
            filtered.forEach(app => {
                const key = discoveredAppKey(app);
                if (isChecked) {
                    adminState.selectedDiscoveredApps.add(key);
                } else {
                    adminState.selectedDiscoveredApps.delete(key);
                }
            });
            renderDiscoveredAppsList();
        }

        function updateSelectAllCheckbox() {
            const selectAllCb = document.getElementById('selectAllDiscovered');
            if (!selectAllCb) return;

            const filtered = adminState.filteredDiscoveredApps || [];
            const selected = adminState.selectedDiscoveredApps || new Set();

            const allSelected = filtered.length > 0 && filtered.every(app => selected.has(discoveredAppKey(app)));
            const someSelected = filtered.some(app => selected.has(discoveredAppKey(app)));

            selectAllCb.checked = allSelected;
            selectAllCb.indeterminate = someSelected && !allSelected;
        }

        function updateBulkActionBar() {
            const bar = document.getElementById('discoveredBulkActions');
            const count = adminState.selectedDiscoveredApps?.size || 0;

            if (count > 0) {
                bar.classList.add('visible');
                document.getElementById('bulkSelectedCount').textContent = `${count} selected`;
            } else {
                bar.classList.remove('visible');
            }
        }

        window.clearDiscoveredSelection = function() {
            if (adminState.selectedDiscoveredApps) {
                adminState.selectedDiscoveredApps.clear();
            }
            renderDiscoveredAppsList();
            updateSelectAllCheckbox();
        }

        function getSelectedUrls() {
            return [...new Set(Array.from(adminState.selectedDiscoveredApps || [], key => JSON.parse(key)[1]))];
        }

        window.openBulkConfigureModal = function() {
            const urls = getSelectedUrls();
            if (urls.length === 0) return;

            // Show selected apps list
            const listContainer = document.getElementById('bulkSelectedList');
            const selectedApps = (adminState.filteredDiscoveredApps || []).filter(app => urls.includes(app.url));
            listContainer.innerHTML = selectedApps.map(app => {
                const displayName = app.override?.nameOverride || app.name;
                return `<div class="bulk-selected-item">
                    <span class="bulk-selected-item-name">${escapeHtml(displayName)}</span>
                    <span style="color:var(--text-tertiary);"> - ${escapeHtml(app.url)}</span>
                </div>`;
            }).join('');

            // Populate category dropdown
            const catSelect = document.getElementById('bulkConfigCategory');
            catSelect.innerHTML = '<option value="">-- Select Category --</option>';
            adminState.categories.forEach(cat => {
                const opt = document.createElement('option');
                opt.value = cat.name;
                opt.textContent = cat.name;
                catSelect.appendChild(opt);
            });
            const newOpt = document.createElement('option');
            newOpt.value = '__new__';
            newOpt.textContent = 'New Category...';
            catSelect.appendChild(newOpt);

            // Populate groups
            const groupContainer = document.getElementById('bulkConfigGroups');
            const allGroups = getAvailableGroups();
            const adminGroups = getAdminGroupNames();

            if (allGroups.length === 0) {
                groupContainer.innerHTML = '<div class="admin-empty">No groups available</div>';
            } else {
                groupContainer.innerHTML = allGroups.map(g => {
                    const isAdminGroup = adminGroups.includes(g);
                    return `
                    <label class="admin-group-checkbox">
                        <input type="checkbox" value="${escapeHtml(g)}" ${isAdminGroup ? 'checked disabled' : ''}>
                        <span class="admin-group-checkbox-label">${escapeHtml(g)}${isAdminGroup ? ' (required)' : ''}</span>
                    </label>`;
                }).join('');
            }

            document.getElementById('bulkConfigureModal').classList.add('open');
        }

        window.closeBulkConfigureModal = function() {
            document.getElementById('bulkConfigureModal').classList.remove('open');
        }

        window.applyBulkConfigure = async function() {
            const urls = getSelectedUrls();
            let category = document.getElementById('bulkConfigCategory').value;
            const checkboxes = document.querySelectorAll('#bulkConfigGroups input[type="checkbox"]:checked');
            const groups = Array.from(checkboxes).map(cb => cb.value);

            // Include admin groups
            getAdminGroupNames().forEach(g => {
                if (!groups.includes(g)) groups.push(g);
            });

            if (category === '__new__') {
                const newCat = prompt('Enter new category name:');
                if (!newCat || !newCat.trim()) return;
                category = newCat.trim();
            }

            if (!category) {
                showToast('Category is required');
                return;
            }

            if (groups.length === 0) {
                showToast('At least one group is required');
                return;
            }

            try {
                const resp = await fetch('/api/admin/discovered-apps/bulk', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls, action: 'show', category, groups })
                });
                if (!resp.ok) throw new Error(await resp.text());
                showToast(`${urls.length} app(s) configured`);
                closeBulkConfigureModal();
                clearDiscoveredSelection();
                await loadDiscoveredAppsData();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }
