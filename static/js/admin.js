        // admin.js - Admin core, system config, API keys, backup/restore

        // Admin Functions
        let adminState = {
            isAdmin: false,
            lldapEnabled: false,
            localAuthEnabled: false,
            authMode: 'authelia',
            currentUser: null,
            users: [],
            groups: [],
            localUsers: [],
            apps: [],
            categories: [],
            icons: [],
            editingApp: null,
            deleteCallback: null,
            discoveredApps: [],
            staleOverrides: [],
            discoveredSourceFilter: 'all',
            selectedDiscoveredApps: new Set(),
            filteredDiscoveredApps: []
        };

        async function loadAdminData() {
            if (!adminState.isAdmin) return;

            try {
                // Load system config first
                await loadSystemConfig();

                // Load apps configuration
                const [appsResp, categoriesResp, iconsResp] = await Promise.all([
                    fetch('/api/admin/config/apps', { credentials: 'include' }),
                    fetch('/api/admin/config/categories', { credentials: 'include' }),
                    fetch('/api/admin/config/icons', { credentials: 'include' })
                ]);

                if (appsResp.ok) {
                    adminState.apps = await appsResp.json();
                    renderAppsList();
                }

                if (categoriesResp.ok) {
                    adminState.categories = await categoriesResp.json();
                    renderCategoriesList();
                }

                if (iconsResp.ok) {
                    adminState.icons = await iconsResp.json();
                }

                // Load LLDAP data if enabled
                if (adminState.lldapEnabled) {
                    document.getElementById('lldapUsersSection').style.display = '';
                    document.getElementById('lldapDivider').style.display = '';
                    document.getElementById('lldapGroupsSection').style.display = '';
                    document.getElementById('lldapGroupsDivider').style.display = '';
                    const [usersResp, groupsResp] = await Promise.all([
                        fetch('/api/admin/users', { credentials: 'include' }),
                        fetch('/api/admin/groups', { credentials: 'include' })
                    ]);

                    if (usersResp.ok) {
                        adminState.users = await usersResp.json();
                        renderUsersList();
                    }

                    if (groupsResp.ok) {
                        adminState.groups = await groupsResp.json();
                        renderGroupsList();
                    }
                }

                // Load local users if local auth is enabled
                if (adminState.localAuthEnabled) {
                    const localUsersResp = await fetch('/api/admin/local-users', { credentials: 'include' });
                    if (localUsersResp.ok) {
                        adminState.localUsers = await localUsersResp.json() || [];
                        renderLocalUsersList();
                    }
                    document.getElementById('localGroupsSection').style.display = '';
                    renderLocalGroupsList();
                }

                // Build unified groups list from all sources (LLDAP, local users,
                // app configs, discovered apps, custom localStorage groups)
                const allGroupNames = new Set();
                // LLDAP groups
                adminState.groups.forEach(g => allGroupNames.add(g.displayName));
                // Local user groups
                if (adminState.localUsers) {
                    adminState.localUsers.forEach(u => {
                        if (u.groups) u.groups.forEach(g => allGroupNames.add(g));
                    });
                }
                // Groups already assigned to apps in config
                if (adminState.apps) {
                    adminState.apps.forEach(a => {
                        if (a.groups) a.groups.forEach(g => allGroupNames.add(g));
                    });
                }
                // Groups on configured discovered apps
                if (adminState.discoveredApps) {
                    adminState.discoveredApps.forEach(a => {
                        if (a.override && a.override.groups) {
                            a.override.groups.forEach(g => allGroupNames.add(g));
                        }
                    });
                }
                // Custom groups from localStorage
                const customGroups = JSON.parse(localStorage.getItem('dashgate-local-groups') || '[]');
                customGroups.forEach(g => allGroupNames.add(g));
                // Always include default groups
                allGroupNames.add('admin');
                allGroupNames.add('users');
                adminState.groups = Array.from(allGroupNames).sort().map(name => ({ displayName: name }));

                // Load Docker discovery status
                await loadDockerDiscoveryStatus();

                // Load Traefik discovery status
                await loadTraefikDiscoveryStatus();

                // Load Nginx discovery status
                await loadNginxDiscoveryStatus();

                // Load NPM discovery status
                await loadNPMDiscoveryStatus();

                // Load Caddy discovery status
                await loadCaddyDiscoveryStatus();

                // Load Unraid discovery status
                await loadUnraidDiscoveryStatus();

                // Load discovered apps for management
                await loadDiscoveredAppsData();
            } catch (e) {
                console.error('Failed to load admin data:', e);
            }
        }

        // Targeted reload functions (avoid reloading all admin data after single mutations)
        async function reloadApps() {
            if (!adminState.isAdmin) return;
            try {
                const [appsResp, categoriesResp] = await Promise.all([
                    fetch('/api/admin/config/apps', { credentials: 'include' }),
                    fetch('/api/admin/config/categories', { credentials: 'include' })
                ]);
                if (appsResp.ok) {
                    adminState.apps = await appsResp.json();
                    renderAppsList();
                }
                if (categoriesResp.ok) {
                    adminState.categories = await categoriesResp.json();
                    renderCategoriesList();
                }
            } catch (e) {
                console.error('Failed to reload apps:', e);
            }
        }

        async function reloadCategories() {
            if (!adminState.isAdmin) return;
            try {
                const resp = await fetch('/api/admin/config/categories', { credentials: 'include' });
                if (resp.ok) {
                    adminState.categories = await resp.json();
                    renderCategoriesList();
                }
            } catch (e) {
                console.error('Failed to reload categories:', e);
            }
        }

        async function reloadLocalUsers() {
            if (!adminState.isAdmin) return;
            try {
                const resp = await fetch('/api/admin/local-users', { credentials: 'include' });
                if (resp.ok) {
                    adminState.localUsers = await resp.json() || [];
                    renderLocalUsersList();
                }
            } catch (e) {
                console.error('Failed to reload local users:', e);
            }
        }

        async function reloadDiscoveryStatus() {
            if (!adminState.isAdmin) return;
            try {
                await Promise.all([
                    loadDockerDiscoveryStatus(),
                    loadTraefikDiscoveryStatus(),
                    loadNginxDiscoveryStatus(),
                    loadNPMDiscoveryStatus(),
                    loadCaddyDiscoveryStatus(),
                    loadUnraidDiscoveryStatus(),
                    loadDiscoveredAppsData()
                ]);
            } catch (e) {
                console.error('Failed to reload discovery status:', e);
            }
        }

        // System Settings Management
        let systemConfigDirty = false;
        let currentSystemConfig = {};

        async function loadSystemConfig() {
            try {
                const resp = await fetch('/api/admin/system-config', { credentials: 'include' });
                if (resp.ok) {
                    const config = await resp.json();
                    currentSystemConfig = config;

                    // General settings
                    document.getElementById('systemSessionDays').value = config.sessionDays || 7;
                    document.getElementById('systemCookieSecure').checked = config.cookieSecure !== false;

                    // Security settings
                    document.getElementById('systemAdminGroup').value = config.adminGroup || 'admin';

                    // Auth providers
                    document.getElementById('systemProxyAuth').checked = config.proxyAuthEnabled || false;
                    document.getElementById('systemTrustedProxies').value = config.trustedProxies || '';
                    document.getElementById('systemLocalAuth').checked = config.localAuthEnabled || false;
                    document.getElementById('systemLDAPAuth').checked = config.ldapAuthEnabled || false;
                    document.getElementById('systemOIDCAuth').checked = config.oidcAuthEnabled || false;
                    document.getElementById('systemAPIKeys').checked = config.apiKeyEnabled || false;

                    // LDAP settings
                    document.getElementById('ldapServer').value = config.ldapServer || '';
                    document.getElementById('ldapBindDN').value = config.ldapBindDN || '';
                    document.getElementById('ldapBaseDN').value = config.ldapBaseDN || '';
                    document.getElementById('ldapUserFilter').value = config.ldapUserFilter || '(uid=%s)';
                    document.getElementById('ldapGroupFilter').value = config.ldapGroupFilter || '(memberUid=%s)';
                    document.getElementById('ldapUserAttr').value = config.ldapUserAttr || 'uid';
                    document.getElementById('ldapEmailAttr').value = config.ldapEmailAttr || 'mail';
                    document.getElementById('ldapDisplayAttr').value = config.ldapDisplayAttr || 'cn';
                    document.getElementById('ldapGroupAttr').value = config.ldapGroupAttr || 'memberOf';
                    document.getElementById('ldapStartTLS').checked = config.ldapStartTLS || false;
                    document.getElementById('ldapSkipVerify').checked = config.ldapSkipVerify || false;

                    // OIDC settings
                    document.getElementById('oidcIssuer').value = config.oidcIssuer || '';
                    document.getElementById('oidcClientID').value = config.oidcClientID || '';
                    document.getElementById('oidcRedirectURL').value = config.oidcRedirectURL || '';
                    document.getElementById('oidcScopes').value = config.oidcScopes || 'openid profile email groups';
                    document.getElementById('oidcGroupsClaim').value = config.oidcGroupsClaim || 'groups';

                    // Update UI visibility
                    toggleTrustedProxiesSection();
                    updateProxyAuthWarning();
                    toggleLDAPSection();
                    toggleOIDCSection();
                    toggleAPIKeySection();
                    toggleLocalAuthSection();

                    systemConfigDirty = false;
                    updateSaveButtonState();

                    // Load API keys if enabled
                    if (config.apiKeyEnabled) {
                        loadAPIKeys();
                    }
                }
            } catch (e) {
                console.error('Failed to load system config:', e);
            }
        }

        function markSystemConfigDirty() {
            systemConfigDirty = true;
            updateSaveButtonState();
        }

        function updateSaveButtonState() {
            const btn = document.getElementById('saveSystemConfig');
            const status = document.getElementById('systemConfigStatus');
            if (systemConfigDirty) {
                btn.disabled = false;
                btn.style.opacity = '1';
                status.textContent = 'Unsaved changes';
                status.style.color = 'var(--orange)';
            } else {
                btn.disabled = true;
                btn.style.opacity = '0.5';
                status.textContent = '';
            }
        }

        function toggleTrustedProxiesSection() {
            const enabled = document.getElementById('systemProxyAuth').checked;
            document.getElementById('trustedProxiesSection').style.display = enabled ? 'block' : 'none';
            updateProxyAuthWarning();
        }

        function updateProxyAuthWarning() {
            const warning = document.getElementById('proxyAuthWarning');
            if (!warning) return;
            const proxyEnabled = document.getElementById('systemProxyAuth').checked;
            const trustedProxies = (document.getElementById('systemTrustedProxies').value || '').trim();
            warning.style.display = (proxyEnabled && !trustedProxies) ? 'block' : 'none';
        }

        function toggleLDAPSection() {
            const enabled = document.getElementById('systemLDAPAuth').checked;
            document.getElementById('ldapConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleOIDCSection() {
            const enabled = document.getElementById('systemOIDCAuth').checked;
            document.getElementById('oidcConfigSection').style.display = enabled ? 'block' : 'none';
        }

        function toggleAPIKeySection() {
            const enabled = document.getElementById('systemAPIKeys').checked;
            document.getElementById('apiKeysSection').style.display = enabled ? 'block' : 'none';
            if (enabled && adminState.apiKeys === undefined) {
                loadAPIKeys();
            }
        }

        function toggleLocalAuthSection() {
            const enabled = document.getElementById('systemLocalAuth').checked;
            document.getElementById('localUsersSection').style.display = enabled ? 'block' : 'none';
            document.getElementById('localUsersDivider').style.display = enabled ? 'block' : 'none';
        }

        async function saveSystemSettings() {
            const proxyAuthEnabled = document.getElementById('systemProxyAuth').checked;
            const localAuthEnabled = document.getElementById('systemLocalAuth').checked;
            const ldapAuthEnabled = document.getElementById('systemLDAPAuth').checked;
            const oidcAuthEnabled = document.getElementById('systemOIDCAuth').checked;
            const apiKeyEnabled = document.getElementById('systemAPIKeys').checked;

            // Validate at least one auth method
            if (!proxyAuthEnabled && !localAuthEnabled && !ldapAuthEnabled && !oidcAuthEnabled) {
                showToast('Enable at least one authentication provider');
                return;
            }

            // Warn if enabling local auth without users
            if (localAuthEnabled && !currentSystemConfig.localAuthEnabled) {
                if (!adminState.localUsers || adminState.localUsers.length === 0) {
                    showToast('Create at least one local user before enabling local auth');
                    return;
                }
            }

            // Validate LDAP settings if enabled
            if (ldapAuthEnabled) {
                const ldapServer = document.getElementById('ldapServer').value.trim();
                const ldapBindDN = document.getElementById('ldapBindDN').value.trim();
                const ldapBaseDN = document.getElementById('ldapBaseDN').value.trim();
                if (!ldapServer || !ldapBindDN || !ldapBaseDN) {
                    showToast('LDAP Server, Bind DN, and Base DN are required');
                    return;
                }
            }

            // Validate OIDC settings if enabled
            if (oidcAuthEnabled) {
                const oidcIssuer = document.getElementById('oidcIssuer').value.trim();
                const oidcClientID = document.getElementById('oidcClientID').value.trim();
                const oidcRedirectURL = document.getElementById('oidcRedirectURL').value.trim();
                if (!oidcIssuer || !oidcClientID || !oidcRedirectURL) {
                    showToast('OIDC Issuer, Client ID, and Redirect URL are required');
                    return;
                }
            }

            const payload = {
                sessionDays: parseInt(document.getElementById('systemSessionDays').value) || 7,
                cookieSecure: document.getElementById('systemCookieSecure').checked,
                adminGroup: document.getElementById('systemAdminGroup').value.trim() || 'admin',
                proxyAuthEnabled,
                trustedProxies: document.getElementById('systemTrustedProxies').value.trim(),
                localAuthEnabled,
                ldapAuthEnabled,
                oidcAuthEnabled,
                apiKeyEnabled,
                // LDAP settings
                ldapServer: document.getElementById('ldapServer').value.trim(),
                ldapBindDN: document.getElementById('ldapBindDN').value.trim(),
                ldapBindPassword: document.getElementById('ldapBindPassword').value,
                ldapBaseDN: document.getElementById('ldapBaseDN').value.trim(),
                ldapUserFilter: document.getElementById('ldapUserFilter').value.trim() || '(uid=%s)',
                ldapGroupFilter: document.getElementById('ldapGroupFilter').value.trim() || '(memberUid=%s)',
                ldapUserAttr: document.getElementById('ldapUserAttr').value.trim() || 'uid',
                ldapEmailAttr: document.getElementById('ldapEmailAttr').value.trim() || 'mail',
                ldapDisplayAttr: document.getElementById('ldapDisplayAttr').value.trim() || 'cn',
                ldapGroupAttr: document.getElementById('ldapGroupAttr').value.trim() || 'memberOf',
                ldapStartTLS: document.getElementById('ldapStartTLS').checked,
                ldapSkipVerify: document.getElementById('ldapSkipVerify').checked,
                // OIDC settings
                oidcIssuer: document.getElementById('oidcIssuer').value.trim(),
                oidcClientID: document.getElementById('oidcClientID').value.trim(),
                oidcClientSecret: document.getElementById('oidcClientSecret').value,
                oidcRedirectURL: document.getElementById('oidcRedirectURL').value.trim(),
                oidcScopes: document.getElementById('oidcScopes').value.trim() || 'openid profile email groups',
                oidcGroupsClaim: document.getElementById('oidcGroupsClaim').value.trim() || 'groups'
            };

            try {
                const resp = await fetch('/api/admin/system-config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(payload)
                });

                if (!resp.ok) throw new Error(await resp.text());

                // Clear password fields after save
                document.getElementById('ldapBindPassword').value = '';
                document.getElementById('oidcClientSecret').value = '';

                systemConfigDirty = false;
                updateSaveButtonState();
                document.getElementById('systemConfigStatus').textContent = 'Saved!';
                document.getElementById('systemConfigStatus').style.color = 'var(--green)';

                // Update local state
                currentSystemConfig = { ...currentSystemConfig, ...payload };

                showToast('System settings saved');

                // Offer to reload if auth providers changed
                setTimeout(() => {
                    if (confirm('Settings saved. Reload page to apply changes?')) {
                        location.reload();
                    }
                }, 500);
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        // API Key Management
        async function loadAPIKeys() {
            try {
                const resp = await fetch('/api/admin/api-keys', { credentials: 'include' });
                if (resp.ok) {
                    adminState.apiKeys = await resp.json() || [];
                    renderAPIKeysList();
                }
            } catch (e) {
                console.error('Failed to load API keys:', e);
            }
        }

        function renderAPIKeysList() {
            const container = document.getElementById('apiKeysList');
            if (!adminState.apiKeys || adminState.apiKeys.length === 0) {
                container.innerHTML = '<div class="admin-empty">No API keys. Click "Create Key" to add one.</div>';
                return;
            }

            container.innerHTML = adminState.apiKeys.map(key => `
                <div class="api-key-item">
                    <div class="api-key-info">
                        <div class="api-key-name">${escapeHtml(key.name)}</div>
                        <div class="api-key-meta">
                            <span class="api-key-prefix">${escapeHtml(key.keyPrefix)}...</span>
                            User: ${escapeHtml(key.username)} |
                            ${key.expiresAt ? `Expires: ${new Date(key.expiresAt).toLocaleDateString()}` : 'Never expires'}
                        </div>
                    </div>
                    <div class="admin-item-actions">
                        <button class="admin-action-btn danger" onclick="confirmDeleteAPIKey(${key.id}, '${escapeHtml(key.name).replace(/'/g, "\\'")}')" title="Revoke">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                            </svg>
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function openCreateAPIKeyModal() {
            document.getElementById('apiKeyCreateForm').style.display = 'block';
            document.getElementById('apiKeyResult').style.display = 'none';
            document.getElementById('createAPIKeyBtn').style.display = 'inline-flex';
            document.getElementById('apiKeyName').value = '';
            document.getElementById('apiKeyUsername').value = '';
            document.getElementById('apiKeyGroups').value = '';
            document.getElementById('apiKeyExpiry').value = '365';
            document.getElementById('apiKeyModal').classList.add('open');
        }

        function closeAPIKeyModal() {
            document.getElementById('apiKeyModal').classList.remove('open');
        }

        async function createAPIKey() {
            const name = document.getElementById('apiKeyName').value.trim();
            const username = document.getElementById('apiKeyUsername').value.trim();
            const groupsStr = document.getElementById('apiKeyGroups').value.trim();
            const expiryDays = parseInt(document.getElementById('apiKeyExpiry').value);

            if (!name || !username) {
                showToast('Name and username are required');
                return;
            }

            const groups = groupsStr ? groupsStr.split(',').map(g => g.trim()).filter(g => g) : [];

            try {
                const resp = await fetch('/api/admin/api-keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ name, username, groups, expiryDays })
                });

                if (!resp.ok) throw new Error(await resp.text());

                const result = await resp.json();

                // Show the API key (only shown once)
                document.getElementById('apiKeyCreateForm').style.display = 'none';
                document.getElementById('apiKeyResult').style.display = 'block';
                document.getElementById('createAPIKeyBtn').style.display = 'none';
                document.getElementById('apiKeyValue').textContent = result.key;

                // Reload keys list
                loadAPIKeys();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        function copyAPIKey() {
            const key = document.getElementById('apiKeyValue').textContent;
            navigator.clipboard.writeText(key).then(() => {
                showToast('API key copied to clipboard');
            });
        }

        function confirmDeleteAPIKey(id, name) {
            document.getElementById('confirmDeleteMessage').textContent = `Revoke API key "${name}"? This cannot be undone.`;
            adminState.deleteCallback = async () => {
                try {
                    const resp = await fetch(`/api/admin/api-keys/${id}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    showToast('API key revoked');
                    closeConfirmDelete();
                    loadAPIKeys();
                } catch (e) {
                    showToast('Error: ' + e.message);
                }
            };
            document.getElementById('confirmDeleteModal').classList.add('open');
        }

        // Backup/Restore
        async function downloadBackup() {
            try {
                const resp = await fetch('/api/admin/backup', { credentials: 'include' });
                if (!resp.ok) throw new Error(await resp.text());

                const blob = await resp.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `dashgate-backup-${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                showToast('Backup downloaded');
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        async function restoreFromBackup(input) {
            const file = input.files[0];
            if (!file) return;

            if (!confirm('This will restore settings from the backup file. Continue?')) {
                input.value = '';
                return;
            }

            try {
                const text = await file.text();
                const backup = JSON.parse(text);

                const resp = await fetch('/api/admin/restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(backup)
                });

                if (!resp.ok) throw new Error(await resp.text());

                const result = await resp.json();
                showToast(`Restored: ${result.restored.systemConfig} config, ${result.restored.userPreferences} preferences`);

                // Reload page to apply changes
                setTimeout(() => {
                    if (confirm('Restore complete. Reload page to apply changes?')) {
                        location.reload();
                    }
                }, 500);
            } catch (e) {
                showToast('Error: ' + e.message);
            }

            input.value = '';
        }
