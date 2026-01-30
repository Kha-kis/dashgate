        // admin-apps.js - App/category/icon management

        function renderAppsList() {
            const container = document.getElementById('appsList');
            const searchTerm = document.getElementById('appSearchInput')?.value.toLowerCase() || '';

            // Build combined list: manual apps + configured discovered apps
            const manualApps = (adminState.apps || []).map(a => ({ ...a, _source: 'manual' }));

            const configuredDiscovered = (adminState.discoveredApps || [])
                .filter(a => a.override && !a.override.hidden)
                .map(a => {
                    const o = a.override;
                    return {
                        name: o.nameOverride || a.name,
                        url: o.urlOverride || a.url,
                        category: o.category || '',
                        description: o.descriptionOverride || '',
                        icon: o.iconOverride || a.icon || '',
                        groups: o.groups || [],
                        _source: 'discovered',
                        _discoverySource: a.source,
                        _discoveredUrl: a.url
                    };
                });

            const allApps = [...manualApps, ...configuredDiscovered];

            const filteredApps = allApps.filter(a =>
                a.name.toLowerCase().includes(searchTerm) ||
                (a.category || '').toLowerCase().includes(searchTerm)
            );

            if (filteredApps.length === 0) {
                container.innerHTML = '<div class="admin-empty">No apps found. Click "Add App" to create one.</div>';
                return;
            }

            container.innerHTML = filteredApps.map(app => {
                const iconHtml = app.icon
                    ? `<img src="/static/icons/${escapeHtml(app.icon)}" alt="">`
                    : `<span style="font-weight:600">${escapeHtml(app.name[0])}</span>`;

                const sourceBadge = app._source === 'discovered'
                    ? `<span class="app-source-badge ${escapeHtml(app._discoverySource)}">${escapeHtml(app._discoverySource)}</span>`
                    : '';

                const metaText = escapeHtml(app.category || '');

                const groupsHtml = app.groups && app.groups.length > 0
                    ? `<div class="admin-item-groups">
                        ${app.groups.slice(0, 3).map(g => `<span class="admin-group-badge">${escapeHtml(g)}</span>`).join('')}
                        ${app.groups.length > 3 ? `<span class="admin-group-badge">+${app.groups.length - 3}</span>` : ''}
                       </div>`
                    : '<div class="admin-item-meta" style="color: var(--orange)">No groups</div>';

                const safeName = escapeHtml(app.name).replace(/'/g, "&#39;");

                if (app._source === 'discovered') {
                    return `
                        <div class="admin-item">
                            <div class="admin-app-icon">${iconHtml}</div>
                            <div class="admin-item-info">
                                <div class="admin-item-name">${escapeHtml(app.name)}</div>
                                <div class="admin-item-meta">${metaText} ${sourceBadge}</div>
                                ${groupsHtml}
                            </div>
                            <div class="admin-item-actions">
                                <button class="admin-action-btn" onclick="openDiscoveredAppModal('${encodeURIComponent(app._discoveredUrl)}')" title="Edit">
                                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                        <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                    </svg>
                                </button>
                                <button class="admin-action-btn danger" onclick="confirmResetDiscoveredApp('${encodeURIComponent(app._discoveredUrl)}', '${safeName}')" title="Reset">
                                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                        <polyline points="3 6 5 6 21 6"/>
                                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                                    </svg>
                                </button>
                            </div>
                        </div>`;
                } else {
                    return `
                        <div class="admin-item">
                            <div class="admin-app-icon">${iconHtml}</div>
                            <div class="admin-item-info">
                                <div class="admin-item-name">${escapeHtml(app.name)}</div>
                                <div class="admin-item-meta">${metaText}</div>
                                ${groupsHtml}
                            </div>
                            <div class="admin-item-actions">
                                <button class="admin-action-btn" onclick="openEditAppConfigModal('${encodeURIComponent(app.url)}')" title="Edit">
                                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                        <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                    </svg>
                                </button>
                                <button class="admin-action-btn danger" onclick="confirmDeleteApp('${encodeURIComponent(app.url)}', '${safeName}')" title="Delete">
                                    <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                        <polyline points="3 6 5 6 21 6"/>
                                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                                    </svg>
                                </button>
                            </div>
                        </div>`;
                }
            }).join('');
        }

        function filterApps() {
            renderAppsList();
        }

        // Create/Edit App Modal
        function openCreateAppModal() {
            adminState.editingApp = null;
            document.getElementById('appConfigTitle').textContent = 'Add App';
            document.getElementById('appConfigOriginalUrl').value = '';
            document.getElementById('appConfigName').value = '';
            document.getElementById('appConfigUrl').value = '';
            document.getElementById('appConfigDesc').value = '';
            document.getElementById('appConfigIcon').value = '';
            updateIconPreview('');

            // Populate category dropdown
            const categorySelect = document.getElementById('appConfigCategory');
            categorySelect.innerHTML = adminState.categories.map(c =>
                `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`
            ).join('') + '<option value="__new__">+ New Category...</option>';

            // Populate groups
            renderAppConfigGroups([]);

            document.getElementById('appConfigModal').classList.add('open');
        }

        function openEditAppConfigModal(encodedUrl) {
            const url = decodeURIComponent(encodedUrl);
            const app = adminState.apps.find(a => a.url === url);
            if (!app) return;

            adminState.editingApp = app;
            document.getElementById('appConfigTitle').textContent = 'Edit App';
            document.getElementById('appConfigOriginalUrl').value = url;
            document.getElementById('appConfigName').value = app.name;
            document.getElementById('appConfigUrl').value = app.url;
            document.getElementById('appConfigDesc').value = app.description || '';
            document.getElementById('appConfigIcon').value = app.icon || '';
            updateIconPreview(app.icon || '');

            // Populate category dropdown
            const categorySelect = document.getElementById('appConfigCategory');
            categorySelect.innerHTML = adminState.categories.map(c =>
                `<option value="${escapeHtml(c.name)}" ${c.name === app.category ? 'selected' : ''}>${escapeHtml(c.name)}</option>`
            ).join('') + '<option value="__new__">+ New Category...</option>';

            // Populate groups
            renderAppConfigGroups(app.groups || []);

            document.getElementById('appConfigModal').classList.add('open');
        }

        function getAdminGroupNames() {
            const str = (typeof currentSystemConfig !== 'undefined' && currentSystemConfig && currentSystemConfig.adminGroup) || 'admin';
            return str.split(',').map(s => s.trim()).filter(Boolean);
        }

        function renderAppConfigGroups(selectedGroups) {
            const container = document.getElementById('appConfigGroups');
            if (adminState.groups.length === 0) {
                container.innerHTML = '<div class="admin-empty">No groups available</div>';
                return;
            }
            const adminGroups = getAdminGroupNames();
            container.innerHTML = adminState.groups.map(group => {
                const isAdminGroup = adminGroups.includes(group.displayName);
                const isChecked = isAdminGroup || selectedGroups.includes(group.displayName);
                return `
                <label class="admin-group-checkbox">
                    <input type="checkbox" value="${escapeHtml(group.displayName)}" ${isChecked ? 'checked' : ''} ${isAdminGroup ? 'disabled' : ''}>
                    <span class="admin-group-checkbox-label">${escapeHtml(group.displayName)}${isAdminGroup ? ' (required)' : ''}</span>
                </label>`;
            }).join('');
        }

        function closeAppConfigModal() {
            document.getElementById('appConfigModal').classList.remove('open');
            adminState.editingApp = null;
        }

        async function saveAppConfig() {
            const originalUrl = document.getElementById('appConfigOriginalUrl').value;
            const name = document.getElementById('appConfigName').value.trim();
            const url = document.getElementById('appConfigUrl').value.trim();
            let category = document.getElementById('appConfigCategory').value;
            const description = document.getElementById('appConfigDesc').value.trim();
            const icon = document.getElementById('appConfigIcon').value;
            const checkboxes = document.querySelectorAll('#appConfigGroups input[type="checkbox"]:checked');
            const groups = Array.from(checkboxes).map(cb => cb.value);
            // Always include admin groups (disabled checkboxes don't appear in :checked)
            getAdminGroupNames().forEach(g => {
                if (!groups.includes(g)) groups.push(g);
            });

            if (!name || !url) {
                showToast('Name and URL are required');
                return;
            }

            if (category === '__new__') {
                const newCat = prompt('Enter new category name:');
                if (!newCat) return;
                category = newCat;
            }

            try {
                const method = originalUrl ? 'PUT' : 'POST';
                const body = {
                    name, url, category, description, icon, groups,
                    ...(originalUrl && { originalUrl })
                };

                const resp = await fetch('/api/admin/config/apps', {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(body)
                });

                if (!resp.ok) throw new Error(await resp.text());

                showToast(originalUrl ? 'App updated' : 'App created');
                closeAppConfigModal();
                await reloadApps();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        function confirmDeleteApp(encodedUrl, name) {
            document.getElementById('confirmDeleteMessage').textContent = `Delete "${name}"? This cannot be undone.`;
            adminState.deleteCallback = async () => {
                try {
                    const resp = await fetch(`/api/admin/config/apps?url=${encodedUrl}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    showToast('App deleted');
                    closeConfirmDelete();
                    await reloadApps();
                } catch (e) {
                    showToast('Error: ' + e.message);
                }
            };
            document.getElementById('confirmDeleteModal').classList.add('open');
        }

        function closeConfirmDelete() {
            document.getElementById('confirmDeleteModal').classList.remove('open');
            adminState.deleteCallback = null;
        }

        function confirmDelete() {
            if (adminState.deleteCallback) adminState.deleteCallback();
        }

        // Icon Management
        let dashboardIconsCache = null;
        let activeIconTab = 'local';

        function updateIconPreview(iconName) {
            const preview = document.getElementById('iconPreview');
            if (iconName) {
                preview.innerHTML = `<img src="/static/icons/${escapeHtml(iconName)}" alt="${escapeHtml(iconName)}">`;
            } else {
                preview.innerHTML = '<span>No icon</span>';
            }
        }

        function openIconSelector() {
            renderIconGrid();
            if (activeIconTab === 'dashboard') {
                renderDashboardIconGrid();
            }
            // Restore active tab state
            document.querySelectorAll('.icon-picker-tab').forEach(t => {
                t.classList.toggle('active', t.dataset.iconTab === activeIconTab);
            });
            document.getElementById('localIconPanel').classList.toggle('active', activeIconTab === 'local');
            document.getElementById('dashboardIconPanel').classList.toggle('active', activeIconTab === 'dashboard');
            document.getElementById('iconSelectorModal').classList.add('open');
        }

        function closeIconSelector() {
            document.getElementById('iconSelectorModal').classList.remove('open');
        }

        function switchIconTab(tab) {
            activeIconTab = tab;
            document.querySelectorAll('.icon-picker-tab').forEach(t => {
                t.classList.toggle('active', t.dataset.iconTab === tab);
            });
            document.getElementById('localIconPanel').classList.toggle('active', tab === 'local');
            document.getElementById('dashboardIconPanel').classList.toggle('active', tab === 'dashboard');

            if (tab === 'local') {
                renderIconGrid();
            } else {
                loadDashboardIcons().then(() => renderDashboardIconGrid());
            }
        }

        function renderIconGrid() {
            const container = document.getElementById('iconGrid');
            const searchTerm = document.getElementById('iconSearchInput')?.value.toLowerCase() || '';
            const currentIcon = window._discoveredIconMode
                ? document.getElementById('discoveredAppIconOverride').value
                : document.getElementById('appConfigIcon').value;

            const filtered = adminState.icons.filter(i => i.toLowerCase().includes(searchTerm));

            if (filtered.length === 0) {
                container.innerHTML = '<div class="admin-empty">No icons found</div>';
                return;
            }

            container.innerHTML = filtered.map(icon => `
                <div class="icon-grid-item ${icon === currentIcon ? 'selected' : ''}" onclick="selectIcon('${escapeHtml(icon)}')">
                    <img src="/static/icons/${escapeHtml(icon)}" alt="${escapeHtml(icon)}">
                </div>
            `).join('');
        }

        async function loadDashboardIcons() {
            if (dashboardIconsCache) return;
            const grid = document.getElementById('dashboardIconGrid');
            grid.innerHTML = '<div class="admin-loading">Loading icons...</div>';
            try {
                const resp = await fetch('/api/admin/config/icons/dashboard-icons', { credentials: 'include' });
                if (resp.ok) dashboardIconsCache = await resp.json();
            } catch (e) {
                grid.innerHTML = '<div class="admin-empty">Failed to load icons</div>';
            }
        }

        function renderDashboardIconGrid() {
            const container = document.getElementById('dashboardIconGrid');
            const info = document.getElementById('dashboardIconInfo');
            const searchTerm = document.getElementById('iconSearchInput')?.value.toLowerCase() || '';

            if (!dashboardIconsCache) {
                container.innerHTML = '<div class="admin-empty">Failed to load icons</div>';
                info.textContent = '';
                return;
            }

            if (searchTerm.length < 1) {
                container.innerHTML = '<div class="admin-empty">Search for an icon above</div>';
                info.textContent = dashboardIconsCache.length + ' icons available';
                return;
            }

            const filtered = dashboardIconsCache.filter(n => n.toLowerCase().includes(searchTerm));
            const maxDisplay = 100;
            const displayed = filtered.slice(0, maxDisplay);

            if (displayed.length === 0) {
                container.innerHTML = '<div class="admin-empty">No icons found</div>';
                info.textContent = '';
                return;
            }

            info.textContent = filtered.length > maxDisplay
                ? `Showing ${maxDisplay} of ${filtered.length} results`
                : `${filtered.length} result${filtered.length !== 1 ? 's' : ''}`;

            container.innerHTML = displayed.map(name => `
                <div class="icon-grid-item" onclick="selectDashboardIcon('${escapeHtml(name)}')" title="${escapeHtml(name)}">
                    <img src="https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/svg/${encodeURIComponent(name)}.svg" loading="lazy" alt="${escapeHtml(name)}">
                </div>
            `).join('');
        }

        async function selectDashboardIcon(name) {
            const items = document.querySelectorAll('#dashboardIconGrid .icon-grid-item');
            items.forEach(el => {
                if (el.getAttribute('title') === name) {
                    el.style.opacity = '0.5';
                    el.style.pointerEvents = 'none';
                }
            });
            try {
                const resp = await fetch('/api/admin/config/icons/download', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name })
                });
                if (!resp.ok) throw new Error(await resp.text());
                const data = await resp.json();
                if (!adminState.icons.includes(data.filename)) {
                    adminState.icons.push(data.filename);
                }
                selectIcon(data.filename);
                showToast('Icon added');
            } catch (e) {
                showToast('Error: ' + e.message);
                items.forEach(el => {
                    if (el.getAttribute('title') === name) {
                        el.style.opacity = '';
                        el.style.pointerEvents = '';
                    }
                });
            }
        }

        function filterIcons() {
            if (activeIconTab === 'local') {
                renderIconGrid();
            } else {
                renderDashboardIconGrid();
            }
        }

        function selectIcon(iconName) {
            if (window._discoveredIconMode) {
                document.getElementById('discoveredAppIconOverride').value = iconName;
                updateDiscoveredIconPreview(iconName);
            } else {
                document.getElementById('appConfigIcon').value = iconName;
                updateIconPreview(iconName);
            }
            closeIconSelector();
        }

        async function uploadIcon(event) {
            const file = event.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('icon', file);

            try {
                const resp = await fetch('/api/admin/config/icons/upload', {
                    method: 'POST',
                    credentials: 'include',
                    body: formData
                });

                if (!resp.ok) throw new Error(await resp.text());

                const data = await resp.json();
                adminState.icons.push(data.filename);
                selectIcon(data.filename);
                showToast('Icon uploaded');
            } catch (e) {
                showToast('Error: ' + e.message);
            }
            event.target.value = '';
        }

        // Category Management
        function renderCategoriesList() {
            const container = document.getElementById('categoriesList');

            if (adminState.categories.length === 0) {
                container.innerHTML = '<div class="admin-empty">No categories</div>';
                return;
            }

            container.innerHTML = adminState.categories.map(cat => `
                <div class="admin-item category-item">
                    <div class="admin-item-icon">
                        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                        </svg>
                    </div>
                    <div class="category-item-info">
                        <div class="category-item-name">${escapeHtml(cat.name)}</div>
                        <div class="category-item-count">${cat.appCount} apps</div>
                    </div>
                    <div class="admin-item-actions">
                        <button class="admin-action-btn" onclick="openEditCategoryModal('${escapeHtml(cat.name).replace(/'/g, "\\'")}')" title="Rename">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                        ${cat.appCount === 0 ? `
                        <button class="admin-action-btn danger" onclick="confirmDeleteCategory('${escapeHtml(cat.name).replace(/'/g, "\\'")}')" title="Delete">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                            </svg>
                        </button>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }

        function openCreateCategoryModal() {
            document.getElementById('categoryModalTitle').textContent = 'Add Category';
            document.getElementById('categoryOldName').value = '';
            document.getElementById('categoryNameInput').value = '';
            document.getElementById('categoryModal').classList.add('open');
        }

        function openEditCategoryModal(name) {
            document.getElementById('categoryModalTitle').textContent = 'Rename Category';
            document.getElementById('categoryOldName').value = name;
            document.getElementById('categoryNameInput').value = name;
            document.getElementById('categoryModal').classList.add('open');
        }

        function closeCategoryModal() {
            document.getElementById('categoryModal').classList.remove('open');
        }

        async function saveCategory() {
            const oldName = document.getElementById('categoryOldName').value;
            const newName = document.getElementById('categoryNameInput').value.trim();

            if (!newName) {
                showToast('Category name required');
                return;
            }

            try {
                const method = oldName ? 'PUT' : 'POST';
                const body = oldName ? { oldName, newName } : { name: newName };

                const resp = await fetch('/api/admin/config/categories', {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(body)
                });

                if (!resp.ok) throw new Error(await resp.text());

                showToast(oldName ? 'Category renamed' : 'Category created');
                closeCategoryModal();
                await reloadApps();
            } catch (e) {
                showToast('Error: ' + e.message);
            }
        }

        function confirmDeleteCategory(name) {
            document.getElementById('confirmDeleteMessage').textContent = `Delete category "${name}"?`;
            adminState.deleteCallback = async () => {
                try {
                    const resp = await fetch(`/api/admin/config/categories?name=${encodeURIComponent(name)}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    showToast('Category deleted');
                    closeConfirmDelete();
                    await reloadCategories();
                } catch (e) {
                    showToast('Error: ' + e.message);
                }
            };
            document.getElementById('confirmDeleteModal').classList.add('open');
        }
