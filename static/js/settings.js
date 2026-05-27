        // settings.js - Settings modal, theme/apply functions, CSS editor, favorites management, import/export

        function sanitizeCSS(css) {
            if (!css) return '';
            // First strip CSS comments to prevent comment-based bypasses
            let sanitized = css.replace(/\/\*[\s\S]*?\*\//g, '');
            // Strip CSS escape sequences (backslash followed by hex digits or chars)
            // that could be used to bypass keyword detection (e.g., \75rl for url)
            sanitized = sanitized.replace(/\\[0-9a-fA-F]{1,6}\s?/g, '_');
            sanitized = sanitized.replace(/\\./g, '_');
            // Block url() which can exfiltrate data
            sanitized = sanitized.replace(/url\s*\(/gi, '/* blocked-url( */');
            // Block @import which can load external stylesheets
            sanitized = sanitized.replace(/@import/gi, '/* blocked-import */');
            // Block expression() (IE legacy)
            sanitized = sanitized.replace(/expression\s*\(/gi, '/* blocked-expression( */');
            // Block behavior: (IE legacy)
            sanitized = sanitized.replace(/behavior\s*:/gi, '/* blocked-behavior: */');
            // Block -moz-binding (Firefox legacy)
            sanitized = sanitized.replace(/-moz-binding\s*:/gi, '/* blocked-binding: */');
            // Block @charset, @namespace (could be used for encoding attacks)
            sanitized = sanitized.replace(/@charset/gi, '/* blocked-charset */');
            sanitized = sanitized.replace(/@namespace/gi, '/* blocked-namespace */');
            return sanitized;
        }

        function openSettings() {
            document.getElementById('settingsModal').classList.add('open');
            updateSettingsUI();
            renderFavoritesList();
            updateSettingsUserSection();
        }

        function closeSettings() {
            document.getElementById('settingsModal').classList.remove('open');
        }

        function initSettingsModal() {
            // Tab switching
            document.querySelectorAll('.settings-tab').forEach(tab => {
                tab.addEventListener('click', () => {
                    document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
                    document.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
                    tab.classList.add('active');
                    document.querySelector(`.settings-panel[data-panel="${tab.dataset.tab}"]`).classList.add('active');

                    // Load admin data when admin tab is clicked
                    if (tab.dataset.tab === 'admin' && adminState.isAdmin) {
                        loadAdminData();
                    }
                    // Render My Apps and Favorites lists when that tab is clicked
                    if (tab.dataset.tab === 'favorites') {
                        renderMyAppsList();
                        renderFavoritesList();
                    }
                });
            });

            // Admin sub-tab switching
            document.querySelectorAll('.admin-subtab').forEach(tab => {
                tab.addEventListener('click', () => {
                    const target = tab.dataset.adminTab;

                    // Update active tab
                    document.querySelectorAll('.admin-subtab').forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');

                    // Show target panel
                    document.querySelectorAll('.admin-subpanel').forEach(p => p.classList.remove('active'));
                    const targetPanel = document.querySelector(`[data-admin-panel="${target}"]`);
                    if (targetPanel) {
                        targetPanel.classList.add('active');
                    }
                });
            });

            // Theme radio buttons
            document.querySelectorAll('input[name="theme"]').forEach(input => {
                input.addEventListener('change', (e) => {
                    settings.theme = e.target.value;
                    saveSettings();
                    applyTheme();
                });
            });

            // Accent color buttons
            document.querySelectorAll('.color-option').forEach(btn => {
                btn.addEventListener('click', () => {
                    settings.accentColor = btn.dataset.color;
                    saveSettings();
                    applyAccentColor();
                    updateColorPicker();
                });
            });

            // Toggle switches
            document.getElementById('showGradient').addEventListener('change', (e) => {
                settings.showGradient = e.target.checked;
                saveSettings();
                applyGradient();
            });

            document.getElementById('showWidgets').addEventListener('change', (e) => {
                settings.showWidgets = e.target.checked;
                saveSettings();
                applyWidgets();
            });

            document.getElementById('showStatus').addEventListener('change', (e) => {
                settings.showStatus = e.target.checked;
                saveSettings();
                applyStatus();
            });

            document.getElementById('openInNewTab').addEventListener('change', (e) => {
                settings.openInNewTab = e.target.checked;
                saveSettings();
                applyLinkBehavior();
            });

            document.getElementById('showCategories').addEventListener('change', (e) => {
                settings.showCategories = e.target.checked;
                saveSettings();
                applyCategories();
            });

            // Icon size radio buttons
            document.querySelectorAll('input[name="iconSize"]').forEach(input => {
                input.addEventListener('change', (e) => {
                    settings.iconSize = e.target.value;
                    saveSettings();
                    applyIconSize();
                });
            });

            // Grid density radio buttons
            document.querySelectorAll('input[name="gridDensity"]').forEach(input => {
                input.addEventListener('change', (e) => {
                    settings.gridDensity = e.target.value;
                    saveSettings();
                    applyGridDensity();
                });
            });

            // Auto-refresh radio buttons
            document.querySelectorAll('input[name="autoRefresh"]').forEach(input => {
                input.addEventListener('change', (e) => {
                    settings.autoRefresh = parseInt(e.target.value);
                    saveSettings();
                    applyAutoRefresh();
                });
            });

            // Close on escape
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && document.getElementById('settingsModal').classList.contains('open')) {
                    closeSettings();
                }
            });

            // Close on backdrop click
            document.querySelector('.settings-backdrop').addEventListener('click', closeSettings);
        }

        function updateSettingsUI() {
            // Theme
            document.querySelector(`input[name="theme"][value="${settings.theme}"]`).checked = true;

            // Accent color
            updateColorPicker();

            // Toggles
            document.getElementById('showGradient').checked = settings.showGradient;
            document.getElementById('showWidgets').checked = settings.showWidgets;
            document.getElementById('showStatus').checked = settings.showStatus;
            document.getElementById('openInNewTab').checked = settings.openInNewTab;
            document.getElementById('showCategories').checked = settings.showCategories;

            // Radio buttons
            document.querySelector(`input[name="iconSize"][value="${settings.iconSize}"]`).checked = true;
            document.querySelector(`input[name="gridDensity"][value="${settings.gridDensity}"]`).checked = true;
            document.querySelector(`input[name="autoRefresh"][value="${settings.autoRefresh}"]`).checked = true;

            // Custom CSS textarea
            const customCSSInput = document.getElementById('customCSSInput');
            if (customCSSInput) {
                customCSSInput.value = settings.customCSS || '';
            }

            // Temperature unit
            const tempUnitSelect = document.getElementById('temperatureUnit');
            if (tempUnitSelect) {
                tempUnitSelect.value = settings.temperatureUnit || 'fahrenheit';
            }

            // Clock format
            const timeFormatSelect = document.getElementById('timeFormat');
            if (timeFormatSelect) {
                timeFormatSelect.value = settings.timeFormat || '12h';
            }

            // Widget config
            renderWidgetConfig();

            // CSS snippets
            renderCSSSnippets();
        }

        function updateColorPicker() {
            document.querySelectorAll('.color-option').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.color === settings.accentColor);
            });
        }

        function saveSettings() {
            localStorage.setItem('dashgate-settings', JSON.stringify(settings));
            debouncedSyncPreferences();
        }

        function applySettings() {
            applyTheme();
            applyAccentColor();
            applyGradient();
            applyIconSize();
            applyGridDensity();
            applyWidgets();
            applyStatus();
            applyLinkBehavior();
            applyAutoRefresh();
            applyCategories();
            applyCustomCSS();
        }

        function applyTheme() {
            document.documentElement.setAttribute('data-theme', settings.theme);
        }

        function applyAccentColor() {
            document.documentElement.setAttribute('data-accent', settings.accentColor);
        }

        function applyGradient() {
            document.body.classList.toggle('gradient-hidden', !settings.showGradient);
        }

        function applyIconSize() {
            document.documentElement.setAttribute('data-icon-size', settings.iconSize);
        }

        function applyGridDensity() {
            document.documentElement.setAttribute('data-grid-density', settings.gridDensity);
        }

        function applyWidgets() {
            document.body.classList.toggle('widgets-hidden', !settings.showWidgets);

            // Per-widget visibility
            const visibility = settings.widgetVisibility || defaultSettings.widgetVisibility;
            document.querySelectorAll('.widget[data-widget]').forEach(el => {
                const id = el.getAttribute('data-widget');
                el.classList.toggle('widget-hidden', !visibility[id]);
            });

            // Per-widget ordering
            const order = settings.widgetOrder || defaultSettings.widgetOrder;
            order.forEach((id, index) => {
                const el = document.querySelector(`.widget[data-widget="${id}"]`);
                if (el) el.style.order = index;
            });
        }

        const WIDGET_LABELS = {
            services: 'Services',
            system: 'System Clock',
            weather: 'Weather',
            notes: 'Quick Notes',
            quicklinks: 'Quick Links'
        };

        function renderWidgetConfig() {
            const container = document.getElementById('widgetConfigList');
            if (!container) return;
            const order = settings.widgetOrder || defaultSettings.widgetOrder;
            const visibility = settings.widgetVisibility || defaultSettings.widgetVisibility;
            container.innerHTML = order.map((id, index) => `
                <div class="widget-config-item">
                    <label class="toggle">
                        <input type="checkbox" ${visibility[id] ? 'checked' : ''} onchange="toggleWidgetVisibility('${id}')">
                        <span class="toggle-slider"></span>
                    </label>
                    <span class="widget-config-label">${WIDGET_LABELS[id] || id}</span>
                    <button class="widget-reorder-btn" onclick="moveWidget('${id}', -1)" ${index === 0 ? 'disabled' : ''} title="Move up">
                        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 15l-6-6-6 6"/></svg>
                    </button>
                    <button class="widget-reorder-btn" onclick="moveWidget('${id}', 1)" ${index === order.length - 1 ? 'disabled' : ''} title="Move down">
                        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg>
                    </button>
                </div>
            `).join('') + `
                <div class="widget-config-item" style="margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--bg-tertiary);">
                    <span class="widget-config-label">Temperature Unit</span>
                    <select id="temperatureUnit" class="admin-input" style="font-size: 13px; padding: 4px 8px; width: auto; margin-left: auto;">
                        <option value="fahrenheit" ${(settings.temperatureUnit || 'fahrenheit') === 'fahrenheit' ? 'selected' : ''}>°F</option>
                        <option value="celsius" ${settings.temperatureUnit === 'celsius' ? 'selected' : ''}>°C</option>
                    </select>
                </div>
                <div class="widget-config-item" style="margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--bg-tertiary);">
                    <span class="widget-config-label">Clock Format</span>
                    <select id="timeFormat" class="admin-input" style="font-size: 13px; padding: 4px 8px; width: auto; margin-left: auto;">
                        <option value="12h" ${(settings.timeFormat || '12h') === '12h' ? 'selected' : ''}>12h</option>
                        <option value="24h" ${settings.timeFormat === '24h' ? 'selected' : ''}>24h</option>
                    </select>
                </div>
            `;

            // Attach temperature unit change handler
            const tempSelect = container.querySelector('#temperatureUnit');
            if (tempSelect) {
                tempSelect.addEventListener('change', (e) => {
                    settings.temperatureUnit = e.target.value;
                    saveSettings();
                    fetchWeather();
                });
            }

            // Attach clock format change handler
            const timeFormatSelect = container.querySelector('#timeFormat');
            if (timeFormatSelect) {
                timeFormatSelect.addEventListener('change', (e) => {
                    settings.timeFormat = e.target.value;
                    saveSettings();
                    updateTime();
                });
            }
        }

        function toggleWidgetVisibility(id) {
            if (!settings.widgetVisibility) {
                settings.widgetVisibility = { ...defaultSettings.widgetVisibility };
            }
            settings.widgetVisibility[id] = !settings.widgetVisibility[id];
            saveSettings();
            applyWidgets();
            renderWidgetConfig();
        }

        function moveWidget(id, direction) {
            if (!settings.widgetOrder) {
                settings.widgetOrder = [...defaultSettings.widgetOrder];
            }
            const order = settings.widgetOrder;
            const index = order.indexOf(id);
            const newIndex = index + direction;
            if (newIndex < 0 || newIndex >= order.length) return;
            [order[index], order[newIndex]] = [order[newIndex], order[index]];
            saveSettings();
            applyWidgets();
            renderWidgetConfig();
        }

        function applyStatus() {
            document.body.classList.toggle('status-hidden', !settings.showStatus);
        }

        function applyCategories() {
            document.body.classList.toggle('categories-hidden', !settings.showCategories);
        }

        function applyLinkBehavior() {
            document.querySelectorAll('.app-item').forEach(el => {
                el.target = settings.openInNewTab ? '_blank' : '_self';
            });
            document.querySelectorAll('.favorite-chip').forEach(el => {
                el.target = settings.openInNewTab ? '_blank' : '_self';
            });
        }

        function applyAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
            if (settings.autoRefresh > 0) {
                autoRefreshInterval = setInterval(refreshHealth, settings.autoRefresh * 1000);
            }
        }

        // Update user profile section in settings
        function updateSettingsUserSection() {
            const section = document.getElementById('settingsUserSection');
            if (isAuthenticated && currentUser) {
                section.style.display = 'flex';
                document.getElementById('settingsUserAvatar').textContent = currentUser.username[0].toUpperCase();
                document.getElementById('settingsUserName').textContent = currentUser.displayName || currentUser.username;
                document.getElementById('settingsUserSource').textContent = currentUser.source || 'Local';

                const syncStatus = document.getElementById('settingsSyncStatus');
                if (prefsSyncEnabled) {
                    syncStatus.classList.remove('offline');
                    syncStatus.innerHTML = '<span class="settings-sync-dot"></span><span>Synced</span>';
                } else {
                    syncStatus.classList.add('offline');
                    syncStatus.innerHTML = '<span class="settings-sync-dot"></span><span>Local only</span>';
                }
            } else {
                section.style.display = 'none';
            }
        }

        // Logout function
        async function logoutUser() {
            try {
                await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
                window.location.reload();
            } catch (e) {
                showToast('Logout failed');
            }
        }

        // Reset settings functions
        function resetGeneralSettings() {
            settings.theme = defaultSettings.theme;
            settings.accentColor = defaultSettings.accentColor;
            settings.showGradient = defaultSettings.showGradient;
            settings.iconSize = defaultSettings.iconSize;
            settings.gridDensity = defaultSettings.gridDensity;
            settings.showWidgets = defaultSettings.showWidgets;
            settings.showStatus = defaultSettings.showStatus;
            settings.widgetOrder = [...defaultSettings.widgetOrder];
            settings.widgetVisibility = { ...defaultSettings.widgetVisibility };
            settings.openInNewTab = defaultSettings.openInNewTab;
            settings.autoRefresh = defaultSettings.autoRefresh;
            settings.temperatureUnit = defaultSettings.temperatureUnit;
            settings.timeFormat = defaultSettings.timeFormat;
            settings.showCategories = defaultSettings.showCategories;
            applySettings();
            updateSettingsUI();
            saveSettings();
            showToast('Settings reset to defaults');
        }

        function resetAdvancedSettings() {
            settings.customCSS = defaultSettings.customCSS;
            applySettings();
            updateSettingsUI();
            saveSettings();
            showToast('Advanced settings reset to defaults');
        }

        // Custom CSS functions
        function applyCustomCSS() {
            let styleEl = document.getElementById('custom-css-style');
            if (!styleEl) {
                styleEl = document.createElement('style');
                styleEl.id = 'custom-css-style';
                document.head.appendChild(styleEl);
            }
            styleEl.textContent = sanitizeCSS(settings.customCSS);
        }

        function applyCustomCSSFromInput() {
            const textarea = document.getElementById('customCSSInput');
            if (textarea) {
                settings.customCSS = textarea.value;
                applyCustomCSS();
                saveSettings();
                showToast('Custom CSS applied');
            }
        }

        function clearCustomCSS() {
            const textarea = document.getElementById('customCSSInput');
            if (textarea) {
                textarea.value = '';
            }
            settings.customCSS = '';
            applyCustomCSS();
            saveSettings();
            showToast('Custom CSS cleared');
        }

        // CSS Snippets
        const CSS_SNIPPETS = [
            {
                name: 'Glassmorphism',
                desc: 'Frosted glass across all panels, cards and widgets',
                preview: 'linear-gradient(135deg, rgba(255,255,255,0.15), rgba(255,255,255,0.05))',
                css: `/* Glassmorphism */
.app-item, .widget, .category-section, .favorites-bar {
    background: rgba(255,255,255,0.05) !important;
    backdrop-filter: blur(16px) saturate(180%) !important;
    -webkit-backdrop-filter: blur(16px) saturate(180%) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
}
.app-item:hover, .widget:hover {
    background: rgba(255,255,255,0.1) !important;
    border-color: rgba(255,255,255,0.15) !important;
}
.dock {
    background: rgba(30,30,30,0.6) !important;
    backdrop-filter: blur(20px) saturate(180%) !important;
    -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
}
.header {
    background: transparent !important;
}
.favorite-chip {
    background: rgba(255,255,255,0.06) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
}`
            },
            {
                name: 'Neon Glow',
                desc: 'Glowing accent outlines on hover across everything',
                preview: 'linear-gradient(135deg, #0a84ff, #5ac8fa)',
                css: `/* Neon Glow */
.app-item:hover {
    box-shadow: 0 0 15px color-mix(in srgb, var(--accent) 40%, transparent),
                0 0 30px color-mix(in srgb, var(--accent) 15%, transparent) !important;
    border-color: var(--accent) !important;
}
.widget:hover {
    box-shadow: 0 0 15px color-mix(in srgb, var(--accent) 30%, transparent) !important;
    border-color: var(--accent) !important;
}
.favorite-chip:hover {
    box-shadow: 0 0 10px color-mix(in srgb, var(--accent) 30%, transparent) !important;
    border-color: var(--accent) !important;
}
.dock-item:hover {
    background: color-mix(in srgb, var(--accent) 20%, transparent) !important;
    box-shadow: 0 0 12px color-mix(in srgb, var(--accent) 25%, transparent) !important;
}
.greeting {
    text-shadow: 0 0 30px color-mix(in srgb, var(--accent) 30%, transparent);
}
.search-input:focus {
    box-shadow: 0 0 20px color-mix(in srgb, var(--accent) 25%, transparent) !important;
    border-color: var(--accent) !important;
}`
            },
            {
                name: 'Pill Shape',
                desc: 'Extra rounded corners on every element',
                preview: 'linear-gradient(135deg, #30d158, #34c759)',
                css: `/* Pill Shape */
.app-item { border-radius: 24px !important; }
.app-icon { border-radius: 16px !important; }
.widget { border-radius: 24px !important; }
.category-section { border-radius: 28px !important; }
.search-input { border-radius: 24px !important; }
.dock { border-radius: 28px !important; }
.favorite-chip { border-radius: 20px !important; }
.favorites-bar { border-radius: 24px !important; }
.app-status { border-radius: 50% !important; }`
            },
            {
                name: 'Compact Dense',
                desc: 'Tight spacing, smaller elements, fit more on screen',
                preview: 'linear-gradient(135deg, #ff9f0a, #ff375f)',
                css: `/* Compact Dense */
.app-item { padding: 10px !important; gap: 6px !important; }
.app-icon { width: 40px !important; height: 40px !important; }
.app-name { font-size: 11px !important; }
.widget { padding: 14px !important; border-radius: 14px !important; }
.widgets-section { gap: 10px !important; }
.widgets-sidebar { width: 260px !important; min-width: 260px !important; }
.category-section { padding: 16px !important; gap: 10px !important; }
.category-header { margin-bottom: 8px !important; }
.header { padding: 16px 0 !important; }
.dock { padding: 6px 12px !important; }
.favorites-bar { padding: 8px 12px !important; gap: 6px !important; }`
            },
            {
                name: 'Gradient Surfaces',
                desc: 'Subtle gradient backgrounds on all surfaces',
                preview: 'linear-gradient(135deg, #bf5af2, #5856d6)',
                css: `/* Gradient Surfaces */
.app-item {
    background: linear-gradient(145deg, var(--bg-secondary), var(--bg-tertiary)) !important;
}
.widget {
    background: linear-gradient(145deg, var(--bg-secondary), var(--bg-tertiary)) !important;
}
.category-section {
    background: linear-gradient(145deg, var(--bg-secondary), var(--bg-tertiary)) !important;
}
.dock {
    background: linear-gradient(180deg, var(--bg-secondary), var(--bg-tertiary)) !important;
}
.favorites-bar {
    background: linear-gradient(145deg, var(--bg-secondary), var(--bg-tertiary)) !important;
}
.favorite-chip {
    background: linear-gradient(145deg, var(--bg-tertiary), var(--bg-primary)) !important;
}`
            },
            {
                name: 'Flat Minimal',
                desc: 'No borders, no shadows, clean and flat everywhere',
                preview: 'linear-gradient(135deg, #636366, #48484a)',
                css: `/* Flat Minimal */
.app-item, .widget, .category-section, .favorites-bar, .favorite-chip {
    border: none !important;
    box-shadow: none !important;
}
.app-item:hover, .widget:hover {
    box-shadow: none !important;
    transform: none !important;
    border: none !important;
    background: var(--bg-tertiary) !important;
}
.dock {
    border: none !important;
    box-shadow: none !important;
}
.search-input {
    border: none !important;
    box-shadow: none !important;
}
.header {
    border: none !important;
}`
            },
            {
                name: 'Elevated Cards',
                desc: 'Deep shadows and lift effects on everything',
                preview: 'linear-gradient(135deg, #1c1c1e, #2c2c2e)',
                css: `/* Elevated Cards */
.app-item, .widget, .category-section {
    box-shadow: 0 4px 20px rgba(0,0,0,0.25), 0 1px 4px rgba(0,0,0,0.15) !important;
    border: none !important;
}
.app-item:hover {
    box-shadow: 0 12px 36px rgba(0,0,0,0.4), 0 2px 8px rgba(0,0,0,0.2) !important;
    transform: translateY(-6px) !important;
}
.widget:hover {
    box-shadow: 0 8px 28px rgba(0,0,0,0.35) !important;
    transform: translateY(-4px) !important;
}
.dock {
    box-shadow: 0 -4px 24px rgba(0,0,0,0.3) !important;
    border: none !important;
}
.favorites-bar {
    box-shadow: 0 2px 12px rgba(0,0,0,0.2) !important;
    border: none !important;
}
.favorite-chip:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25) !important;
}`
            },
            {
                name: 'Smooth Motion',
                desc: 'Fluid animations on hover for cards, widgets, dock and chips',
                preview: 'linear-gradient(135deg, #ff375f, #ff9f0a)',
                css: `/* Smooth Motion */
.app-item, .widget, .favorite-chip, .dock-item {
    transition: all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}
.app-item:hover {
    transform: translateY(-8px) scale(1.03) !important;
    box-shadow: 0 16px 32px rgba(0,0,0,0.3) !important;
}
.widget:hover {
    transform: translateY(-4px) scale(1.015) !important;
    box-shadow: 0 12px 24px rgba(0,0,0,0.25) !important;
}
.favorite-chip:hover {
    transform: translateY(-3px) scale(1.05) !important;
}
.dock-item:hover {
    transform: translateY(-4px) scale(1.15) !important;
}
.app-icon img, .app-icon svg {
    transition: transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
}
.app-item:hover .app-icon img,
.app-item:hover .app-icon svg {
    transform: scale(1.1) rotate(3deg) !important;
}`
            },
            {
                name: 'Accent Borders',
                desc: 'Left accent stripe on cards, widgets and categories',
                preview: 'linear-gradient(180deg, var(--accent, #0a84ff), #5856d6)',
                css: `/* Accent Borders */
.app-item {
    border-left: 3px solid var(--accent) !important;
    border-radius: 4px 16px 16px 4px !important;
}
.widget {
    border-left: 3px solid var(--accent) !important;
    border-radius: 4px 20px 20px 4px !important;
}
.category-section {
    border-left: 4px solid var(--accent) !important;
    border-radius: 4px 20px 20px 4px !important;
}
.favorite-chip {
    border-bottom: 2px solid var(--accent) !important;
}
.dock {
    border-top: 2px solid var(--accent) !important;
}`
            },
            {
                name: 'Hidden Dock',
                desc: 'Auto-hide dock, slides up on hover',
                preview: 'linear-gradient(135deg, #5856d6, #af52de)',
                css: `/* Hidden Dock */
.dock {
    transform: translateY(calc(100% - 6px)) !important;
    transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1) !important;
    opacity: 0.6;
}
.dock:hover {
    transform: translateY(0) !important;
    opacity: 1;
}
.dock::before {
    content: '';
    position: absolute;
    top: -20px;
    left: 0;
    right: 0;
    height: 20px;
}`
            },
            {
                name: 'Wide Sidebar',
                desc: 'Wider widget sidebar with more breathing room',
                preview: 'linear-gradient(135deg, #30d158, #5ac8fa)',
                css: `/* Wide Sidebar */
.widgets-sidebar {
    width: 360px !important;
    min-width: 360px !important;
}
.widget {
    padding: 24px !important;
}
.widget-title {
    font-size: 16px !important;
}
.widget-value {
    font-size: 32px !important;
}
.status-grid {
    gap: 16px !important;
}`
            },
            {
                name: 'Full Width',
                desc: 'No sidebar, full-width app grid layout',
                preview: 'linear-gradient(135deg, #ff9f0a, #ffd60a)',
                css: `/* Full Width */
.widgets-sidebar {
    display: none !important;
}
.main-layout {
    display: block !important;
}
.main-content {
    max-width: 100% !important;
}
.app-grid {
    grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)) !important;
}`
            },
        ];

        function renderCSSSnippets() {
            const grid = document.getElementById('cssSnippetsGrid');
            if (!grid) return;
            const currentCSS = settings.customCSS || '';
            grid.innerHTML = CSS_SNIPPETS.map((snippet, i) => {
                const isActive = currentCSS.includes(snippet.css.split('\n')[0]);
                return `
                <button class="css-snippet-btn${isActive ? ' snippet-active' : ''}" onclick="toggleCSSSnippet(${i})">
                    <div class="css-snippet-name">${snippet.name}</div>
                    <div class="css-snippet-desc">${snippet.desc}</div>
                    <div class="css-snippet-preview" style="background: ${snippet.preview};"></div>
                </button>`;
            }).join('');
        }

        function toggleCSSSnippet(index) {
            const snippet = CSS_SNIPPETS[index];
            if (!snippet) return;
            const textarea = document.getElementById('customCSSInput');
            let css = settings.customCSS || '';
            const firstLine = snippet.css.split('\n')[0];

            if (css.includes(firstLine)) {
                // Remove snippet
                css = css.replace(snippet.css, '').replace(/\n{3,}/g, '\n\n').trim();
            } else {
                // Add snippet
                css = css ? css + '\n\n' + snippet.css : snippet.css;
            }

            settings.customCSS = css;
            if (textarea) textarea.value = css;
            applyCustomCSS();
            saveSettings();
            renderCSSSnippets();
            showToast(css.includes(firstLine) ? `${snippet.name} enabled` : `${snippet.name} removed`);
        }

        // Favorites list management in settings
        function renderFavoritesList() {
            const list = document.getElementById('favoritesList');
            const empty = document.getElementById('favoritesEmpty');

            if (favorites.length === 0) {
                list.style.display = 'none';
                empty.style.display = 'block';
                return;
            }

            list.style.display = 'flex';
            empty.style.display = 'none';

            list.innerHTML = favorites.map((f, i) => `
                <div class="favorites-item" draggable="true" data-index="${i}">
                    <div class="favorites-item-drag">
                        <svg width="16" height="16" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M8 6a2 2 0 11-4 0 2 2 0 014 0zm0 6a2 2 0 11-4 0 2 2 0 014 0zm0 6a2 2 0 11-4 0 2 2 0 014 0zm8-12a2 2 0 11-4 0 2 2 0 014 0zm0 6a2 2 0 11-4 0 2 2 0 014 0zm0 6a2 2 0 11-4 0 2 2 0 014 0z"/>
                        </svg>
                    </div>
                    <div class="favorites-item-icon">
                        ${f.icon ? `<img src="/static/icons/${escapeHtml(f.icon)}" alt="">` : `<span style="font-weight:600;font-size:14px">${escapeHtml(f.name[0])}</span>`}
                    </div>
                    <span class="favorites-item-name">${escapeHtml(f.name)}</span>
                    <button class="favorites-item-remove" onclick="removeFavoriteByIndex(${i})">
                        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
            `).join('');

            // Setup drag and drop
            initFavoritesDragDrop();
        }

        function initFavoritesDragDrop() {
            const list = document.getElementById('favoritesList');
            if (!list || list.dataset.dragInit) return; // prevent re-init
            list.dataset.dragInit = 'true';

            let draggedItem = null;

            list.addEventListener('dragstart', function(e) {
                const item = e.target.closest('.favorites-item');
                if (!item) return;
                draggedItem = item;
                item.classList.add('dragging');
                e.dataTransfer.effectAllowed = 'move';
            });

            list.addEventListener('dragend', function(e) {
                const item = e.target.closest('.favorites-item');
                if (item) item.classList.remove('dragging');
                draggedItem = null;
            });

            list.addEventListener('dragover', function(e) {
                const item = e.target.closest('.favorites-item');
                if (!item) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
            });

            list.addEventListener('drop', function(e) {
                const item = e.target.closest('.favorites-item');
                if (!item) return;
                e.preventDefault();
                if (draggedItem && draggedItem !== item) {
                    const fromIndex = parseInt(draggedItem.dataset.index);
                    const toIndex = parseInt(item.dataset.index);

                    // Reorder favorites array
                    const [moved] = favorites.splice(fromIndex, 1);
                    favorites.splice(toIndex, 0, moved);

                    localStorage.setItem('dashgate-favorites', JSON.stringify(favorites)); debouncedSyncPreferences();
                    renderFavoritesList();
                    renderFavorites();
                }
            });
        }

        function removeFavoriteByIndex(index) {
            const removed = favorites.splice(index, 1)[0];
            localStorage.setItem('dashgate-favorites', JSON.stringify(favorites)); debouncedSyncPreferences();
            renderFavoritesList();
            renderFavorites();
            showToast(`Removed ${removed.name} from favorites`);
        }

        function clearAllFavorites() {
            if (favorites.length === 0) return;
            favorites = [];
            localStorage.setItem('dashgate-favorites', JSON.stringify(favorites)); debouncedSyncPreferences();
            renderFavoritesList();
            renderFavorites();
            showToast('All favorites cleared');
        }

        // Import/Export
        function exportSettings() {
            const data = {
                settings: settings,
                favorites: favorites,
                exportedAt: new Date().toISOString(),
                version: 1
            };
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `dashgate-settings-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Settings exported');
        }

        function importSettings(event) {
            const file = event.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const data = JSON.parse(e.target.result);

                    if (data.settings) {
                        if (data.settings.customCSS) {
                            data.settings.customCSS = sanitizeCSS(data.settings.customCSS);
                        }
                        settings = { ...defaultSettings, ...data.settings };
                        saveSettings();
                        applySettings();
                    }

                    if (data.favorites) {
                        favorites = data.favorites;
                        localStorage.setItem('dashgate-favorites', JSON.stringify(favorites)); debouncedSyncPreferences();
                        renderFavorites();
                        renderFavoritesList();
                    }

                    updateSettingsUI();
                    showToast('Settings imported successfully');
                } catch (err) {
                    showToast('Failed to import settings');
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }
