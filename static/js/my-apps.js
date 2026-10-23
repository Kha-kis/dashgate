        // my-apps.js - Custom personal app management for DashGate

        function renderMyAppsList() {
            const container = document.getElementById('myAppsList');
            const empty = document.getElementById('myAppsEmpty');

            if (!container || !empty) return;
            updateMyAppsMigrationNotice();
            updateMyAppsPendingNotice();
            container.replaceChildren();

            if (myApps.length === 0) {
                empty.style.display = '';
                return;
            }

            empty.style.display = 'none';
            myApps.forEach((app, i) => {
                if (!app || typeof app.name !== 'string') return;
                const row = document.createElement('div');
                row.className = 'favorites-item';
                const icon = document.createElement('div');
                icon.className = 'favorites-item-icon';
                const fallback = document.createElement('span');
                fallback.style.cssText = 'font-weight:600;font-size:14px';
                fallback.textContent = app.name[0] || '';
                if (isSafePersonalAppURL(app.icon)) {
                    const img = document.createElement('img');
                    img.src = app.icon;
                    img.alt = '';
                    img.addEventListener('error', () => img.replaceWith(fallback));
                    icon.appendChild(img);
                } else {
                    icon.appendChild(fallback);
                }
                const name = document.createElement('span');
                name.className = 'favorites-item-name';
                name.textContent = app.name;
                const edit = document.createElement('button');
                edit.className = 'favorites-item-remove';
                edit.title = 'Edit';
                edit.style.color = 'var(--text-secondary)';
                edit.setAttribute('aria-label', 'Edit ' + app.name);
                edit.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>';
                edit.addEventListener('click', () => openEditMyAppModal(i));
                const remove = document.createElement('button');
                remove.className = 'favorites-item-remove';
                remove.title = 'Delete';
                remove.setAttribute('aria-label', 'Delete ' + app.name);
                remove.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>';
                remove.addEventListener('click', () => deleteMyApp(i));
                row.append(icon, name, edit, remove);
                container.appendChild(row);
            });
        }

        function getLegacyMyApps() {
            try {
                const saved = JSON.parse(localStorage.getItem('dashgate-my-apps-legacy-backup') || '[]');
                return Array.isArray(saved) ? saved : [];
            } catch (_) {
                return [];
            }
        }

        function updateMyAppsMigrationNotice() {
            const notice = document.getElementById('myAppsMigrationNotice');
            if (notice) {
                notice.style.display = prefsSyncEnabled &&
                    !localStorage.getItem('dashgate-my-apps-legacy-restored') &&
                    localStorage.getItem('dashgate-my-apps-legacy-backup') !== null ? '' : 'none';
            }
        }

        function updateMyAppsPendingNotice() {
            const notice = document.getElementById('myAppsPendingNotice');
            if (notice) notice.style.display = prefsSyncEnabled && getPendingMyApps() ? '' : 'none';
        }

        function describePersonalApps(apps) {
            return apps.map((app, index) => [
                `${index + 1}. ${app?.name || '(invalid app)'}: ${app?.url || '(no URL)'}`,
                `Description: ${app?.description || '(none)'}`,
                `Icon: ${app?.icon || '(none)'}`
            ].join('\n')).join('\n\n') || '(none)';
        }

        function validPersonalApps(apps) {
            return Array.isArray(apps) && apps.every(app =>
                app && typeof app.name === 'string' && app.name.trim().length > 0 &&
                typeof app.url === 'string' && isSafePersonalAppURL(app.url) &&
                (app.description == null || typeof app.description === 'string') &&
                (app.icon == null || (typeof app.icon === 'string' &&
                    (!app.icon || isSafePersonalAppURL(app.icon)))));
        }

        async function discardPendingMyApps() {
            if (!getPendingMyApps() || !prefsSyncEnabled) return;
            await preferenceWriteTail;
            if (!getPendingMyApps()) return;
            try {
                const identityResponse = await fetch('/api/auth/me', { credentials: 'include' });
                if (!identityResponse.ok) throw new Error(`HTTP ${identityResponse.status}`);
                const activeUser = await identityResponse.json();
                if (activeUser.source !== currentUser?.source || activeUser.username !== currentUser?.username) {
                    showToast('Signed-in account changed. Reload this page.');
                    return;
                }
                const response = await fetch('/api/user/preferences', { credentials: 'include' });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const serverPrefs = await response.json();
                const current = Array.isArray(serverPrefs.myApps) ? serverPrefs.myApps : [];
                if (!confirm(`Discard your unsynced browser My Apps and keep the current account list?\n\nCurrent account apps:\n${describePersonalApps(current)}\n\nUnsynced browser apps:\n${describePersonalApps(getPendingMyApps() || [])}`)) return;
                localStorage.removeItem(myAppsPendingKey());
                pendingMyAppsRecoveryRequired = false;
                myApps = current;
                localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
                renderMyAppsList();
                renderMyAppsOnDashboard();
                showToast('Current account apps kept');
            } catch (_) {
                showToast('Could not check account apps. Try again.');
            }
        }

        async function retryMyAppsSync() {
            const pending = getPendingMyApps();
            if (!pending || !prefsSyncEnabled) return;
            if (!validPersonalApps(pending)) {
                showToast('Unsynced apps contain invalid links. Keep account apps to discard them.');
                return;
            }
            try {
                const response = await fetch('/api/user/preferences', { credentials: 'include' });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const serverPrefs = await response.json();
                const current = Array.isArray(serverPrefs.myApps) ? serverPrefs.myApps : [];
                if (!confirm(`Replace the current account My Apps with your unsynced browser list?\n\nCurrent account apps:\n${describePersonalApps(current)}\n\nUnsynced browser apps:\n${describePersonalApps(pending)}`)) return;
                myApps = pending;
                pendingMyAppsRecoveryRequired = false;
                localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
                renderMyAppsList();
                renderMyAppsOnDashboard();
                if (await syncPreferencesToServer({ ...serverPrefs, myApps: pending })) showToast('Personal apps synced');
                else showToast('Personal apps could not be synced. Try again.');
            } catch (error) {
                showToast('Could not check account apps. Try again.');
            }
        }

        function canEditMyApps() {
            if (prefsSyncEnabled && currentUser && !pendingMyAppsRecoveryRequired) return true;
            showToast(pendingMyAppsRecoveryRequired
                ? 'Review unsynced personal apps before editing'
                : 'Wait for account preferences to load');
            return false;
        }

        async function restoreLegacyMyApps() {
            if (pendingMyAppsRecoveryRequired) {
                showToast('Review unsynced personal apps before restoring older apps');
                return;
            }
            const legacy = getLegacyMyApps();
            if (!validPersonalApps(legacy)) {
                showToast('Older apps contain invalid links and cannot be restored');
                return;
            }
            if (!prefsSyncEnabled) return;
            const preview = describePersonalApps(legacy);
            let serverPrefs;
            try {
                const response = await fetch('/api/user/preferences', { credentials: 'include' });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                serverPrefs = await response.json();
            } catch (_) {
                showToast('Could not check account apps. Try again.');
                return;
            }
            const currentApps = Array.isArray(serverPrefs.myApps) ? serverPrefs.myApps : [];
            const current = describePersonalApps(currentApps);
            if (!confirm(`Replace this account's My Apps with the older browser list?\n\nCurrent account apps:\n${current}\n\nOlder browser apps:\n${preview || '(none)'}`)) return;
            myApps = legacy;
            localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
            markMyAppsPending();
            renderMyAppsList();
            renderMyAppsOnDashboard();
            clearTimeout(_syncTimeout);
            if (await syncPreferencesToServer({ ...serverPrefs, myApps: legacy })) {
                localStorage.removeItem('dashgate-my-apps-legacy-backup');
                localStorage.setItem('dashgate-my-apps-legacy-restored', '1');
                updateMyAppsMigrationNotice();
                showToast('Older apps restored');
            } else {
                showToast('Could not sync older apps. Retry Restore older apps.');
            }
        }

        function openMyAppModal() {
            document.getElementById('myAppModalTitle').textContent = 'Add Personal App';
            document.getElementById('myAppEditIndex').value = '';
            document.getElementById('myAppName').value = '';
            document.getElementById('myAppUrl').value = '';
            document.getElementById('myAppDesc').value = '';
            document.getElementById('myAppIcon').value = '';
            document.getElementById('myAppModal').classList.add('open');
        }

        function openEditMyAppModal(index) {
            const app = myApps[index];
            if (!app) return;

            document.getElementById('myAppModalTitle').textContent = 'Edit Personal App';
            document.getElementById('myAppEditIndex').value = index;
            document.getElementById('myAppName').value = app.name;
            document.getElementById('myAppUrl').value = app.url;
            document.getElementById('myAppDesc').value = app.description || '';
            document.getElementById('myAppIcon').value = app.icon || '';
            document.getElementById('myAppModal').classList.add('open');
        }

        function closeMyAppModal() {
            document.getElementById('myAppModal').classList.remove('open');
        }

        function saveMyApp() {
            if (!canEditMyApps()) return;
            const indexStr = document.getElementById('myAppEditIndex').value;
            const name = document.getElementById('myAppName').value.trim();
            const url = document.getElementById('myAppUrl').value.trim();
            const description = document.getElementById('myAppDesc').value.trim();
            const icon = document.getElementById('myAppIcon').value.trim();

            if (!name || !url) {
                showToast('Name and URL are required');
                return;
            }

            if (!isSafePersonalAppURL(url) || (icon && !isSafePersonalAppURL(icon))) {
                showToast('App and icon URLs must use valid http:// or https:// links', 'error');
                return;
            }

            const app = { name, url, description, icon };

            if (indexStr !== '') {
                myApps[parseInt(indexStr)] = app;
                showToast('App updated');
            } else {
                myApps.push(app);
                showToast('App added');
            }

            localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
            markMyAppsPending();
            debouncedSyncPreferences();
            closeMyAppModal();
            renderMyAppsList();
            renderMyAppsOnDashboard();
        }

        function deleteMyApp(index) {
            if (!canEditMyApps()) return;
            if (!confirm(`Delete "${myApps[index].name}"?`)) return;
            myApps.splice(index, 1);
            localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
            markMyAppsPending();
            debouncedSyncPreferences();
            renderMyAppsList();
            renderMyAppsOnDashboard();
            showToast('App deleted');
        }

        function exportMyApps() {
            if (myApps.length === 0) {
                showToast('No apps to export');
                return;
            }
            const data = {
                myApps: myApps,
                exportedAt: new Date().toISOString(),
                version: 1
            };
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `my-apps-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('My Apps exported');
        }

        function importMyApps(event) {
            if (!canEditMyApps()) {
                event.target.value = '';
                return;
            }
            const file = event.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const data = JSON.parse(e.target.result);
                    if (validPersonalApps(data.myApps)) {
                        myApps = data.myApps;
                        localStorage.setItem('dashgate-my-apps', JSON.stringify(myApps));
                        markMyAppsPending();
                        debouncedSyncPreferences();
                        renderMyAppsList();
                        renderMyAppsOnDashboard();
                        showToast(`Imported ${myApps.length} apps`);
                    } else {
                        showToast('Invalid file format');
                    }
                } catch (err) {
                    showToast('Failed to import');
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }

        function isSafePersonalAppURL(value) {
            if (typeof value !== 'string') return false;
            try {
                const url = new URL(value);
                return url.protocol === 'http:' || url.protocol === 'https:';
            } catch (_) {
                return false;
            }
        }

        // Render My Apps on DashGate
        function renderMyAppsOnDashboard() {
            let myAppsSection = document.getElementById('myAppsSection');
            const mainContent = document.querySelector('.main-content');
            const emptyState = mainContent?.querySelector('.empty-state');
            const safeApps = myApps.filter(app =>
                app && typeof app.name === 'string' && app.name.length > 0 && isSafePersonalAppURL(app.url)
            );

            if (safeApps.length === 0) {
                if (myAppsSection) myAppsSection.remove();
                if (emptyState) emptyState.style.display = '';
                initApps();
                updateCounts();
                return;
            }

            if (emptyState) emptyState.style.display = 'none';

            if (!myAppsSection) {
                myAppsSection = document.createElement('section');
                myAppsSection.id = 'myAppsSection';
                myAppsSection.className = 'category-section';
                const firstCategory = mainContent?.querySelector('.category-section');
                if (firstCategory) {
                    firstCategory.parentNode.insertBefore(myAppsSection, firstCategory);
                } else {
                    mainContent?.appendChild(myAppsSection);
                }
            }

            const header = document.createElement('div');
            header.className = 'category-header';
            const title = document.createElement('h2');
            title.className = 'category-name';
            title.textContent = 'My Apps';
            const count = document.createElement('span');
            count.className = 'category-count';
            count.textContent = String(safeApps.length);
            header.append(title, count);
            const grid = document.createElement('div');
            grid.className = 'app-grid';
            safeApps.forEach(app => {
                const link = document.createElement('a');
                link.href = app.url;
                link.target = settings.openInNewTab ? '_blank' : '_self';
                link.rel = 'noopener noreferrer';
                link.className = 'app-item';
                link.dataset.name = app.name;
                link.dataset.url = app.url;
                link.dataset.desc = typeof app.description === 'string' ? app.description : '';
                link.dataset.status = 'unknown';
                const wrapper = document.createElement('div');
                wrapper.className = 'app-icon-wrapper';
                const icon = document.createElement('div');
                icon.className = 'app-icon';
                const fallback = document.createElement('span');
                fallback.className = 'app-icon-fallback';
                fallback.textContent = app.name[0];
                if (isSafePersonalAppURL(app.icon)) {
                    const img = document.createElement('img');
                    img.src = app.icon;
                    img.alt = app.name;
                    fallback.style.display = 'none';
                    img.addEventListener('error', () => {
                        img.style.display = 'none';
                        fallback.style.display = 'block';
                    });
                    icon.appendChild(img);
                }
                icon.appendChild(fallback);
                const status = document.createElement('div');
                status.className = 'app-status unknown';
                wrapper.append(icon, status);
                const name = document.createElement('span');
                name.className = 'app-name';
                name.textContent = app.name;
                link.append(wrapper, name);
                grid.appendChild(link);
            });
            myAppsSection.replaceChildren(header, grid);
            initApps();
            updateCounts();

            // Context menu is handled by delegated listener on .main-content
        }

        // Initialize My Apps on page load
        document.addEventListener('DOMContentLoaded', () => {
            renderMyAppsOnDashboard();
        });
