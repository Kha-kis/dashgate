// app.js - Global state, init, search, favorites, context menu, health refresh, PWA

// State
let apps = [];
let favorites = (() => {
  try {
    return JSON.parse(localStorage.getItem("dashgate-favorites") || "[]");
  } catch {
    return [];
  }
})();
let myApps = (() => {
  try {
    return JSON.parse(localStorage.getItem("dashgate-my-apps") || "[]");
  } catch {
    return [];
  }
})();
let searchIndex = -1;
let contextTarget = null;
let autoRefreshInterval = null;
let isAuthenticated = false;
let currentUser = null;
let prefsSyncEnabled = false;

// Default settings
const defaultSettings = {
  theme: "dark",
  accentColor: "blue",
  showGradient: true,
  iconSize: "medium",
  gridDensity: "comfortable",
  showWidgets: true,
  showStatus: true,
  openInNewTab: true,
  autoRefresh: 0,
  showCategories: true,
  customCSS: "",
  temperatureUnit: "fahrenheit",
  timeFormat: "12h",
  widgetOrder: ["services", "system", "weather", "notes", "quicklinks"],
  widgetVisibility: {
    services: true,
    system: true,
    weather: true,
    notes: true,
    quicklinks: true,
  },
};

// Load settings from localStorage initially (will be overwritten by server if authenticated)
let settings = {
  ...defaultSettings,
  ...(() => {
    try {
      return JSON.parse(localStorage.getItem("dashgate-settings") || "{}");
    } catch {
      return {};
    }
  })(),
};

// Initialize
document.addEventListener("DOMContentLoaded", async () => {
  initApps();
  applySettings();
  renderFavorites();
  updateCounts();
  updateTime();
  setInterval(updateTime, 1000);
  initKeyboard();
  initContextMenu();
  initSettingsModal();
  checkAdminStatus();

  // Event delegation for search results (single listener instead of per-element)
  document
    .getElementById("searchResults")
    ?.addEventListener("click", function (e) {
      const result = e.target.closest(".search-result");
      if (result) {
        const url = result.dataset.url;
        if (url) {
          const openInNewTab = (() => {
            try {
              return JSON.parse(
                localStorage.getItem("dashgate-settings") || "{}",
              ).openInNewTab;
            } catch {
              return true;
            }
          })();
          if (openInNewTab) {
            window.open(url, "_blank");
          } else {
            window.location.href = url;
          }
          closeSearch();
        }
      }
    });

  // Try to load preferences from server (will sync localStorage if authenticated)
  await loadServerPreferences();
});

// Load preferences from server if authenticated
async function loadServerPreferences() {
  try {
    const resp = await fetch("/api/auth/me", { credentials: "include" });
    if (resp.ok) {
      currentUser = await resp.json();
      isAuthenticated = true;

      // Load preferences from server
      const prefsResp = await fetch("/api/user/preferences", {
        credentials: "include",
      });
      if (prefsResp.ok) {
        const serverPrefs = await prefsResp.json();
        prefsSyncEnabled = true;

        // Merge server prefs with defaults
        if (serverPrefs.settings) {
          settings = { ...defaultSettings, ...serverPrefs.settings };
          applySettings();
        }
        if (serverPrefs.favorites) {
          favorites = serverPrefs.favorites;
          renderFavorites();
        }
        if (serverPrefs.myApps) {
          myApps = serverPrefs.myApps;
          renderMyAppsList();
        }
      }

      // Update user section in settings
      updateSettingsUserSection();
    }
  } catch (e) {
    console.log("Not authenticated or server unavailable");
  }
}

// Save all preferences to server
async function syncPreferencesToServer() {
  if (!prefsSyncEnabled) return;

  try {
    await fetch("/api/user/preferences", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({
        settings: settings,
        favorites: favorites,
        myApps: myApps,
      }),
    });
  } catch (e) {
    console.error("Failed to sync preferences:", e);
  }
}

// Debounced version to avoid rapid repeated server syncs
let _syncTimeout = null;
function debouncedSyncPreferences() {
  clearTimeout(_syncTimeout);
  _syncTimeout = setTimeout(syncPreferencesToServer, 500);
}

function initApps() {
  apps = Array.from(document.querySelectorAll(".app-item")).map((el) => ({
    element: el,
    name: el.dataset.name,
    url: el.dataset.url,
    desc: el.dataset.desc || "",
    icon: el.dataset.icon,
    status: el.dataset.status,
  }));
}

function updateCounts() {
  const online = apps.filter((a) => a.status === "online").length;
  const offline = apps.filter((a) => a.status === "offline").length;
  document.getElementById("onlineCount").textContent = online;
  document.getElementById("offlineCount").textContent = offline;
  document.getElementById("totalCount").textContent = apps.length;
}

function updateTime() {
  const now = new Date();
  const hour12 = (settings.timeFormat || "12h") === "12h";
  document.getElementById("currentTime").textContent = now.toLocaleTimeString(
    "en-US",
    { hour: "2-digit", minute: "2-digit", hour12 },
  );
  document.getElementById("currentDate").textContent = now.toLocaleDateString(
    "en-US",
    { weekday: "long", month: "long", day: "numeric" },
  );
}

// Search
function openSearch() {
  document.getElementById("searchModal").classList.add("open");
  document.getElementById("searchInput").focus();
  renderSearchResults("");
}

function closeSearch() {
  document.getElementById("searchModal").classList.remove("open");
  document.getElementById("searchInput").value = "";
  searchIndex = -1;
}

function renderSearchResults(query) {
  const results = document.getElementById("searchResults");
  const q = query.toLowerCase();
  const filtered = apps.filter(
    (a) => a.name.toLowerCase().includes(q) || a.desc.toLowerCase().includes(q),
  );

  if (filtered.length === 0) {
    results.innerHTML = '<div class="search-empty">No apps found</div>';
    return;
  }

  results.innerHTML = filtered
    .map(
      (app, i) => `
                <div class="search-result ${i === searchIndex ? "selected" : ""}"
                     data-url="${escapeHtml(app.url)}" data-index="${i}">
                    <div class="search-result-icon">
                        ${app.icon ? `<img src="/static/icons/${escapeHtml(app.icon)}" alt="">` : `<span style="font-weight:600">${escapeHtml(app.name[0])}</span>`}
                    </div>
                    <div class="search-result-info">
                        <div class="search-result-name">${escapeHtml(app.name)}</div>
                        <div class="search-result-desc">${escapeHtml(app.desc || app.url)}</div>
                    </div>
                </div>
            `,
    )
    .join("");
}

document.getElementById("searchInput").addEventListener("input", (e) => {
  searchIndex = -1;
  renderSearchResults(e.target.value);
});

// Keyboard
function initKeyboard() {
  document.addEventListener("keydown", (e) => {
    const modal = document.getElementById("searchModal");
    const isOpen = modal.classList.contains("open");

    // Open search
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      isOpen ? closeSearch() : openSearch();
      return;
    }

    if (
      e.key === "/" &&
      !isOpen &&
      document.activeElement.tagName !== "INPUT"
    ) {
      e.preventDefault();
      openSearch();
      return;
    }

    if (!isOpen) return;

    // Navigate results
    const results = document.querySelectorAll(".search-result");
    if (e.key === "ArrowDown") {
      e.preventDefault();
      searchIndex = Math.min(searchIndex + 1, results.length - 1);
      updateSearchSelection();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      searchIndex = Math.max(searchIndex - 1, 0);
      updateSearchSelection();
    } else if (e.key === "Enter" && searchIndex >= 0) {
      e.preventDefault();
      results[searchIndex]?.click();
    } else if (e.key === "Escape") {
      closeSearch();
    }
  });
}

function updateSearchSelection() {
  document.querySelectorAll(".search-result").forEach((el, i) => {
    el.classList.toggle("selected", i === searchIndex);
    if (i === searchIndex) el.scrollIntoView({ block: "nearest" });
  });
}

// Favorites
function toggleFavorite(url, name, icon) {
  const idx = favorites.findIndex((f) => f.url === url);
  if (idx >= 0) {
    favorites.splice(idx, 1);
    showToast(`Removed ${name} from favorites`);
  } else {
    favorites.push({ url, name, icon });
    showToast(`Added ${name} to favorites`);
  }
  localStorage.setItem("dashgate-favorites", JSON.stringify(favorites));
  debouncedSyncPreferences();
  renderFavorites();
}

function renderFavorites() {
  const bar = document.getElementById("favoritesBar");
  if (favorites.length === 0) {
    bar.style.display = "none";
    return;
  }
  bar.style.display = "flex";
  const target = settings.openInNewTab ? "_blank" : "_self";
  bar.innerHTML = favorites
    .map(
      (f) => `
                <a href="${escapeHtml(f.url)}" target="${target}" class="favorite-chip">
                    <div class="favorite-chip-icon">
                        ${f.icon ? `<img src="/static/icons/${escapeHtml(f.icon)}" alt="">` : `<span style="font-weight:600;font-size:12px">${escapeHtml(f.name[0])}</span>`}
                    </div>
                    <span class="favorite-chip-name">${escapeHtml(f.name)}</span>
                </a>
            `,
    )
    .join("");
}

function toggleFavoritesView() {
  const bar = document.getElementById("favoritesBar");
  bar.scrollIntoView({ behavior: "smooth" });
}

// Dependencies Modal
let depsData = [];

async function openDepsModal() {
  document.getElementById("depsModal").classList.add("open");
  await loadDependencies();
}

function closeDepsModal() {
  document.getElementById("depsModal").classList.remove("open");
}

async function loadDependencies() {
  const graph = document.getElementById("depsGraph");
  graph.innerHTML = '<div class="deps-empty">Loading dependencies...</div>';

  try {
    const resp = await fetch("/api/dependencies");
    if (!resp.ok) throw new Error("Failed to fetch");

    depsData = await resp.json();

    if (depsData.length === 0) {
      graph.innerHTML = '<div class="deps-empty">No services configured</div>';
      return;
    }

    // Filter to only show services with dependencies
    const withDeps = depsData.filter(
      (n) =>
        (n.depends_on && n.depends_on.length > 0) ||
        (n.depended_by && n.depended_by.length > 0),
    );

    if (withDeps.length === 0) {
      graph.innerHTML = `
                        <div class="deps-empty">
                            <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="opacity: 0.5; margin-bottom: 12px;">
                                <circle cx="18" cy="5" r="3"/>
                                <circle cx="6" cy="12" r="3"/>
                                <circle cx="18" cy="19" r="3"/>
                                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                                <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                            </svg>
                            <p>No dependencies configured</p>
                            <p style="font-size: 12px; margin-top: 8px;">Add <code>depends_on</code> to your apps in config.yaml</p>
                        </div>
                    `;
      return;
    }

    renderDepsGraph(withDeps);
  } catch (error) {
    graph.innerHTML =
      '<div class="deps-empty">Failed to load dependencies</div>';
  }
}

function renderDepsGraph(data) {
  const graph = document.getElementById("depsGraph");
  graph.innerHTML = data
    .map(
      (node) => `
                <div class="deps-node" data-name="${escapeHtml(node.name.toLowerCase())}">
                    <div class="deps-node-header">
                        <div class="deps-node-icon">
                            ${node.icon ? `<img src="/static/icons/${escapeHtml(node.icon)}" alt="">` : `<span style="font-weight:600;font-size:16px">${escapeHtml(node.name[0])}</span>`}
                        </div>
                        <div class="deps-node-info">
                            <div class="deps-node-name">${escapeHtml(node.name)}</div>
                            <div class="deps-node-status ${node.status || ""}">${node.status || "unknown"}</div>
                        </div>
                    </div>
                    <div class="deps-relations">
                        <div class="deps-relation-group">
                            <div class="deps-relation-label">Depends On</div>
                            <div class="deps-relation-list">
                                ${
                                  node.depends_on && node.depends_on.length > 0
                                    ? node.depends_on
                                        .map(
                                          (d) =>
                                            `<span class="deps-relation-chip upstream">${escapeHtml(d)}</span>`,
                                        )
                                        .join("")
                                    : '<span class="deps-relation-none">None</span>'
                                }
                            </div>
                        </div>
                        <div class="deps-relation-group">
                            <div class="deps-relation-label">Required By</div>
                            <div class="deps-relation-list">
                                ${
                                  node.depended_by &&
                                  node.depended_by.length > 0
                                    ? node.depended_by
                                        .map(
                                          (d) =>
                                            `<span class="deps-relation-chip downstream">${escapeHtml(d)}</span>`,
                                        )
                                        .join("")
                                    : '<span class="deps-relation-none">None</span>'
                                }
                            </div>
                        </div>
                    </div>
                </div>
            `,
    )
    .join("");
}

function filterDeps(query) {
  const q = query.toLowerCase();
  document.querySelectorAll(".deps-node").forEach((node) => {
    const name = node.dataset.name;
    node.style.display = name.includes(q) ? "block" : "none";
  });
}

// Context menu
function initContextMenu() {
  // Delegated contextmenu listener on .main-content for all .app-item elements
  document
    .querySelector(".main-content")
    ?.addEventListener("contextmenu", function (e) {
      const appItem = e.target.closest(".app-item");
      if (!appItem) return;
      e.preventDefault();
      contextTarget = appItem;
      showContextMenu(e.clientX, e.clientY);
    });

  document.addEventListener("click", () => {
    document.getElementById("contextMenu").classList.remove("open");
  });

  document.querySelectorAll(".context-item").forEach((item) => {
    item.addEventListener("click", () => {
      if (!contextTarget) return;
      const action = item.dataset.action;
      const url = contextTarget.dataset.url;
      const name = contextTarget.dataset.name;
      const icon = contextTarget.dataset.icon;

      if (action === "open") window.open(url, "_blank");
      if (action === "copy") {
        navigator.clipboard.writeText(url);
        showToast("URL copied");
      }
      if (action === "favorite") toggleFavorite(url, name, icon);
    });
  });
}

function showContextMenu(x, y) {
  const menu = document.getElementById("contextMenu");
  const isFav = favorites.some((f) => f.url === contextTarget.dataset.url);
  document.getElementById("contextFavText").textContent = isFav
    ? "Remove from favorites"
    : "Add to favorites";

  menu.style.left = Math.min(x, window.innerWidth - 200) + "px";
  menu.style.top = Math.min(y, window.innerHeight - 150) + "px";
  menu.classList.add("open");
}

async function refreshHealth() {
  showToast("Refreshing status...");
  try {
    const resp = await fetch("/api/health", { credentials: "include" });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const data = await resp.json();
    data.forEach((cat) => {
      cat.apps.forEach((app) => {
        const el = document.querySelector(
          `.app-item[data-url="${CSS.escape(app.url)}"]`,
        );
        if (el) {
          el.dataset.status = app.status;
          el.querySelector(".app-status").className =
            `app-status ${app.status}`;
        }
      });
    });
    initApps();
    updateCounts();
    showToast("Status updated");
  } catch (e) {
    showToast("Failed to refresh");
  }
}

async function checkAdminStatus() {
  try {
    const resp = await fetch("/api/admin/check", { credentials: "include" });
    if (resp.ok) {
      const data = await resp.json();
      adminState.isAdmin = data.isAdmin;
      adminState.lldapEnabled = data.lldapEnabled;
      adminState.localAuthEnabled = data.localAuthEnabled;
      adminState.authMode = data.authMode || "authelia";
      adminState.currentUser = data.user;

      const adminTab = document.getElementById("adminTab");
      if (adminTab && adminState.isAdmin) {
        adminTab.style.display = "flex";
      }

      // Show/hide local users and groups sections based on auth mode
      if (adminState.localAuthEnabled) {
        const localUsersSection = document.getElementById("localUsersSection");
        const localUsersDivider = document.getElementById("localUsersDivider");
        if (localUsersSection) localUsersSection.style.display = "block";
        if (localUsersDivider) localUsersDivider.style.display = "block";
        const localGroupsSection =
          document.getElementById("localGroupsSection");
        if (localGroupsSection) localGroupsSection.style.display = "";
      }

      // Preload admin data so it's ready when admin tab is clicked
      if (adminState.isAdmin && typeof loadAdminData === "function") {
        loadAdminData();
      }

      // Show logout button if using local auth
      if (
        adminState.authMode === "local" ||
        (adminState.authMode === "hybrid" &&
          adminState.currentUser?.source === "local")
      ) {
        addLogoutButton();
      }
    }
  } catch (e) {
    console.error("Failed to check admin status:", e);
  }
}

function addLogoutButton() {
  const userAvatar = document.querySelector(".user-avatar");
  if (userAvatar && !document.getElementById("logoutBtn")) {
    userAvatar.style.cursor = "pointer";
    userAvatar.title = "Click to logout";
    userAvatar.onclick = () => {
      if (confirm("Are you sure you want to logout?")) {
        logout();
      }
    };
  }
}

async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    if ("serviceWorker" in navigator && navigator.serviceWorker.controller) {
      navigator.serviceWorker.controller.postMessage({ type: "CLEAR_CACHES" });
    }
    window.location.href = "/login";
  } catch (e) {
    showToast("Logout failed");
  }
}

// PWA Service Worker Registration
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker
      .register("/sw.js", { scope: "/" })
      .then((registration) => {
        console.log("SW registered:", registration.scope);

        // Check for updates periodically
        setInterval(
          () => {
            registration.update();
          },
          60 * 60 * 1000,
        ); // Check every hour
      })
      .catch((error) => {
        console.log("SW registration failed:", error);
      });
  });

  // Handle offline/online status
  window.addEventListener("online", () => {
    showToast("Back online");
    document.body.classList.remove("offline");
  });

  window.addEventListener("offline", () => {
    showToast("You are offline");
    document.body.classList.add("offline");
  });
}
