// admin-users.js - LLDAP/local users and groups management

// Read-only User List
function renderUsersList() {
  const container = document.getElementById("usersList");
  const searchTerm =
    document.getElementById("userSearchInput")?.value.toLowerCase() || "";

  const filteredUsers = adminState.users.filter(
    (u) =>
      u.id.toLowerCase().includes(searchTerm) ||
      u.email.toLowerCase().includes(searchTerm) ||
      (u.displayName && u.displayName.toLowerCase().includes(searchTerm)),
  );

  if (filteredUsers.length === 0) {
    container.innerHTML = '<div class="admin-empty">No users found</div>';
    return;
  }

  container.innerHTML = filteredUsers
    .map(
      (user) => `
                <div class="admin-item">
                    <div class="admin-item-avatar">${escapeHtml((user.displayName || user.id)[0].toUpperCase())}</div>
                    <div class="admin-item-info">
                        <div class="admin-item-name">${escapeHtml(user.displayName || user.id)}</div>
                        <div class="admin-item-meta">${escapeHtml(user.email)}</div>
                        ${
                          user.groups && user.groups.length > 0
                            ? `
                            <div class="admin-item-groups">
                                ${user.groups
                                  .slice(0, 3)
                                  .map(
                                    (g) =>
                                      `<span class="admin-group-badge">${escapeHtml(g)}</span>`,
                                  )
                                  .join("")}
                                ${user.groups.length > 3 ? `<span class="admin-group-badge">+${user.groups.length - 3}</span>` : ""}
                            </div>
                        `
                            : ""
                        }
                    </div>
                </div>
            `,
    )
    .join("");
}

function filterUsers() {
  renderUsersList();
}

// Read-only Group List
function renderGroupsList() {
  const container = document.getElementById("groupsList");

  if (adminState.groups.length === 0) {
    container.innerHTML = '<div class="admin-empty">No groups found</div>';
    return;
  }

  container.innerHTML = adminState.groups
    .map(
      (group) => `
                <div class="admin-item">
                    <div class="admin-item-icon">
                        <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                            <circle cx="9" cy="7" r="4"/>
                            <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
                        </svg>
                    </div>
                    <div class="admin-item-info">
                        <div class="admin-item-name">${escapeHtml(group.displayName)}</div>
                        <div class="admin-item-meta">${group.users ? group.users.length : 0} members</div>
                    </div>
                </div>
            `,
    )
    .join("");
}

// Local User Management
function renderLocalUsersList() {
  const container = document.getElementById("localUsersList");
  if (!container) return;

  const searchTerm =
    document.getElementById("localUserSearchInput")?.value.toLowerCase() || "";

  const filteredUsers = (adminState.localUsers || []).filter(
    (u) =>
      u.username.toLowerCase().includes(searchTerm) ||
      (u.email && u.email.toLowerCase().includes(searchTerm)) ||
      (u.displayName && u.displayName.toLowerCase().includes(searchTerm)),
  );

  if (filteredUsers.length === 0) {
    container.innerHTML =
      '<div class="admin-empty">No local users found. Click "Add User" to create one.</div>';
    return;
  }

  container.innerHTML = filteredUsers
    .map(
      (user) => `
                <div class="admin-item">
                    <div class="admin-item-avatar">${escapeHtml((user.displayName || user.username)[0].toUpperCase())}</div>
                    <div class="admin-item-info">
                        <div class="admin-item-name">${escapeHtml(user.displayName || user.username)}</div>
                        <div class="admin-item-meta">${escapeHtml(user.username)}${user.email ? " \u2022 " + escapeHtml(user.email) : ""}</div>
                        ${
                          user.groups && user.groups.length > 0
                            ? `
                            <div class="admin-item-groups">
                                ${user.groups
                                  .slice(0, 3)
                                  .map(
                                    (g) =>
                                      `<span class="admin-group-badge">${escapeHtml(g)}</span>`,
                                  )
                                  .join("")}
                                ${user.groups.length > 3 ? `<span class="admin-group-badge">+${user.groups.length - 3}</span>` : ""}
                            </div>
                        `
                            : '<div class="admin-item-meta" style="color: var(--text-tertiary)">No groups</div>'
                        }
                    </div>
                    <div class="admin-item-actions">
                        <button class="admin-action-btn" onclick="openPasswordResetModal(${user.id}, '${escapeHtml(user.username).replace(/'/g, "\\'")}')" title="Reset Password">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                                <path d="M7 11V7a5 5 0 0110 0v4"/>
                            </svg>
                        </button>
                        <button class="admin-action-btn" onclick="openEditLocalUserModal(${user.id})" title="Edit">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                        <button class="admin-action-btn danger" onclick="confirmDeleteLocalUser(${user.id}, '${escapeHtml(user.username).replace(/'/g, "\\'")}')" title="Delete">
                            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                            </svg>
                        </button>
                    </div>
                </div>
            `,
    )
    .join("");
}

function filterLocalUsers() {
  renderLocalUsersList();
}

function openCreateLocalUserModal() {
  document.getElementById("localUserModalTitle").textContent = "Add Local User";
  document.getElementById("localUserEditId").value = "";
  document.getElementById("localUserUsername").value = "";
  document.getElementById("localUserUsername").disabled = false;
  document.getElementById("localUserPassword").value = "";
  document.getElementById("localUserPasswordGroup").style.display = "block";
  document.getElementById("localUserDisplayName").value = "";
  document.getElementById("localUserEmail").value = "";

  // Reset group checkboxes
  document
    .querySelectorAll('#localUserGroups input[type="checkbox"]')
    .forEach((cb) => (cb.checked = false));

  // Populate groups from LLDAP if available
  populateLocalUserGroups([]);

  document.getElementById("localUserModal").classList.add("open");
}

function openEditLocalUserModal(userId) {
  const user = adminState.localUsers.find((u) => u.id === userId);
  if (!user) return;

  document.getElementById("localUserModalTitle").textContent =
    "Edit Local User";
  document.getElementById("localUserEditId").value = userId;
  document.getElementById("localUserUsername").value = user.username;
  document.getElementById("localUserUsername").disabled = true;
  document.getElementById("localUserPassword").value = "";
  document.getElementById("localUserPasswordGroup").style.display = "none";
  document.getElementById("localUserDisplayName").value =
    user.displayName || "";
  document.getElementById("localUserEmail").value = user.email || "";

  // Populate groups
  populateLocalUserGroups(user.groups || []);

  document.getElementById("localUserModal").classList.add("open");
}

function getLocalGroups() {
  const groups = new Set(["admin", "users"]);
  if (adminState.localUsers) {
    adminState.localUsers.forEach((u) => {
      if (u.groups) u.groups.forEach((g) => groups.add(g));
    });
  }
  if (adminState.managedGroups) {
    adminState.managedGroups.forEach((g) => groups.add(g.name));
  }
  if (adminState.groups) {
    adminState.groups.forEach((g) => groups.add(g.displayName));
  }
  return Array.from(groups).sort();
}

function populateLocalUserGroups(selectedGroups) {
  const container = document.getElementById("localUserGroups");
  const allGroups = getLocalGroups();

  container.innerHTML = allGroups
    .map(
      (group) => `
                <label class="admin-group-checkbox">
                    <input type="checkbox" value="${escapeHtml(group)}" ${selectedGroups.includes(group) ? "checked" : ""}>
                    <span class="admin-group-checkbox-label">${escapeHtml(group)}</span>
                </label>
            `,
    )
    .join("");
}

function renderLocalGroupsList() {
  const container = document.getElementById("localGroupsList");
  if (!container) return;
  const allGroups = getLocalGroups();
  const managedNames = new Set(
    (adminState.managedGroups || []).map((g) => g.name),
  );
  const lldapNames = new Set(
    (adminState.groups || []).map((g) => g.displayName),
  );

  const counts = {};
  allGroups.forEach((g) => (counts[g] = 0));
  if (adminState.localUsers) {
    adminState.localUsers.forEach((u) => {
      if (u.groups)
        u.groups.forEach((g) => {
          if (counts[g] !== undefined) counts[g]++;
        });
    });
  }

  if (allGroups.length === 0) {
    container.innerHTML = '<div class="admin-empty">No groups yet</div>';
    return;
  }

  container.innerHTML = allGroups
    .map((group) => {
      const isDefault = group === "admin" || group === "users";
      const isManaged = managedNames.has(group);
      const isLldap = lldapNames.has(group) && !isManaged;
      let badge = "";
      let deleteBtn = "";
      if (isDefault) {
        badge =
          '<span class="admin-readonly-badge" style="font-size:10px;">built-in</span>';
      } else if (isLldap) {
        badge =
          '<span class="admin-readonly-badge" style="font-size:10px;">LLDAP</span>';
      } else if (isManaged) {
        deleteBtn = `<button class="admin-action-btn danger" onclick="removeLocalGroup('${escapeHtml(group).replace(/'/g, "\\'")}')" title="Remove group">
                        <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                        </svg>
                    </button>`;
      } else {
        // Orphan group (exists on users but not in any source)
        badge =
          '<span class="admin-readonly-badge" style="font-size:10px;">in use</span>';
      }
      return `
                <div class="admin-item" style="padding:10px 12px;">
                    <div class="admin-item-info" style="flex:1;">
                        <div class="admin-item-name">${escapeHtml(group)}</div>
                        <div class="admin-item-meta">${counts[group] || 0} user${counts[group] !== 1 ? "s" : ""}</div>
                    </div>
                    ${badge}
                    ${deleteBtn}
                </div>`;
    })
    .join("");
}

async function addLocalGroup() {
  const input = document.getElementById("newLocalGroupInput");
  const name = input.value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "");
  if (!name) {
    showToast("Enter a group name");
    return;
  }

  const existing = getLocalGroups();
  if (existing.includes(name)) {
    showToast("Group already exists");
    return;
  }

  try {
    const resp = await fetch("/api/admin/managed-groups", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ name }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    input.value = "";
    await reloadManagedGroups();
    showToast(`Group "${name}" created`);
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

async function removeLocalGroup(name) {
  const usersWithGroup = (adminState.localUsers || []).filter(
    (u) => u.groups && u.groups.includes(name),
  );
  if (usersWithGroup.length > 0) {
    showToast(
      `Cannot remove: ${usersWithGroup.length} user(s) still in this group`,
    );
    return;
  }
  try {
    const resp = await fetch(
      `/api/admin/managed-groups/${encodeURIComponent(name)}`,
      {
        method: "DELETE",
        credentials: "include",
      },
    );
    if (!resp.ok) throw new Error(await resp.text());
    await reloadManagedGroups();
    showToast(`Group "${name}" removed`);
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

function closeLocalUserModal() {
  document.getElementById("localUserModal").classList.remove("open");
}

async function reloadManagedGroups() {
  try {
    const resp = await fetch("/api/admin/managed-groups", {
      credentials: "include",
    });
    if (resp.ok) {
      adminState.managedGroups = (await resp.json()) || [];
    }
  } catch (e) {
    console.error("Failed to reload managed groups:", e);
  }
  renderLocalGroupsList();
}

async function saveLocalUser() {
  const editId = document.getElementById("localUserEditId").value;
  const username = document.getElementById("localUserUsername").value.trim();
  const password = document.getElementById("localUserPassword").value;
  const displayName = document
    .getElementById("localUserDisplayName")
    .value.trim();
  const email = document.getElementById("localUserEmail").value.trim();
  const checkboxes = document.querySelectorAll(
    '#localUserGroups input[type="checkbox"]:checked',
  );
  const groups = Array.from(checkboxes).map((cb) => cb.value);

  if (!username) {
    showToast("Username is required");
    return;
  }

  // Prevent admin from removing their own admin role
  if (editId && currentUser && currentUser.username === username) {
    const adminGroupStr =
      (typeof currentSystemConfig !== "undefined" &&
        currentSystemConfig &&
        currentSystemConfig.adminGroup) ||
      "admin";
    const adminGroupNames = adminGroupStr
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const hasAdmin = groups.some((g) => adminGroupNames.includes(g));
    if (!hasAdmin) {
      showToast("Cannot remove admin role from your own account");
      return;
    }
  }

  if (!editId && !password) {
    showToast("Password is required for new users");
    return;
  }

  try {
    let resp;
    if (editId) {
      // Update existing user
      resp = await fetch(`/api/admin/local-users/${editId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, displayName, groups }),
      });
    } else {
      // Create new user
      resp = await fetch("/api/admin/local-users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          username,
          password,
          email,
          displayName,
          groups,
        }),
      });
    }

    if (!resp.ok) throw new Error(await resp.text());

    showToast(editId ? "User updated" : "User created");
    closeLocalUserModal();
    await reloadLocalUsers();
  } catch (e) {
    showToast("Error: " + e.message);
  }
}

function confirmDeleteLocalUser(userId, username) {
  if (adminState.currentUser && adminState.currentUser.username === username) {
    showToast("Cannot delete yourself");
    return;
  }

  document.getElementById("confirmDeleteMessage").textContent =
    `Delete user "${username}"? This will also delete all their sessions.`;
  adminState.deleteCallback = async () => {
    try {
      const resp = await fetch(`/api/admin/local-users/${userId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!resp.ok) throw new Error(await resp.text());
      showToast("User deleted");
      closeConfirmDelete();
      await reloadLocalUsers();
    } catch (e) {
      showToast("Error: " + e.message);
    }
  };
  document.getElementById("confirmDeleteModal").classList.add("open");
}

function openPasswordResetModal(userId, username) {
  document.getElementById("passwordResetUserId").value = userId;
  document.getElementById("passwordResetUsername").textContent = username;
  document.getElementById("newPasswordInput").value = "";
  document.getElementById("confirmPasswordInput").value = "";
  document.getElementById("passwordResetModal").classList.add("open");
}

function closePasswordResetModal() {
  document.getElementById("passwordResetModal").classList.remove("open");
}

async function resetPassword() {
  const userId = document.getElementById("passwordResetUserId").value;
  const newPassword = document.getElementById("newPasswordInput").value;
  const confirmPassword = document.getElementById("confirmPasswordInput").value;

  if (!newPassword) {
    showToast("Password is required");
    return;
  }

  if (newPassword !== confirmPassword) {
    showToast("Passwords do not match");
    return;
  }

  if (newPassword.length < 8) {
    showToast("Password must be at least 8 characters");
    return;
  }

  try {
    const resp = await fetch(`/api/admin/local-users/${userId}/password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ password: newPassword }),
    });

    if (!resp.ok) throw new Error(await resp.text());

    showToast("Password reset successfully");
    closePasswordResetModal();
  } catch (e) {
    showToast("Error: " + e.message);
  }
}
