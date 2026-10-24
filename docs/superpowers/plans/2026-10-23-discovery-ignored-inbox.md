# Discovery Inbox Dismissal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let admins dismiss noisy discovered routes from the inbox and restore them later, with dismissal surviving discovery scans and restarts.

**Architecture:** Store ignored source/URL pairs independently of published-app overrides. The admin API validates and atomically applies dismiss/restore actions; the existing discovery GET adds ignored records. The admin UI filters the inbox and renders a separate restore list.

**Tech Stack:** Go 1.24+, SQLite/CGO, vanilla JavaScript, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-23-discovery-ignored-inbox-design.md`

## Global Constraints

- Dismissal is inbox triage and never publishes an app or changes dashboard visibility.
- Dismiss only currently discovered unconfigured or Hidden entries; preserve configured visible entries.
- Key ignored records by both `source` and `url`; cap each batch at 100.
- Keep existing `active` and `stale` API fields, Hidden behavior, and CSRF/admin middleware.
- Restore remains possible after the source stops reporting the entry.

## Review Focus

- Same URL from two sources: dismissing one must leave the other in the inbox (Task 1 test).
- One invalid pair in a batch: no other pair should be persisted (Task 1 test).
- Published override submitted for dismissal: reject it without hiding or changing it (Task 1 test).
- Ignored route disappears from discovery: retain its restore record (Task 1 test).
- A failed dismiss request in the browser: retain the inbox row and show the error (Task 2 test).

---

### Task 1: Persistent ignore records and admin API

**Files:**
- Modify: `internal/database/database.go`, `internal/handlers/helpers_test.go`, `internal/handlers/discovered.go`, `main.go`
- Create: `internal/models/ignored_discovered_app.go`, `internal/database/ignored_discovered_apps.go`, `internal/handlers/ignored_discovered_apps_test.go`

**Interfaces:**
- Produce: `models.IgnoredDiscoveredApp` with `Source`, `URL`, `Name`, and `CreatedAt` JSON fields.
- Produce: `database.ListIgnoredDiscoveredApps(app *server.App) ([]models.IgnoredDiscoveredApp, error)`, `database.DismissDiscoveredApps(app *server.App, items []models.IgnoredDiscoveredApp) error`, and `database.RestoreIgnoredDiscoveredApps(app *server.App, items []models.IgnoredDiscoveredApp) error`.
- Produce: `handlers.IgnoredDiscoveredAppsHandler(app *server.App) http.HandlerFunc` for `POST /api/admin/discovered-apps/ignored` with `{action:"dismiss"|"restore", items:[{source,url}]}`.

- [ ] **Step 1: Write failing Go tests** for source/URL identity, persistence after reopening SQLite, stale restore, rejection of published entries, a mixed-validity batch with no writes, and invalid/oversized requests. Assert the existing `GET /api/admin/discovered-apps` keeps `active` and `stale` and adds `ignored`.
- [ ] **Step 2: Run focused tests to verify RED.** Run `go test ./internal/handlers -run 'TestIgnoredDiscovered|TestAdminDiscoveredApps' -count=1` in the CGO-enabled Go 1.26 WSL Docker environment. Expected: missing ignore API/schema or behavioral assertion failure.
- [ ] **Step 3: Add the table, database functions, handler, and route.** Create `ignored_discovered_apps(source TEXT NOT NULL, url TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(source,url))`. Validate all items before opening the write transaction; use the current raw discovery set and override state to authorize dismissal. Restore deletes matching pairs even when discovery is stale. Extend the existing GET response with persisted ignored rows.
- [ ] **Step 4: Run focused tests to verify GREEN**, then `go test ./...`, `go vet ./...`, and `go build -buildvcs=false` in the same environment.
- [ ] **Step 5: Commit** the Task 1 files with `git commit -m "Persist ignored discovery entries"`.

### Task 2: Inbox dismissal and restoration UI

**Files:**
- Modify: `static/js/admin-discovery.js`, `templates/index.html`, `e2e/tests/admin.spec.ts`, `README.md`, `CHANGELOG.md`

**Interfaces:**
- Consume: `GET /api/admin/discovered-apps` fields `active`, `stale`, and `ignored`; `POST /api/admin/discovered-apps/ignored` action/items contract from Task 1.
- Produce: per-row Dismiss, bulk Dismiss, collapsed Ignored section, and per-row Restore.

- [ ] **Step 1: Write failing Playwright tests** for individual and bulk dismiss, accurate inbox badge, restore, and a failed POST that leaves the row visible with a toast. Use route fixtures for UI behavior while Task 1's Go tests cover real persistence and authorization.
- [ ] **Step 2: Run focused tests to verify RED.** Run `npm test -- --grep "discovery inbox"` from `e2e` against the local test server. Expected: missing Dismiss/Restore controls.
- [ ] **Step 3: Implement the UI.** Filter ignored pairs from the actionable inbox, clear selection after successful dismiss, render the ignored list with saved name/source and stale marker, and restore via the new API. Keep server state authoritative after success and error. Update README and changelog with the admin workflow.
- [ ] **Step 4: Run focused tests to verify GREEN**, then the complete end-to-end suite and Go suite.
- [ ] **Step 5: Commit** the Task 2 files with `git commit -m "Add discovery inbox dismiss and restore controls"`.

### Task 3: Whole-change verification and review

**Files:** No product files unless a finding requires a fix.

- [ ] **Step 1: Run** `git diff --check`, `go test ./...`, `go vet ./...`, `go build -buildvcs=false`, and the complete Playwright suite. Record exact commands and results.
- [ ] **Step 2: Request an independent code, security, and usability review.** Address findings with regression tests and rerun affected checks.
- [ ] **Step 3: Push the branch, open a draft PR, and wait for exact-head CI.** Keep release and production deployment as separate follow-up decisions after the PR is ready.
