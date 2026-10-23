# Open Issues Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve or verify DashGate issues #18, #14, and #13 against the current main branch, with regression coverage and release readiness evidence.

**Architecture:** Keep browser fixes in the existing dashboard and admin scripts. Exercise actual dashboard behavior in Playwright and use the real admin APIs where possible. Treat historical reports separately from bugs reproducible on current main.

**Tech Stack:** Go 1.24+, SQLite, vanilla JavaScript, Playwright/TypeScript.

**Spec:** GitHub issues #18, #14, and #13 (links in the repository issue tracker).

## Global Constraints

- Preserve existing authentication and group access boundaries.
- Do not publish a release or deploy during this plan; review release readiness after fixes and verification.
- Do not change the meaning of environment-controlled discovery settings.

## Review Focus

- Personal apps with categories, without categories, and after loading preferences from another browser.
- An empty server My Apps list replacing stale browser data.
- Admin users list and Add User modal after fresh login with local auth enabled.
- Discovered apps appearing in the inbox and configured apps appearing in Manage Apps.
- Discovery save requests rejected because environment variables control a source; no false success message.

---

### Task 1: My Apps dashboard (#18)

**Files:** `static/js/my-apps.js`, `static/js/app.js`, `e2e/tests/dashboard.spec.ts`.

**Interfaces:** `renderMyAppsOnDashboard()` reads `myApps` and inserts or removes `#myAppsSection` in `.main-content`; `loadServerPreferences()` updates browser state from `/api/user/preferences`.

- [x] Add Playwright tests for saving a personal app, reload, empty-category fallback, server preference loading in a fresh browser context, and server-side deletion replacing stale local data.
- [x] Run focused tests and confirm the expected failures.
- [x] Fix the insertion anchor and server preference render/localStorage update.
- [x] Run focused tests and confirm they pass.

### Task 2: Admin and discovery (#14, #13)

**Files:** `static/js/admin-discovery.js`, `e2e/tests/admin.spec.ts`, and focused Go tests if a server defect is found.

**Interfaces:** `loadAdminData()` loads local users and discovered apps; `saveDiscoverySettings()` sends six source PUTs and reports partial failures accurately.

- [x] Add Playwright coverage for real local-user listing and Add User modal, discovered-app inbox/rendering, and a rejected discovery save.
- [x] Run focused tests and distinguish current failures from historical v1.5.1 behavior.
- [x] Fix reproduced defects only; document external OIDC claim configuration if that symptom cannot be reproduced locally.
- [x] Run focused tests and confirm they pass.

### Task 3: Whole-change verification and release review

**Files:** `CHANGELOG.md`, `README.md` only where verified behavior or setup guidance changes.

- [x] Run JavaScript syntax checks, Go tests/vet/build, and the relevant Playwright suite.
- [x] Review changed code and documentation for security and regressions. Addressed the account-switch write boundary, pending-copy lockout, malformed imports, and ordered write handling found during review.
- [ ] Commit, open a PR with issue mapping and evidence, and check CI.
- [ ] Review release scope, documentation, and version choice; leave tagging and deployment for the release decision.
