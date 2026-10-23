# Access Explanation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let admins explain a saved user's access to any current DashGate app without changing access rules.

**Architecture:** Add read-only admin user and app catalogs plus an evaluation endpoint. Share decision helpers with dashboard filtering so explanations track actual visibility. Add a small form in Admin > Users and document snapshot limits.

**Tech Stack:** Go, SQLite, vanilla JavaScript, HTML.

**Spec:** `docs/superpowers/plans/2026-10-23-access-explanation-design.md`

## Global Constraints

- Keep current visibility behavior unchanged.
- Require admin access for both endpoints.
- Do not expose password hashes or identity tokens.
- Label stored external groups as snapshots.

## Review Focus

- Config app with no groups: admin-only.
- Discovered app without override or marked hidden: not visible even to admin.
- Discovered app with empty groups and visible override: visible to every authenticated user.
- Effective config mapping overrides the app's own groups.
- OIDC, LDAP, and proxy groups can become stale after the last stored update.

---

### Task 1: Decision model and endpoints

**Files:** `internal/handlers/access_explanation.go`, `internal/handlers/access_explanation_test.go`, `internal/handlers/dashboard.go`, `main.go`.

- [x] Write failing tests for the five visibility cases above and endpoint input validation.
- [x] Run focused tests and confirm failure.
- [x] Implement shared decision helpers, user catalog, and evaluation endpoint.
- [x] Run focused tests and confirm pass.

### Task 2: Admin presentation and docs

**Files:** `templates/index.html`, `static/js/admin.js`, `static/js/admin-discovery.js`, `e2e/tests/admin.spec.ts`, `README.md`, `CHANGELOG.md`.

- [x] Add user/app selectors and an explicit explanation result with snapshot wording.
- [x] Correct the README and describe the admin tool.
- [x] Add and run a browser test for the Admin selection and explanation flow.
- [x] Run Go tests, JS syntax check, and build; inspect the resulting diff.
