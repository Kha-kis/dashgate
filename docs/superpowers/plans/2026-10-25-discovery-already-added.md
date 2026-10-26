# Discovery Already Added Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move discovered routes that exactly match published app URLs into an inspectable Already added section.

**Architecture:** Partition current actionable discovery results in `admin-discovery.js` using published URLs from admin state. Render the matching routes in a collapsed section and recalculate after either apps or discovery data reloads. No server schema or API change.

**Tech Stack:** Existing plain JavaScript admin UI, HTML template, CSS, Playwright E2E.

**Spec:** `docs/superpowers/specs/2026-10-25-discovery-already-added-design.md`

## Global Constraints

- Compare only absolute HTTP(S) URLs. URL parsing may canonicalize the host and default port, but path case, non-root trailing slash, and query remain significant.
- Hidden overrides remain actionable; manual Ignored and enabled ignore rules retain precedence.
- No publication, access, discovery source, or persistent database changes.

## Review Focus

- Published app URL with implicit root slash versus discovered explicit root slash: group together.
- Path or query near matches: stay actionable.
- Hidden override matching a published app URL: stay actionable.
- A discovered override whose raw URL duplicates a manual app cannot make another route Already added.
- Long names and URLs remain readable in the expanded section on narrow screens.
- Deleted or edited published app: route returns to the inbox after apps reload.
- Search and source filters: apply to Already added independently, without changing its total count or bulk selection.

---

### Task 1: Group already published routes in Admin > Content

**Files:**
- Modify: `static/js/admin-discovery.js`, `static/js/admin.js`, `static/css/dashgate.css`, `templates/index.html`, `README.md`
- Test: `test/discovery-already-added.test.cjs`, `e2e/tests/admin.spec.ts`

**Interfaces:**
- Consume `adminState.apps`, `adminState.discoveredApps`, `adminState.ignoredDiscoveredApps`, `adminState.discoveryRuleMatches`.
- Produce `renderAlreadyAddedDiscoveredApps(routes)` and `publishedAppForDiscoveredRoute(route)` in `admin-discovery.js`; keep `renderDiscoveredAppsList()` as the partition entrypoint.

- [x] **Step 1: Write a failing Playwright test.** Fixture a published manual app at `http://localhost:3000`, root URL discovery match, `/api` near match, Hidden override, unique route, and ignored/rule-matched routes. Assert the inbox badge, Already added section, search/filter behavior, and the route's return after removing the manual app from the fixture and reloading.
- [x] **Step 2: Run the focused test and confirm failure because the section is absent.** `npx playwright test --project=main --grep "already added discovery"` from `e2e` with the test server built.
- [x] **Step 3: Implement the partition and UI.** Compare normalized HTTP(S) URLs, keep Hidden overrides actionable, preserve Ignored and rule precedence, and render escaped names/URLs in `#discoveryAlreadyAddedSection`.
- [x] **Step 4: Re-render on published app edits.** `reloadApps()` calls `renderDiscoveredAppsList()` after updating `adminState.apps`; discovery reload already does so.
- [x] **Step 5: Document the section in README.** Explain matching and that it does not change publication or access.
- [x] **Step 6: Run the focused E2E test, full E2E suite, and Go suite where available.** Confirm zero failures, inspect the diff, then commit.
