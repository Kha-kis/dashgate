# Discovery Ignore Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let admins preview and manage source-scoped URL path rules that remove matching actionable routes from the discovery inbox now and on later scans.

**Architecture:** Persist rule definitions separately from exact manual dismissals. A pure Go matcher normalizes rule input and evaluates current discovered routes; the admin API uses it for both unsaved previews and saved-rule matches. The browser renders the server's match results and leaves dashboard publication and access logic untouched.

**Tech Stack:** Go 1.24+, SQLite, vanilla JavaScript, Playwright/TypeScript.

**Spec:** `docs/superpowers/specs/2026-10-25-discovery-ignore-rules-design.md`

## Global Constraints

- Rule source is exactly one of `docker`, `traefik`, `nginx`, `npm`, `caddy`, `unraid`; no source-wide or root-path rule.
- The matcher makes no network request. A rule only removes unconfigured or Hidden routes from the admin inbox; it never changes dashboard access or discovery overrides.
- Manual `ignored_discovered_apps` entries remain independent and persistent. Existing installs start with zero rules.
- Preview and saved rules use the same matcher; preview is a snapshot and future routes may match.
- New admin endpoints use `RequireAdmin`, existing CSRF middleware, strict bounded JSON, and clear error responses.
- Go tests and builds require CGO for SQLite. On Windows, run them in a Linux Go container if local GCC is unavailable.
- This plan does not include a release or production deployment.

## Review Focus

- A trailing-slash or default-port spelling difference should not silently broaden or defeat an intended match; Task 1 tests both.
- A URL with an encoded slash or malformed percent escape should not cross a path-segment boundary; Task 1 tests it.
- Two active rules may match one route; Task 2 returns that route once with a stable rule ID.
- Restoring a manual dismissal while an active rule still matches should not put the route back in the inbox; Tasks 2 and 3 test it.
- A failed rule fetch or save should leave the previous inbox visible and report the error; Task 3 tests it.

---

### Task 1: Rule model, persistence, and pure matcher

**Files:**
- Create: `internal/models/discovery_ignore_rule.go`
- Create: `internal/discovery/ignore_rules.go`, `internal/discovery/ignore_rules_test.go`
- Create: `internal/database/discovery_ignore_rules.go`, `internal/database/discovery_ignore_rules_test.go`
- Modify: `internal/database/database.go`

**Interfaces:**
- Produce `models.DiscoveryIgnoreRule{ID int64, Source, Origin, PathPrefix string, Enabled bool, CreatedAt, UpdatedAt string}` and `models.DiscoveryRuleMatch{Source, URL string, RuleID int64}`.
- Produce `discovery.NormalizeIgnoreRule(source, origin, pathPrefix string) (models.DiscoveryIgnoreRule, error)`, `discovery.MatchesIgnoreRule(rule models.DiscoveryIgnoreRule, app models.DiscoveredAppWithOverride) bool`, and `discovery.MatchIgnoreRules(rules []models.DiscoveryIgnoreRule, apps []models.DiscoveredAppWithOverride) []models.DiscoveryRuleMatch`.
- Produce `database.ListDiscoveryIgnoreRules(app *server.App) ([]models.DiscoveryIgnoreRule, error)`, `CreateDiscoveryIgnoreRule(app *server.App, rule models.DiscoveryIgnoreRule) (models.DiscoveryIgnoreRule, error)`, `UpdateDiscoveryIgnoreRule(app *server.App, rule models.DiscoveryIgnoreRule) error`, and `DeleteDiscoveryIgnoreRule(app *server.App, id int64) error`.

- [ ] **Step 1: Write failing matcher tests.** Assert `/health` matches `/health` and `/health/live`, not `/healthz`; source, scheme, host, effective port, case, query/fragment, malformed URL, encoded slash, future discovered routes, and visible override cases follow the spec.
- [ ] **Step 2: Run `go test ./internal/discovery -run IgnoreRule -count=1`.** Expect failure from missing functions/types.
- [ ] **Step 3: Implement normalization and matching.** Normalize scheme/hostname/default port; compare escaped path at whole-segment boundaries; reject origin path/userinfo/query/fragment, root path, invalid source, and oversized origin/prefix (512/2048 bytes).
- [ ] **Step 4: Run the focused matcher test.** Expect PASS.
- [ ] **Step 5: Write failing persistence tests.** Assert clean install has zero rules, CRUD survives DB reopen, duplicate source/origin/path is rejected, and a maximum of 100 rules is enforced.
- [ ] **Step 6: Run `go test ./internal/database -run DiscoveryIgnoreRule -count=1`.** Expect failure from missing schema/functions.
- [ ] **Step 7: Add the table and transactional CRUD.** Use `CREATE TABLE IF NOT EXISTS`, unique `(source, origin, path_prefix)`, parameterized SQL, and a transaction to enforce the 100-rule limit on creation.
- [ ] **Step 8: Run both focused test packages and commit.** Expect PASS; commit matcher, model, schema, persistence, and tests.

### Task 2: Admin rule API and discovery response

**Files:**
- Create: `internal/handlers/discovery_ignore_rules.go`, `internal/handlers/discovery_ignore_rules_test.go`
- Modify: `internal/handlers/discovered.go`, `internal/handlers/helpers_test.go`, `main.go`

**Interfaces:**
- Consume Task 1's model, database, and matcher functions.
- Produce `GET/POST /api/admin/discovery-ignore-rules`, `PUT/DELETE /api/admin/discovery-ignore-rules/{id}`, and `POST /api/admin/discovery-ignore-rules/preview`. Preview returns `{count, matches}` with at most 100 listed matches.
- Extend `GET /api/admin/discovered-apps` with `ignoreRules` and `ruleMatches` while preserving existing keys.

- [ ] **Step 1: Write failing handler tests.** Cover preview/save agreement, empty-preview save, no-rules response, source/path validation, unknown JSON fields, 16 KiB body limit, wrong methods, missing IDs, duplicate/limit errors, enabled toggle, admin-only routing, CSRF middleware, and DB failure.
- [ ] **Step 2: Write integration tests for a visible configured route, overlapping rules, and a route that is both manually dismissed and rule-matched.** Assert the visible route is never in `ruleMatches`, overlap appears once with the lowest rule ID, and manual Restore leaves the route matched.
- [ ] **Step 3: Run `go test ./internal/handlers -run DiscoveryIgnoreRule -count=1`.** Expect failure from missing endpoints/response fields.
- [ ] **Step 4: Implement `DiscoveryIgnoreRulesHandler(app *server.App) http.HandlerFunc` and `DiscoveryIgnoreRuleByIDHandler(app *server.App) http.HandlerFunc`.** Parse strict bounded JSON, normalize on preview/create/update, treat `enabled` as explicit input, map validation/duplicate/limit errors to 400/409, and do not echo internal DB errors.
- [ ] **Step 5: Add admin routes and extend `AdminDiscoveredAppsHandler`.** Use one server-computed active match list; return empty arrays when there are no rules.
- [ ] **Step 6: Run focused handler tests and the existing ignored-app handler tests.** Expect PASS; commit the API and tests.

### Task 3: Admin inbox rule controls and browser coverage

**Files:**
- Modify: `static/js/admin.js`, `static/js/admin-discovery.js`, `templates/index.html`, `static/css/dashgate.css`
- Test: `e2e/tests/admin.spec.ts`

**Interfaces:**
- Consume Task 2's `ignoreRules`, `ruleMatches`, rule CRUD, and preview response.
- Produce an **Ignore rules** section and editor next to the existing inbox and **Ignored** list.

- [ ] **Step 1: Write failing Playwright cases.** Create from a route, preview before Save, invalidate preview after edits, save an empty preview, inspect current match counts, filter the rule-matched section, disable/re-enable/delete, preserve a published app, and explain why restoring a manually dismissed route still leaves it rule-matched.
- [ ] **Step 2: Add a failure case.** A failed list refresh or write leaves existing rows visible, gives a visible error, and does not claim success.
- [ ] **Step 3: Run focused `admin.spec.ts` tests.** Expect failure from absent controls.
- [ ] **Step 4: Add rule and match arrays to `adminState` and load them with existing discovered data.** Filter inbox by source/URL keys in `ruleMatches`; keep manual Ignored separate and preserve existing `active` consumers.
- [ ] **Step 5: Build rule controls and editor.** Prefill from a selected route, invalidate preview whenever input changes, require preview before Save, show current matches and future-route notice, and show edit/enable/disable/delete controls. Escape untrusted names/URLs in rendered HTML and avoid embedding raw values in inline handlers.
- [ ] **Step 6: Run focused Playwright cases and JS syntax checks.** Expect PASS; commit UI and tests.

### Task 4: Documentation and whole-change verification

**Files:**
- Modify: `README.md`, `CHANGELOG.md`

**Interfaces:** Document admin rule matching, preview limits, reversibility, and separate manual dismissal; no API contract changes.

- [ ] **Step 1: Update README and Unreleased changelog.** Explain source/origin/path matching, preview snapshot, and unchanged dashboard visibility.
- [ ] **Step 2: Run `go test ./...`, `go vet ./...`, `go build ./...`, relevant Playwright tests, JS syntax checks, and `git diff --check`.** Expect all PASS; use Linux Docker for Go+SQLite where Windows CGO is unavailable.
- [ ] **Step 3: Review the complete diff for access-control changes, unsafe HTML, data loss, matcher surprises, and regressions.** Fix findings and rerun affected checks.
- [ ] **Step 4: Commit docs/fixes, push the feature branch, open a PR, and check exact-head CI.** Do not tag, merge, release, or deploy before the final review.
