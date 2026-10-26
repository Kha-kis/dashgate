# Discovery Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show accurate scan status and a searchable explanation of each current discovery route inline in Admin → Discovery.

**Architecture:** Each `DiscoveryManager` owns a process-local scan snapshot and serializes scans for its source. Existing admin source GET endpoints expose that snapshot. A shared client-side route partition feeds both the Content inbox and per-source diagnostics, so their disposition labels agree.

**Tech Stack:** Go 1.24 module with SQLite/CGO, vanilla JavaScript and HTML/CSS, Playwright end-to-end tests.

**Spec:** `docs/superpowers/specs/2026-10-26-discovery-diagnostics-design.md`

## Global Constraints

- Preserve current discovery results, publication, access groups, source settings, and existing GET/POST response behavior.
- Disabled sources clear routes and prior scan metadata; re-enabled sources start at Waiting.
- A failed scan may retain the previous app snapshot, but must label its count as last successful.
- All diagnostics are admin-only, process-local, and read-only; no secret-bearing raw errors in responses.
- The UI stays in the current Settings modal and works with keyboard and narrow widths.
- Run the `go test` commands below in a Go 1.24+ environment with CGO and a C compiler; this Windows checkout currently has Go 1.26 but no `gcc`, so use a Linux container/host or CI if the local Docker daemon is unavailable.

## Review Focus

1. Failure after success: the source still has prior routes, but the latest attempt must say Failed and the count must say last successful. Tested in Task 1 and Task 5.
2. Timer and manual refresh overlap: one source scan must publish only one current result; stop/restart cannot republish an old result. Tested in Task 1 and Task 2.
3. Nginx unreadable include or file: partial results must report a warning, while intentionally skipped paths must not. Tested in Task 4.
4. Userinfo, API keys, or query secrets in upstream errors: JSON and UI must expose only bounded issue codes and safe copy. Tested in Task 3 and Task 5.
5. Duplicate URLs across sources, Hidden overrides, and stale ignored entries: current route counts and Content disposition must agree without counting stale data. Tested in Task 6 and Task 7.

---

## File map

- `internal/server/discovery_scan.go` owns the scan snapshot, synchronization, safe issue codes, and atomic publication of a successful app set. `internal/server/server.go` keeps the existing manager and adds this state.
- `internal/discovery/{docker,traefik,npm,caddy,unraid}.go` report a terminal scan result on every path. `internal/discovery/nginx.go` also reports partial file/include reads.
- `internal/handlers/admin_discovery.go` adds `scan` metadata to existing admin source GET responses. `main.go` keeps existing routes and `RequireAdmin` wrappers.
- `static/js/admin-discovery.js` owns a pure route-disposition helper, scan rendering, search/filter behavior, and refresh updates. `templates/index.html` adds inline markup under each enable row; `static/css/dashgate.css` styles the compact summary and details.
- `README.md` documents what scan status and route dispositions mean. Tests sit beside the relevant Go packages and in `e2e/tests/admin.spec.ts`.

### Task 1: Scan snapshot and source lifecycle

**Files:** Create `internal/server/discovery_scan.go`, `internal/server/discovery_scan_test.go`; modify `internal/server/server.go`.

**Interfaces:** Define `DiscoveryScanState` constants `waiting`, `scanning`, `completed`, `warning`, `failed`, `disabled`; `DiscoveryScanResult{Apps []models.App, WarningCount int, IssueCode string}`; `DiscoveryScanSnapshot{State, StartedAt, CompletedAt, LastSuccessAt, LastSuccessCount, WarningCount, IssueCode}`. Add `(*DiscoveryManager).EnableScan()`, `DisableScan()`, `RunScan(func() (DiscoveryScanResult, string)) bool`, and `GetScanSnapshot() DiscoveryScanSnapshot`. The callback's empty failure code means success. Codes are bounded constants (`missing_config`, `invalid_config`, `unreachable`, `upstream_auth`, `bad_response`, `decode_failed`, `partial_read`, `internal_error`); raw errors stay in logs only.

- [ ] **Step 1: Write failing manager tests.** `TestDiscoveryScanLifecycle` asserts Waiting → Scanning → Completed, a zero-app success, failure after success retaining the last count/time, warning result, and Disabled → Waiting clearing prior metadata. `TestDiscoveryScanCoalescesAndInvalidates` blocks one scan, rejects a second, disables/re-enables, and proves the old scan cannot republish apps or status. `TestDiscoveryScanPanic` proves a callback panic becomes `internal_error` and releases the scanning state.
- [ ] **Step 2: Run the tests and confirm failure.** Run `go test ./internal/server -run 'TestDiscoveryScan' -count=1`; expect missing interfaces or failing assertions.
- [ ] **Step 3: Implement the manager interfaces.** `RunScan` coalesces per source; successful publication of apps and scan metadata is atomic relative to disable, while failure leaves the current apps alone. Return false when disabled or already scanning. Never store a raw error string.
- [ ] **Step 4: Run `go test ./internal/server -count=1`; expect PASS.**
- [ ] **Step 5: Commit.** `git add internal/server/discovery_scan.go internal/server/discovery_scan_test.go internal/server/server.go` then `git commit -m "feat: track discovery scan lifecycle"`.

### Task 2: Report Docker and Traefik scans

**Files:** Modify `internal/discovery/docker.go`, `traefik.go`; create `internal/discovery/scan_reporting_network_test.go`.

**Interfaces:** Each existing `Discover*Apps(app *server.App)` remains callable by its loop and refresh handler. It invokes its manager's `RunScan` callback, which returns discovered apps or a safe failure code. Start calls `EnableScan`; stop calls `DisableScan`. Keep source-specific logging and previous result-retention behavior.

- [ ] **Step 1: Write failing source tests.** Use `httptest` or temporary sockets as appropriate. Assert missing socket/configuration, unreachable upstream, non-200 response, malformed response, zero matches, and normal result produce the expected scan state/code/count. Start a manual refresh while a scan is blocked and assert coalescing and stop invalidation.
- [ ] **Step 2: Run `go test ./internal/discovery -run 'TestDockerScanReporting|TestTraefikScanReporting|TestDiscoveryRefreshOverlap' -count=1`; expect failure.**
- [ ] **Step 3: Instrument Docker and Traefik.** Replace early silent returns with safe issue codes, return parsed apps to `RunScan`, and preserve filtering and logs. Panic recovery must be effective for timer and manual calls. Update each loop's enable/disable lifecycle without changing its 60-second schedule.
- [ ] **Step 4: Run the focused tests and `go test ./internal/discovery -count=1`; expect PASS.**
- [ ] **Step 5: Commit.** Commit only these source files and the test with `feat: report docker and traefik scans`.

### Task 3: Report NPM, Caddy, and Unraid scans

**Files:** Modify `internal/discovery/npm.go`, `caddy.go`, `unraid.go`; create `internal/discovery/scan_reporting_api_test.go`.

**Interfaces:** Each existing `Discover*Apps(app *server.App)` remains callable and uses its manager's `RunScan`. Start calls `EnableScan`; stop calls `DisableScan`. Every error path maps to a safe issue code; missing credentials are `missing_config` and 401/403 are `upstream_auth`.

- [ ] **Step 1: Write failing source tests.** Cover missing credentials, unreachable API, auth failure, malformed response, zero matches, and normal result for each source. Include an upstream URL with `user:password` and `?api_key=secret`; neither secret may appear in `GetScanSnapshot()` or marshalled status.
- [ ] **Step 2: Run `go test ./internal/discovery -run 'TestNPMScanReporting|TestCaddyScanReporting|TestUnraidScanReporting' -count=1`; expect failure.**
- [ ] **Step 3: Instrument the three sources.** Return apps or safe failure codes to `RunScan`; preserve existing source-specific filtering, logs, and 60-second loops.
- [ ] **Step 4: Run focused and package tests; expect PASS.**
- [ ] **Step 5: Commit.** Commit these sources and the test with `feat: report API discovery scans`.

### Task 4: Nginx partial scan warnings

**Files:** Modify `internal/discovery/nginx.go`; create `internal/discovery/nginx_scan_test.go`.

**Interfaces:** The existing `DiscoverNginxApps(app *server.App)` uses `RunScan`. A missing/non-directory root is a failed scan. Read failures in an otherwise usable tree produce `WarningCount > 0` and `IssueCode=partial_read`; normal skipped locations and duplicate URLs are not warnings.

- [ ] **Step 1: Write failing tests.** Assert missing root fails, a valid empty tree completes with zero routes, a valid file plus a simulated unreadable file/include yields a partial result and warning, and skipped `/health` or duplicate URL leaves WarningCount zero. Reuse temp-dir patterns in `nginx_include_test.go`; inject a failing reader rather than relying on OS permissions.
- [ ] **Step 2: Run `go test ./internal/discovery -run 'TestNginxScan' -count=1`; expect failure.**
- [ ] **Step 3: Instrument root, file, and include handling.** Thread a warning counter through include resolution without logging duplicate warnings as separate scan issues; return apps to `RunScan`. Preserve Nginx route parsing and existing rate-limited logging.
- [ ] **Step 4: Run focused and package tests; expect PASS.**
- [ ] **Step 5: Commit.** Commit Nginx files with `feat: surface partial nginx scans`.

### Task 5: Admin scan status contract

**Files:** Modify `internal/handlers/admin_discovery.go`; create `internal/handlers/admin_discovery_status_test.go`.

**Interfaces:** Add a `scan` object to all six existing admin source GET JSON responses using `GetScanSnapshot()`; retain `enabled`, `appCount`, and existing configuration keys. JSON uses lowercase state/code strings, RFC3339 timestamps or `null`, `lastSuccessCount`, and `warningCount`. A failed scan includes both failure code and last-success metadata. No new public endpoint or refresh method.

- [ ] **Step 1: Write failing handler tests.** Cover all six responses and existing fields, disabled/waiting/completed/failed states, previous count after failure, safe JSON with secret-bearing upstream errors, and non-admin denial through the same `RequireAdmin` wrapping used in `main.go`.
- [ ] **Step 2: Run `go test ./internal/handlers -run 'TestAdminDiscoveryScanStatus' -count=1`; expect failure.**
- [ ] **Step 3: Add a shared status response helper.** Convert only safe codes and timestamps; avoid serializing raw error objects or config secrets. Keep existing handler field names stable.
- [ ] **Step 4: Run focused and package tests; expect PASS.**
- [ ] **Step 5: Commit.** Commit handler changes with `feat: expose admin discovery scan status`.

### Task 6: Shared route disposition

**Files:** Modify `static/js/admin-discovery.js`, `e2e/tests/admin.spec.ts`.

**Interfaces:** Add pure `partitionDiscoveredRoutes(active, ignored, ruleMatches, publishedApps)` returning keyed arrays for `inbox`, `alreadyAdded`, `ignored`, `ruleMatched`, and `configured`, each entry carrying a reason and matching app/rule where applicable. Key by `[source,url]`. `renderDiscoveredAppsList()` consumes the partition without changing existing Content behavior. The per-source diagnostics UI in Task 7 consumes the same object.

- [ ] **Step 1: Write a failing Playwright case.** Fixture identical URLs in two sources, a Hidden override, a published URL match, a configured override, a manual dismissal, a rule match, and a stale ignored entry. Call the pure helper with `page.evaluate` and assert each currently active route has one disposition; assert Content's existing lists and badge keep their behavior and stale ignored entries remain restorable only in Content.
- [ ] **Step 2: Run `cd e2e && npx playwright test tests/admin.spec.ts -g 'discovery disposition'`; expect failure.**
- [ ] **Step 3: Extract the current partition rules into the pure helper.** Preserve manual dismissal/rule precedence, exact normalized HTTP(S) URL matching for Already added, and Hidden override behavior. Ensure the helper supplies safe reason data but does not render HTML.
- [ ] **Step 4: Run the focused test and existing discovery tests; expect PASS.**
- [ ] **Step 5: Commit.** Commit JS and test with `refactor: share discovery route disposition`.

### Task 7: Inline diagnostics and accessible route details

**Files:** Modify `templates/index.html`, `static/css/dashgate.css`, `static/js/admin-discovery.js`, `static/js/admin.js`, `e2e/tests/admin.spec.ts`.

**Interfaces:** Add one `discoveryScanSummary-<source>` and `discoveryScanDetails-<source>` container under each source enable row. `renderDiscoveryScanStatus(source, scan)` renders safe copy for all states. `renderDiscoveryScanDetails(source, partition)` displays source-scoped current routes, search, disposition filter, unfiltered counts, and reason. Source refresh calls existing POST, then polls GET for a new or in-progress attempt and its terminal state; stop polling when the modal closes.

- [ ] **Step 1: Write failing Playwright cases.** Fixture source GET scan metadata and admin discovered-apps data. Check completed/zero, failed-with-last-success, waiting/disabled, details search/filter, matched app/rule explanations, all-six-source placement, keyboard expansion, mobile wrapping, and a failed admin-data fetch showing Unavailable instead of zero. Check that opening details makes no upstream or mutation request.
- [ ] **Step 2: Run `cd e2e && npx playwright test tests/admin.spec.ts -g 'discovery diagnostics'`; expect failure.**
- [ ] **Step 3: Add the inline markup and CSS.** Match existing Settings row/card styles, use real buttons and `aria-expanded`/labels, and escape every route name, URL, and reason. Do not change source configuration controls.
- [ ] **Step 4: Render scan states and current route dispositions.** Re-render when source status, catalog, discovered routes, override, dismissal, or rule data changes. On manual refresh, capture the previous attempt timestamp, show local “Refresh requested,” and wait for a newer attempt before accepting a terminal result; coalesced refresh may use the in-progress attempt. Bound polling to the open modal and end with a retry message on timeout.
- [ ] **Step 5: Run focused and full Playwright admin tests; expect PASS.**
- [ ] **Step 6: Commit.** Commit UI and tests with `feat: show inline discovery diagnostics`.

### Task 8: Documentation and final verification

**Files:** Modify `README.md`; optionally add a focused entry to `CHANGELOG.md` when preparing the eventual release.

**Interfaces:** Explain statuses, last successful counts, process restart reset, current-route dispositions, and the limit that a route absent from the last successful scan has no inferred cause.

- [ ] **Step 1: Update README beside App Discovery instructions.** Keep examples free of credentials and distinguish source test from a completed scan.
- [ ] **Step 2: Run `git diff --check`, `go test ./internal/server ./internal/discovery ./internal/handlers`, and `cd e2e && npx playwright test tests/admin.spec.ts`; expect clean diff and all tests PASS.** Use the CGO-capable environment noted above for Go.
- [ ] **Step 3: Review the complete branch against the spec, including error redaction, data freshness, and accessible mobile layout; fix findings and repeat only affected tests.**
- [ ] **Step 4: Commit.** Commit README and any final fixes with `docs: explain discovery diagnostics`.

## Execution handoff

This branch must receive an independent code, security, and usability review before merge. Prepare a PR after implementation and green verification. Release and production deployment are later decisions, with their own backup, digest, health, database, and browser checks.
