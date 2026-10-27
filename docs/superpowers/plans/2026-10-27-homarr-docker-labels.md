# Homarr Docker Label Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover Homarr-labeled Docker routes in DashGate's existing admin inbox.

**Architecture:** Extend `dockerContainerApp` with a Homarr branch between explicit DashGate labels and Homepage fallback. Reuse Docker scanning and discovered-app review without changing storage or publication.

**Tech Stack:** Go 1.24 module, vanilla HTML, Markdown; Go tests use CGO.

**Spec:** `docs/superpowers/specs/2026-10-27-homarr-docker-labels-design.md`

## Global Constraints

- Read only `homarr.name`, `homarr.href`, and `homarr.description` into app metadata.
- Preserve explicit `dashgate.enable` precedence and existing Homepage fallback.
- Never publish discovered routes or probe unreviewed URLs.

## Review Focus

- Missing `homarr.href`: skip the Homarr entry without falling back to Homepage when `homarr.name` is present.
- URL userinfo or non-HTTP(S) scheme: skip before discovery.
- `homarr.hide` present with an empty value: skip the Homarr entry.
- Mixed Homarr/Homepage metadata: never combine fields or create two routes.
- Homarr group, board, icon, ping, integration, and widget labels: never alter DashGate access, trigger requests, or enter app fields.

---

### Task 1: Docker label mapping

**Files:** Modify `internal/discovery/docker.go`; modify `internal/discovery/docker_labels_test.go`; modify the Docker scan integration test in `internal/discovery/scan_reporting_api_test.go` or add one in `internal/discovery` if that fixture is unsuitable.

**Interfaces:** `dockerContainerApp(models.DockerContainer) *models.App` keeps its signature and returns at most one app. The Homarr branch is selected by presence of `homarr.name` after explicit DashGate labels.

- [x] Add table cases with literal expected name, URL, description, status, empty groups and icon: Homarr-only; Homarr-over-Homepage; DashGate-over-Homarr; DashGate-disabled; incomplete Homarr; malformed URL; `homarr.hide` with empty value; Homepage fallback when Homarr name is absent; ignored Homarr metadata.
- [x] Run `go test ./internal/discovery -run TestDockerHomarrLabels -count=1` and confirm missing Homarr behavior fails.
- [x] Implement the minimal Homarr branch and shared URL validation as needed, leaving DashGate behavior intact.
- [x] Run focused discovery tests and then `go test ./... -count=1`; confirm green.
- [x] Add a scan-level case proving Homarr metadata reaches the Docker source. The mapper cases already failed on the baseline; this supplementary scan case exercises the existing Docker pipeline.
- [x] Commit code and tests.

### Task 2: Documentation and final validation

**Files:** Modify `README.md`; modify Docker discovery settings hint in `templates/index.html`; keep this plan current.

**Interfaces:** No API change. Admins continue to configure category, icon, and access groups before publication.

- [x] Document example Homarr labels, precedence, hide behavior, ignored fields, and review step in README and settings hint.
- [x] Run the discovery inbox Playwright check, `go test ./... -count=1`, and `gofmt` verification.
- [x] Review security, code behavior, and usability against the spec and address material findings; the fresh review found no actionable issues.
- [x] Commit documentation and verified fixes; open PR #39 and confirm Build & Test, E2E Tests, and Docker Build & Push all passed.
