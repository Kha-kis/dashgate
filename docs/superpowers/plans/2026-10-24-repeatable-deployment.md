# Repeatable Compose Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give DashGate operators a checked, repeatable Compose upgrade with a verified backup and explicit rollback path.

**Architecture:** A standard-library Python script runs on the Linux Docker host and accepts explicit paths and digest-pinned image references. A runbook describes transfer, invocation, browser smoke checks, and manual recovery.

**Tech Stack:** Python 3 standard library, Docker Compose CLI, SQLite.

**Spec:** `docs/superpowers/specs/2026-10-24-repeatable-deployment.md`

## Global Constraints

- Preserve the entire data directory, Compose file, and `.env` without logging their contents.
- Keep the database backup consistent with a live SQLite WAL database.
- Require an exact expected image pin and target digest; never edit a different service or restart dependencies.
- Do not automatically roll back a container after it may have migrated the database.
- Do not run the new script on production during implementation.

## Review Focus

- A current image mismatch must fail before a backup or Compose write.
- A live WAL database snapshot must pass SQLite quick check and contain committed data.
- A Compose validation failure after editing must restore the original file.
- A failed health/version check must retain the backup and clearly report recovery information.
- The script must never print `.env`, config, or database contents.

### Task 1: Script and safety tests

**Files:** Create `scripts/deploy_compose.py`, `scripts/test_deploy_compose.py`.

- [ ] Write failing tests for image validation, WAL snapshot, exact Compose replacement, one-service rollout, and post-start failure behavior.
- [ ] Run the tests and confirm the expected failures.
- [ ] Implement preflight, backup, rollout, and verification as small testable functions; use Python's `sqlite3.backup` and atomic file replacement.
- [ ] Rerun the focused suite and Python syntax check.
- [ ] Commit the script and tests.

### Task 2: Operator runbook

**Files:** Create `docs/deployment.md`; modify `README.md` to link it.

- [ ] Document digest lookup, host prerequisites, secure script transfer, preflight, deployment, browser smoke, and manual rollback from the saved backup.
- [ ] Check commands against the script interface and run `git diff --check`.
- [ ] Commit the documentation.

### Task 3: Final review and delivery

**Files:** No product changes unless review finds an issue.

- [ ] Run the complete new script test suite and syntax check; inspect the final diff.
- [ ] Obtain an independent code/data-safety review and resolve actionable findings.
- [ ] Push a PR and verify its exact-head CI; do not run the new script on production.
