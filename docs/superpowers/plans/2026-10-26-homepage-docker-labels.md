# Homepage Docker Label Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover Homepage-labeled Docker routes in DashGate's existing admin inbox.

**Architecture:** Extend the Docker container-to-app mapping with a Homepage fallback only when `dashgate.enable` is absent. Reuse Docker scanning and discovered-app review.

**Tech Stack:** Go 1.24 module, vanilla HTML, Markdown; Go tests run with CGO.

**Spec:** `docs/superpowers/specs/2026-10-26-homepage-docker-labels-design.md`

## Tasks

- [x] Add failing unit cases for Homepage labels, precedence, link validation, and access-group isolation.
- [x] Add the Docker mapping fallback and preserve DashGate label behavior.
- [x] Cover Homepage labels in the Docker scan integration test.
- [x] Explain supported labels in README and Admin → Discovery.
- [x] Format Go code and run focused and full tests.
- [x] Review the change for code, security, and usability regressions; address findings.
- [x] Create a PR and verify CI.
