# Discovery inbox dismissal

## Intent

Admins need to clear routes such as webhooks and health checks from the discovered-app inbox so new dashboard candidates are easier to find. Dismissal persists across discovery scans and can be undone.

## Goals and boundaries

- Add **Dismiss** to each inbox entry and to the existing bulk selection bar.
- Keep dismissed entries in a collapsed **Ignored** section with a **Restore** control. Include entries whose discovery source no longer reports them so an admin can still remove the ignore rule.
- Count only actionable, non-ignored entries in the inbox badge. Keep search and source filtering on the actionable list.
- Keep the current dashboard publication and Hidden behavior. Dismissal is inbox triage; it does not publish an app or change who can see one.
- Limit dismissal to currently discovered entries that are unconfigured or Hidden. Preserve configured, visible entries and their overrides.
- Do not infer which routes should be ignored automatically in this change.

## Approaches

1. **Chosen: separate persistent Ignored list.** Store a source/URL pair and a display-name snapshot in its own SQLite table. This makes dismissal independent of the existing app override and Hidden fields. It requires one new admin API action and an inbox section.
2. **Alternative: add dismissal to overrides.** This reuses persistence and some APIs, but mixes inbox triage with publication settings and would require a migration and careful changes to existing override consumers.

## Behavior and data flow

1. Create `ignored_discovered_apps` with `(source, url)` as the primary key, `name`, and `created_at`. The source/URL pair prevents dismissing the same URL from an unrelated discovery source. Existing databases gain the table through `CREATE TABLE IF NOT EXISTS` on startup.
2. Extend `GET /api/admin/discovered-apps` with an `ignored` list while preserving `active` and `stale`. The active discovery data still drives dashboard access checks; the admin UI removes ignored pairs from its inbox display.
3. Add an admin-only action endpoint for batch `dismiss` and `restore` of source/URL pairs. Dismiss checks every pair against current discovery data, rejects configured visible entries, caps the batch at 100, and saves the batch atomically. Restore removes saved pairs and is safe to repeat. Existing CSRF middleware applies.
4. The UI sends an action only after an admin clicks Dismiss or Restore. It reloads the lists after success and leaves them visible with an error message on failure. The Ignored section shows the saved name and source and marks entries that are no longer discovered.

## Verification

- Database and handler tests cover persistence after reload, source/URL identity, rejected configured entries, atomic bulk failure, and restoration.
- Browser coverage checks individual dismissal, bulk dismissal, inbox count, restore, and an unchanged published app.
- Run Go tests, vet, build, end-to-end tests, code/security review, and exact-head CI before considering a release.
