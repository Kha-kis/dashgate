# Discovery ignore rules

## Intent

Admins already dismiss individual discovered routes by source and URL. Repeated webhook, health, and similar routes from the same source still need manual dismissal. Add optional rules that remove matching routes from the admin inbox now and on later scans, with a preview before saving.

This is a DashGate product feature. It does not configure external discovery sources, host monitoring, backups, or deployment.

## Goals and boundaries

- An admin can create, edit, disable, enable, and delete a rule for one discovery source, one HTTP(S) origin, and one path prefix.
- A preview lists currently discovered inbox routes the proposed rule would remove and reports a count. It states that future routes can also match.
- Active rules affect only inbox triage. They never publish, hide, modify, or revoke access to a configured visible app.
- Manual Dismiss and Restore keep their existing separate, persistent source/URL entries. Disabling or deleting a rule returns its matching routes to the inbox unless they are also manually dismissed or covered by another active rule.
- The inbox badge counts actionable routes after manual dismissals and active rules. Search and source filters work on the remaining inbox and on rule-matched routes.
- No rule is inferred or enabled automatically. Existing installs have no rules and retain current behavior.

Non-goals: a new discovery provider, free-form regular expressions, domain-wide root rules, alerts, changes to dashboard visibility, and changes to the source scan schedule.

## Approaches

1. **Chosen: live rules separate from manual dismissals.** Store rule definitions in a new table and evaluate them against each current discovery result. The preview and inbox use the same server-side matcher. Rules naturally cover future routes and disappear cleanly when disabled. This adds a small matching layer and an admin management surface.
2. **Alternative: bulk-create manual dismissals from a preview.** Reuses the current table and API, but new routes would reappear after each scan; it does not solve repeated triage.
3. **Alternative: source-wide regular expressions.** More flexible, but harder to preview or reason about and easier to over-match. It is unnecessary for the observed webhook/health path use case.

The other direction considered was adding another discovery source. DashGate already supports Docker, Traefik, Nginx, NPM, Caddy, and Unraid; no missing source was identified. A new provider would add credential and maintenance work without addressing repeated inbox triage.

## Rule identity and matching

- A rule stores a generated ID, source, normalized HTTP(S) origin, path prefix, enabled flag, and created/updated timestamps. The source must be one of DashGate's six known discovery sources.
- Origin includes scheme, hostname, and effective port. Scheme and hostname compare case-insensitively; port compares exactly after normalizing default HTTP(S) ports. Userinfo, query, and fragment are not accepted in rule input.
- Path prefixes begin with `/`, contain at least one non-empty segment, and match whole segments: `/health` matches `/health` and `/health/live`, but not `/healthz`. Path matching is case-sensitive. Query and fragment on discovered URLs do not affect matching. Invalid discovered URLs do not match.
- V1 excludes the root prefix `/` to prevent accidentally clearing an entire origin. Rule input is length-bounded, duplicate source/origin/prefix rules are rejected, and the table has a bounded rule count.
- Matching uses URL parsing only; creating or previewing a rule never makes a network request to its origin.
- A rule applies only when the currently discovered route is unconfigured or has a Hidden override. A visible configured app is always excluded, even if its URL matches. The server computes and returns rule matches; the browser does not independently decide what a rule matches.

## API and persistence

- Add `discovery_ignore_rules` through `CREATE TABLE IF NOT EXISTS` on startup; no existing data is migrated or removed.
- Add admin-only rule list/create/update/delete endpoints and an admin-only preview endpoint. Writes use existing CSRF protection; request bodies are bounded and reject unknown fields. Preview validates the unsaved rule and returns a bounded list of current actionable matches plus the full count.
- Extend `GET /api/admin/discovered-apps` with `ignoreRules` and `ruleMatches` while preserving `active`, `stale`, and `ignored`. Each rule match identifies source, URL, and matching rule ID. If multiple rules match, the route appears once in the response, with a stable matching rule ID for display.
- The server computes previews and saved-rule matches with the same function. A preview is a current snapshot, not a guarantee that a later scan has the same routes.
- Database failures return an error rather than an empty inbox or a success message. Rule writes are atomic.

## Admin experience

- Add an **Ignore rules** section beside the inbox and existing **Ignored** list. Show each rule's source, origin/path prefix, enabled state, and current match count. Include edit, enable/disable, and delete controls.
- An admin can start a rule from an inbox route, which pre-fills its source, origin, and path prefix, or create one manually. The editor previews matches before Save becomes available. Editing a rule invalidates the old preview and requires a new one.
- Preview shows route name, source, and URL for currently actionable matches, plus a note that future routes may match. An empty preview can still be saved to cover future routes.
- Rule-matched routes remain inspectable in a collapsed section with their matching rule and a direct route to edit or disable it. Manual ignored entries remain in the existing section with their existing Restore action. If a route is both manually dismissed and rule-matched, restoring its manual dismissal leaves it matched by the rule and the UI explains that.
- Loading or write failures keep the current list and show a clear error; controls do not claim success until the server confirms it.

## Verification and release boundary

- Unit and database tests cover origin/port normalization, segment boundaries, case behavior, query handling, invalid input, duplicate and limit rejection, future-route matching, overlapping rules, manual dismissal precedence, and unchanged visible configured apps.
- Handler tests cover admin-only access, CSRF integration, bounded payloads, preview/save consistency, atomic writes, and database errors.
- Browser tests cover creating from a route, previewing, saving, rule-matched inspection, disabling/re-enabling, deleting, filtering, and manual Restore interaction.
- Run Go tests/vet/build, relevant Playwright tests, code and security review, and exact-head CI. Update the product README and changelog. Release and deployment decisions follow only after the feature is reviewed and verified.
