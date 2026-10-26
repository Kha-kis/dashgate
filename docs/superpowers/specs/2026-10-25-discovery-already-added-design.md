# Discovery routes already on the dashboard

## Intent

The live v1.5.7 inbox contains 53 actionable routes, 29 of which have the same navigation URL as an app already on the dashboard. Keep new candidates visible without asking admins to dismiss known apps one by one.

## Behavior

- Move an unconfigured discovered route whose URL matches a published app into a collapsed **Already added** section in Admin > Content. Show its discovered name, source, URL, and matching dashboard app name. The section uses the existing search and source filters.
- Compute matches from current published manual apps and published discovered apps. Do not persist a dismissal or create an override. If the published app is removed or its URL changes, the route returns to the inbox on refresh.
- Compare absolute HTTP(S) URLs after standard URL parsing. Scheme, host, effective port, path, and query must match. Preserve meaningful path case and non-root trailing slashes. Invalid and non-HTTP(S) URLs never match.
- Leave Hidden discovered overrides in the actionable inbox. Apply manual dismissal and ignore rules before the Already added grouping. Published apps, access groups, visibility, and discovery source settings are unchanged.
- The inbox badge and bulk selection count only actionable routes. Already added entries have no Configure or Dismiss control in their collapsed section.

## Approaches

1. **Chosen: separate Already added section.** Clears known apps from triage while keeping them inspectable and reversible by data changes.
2. Hide exact matches silently. Simpler UI, but admins lose a way to inspect why a discovered route disappeared.
3. Keep all matches in the inbox and bulk dismiss. No product change, but requires repeated manual work and persisted dismissals.

## Verification

Use browser tests with a published manual app, a matching discovered route, a unique route, a near match, and a Hidden override. Verify search/filter, app removal, and no effect on dashboard links or discovery rule matches.
