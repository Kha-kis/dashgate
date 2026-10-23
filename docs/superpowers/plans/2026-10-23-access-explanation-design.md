# Access explanation design

Admins can select a stored user and an app in Admin > Users to see whether that app appears on the user's dashboard and why. The result shows the user's stored groups, the app's effective groups, app source, matching group if any, and a plain-language reason. Stored groups from OIDC, LDAP, and proxy authentication are snapshots; the UI says so and never claims to inspect a live identity provider or token.

The explanation uses the dashboard's existing visibility rules. Configured apps with no effective groups are admin-only. Discovered apps need a saved override, cannot be hidden, and are visible to all when the override has no groups. Admins bypass group restrictions but do not bypass the discovered app's unpublished or hidden state. The tool is read-only and admin-only. It does not change memberships or visibility.

The first version covers users stored in DashGate's database and apps in the current configured or discovery catalog. It reports unavailable discovery entries as absent rather than guessing about an integration's unseen inventory. The README documents the differing empty-group rules.

## Approaches

- **Chosen: server-side explanation from saved user and app state.** Reuses DashGate's authoritative visibility rules, allows OIDC/LDAP/proxy snapshots, and keeps all decisions behind admin authentication.
- **Browser-only simulation.** Faster to build, but can drift from server behavior and cannot reliably identify saved user sources.
- **Identity-provider live lookup.** Would be more current for some users, but adds provider-specific privileges and cannot cover every authentication mode consistently.
