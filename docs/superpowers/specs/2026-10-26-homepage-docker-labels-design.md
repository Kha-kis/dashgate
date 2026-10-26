# Homepage Docker label discovery design

## Intent

Admins who already enabled DashGate Docker discovery can review services labeled for Homepage without relabeling each container. This uses the existing Docker source, scan diagnostics, inbox, ignore rules, and Configure action. It does not publish a route automatically.

## Choice

Accept `homepage.name` plus an absolute HTTP(S) `homepage.href`, with optional `homepage.description`. This is a smaller integration than a new source or widget system and works with the Docker API access DashGate already has. A one-time Homepage YAML import already exists, but does not keep up with live Docker changes.

Explicit `dashgate.enable` takes precedence: `true` keeps current DashGate label parsing without mixing Homepage fields, and any other value excludes the container. Containers with no DashGate enable label may use Homepage labels. The Docker source identity and the existing route URL identity stay unchanged.

## Security and usability

- Reject incomplete Homepage labels, non-HTTP(S) links, missing hosts, and URL userinfo before they enter discovery.
- Do not map `homepage.group` to `App.Groups`: Homepage uses it for display, while DashGate uses groups to control access. Admins select DashGate category and access groups in Configure.
- Do not import `homepage.icon` because DashGate expects a local icon asset, or any `homepage.widget.*` data because it may contain credentials. Admins can select a local icon in Configure.
- Keep existing DashGate label behavior, including its group and dependency parsing. No configuration or database migration is needed.
- Update the Docker settings hint and README so the supported labels and review step are visible.

## Acceptance

Tests cover Homepage discovery through the Docker scan, explicit label precedence, disabled containers, malformed/incomplete Homepage links, and the separation of Homepage category and widget data from DashGate authorization fields. Full Go tests, formatting, and the relevant UI check must pass before proposing integration.
