# Homarr Docker label discovery design

## Intent

Admins who already use Homarr Docker labels should see those services in DashGate's existing discovery inbox without relabeling containers. DashGate's Docker source, scan status, inbox, ignore rules, and Configure action remain the review path. Discovery never publishes an app by itself.

## Approaches

- **Chosen: read basic Homarr labels in the existing Docker source.** This reuses the current scan and review flow, needs no new Docker access or database migration, and broadens compatibility for Homarr users.
- Suggest a DashGate category from Homepage's `group` label. This would reduce configuration effort for the just-added Homepage routes, but help only those routes and require a new suggestion field in the discovery API and UI.
- Add a separate Homarr API integration. This would require credentials, network access, and source configuration for data the existing Docker scan can already read.

## Behavior

- An explicit `dashgate.enable` label keeps its current precedence. `true` uses only DashGate labels; every other value excludes the container.
- When `dashgate.enable` is absent and `homarr.name` is present, use Homarr labels. Require a nonblank `homarr.name` and an absolute HTTP(S) `homarr.href` with a host and no URL userinfo. Copy only `homarr.name`, `homarr.href`, and optional `homarr.description` into the discovered route. A malformed or incomplete Homarr entry does not fall back to Homepage labels.
- The presence of `homarr.hide` excludes a Homarr-labeled entry regardless of its value. If `homarr.name` is absent, existing Homepage fallback behavior remains unchanged, including when unrelated `homarr.*` labels are present.
- For a container with valid Homarr and Homepage labels, Homarr wins. The route keeps source `docker` and its existing URL-based discovery identity. No extra app is produced from the same container.
- Ignore `homarr.group`, `homarr.board`, `homarr.icon`, `homarr.ping`, `homarr.id`, `homarr.integration`, `homarr.widget`, and any other Homarr labels. In particular, a board or group is not a DashGate access group, a ping address cannot trigger server-side requests, and an icon URL is not a DashGate local icon asset. The admin chooses category, icon, and access groups in Configure.

## Safety and usability

- Unreviewed discovered URLs remain excluded from DashGate's server-side health checker. Label values are rendered as data in the admin UI.
- The README and Docker discovery settings hint explain Homarr's supported fields, precedence, `homarr.hide`, and the Configure step.
- The existing Docker source enabled state, connection settings, scan interval, and publication behavior do not change.

## Acceptance

Test the Docker label mapper and scan with Homarr-only labels, Homarr/Homepage precedence, explicit DashGate enable and disable, missing or malformed Homarr fields, `homarr.hide` presence, and ignored metadata. Confirm unreviewed Homarr routes cause no health requests and remain safe when rendered in admin actions. Run the full Go suite and relevant UI checks before opening a PR.
