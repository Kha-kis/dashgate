# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.7] - 2026-02-05

### Added
- **Unraid discovery** — discover Docker containers from Unraid 7.2+ via GraphQL API with `x-api-key` authentication
- **Unraid CA template support** — handle `[IP]` and `[PORT:default]` placeholders in WebUI URLs, resolve relative icon paths against Unraid server
- **Unraid connection testing** — test API connectivity and view container count from admin UI

## [1.0.6] - 2026-02-05

### Added
- **Multi-select bulk configure for discovered apps** — select multiple discovered apps via checkboxes and configure category and groups in a single operation (#6)

## [1.0.5] - 2026-02-05

### Fixed
- **Discovered apps health checks** — discovered apps now included in health checks, showing online/offline status instead of "unknown" (#4)

## [1.0.4] - 2026-02-05

### Fixed
- **Discovered app URL Override field** — removed misleading asterisk from optional field, clarified it uses discovered URL if left blank (#4)
- **Icon selector modal z-index** — icon picker now appears above discovered app modal instead of behind it (#4)
- **Docker discovery log message** — now shows container count when no apps found (e.g., "found 15 containers, 0 with dashgate.enable=true label") (#5)

### Changed
- Service worker cache version bumped to v7

## [1.0.3] - 2026-02-04

### Added
- **Nginx discovery filtering** — skip noisy paths (auth endpoints, API sub-paths, websocket routes, static assets, health checks) and regex-based location patterns
- **Nginx discovery deduplication** — sub-paths of already-discovered apps are filtered out per host
- **Docker socket proxy support** — documented TCP-based socket proxy setup for improved security

### Fixed
- **NPM discovery type mismatch** — handle `ssl_forced` and `enabled` fields returned as numbers (0/1) instead of booleans (#4)
- **Docker socket permission denied** — entrypoint auto-detects socket group and adds user to it (#4)

## [1.0.2] - 2026-02-04

### Added
- **PUID/PGID support** — container user ID can be configured via environment variables for NAS compatibility (Unraid, TrueNAS) (#2)
- **COOKIE_SECURE environment variable** — override secure cookie setting without admin access

### Fixed
- **Login not working behind reverse proxy** — auto-detect HTTPS via `X-Forwarded-Proto` header for proper cookie Secure flag (#3)
- **Permission denied on /config** — entrypoint now adjusts file ownership to match PUID/PGID (#2)

## [1.0.1] - 2026-01-30

### Added
- **Nginx location block discovery** — apps defined as `location /app { proxy_pass ...; }` within server blocks are now discovered, not just standalone server blocks
- **Nginx include inlining** — `include` directives (including glob patterns like `/etc/nginx/apps/*.conf`) are resolved and parsed recursively (depth-limited to 3)
- **Extensionless config file support** — Nginx `sites-enabled/` files without `.conf` extension are now processed
- **Icon persistence** — uploaded icons now stored in `/config/icons/` (persistent volume) instead of inside the container; bundled icons seeded on first run

### Changed
- Branding files (favicon, PWA icons) moved from `static/icons/` to `static/branding/` — no longer appear in admin icon picker
- `ICONS_PATH` default changed from `/app/static/icons` to `/config/icons`
- Service worker cache version bumped to v5
- Discovery stop functions use explicit lock management instead of fragile defer pattern (all 5 modules)
- Nginx config regexes compiled once at package level instead of per-cycle
- Comment-aware brace counting in Nginx config parser
- Included config file size capped at 1 MB
- Panic recovery in discovery goroutines now logs stack traces

### Fixed
- Health check falls back to GET when HEAD returns non-success (fixes false "offline" for apps like File Browser that don't handle HEAD)
- File descriptor leak in `neuteredFileSystem` directory index check
- Double-unlock risk in all discovery Stop functions (nginx, docker, traefik, caddy, npm)
- Nginx comments containing braces no longer corrupt block extraction
- Include error messages no longer leak filesystem paths
- Docker build now strips `v` prefix from version tag
- Custom icons in `/config/icons/` now take priority over bundled icons with cascading fallback (#1)

### Security
- Symlinks skipped during icon seeding to prevent sensitive file exposure

## [1.0.0] - 2025-01-30

Initial public release.

### Authentication

- Multi-method authentication with simultaneous provider support
- Local user accounts with bcrypt password hashing (SHA-256 pre-hash for >72 byte passwords)
- LDAP/Active Directory authentication with configurable filters, attribute mappings, and StartTLS
- OIDC/OAuth2 flow with configurable scopes, groups claim, and automatic user provisioning
- Proxy header authentication (Authelia/Authentik) with trusted proxy IP validation
- API key authentication with bcrypt-hashed keys, prefix lookup, expiration, and usage tracking
- Configurable session duration with HttpOnly/Secure/SameSite cookies
- Session fixation prevention — existing sessions invalidated on new login
- First-time setup wizard for guided auth provider configuration

### DashGate

- Category-based app organization with YAML or UI-based configuration
- Group-based access control — users only see apps their groups permit
- Real-time health status indicators (online/offline/unknown) via background checks
- Service dependency graph with forward and reverse dependency tracking
- Per-user theme preferences (light/dark mode, accent colors)
- Progressive Web App with service worker, offline page, and install support
- Self-hosted Inter font family (no external CDN)

### Admin Panel

- App catalog CRUD — add, edit, delete apps and categories from the UI
- Custom icon upload with file type validation and SVG XSS scanning
- Local user management — create, update, delete users and reset passwords
- API key management with scoped permissions and optional expiration
- System configuration editor for auth, session, and proxy settings
- LLDAP directory browsing (read-only users and groups)
- Audit logging for all admin actions with IP tracking
- Backup and restore of system configuration and user data
- Discovered app override management (rename, re-icon, re-categorize, hide/show)

### App Discovery

- Docker container discovery via socket API with label-based metadata
- Traefik router discovery via API with basic auth support
- Nginx configuration file parsing for server blocks
- Nginx Proxy Manager proxy host discovery via API
- Caddy reverse proxy route discovery via admin API
- Unraid Docker container discovery via GraphQL API
- Per-source enable/disable, manual refresh, and connection testing
- Override system for customizing discovered app display and access

### Security

- Content Security Policy with per-request nonces for inline scripts
- CSRF protection via double-submit cookie with constant-time comparison
- Per-IP rate limiting on login endpoints (configurable limit and window)
- Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- AES-256-GCM encryption at rest for sensitive config values (passwords, secrets)
- Encryption key management via environment variable or auto-generation
- Request body size limiting (1 MB) to prevent DoS
- URL scheme validation to block javascript: XSS in app URLs
- Directory listing disabled on static file server
- Open redirect prevention on login/OIDC callbacks
- Non-root Docker container (uid 1000)

### Infrastructure

- Embedded SQLite database with WAL mode, automatic schema creation, and migrations
- Graceful shutdown — all background goroutines (health checker, session cleanup, rate limiter) stop cleanly via context cancellation
- Panic recovery in all background goroutines
- Multi-stage Docker build with Alpine runtime (~9.5 MB image)
- Docker Compose configuration with volume mounts
- Background health checker with concurrent checks (semaphore-limited to 20)
- Periodic session cleanup (hourly)
- Configuration hierarchy: environment variables > database > YAML > defaults
- Version tracking via build-time ldflags injection
- End-to-end test suite (Playwright) covering auth, DashGate dashboard, admin, setup, and settings
- Encryption unit tests
- Windows build scripts (batch and PowerShell) with MSYS2/MinGW CGO support
