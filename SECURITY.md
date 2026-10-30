# Security Policy

## Supported Versions

Security fixes are targeted at the latest release. Upgrade to the newest published version before reporting a problem that may already be fixed.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities by emailing the maintainer or using [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) feature on this repository.

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgment within 72 hours. A fix will be developed privately and released as a patch version as soon as possible.

## Security Architecture

This application handles authentication credentials and session management. The following security measures are in place:

### Authentication & Sessions

- Passwords hashed with bcrypt (SHA-256 pre-hash for inputs exceeding 72 bytes)
- Cryptographic session tokens (32 bytes, hex-encoded)
- Session fixation prevention — old sessions invalidated on login
- HttpOnly, Secure, and SameSite cookie attributes
- Per-IP rate limiting on login endpoints

### Encryption

- Sensitive configuration values (LDAP passwords, OIDC client secrets, discovery credentials) are encrypted at rest with AES-256-GCM
- Encryption key can be provided via `ENCRYPTION_KEY` environment variable or is auto-generated and stored in the database
- For production deployments, providing a stable key via environment variable is recommended

### Request Protection

- CSRF protection using double-submit cookie pattern with constant-time comparison
- Content Security Policy with per-request nonces
- HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy headers
- 1 MB request body size limit
- URL validation to prevent open redirects and javascript: XSS
- SVG upload scanning for embedded scripts

### Proxy Authentication

- Proxy auth headers (`Remote-User`, `Remote-Groups`) are only accepted from configured trusted proxy IPs/CIDRs
- Requests from untrusted IPs with proxy headers are rejected and logged

## Production Recommendations

1. **Use HTTPS** — deploy behind a TLS-terminating reverse proxy
2. **Set `ENCRYPTION_KEY`** — provide a stable 64-character hex key via environment variable rather than relying on auto-generation (`openssl rand -hex 32`)
3. **Configure trusted proxies** — if using proxy auth, restrict accepted IPs to your reverse proxy
4. **Set `COOKIE_SECURE=true`** — ensure session cookies require HTTPS (default)
5. **Review audit logs** — monitor the `/api/admin/audit-log` endpoint
6. **Restrict Docker API access** — prefer a socket proxy limited to the API sections and methods discovery needs. A `:ro` bind mount of `/var/run/docker.sock` does not make Docker API access read-only; anyone who can connect to the socket may gain broad daemon privileges. See the [Docker discovery setup](README.md#docker).
7. **Use strong passwords** — enforce passwords well above the 8-character minimum
8. **Keep updated** — apply security patches promptly
