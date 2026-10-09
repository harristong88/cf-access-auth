# Security and compatibility notes

## Trust boundary

Cloudflare Access controls admission and authenticates Google identities. The module verifies the signed application assertion at the origin and binds it to an app-local account. Only the app assigns roles, home directories, and permissions. Neither a valid email header nor a pre-existing local session bypasses verification.

Keep origins inaccessible except through the intended tunnel; local JWT verification does not check Cloudflare's current revocation list. A stolen, still-valid JWT could otherwise be replayed directly against an exposed origin. Revocation/logout is enforced at the edge, with the propagation behavior documented by Cloudflare. This library cannot promise instantaneous revocation of a cryptographically valid JWT offline.

Use the real per-app AUD. Configuring the same audience across unrelated apps intentionally widens the accepted token scope. Do not pass browser-controlled issuer/AUD configuration. Team domains are restricted to HTTPS `*.cloudflareaccess.com` origins; custom issuer hosts are outside v1.

The middleware protects only paths mounted beneath it. WebSocket handshakes, background jobs, CLI clients, and non-browser service-token access need their own deliberate integration. Long-lived connections do not receive a new HTTP authentication check for every message. This v1 is designed for human HTTP requests.

## Application responsibilities

Keep existing resource authorization, CSRF defenses, and secure session cookies. JWT verification is not CSRF protection. Replacing login must also remove registration, password reset, alternate API sessions, and any unguarded handlers in your own app; the examples demonstrate the relevant integration but cannot discover those paths in repositories not supplied here.

The Express SQLite store is an app-owned runnable example. The PHP verifier owns no accounts: each consumer must resolve identities transactionally in its own account repository, retain disabled-account bindings, and control role/home assignment. FileGator's implementation and migration tools live in its repository.

PHP sees the headers your web server exposes. Duplicate values that are preserved as arrays or joined with commas are rejected. Configure upstream proxies/web servers to reject duplicate assertion headers rather than silently discard all but one; a PHP application cannot reconstruct headers discarded before it receives a request. Express checks Node's original `rawHeaders` as well.

Restrict write access to PHP cache/database directories and the storage root to the app OS user. Do not allow users to replace directory ancestors while homes are being provisioned. FileGator and its filesystem adapter still own containment/security for uploaded files and archives. Symlink/traversal checks in home provisioning do not replace auditing the file manager itself.

## Pinned upstream dependency findings

On 2026-10-08, the module's own npm and Composer dependency audits passed. The deliberately pinned FileGator v7.16.5 dependency tree had four production Composer advisories across three existing packages:

- `symfony/http-foundation`: CVE-2025-64500 and CVE-2024-50345.
- `symfony/polyfill-intl-idn`: CVE-2026-46644.
- `league/flysystem`: CVE-2026-102601.

Its locked frontend/build dependency tree also reported 191 npm advisories (including transitive build dependencies). These belong to the upstream baseline, not the new verifier dependency. This integration does not upgrade FileGator's framework or storage stack. Review/update your fork's dependencies before production use; Cloudflare authentication does not remediate those advisories.

The module uses PHP-JWT 7.2+ instead of the vulnerable 6.x line. Dependency lockfiles are included for reproducible module development; consumers retain their own resolved lockfiles.
