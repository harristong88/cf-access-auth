# Implementation validation — 2026-10-08

Completed locally:

- 35 Node checks passed on Node 22.12.0 in Docker and Node 26.11.0 on the host, including TypeScript compilation, Express guards, shared JWT cases, key rotation/outages, and concurrent SQLite first logins. SQLite is explicitly enabled for Node 22.12.
- 38 PHP checks passed on PHP 8.1 and 8.5 in Docker, including the real FileGator `AuthInterface`, shared token cases, persistent key caching, six-worker coalescing/provisioning, account linking and tombstones, safe homes, and read-only migration checks.
- The v7.16.5 patch applies cleanly against the exact pinned release files.
- Patched FileGator frontend production build passed. Chromium and HTTP checks passed for startup, password-free UI, admin creation, uploads/downloads, private homes, identity/CSRF/session changes, batch archive isolation, partial-upload isolation, and logout navigation.
- A clean Node consumer installed the npm tarball and verified the shared signed fixture without repository development dependencies.
- A clean Composer consumer installed the PHP ZIP and verified identity, migration bin proxies, applied import, and account disabling. The final ZIP excludes development vendor files and test transports.
- Composer manifest validation passed. The module's npm and Composer dependency audits reported no advisories; pinned FileGator dependency findings are recorded separately in `security.md`.

The Chromium logout test simulated the edge endpoint. Live Google login, Access policy enforcement, real Cloudflare JWKS transport, real logout propagation, production deployment, and integration into the user's unavailable app/fork were not exercised. Follow `testing.md` for those acceptance checks.

CI is configured for Node 22.12/24, PHP 8.1/8.3/8.5, and the pinned FileGator browser flow. Remote GitHub Actions have not been run from this local implementation.
