# Security remediation — October 13, 2026

## Authentication changes

- Node backs off failed JWKS downloads for the configured cooldown, covering network, HTTP, JSON, and JWKS structure errors. Fresh matching keys remain usable during backoff. Concurrent failed lookups share the download; requests resume downloading after backoff expires.
- PHP reads atomically published snapshots without taking the refresh lock. A separate lock coordinates downloads across processes. Fresh matching keys remain usable while an unknown-key refresh is stalled or fails. Snapshot and lock files use private permissions.
- Node, PHP, and Python reject unsupported `crit` headers and invalid `b64` values. Node and PHP validate protected headers before fetching keys. Node also rejects trailing token newlines and reports malformed headers as unauthorized.
- Python now requires the reviewed PyJWT 2.15.1 release or newer within the 2.x series.
- Shared signed fixtures cover critical headers, unencoded payload flags, and absent/invalid key IDs. Regression checks cover download failures, failure recovery, warm-cache availability, and cross-process PHP behavior.

Restart all PHP workers together when upgrading from the old cache implementation. Existing cached JSON snapshots remain readable, but mixed versions use different refresh locks. Older release tags precede these authentication changes; deploy a revision incorporating this remediation.

## Verification

| Check | Result |
| --- | --- |
| Node 26.11 / Express tests and example type checking | 47 tests passed; type checking passed |
| Minimum supported Node 22.12 in a clean Linux container | 47 tests passed; type checking passed |
| PHP 8.1 in an isolated container | 41 checks passed, including concurrent workers and warm-cache access during stalled refresh |
| Python 3.13 against the updated source | 46 tests passed |
| npm resolved dependency audit | No known advisories |
| Composer locked production dependency audit | No advisories or abandoned packages |
| Python isolated dependency environment audit | No known advisories; local unpublished package reviewed manually |
| Publication source secret scan | No findings after a narrow synthetic-fixture exception |

CI now runs npm and Python dependency audits alongside the existing Composer audit, and scans full Git history with a digest-pinned [Gitleaks image](https://github.com/gitleaks/gitleaks). The only scanner exception applies to JWT findings in the generated synthetic fixture file. Private-key and other rules remain active there.

## Repository privacy cleanup

The private account email appeared in author/committer metadata on five original commits, with no occurrences in historical tracked file contents. The annotated release tag also requires tagger metadata sanitization. Future local commits use the repository owner's existing GitHub noreply address.

The initial history scan flagged 25 synthetic fixture JWTs and two public sample private keys in the dependency's README. No live authentication credentials were identified. One historical commit also accidentally included installed dependencies and generated release artifacts. Cleanup removes `node_modules/`, `vendor/`, `php/vendor/`, `dist/`, and `.artifacts/` from versioned history while keeping source and lockfiles.

Local history cleanup is complete. All locally stored Git commit, tag, and blob objects were checked for the private address, with zero matches. The tested current source tree was preserved exactly. Generated dependency/build paths are absent from every historical commit, and the sanitized full-history Gitleaks scan reports no findings. Both published branches (`main`, `codex/identity-only-php-v0.3.0`) and release tags (`v0.2.0`, `v0.3.0`) were atomically updated on GitHub with exact expected-ref checks.

Remote verification identified one remaining GitHub-owned reference: `refs/pull/1/head` still points to the original pre-cleanup Python commit, which contains the private author/committer email. This read-only reference cannot be rewritten or deleted through a normal Git push. The cleanup is therefore complete for writable branches/tags, but the private metadata is not fully erased from GitHub. GitHub-side removal or a fresh repository is required before claiming complete public-history privacy; GitHub Support decides whether it will remove personal metadata. No support request was sent automatically.

Rewriting published history changes commit and tag identifiers. Existing consumers must update their pinned revisions, and existing clones should be replaced or carefully reset to the sanitized history. Old copies, forks, pull-request refs, and cached GitHub commit pages cannot be erased by a branch/tag push alone. See [GitHub's history-removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## Remaining acceptance scope

No deployment or live Cloudflare account was available. Origin isolation, actual Access admission/logout, application route coverage, resource authorization, and CSRF protections still require deployment-specific verification. Passing these checks does not certify an arbitrary consuming application.
