# Distribution

The Git repository contains independent npm, Composer, and Python packages. PHP v0.3.0 is an identity-only release. Node and Python APIs are unchanged.

The October 13, 2026 security hardening is on `main` and is described in [remediation results](security-remediation-2026-10-13.md). Existing `v0.2.0` and `v0.3.0` tags have sanitized identities but retain their historical source behavior. Publish a patched release containing the hardening before recommending those packages for new production deployments.

## Composer consumer

Add a VCS repository for `https://github.com/harristong88/cf-access-auth.git` to the consumer's composer.json, then run `composer require cf-access/auth:0.3.0`. Commit composer.lock, which records the selected release commit. Deploy with `composer install --no-dev --prefer-dist`.

For coordinated development, use a temporary Composer path repository with `options.symlink=false`. Replace it with the released Git version before deployment; production must not depend on a sibling checkout.

`composer archive --format=zip` creates a standalone PHP distribution. Verify it in a clean consumer without development dependencies. The archive excludes other language sources, fixtures, test transports, and vendor directories.

For npm, run `npm ci && npm pack`. For Python, install the `python/` package from an immutable release commit. Each consumer retains its own lockfile.
