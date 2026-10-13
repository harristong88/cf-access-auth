# Testing

Run `npm ci && npm run check`, `composer install && composer test`, and the Python suite as documented in readme.md. PHP tests cover signed fixtures, ambiguous headers, JWKS rotation/outages, safe diagnostics, and cross-process cache coordination. PHP tests require no FileGator classes or account database.

Before changing verifier structure, preserve the existing fixture results, complete
identity shape, key-fetch counts, configuration boundaries, and native cache behavior.
`fixtures/README.md` describes the shared case metadata. The Node, PHP, and Python
runners all use it; native suites also record deliberate language differences.
Python expiry tests control the clock rather than changing private cache fields.

After moving runtime files, run the installed-package checks:

- Node: `npm run test:package` packs the library, installs it outside the checkout,
  checks the core without Express, then authenticates through Express 4 and 5.
- PHP: `composer test-package` archives the library and installs its extracted
  contents into a separate Composer consumer. This test needs the ZIP extension
  and Composer; ZIP is not a production verifier requirement.
- Python: install `build` and `wheel`, then run `python scripts/smoke-python-package.py`.
  It builds a wheel, creates a fresh environment, and verifies public imports and
  authentication without loading checkout classes.

These checks clean their temporary consumer directories and may download dependencies.
CI runs them in addition to the native suites. The Python checker must run with
Python 3.12+; source tests should run from `python/` or with `PYTHONPATH=python`.

FileGator account, migration, HTTP and Chromium tests now live in the FileGator repository. Its external-auth guide describes their commands. Generated signed fixtures are test-only and are not Cloudflare credentials. Never deploy a fixture JWKS transport.

Live acceptance must use the real team domain, per-application AUD, admitted identity, and restricted origin. Verify rejected admission, local disabled-account rejection, current permissions, and actual edge logout separately from fixture tests.
