# Testing

Run `npm ci && npm run check`, `composer install && composer test`, and the Python suite as documented in readme.md. PHP tests cover signed fixtures, ambiguous headers, JWKS rotation/outages, safe diagnostics, and cross-process cache coordination. PHP tests require no FileGator classes or account database.

FileGator account, migration, HTTP and Chromium tests now live in the FileGator repository. Its external-auth guide describes their commands. Generated signed fixtures are test-only and are not Cloudflare credentials. Never deploy a fixture JWKS transport.

Live acceptance must use the real team domain, per-application AUD, admitted identity, and restricted origin. Verify rejected admission, local disabled-account rejection, current permissions, and actual edge logout separately from fixture tests.
