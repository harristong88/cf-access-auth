# Shared verification contract

Generate `tokens.json` with `npm run fixtures`. Signing keys are generated in memory;
only synthetic assertions and public keys are saved. Never add production tokens.

Each case contains:

- `token`: the verifier input.
- `status`: the expected default outcome; 200 means a returned identity.
- `statuses`: optional overrides keyed by `node`, `php`, or `python`, recording
  existing language differences without silently changing them.
- `identity`: the complete expected result for successful cases. Python uses
  `expires_at` instead of the fixture's `expiresAt` spelling.
- `keyFetches`: expected download count on a new verifier. Header/syntax rejection
  cases must reject without fetching keys.
- `keySet`: an optional fixture key-document name; otherwise use `jwks`.

All three runners consume these expectations. Add rules to the generator rather
than maintaining separate case-name lists in language-specific tests. Stateful
cache, configuration, and framework tests stay in each native test suite.
