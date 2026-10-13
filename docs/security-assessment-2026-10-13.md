# Security assessment — October 13, 2026

Assessed the pre-remediation working tree, which was initially clean.

The findings below record the initial assessment. They were subsequently addressed; see [remediation results](security-remediation-2026-10-13.md) for current status and verification.

## Verdict and scope

No authentication bypass was found in the reviewed code or executed tests. The core uses a fixed Cloudflare key endpoint, restricts verification to RS256, checks issuer and audience, requires human application identity claims, and fails closed. Two availability weaknesses should be addressed before production sign-off. This assessment does not establish that a deployed application is secure: Cloudflare policies, tunnel/origin exposure, real logout/revocation, application authorization, and alternate application login routes were not available for inspection.

Reviewed Node core, Express middleware, Python verifier, PHP verifier/cache, Express account example, dependency manifests/lockfiles, CI, and existing security tests. Application code was not changed. PHP findings are based on source inspection; PHP execution was unavailable.

## Findings

### 1. Medium: Node retries failed JWKS downloads without failure backoff

Location: `src/index.ts:48–50`, delegating refresh to `jose`'s remote JWKS implementation.

The configured cooldown is based on the last **successful** download, not the last attempted download. If the key endpoint is unavailable, every sequential token verification can initiate another download. Concurrent in-flight requests are coalesced, but subsequent requests retry immediately. This also happens for attacker-chosen unknown key IDs once the last successful fetch is outside the cooldown window.

Evidence: with the default 30-second cooldown on a cold verifier, ten sequential requests caused ten failed downloads and ten 503 responses. In a warm-cache probe with a shortened 10ms cooldown, ten unsigned, attacker-chosen-key assertions caused ten failed downloads after the cooldown elapsed. A legitimate token still worked using its fresh cached key.

Impact: request traffic can amplify an upstream outage into repeated outbound requests and pending request load. Exploitation requires requests to reach the verifier, such as through a directly reachable origin or another integration accepting raw assertions. Cloudflare edge admission can reduce this exposure. This does not bypass authentication.

Recommendation: add failure backoff keyed to the configured issuer, including cold/expired-cache failures and unknown-key refresh failures. Keep fresh known keys usable while backing off. Test sequential failures as well as concurrent failures. Validate `kid` before invoking remote key selection.

Reproduction from the repository root after building:

```javascript
// Run with: node --input-type=module
import { readFileSync } from 'node:fs';
import { createAccessVerifier } from './dist/index.js';
const f = JSON.parse(readFileSync('fixtures/tokens.json', 'utf8'));
let fetches = 0;
const verifier = createAccessVerifier({
  teamDomain: f.issuer, audience: f.audience, cooldownDuration: 30000,
  fetch: async () => { fetches++; throw new TypeError('offline'); },
});
for (let i = 0; i < 10; i++) {
  try { await verifier.verifyToken(f.cases.valid.token); } catch {}
}
console.log({fetches}); // Observed: 10; desired during backoff: 1.
```

### 2. Medium: PHP remote refresh blocks fresh-key authentication across workers

Location: `php/src/JwksCache.php:34–55` and `:73`.

Every lookup obtains an exclusive lock before reading cached keys. Unknown-key refresh holds that same lock throughout the network fetch. After the cooldown expires, an unsigned assertion with an unknown `kid` can trigger a slow fetch. Requests using fresh, known keys must wait for the fetch even though their authentication could complete offline. With default settings, the lock wait can last approximately five seconds and may return `JWKS_CACHE_BUSY`/503. The cooldown bounds repeated probes but does not eliminate periodic blocking.

Impact: slow key-endpoint responses can delay legitimate authentication across PHP workers and occupy worker capacity. This is an availability issue, requiring request access to the verifier; no signature bypass was identified. Source-confirmed lock behavior; timing and worker exhaustion were not reproduced here.

Recommendation: separate the refresh coordination lock from reads of the published cache. Publish validated cache snapshots atomically and permit readers to use fresh matching keys during refresh. Add a multi-process test with a slow unknown-key refresh and a simultaneous known-key request.

### 3. Low: PHP does not enforce critical JOSE header semantics

Location: `php/src/AccessVerifier.php:39–43` and the installed `firebase/php-jwt` decoder.

PHP checks `alg` and `kid` but does not reject unsupported `crit` extensions or explicitly reject `b64=false`. The installed decoder does not implement those header checks either. Python explicitly checks these fields; Node delegates critical-extension handling to `jose`. Unsupported critical extensions must cause rejection under [RFC 7515, section 4.1.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11).

No practical Cloudflare authentication exploit was demonstrated: a modified protected header still requires a valid trusted signature. Treat this as defensive validation and cross-language consistency work. Reject critical extensions not explicitly supported, reject unencoded JWT payloads, and add signed negative fixtures. PHP runtime verification remains outstanding.

## Validation results

| Check | Result |
| --- | --- |
| Node/Express suite and example type checking | 35 tests passed; type checking passed |
| Python suite | 38 tests passed on Python 3.13.7 with PyJWT 2.15.1 |
| Node outage probes | Failure-backoff weakness reproduced, including unsigned unknown-key assertions |
| Python deeply nested unsigned header probe | Safely rejected as `AccessError` with current PyJWT |
| npm dependency audit | Zero known advisories in the resolved dependency tree |
| Python resolved dependency audit | No advisories for module runtime dependencies; audit reported advisories for the temporary environment's pip 25.2 installer |
| PHP dependency advisory lookup | Packagist returned historical advisories affecting versions below 7.0.0; none apply to locked `firebase/php-jwt` 7.2.1 |
| PHP test suite / Composer audit | Not executed: PHP/Composer absent; Docker daemon stopped |

The first Express run hit a sandbox restriction on localhost listeners; the authorized rerun passed. Python dependencies and audit tooling were installed in an isolated temporary environment, not the system Python. The local package itself was skipped by pip-audit because it is not published on PyPI; its code was reviewed manually. Dependency audit results are a dated snapshot and do not cover arbitrary versions permitted by dependency ranges. In particular, the Python manifest permits older PyJWT releases; raise the minimum to a reviewed patched release and audit the actual deployment lockfile.

Packagist lookup: [security advisory API](https://packagist.org/api/security-advisories/?packages%5B%5D=firebase%2Fphp-jwt). This was a direct advisory lookup, not a completed Composer audit.

## Deployment conditions still requiring verification

- Restrict origin access to the intended tunnel and confirm the real per-application audience. Offline JWT verification cannot establish current edge revocation; a stolen valid token can otherwise be replayed. See [Cloudflare application-token documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/).
- Confirm every sensitive route is behind authentication, including alternate login/API handlers and WebSocket handshakes. Preserve resource authorization and CSRF protection.
- Verify disabled-account denial, current permissions, and edge logout using real identities. The Express example deliberately links previously unbound accounts by verified email and can bootstrap administrators by email; confirm email ownership/reassignment and approved identity-provider policy before adopting that behavior.
- Ensure the PHP cache directory and all ancestors are private to the application OS user. The cache does not defend against a local actor who can replace its files or ancestor directories.
- Ensure production never installs a fixture transport. No live credentials or persisted private signing keys were identified in the reviewed source; test fixtures contain synthetic assertions and public keys.
- Audit the consuming application's own resolved dependencies. FileGator and other consumers were outside this assessment.

Recommended next work: fix the Node backoff and PHP locking behavior, complete PHP runtime validation, then perform live deployment acceptance checks.
