# cf-access-auth

Replace application passwords with **verified Cloudflare Access identities**, while keeping accounts, permissions, and data inside each app.

This repository is both an npm package (`cf-access-auth`) and a Composer package (`cf-access/auth`). It includes a runnable Express example, reusable PHP and Python verifiers and shared security fixtures. No additional authentication service or Cloudflare API credential is required.

## Request flow

Browser → Cloudflare Access / Google login → Tunnel → JWT verification → local account → existing app authorization.

Always verify `Cf-Access-Jwt-Assertion`; never treat the email header as proof of identity. The JWT proves who signed in and which Access application issued the token. It does **not** grant local administrator or file permissions. Each app needs its own AUD, account resolver, and login/UI integration.

## Node / Express

Requires Node 22.12+; ESM with TypeScript declarations. Import the core without installing Express, or use the optional Express adapter.

```bash
npm install /path/to/cf-access-auth
```

```ts
import { cfAccessMiddleware } from 'cf-access-auth/express';

app.use(cfAccessMiddleware({
  teamDomain: process.env.CF_TEAM_DOMAIN!,
  audience: process.env.CF_ACCESS_AUD!,
  resolveUser: identity => yourAccounts.resolve(identity),
  onDiagnostic: event => console.warn(event),
}));

app.get('/api/me', (req, res) => res.json(req.cfAccessUser));
```

`req.cfAccessIdentity` is `{ issuer, subject, email, expiresAt }`; `req.cfAccessUser` is your app's user object. The resolver must implement transactional first-login mapping and load current permissions. Return no user or throw `new AccessError('ACCOUNT_DENIED', 403)` to deny access; unexpected errors go to your Express error handler. The generic core exposes `createAccessVerifier(config).verifyToken(token)` and `.authenticateRequest(headers)`.

Run the included example from this repository checkout:

```bash
npm ci
CF_TEAM_DOMAIN=https://yourteam.cloudflareaccess.com \
CF_ACCESS_AUD=your-app-audience \
CF_ADMIN_EMAILS=owner@example.com npm run example
```

The example binds to `127.0.0.1:3000`, uses an app-local SQLite database, exposes `/api/me`, and has no password routes. The npm scripts enable SQLite on Node 22.12 with `--experimental-sqlite`; newer Node versions expose it by default. Older versions can emit an experimental warning. It issues no local session; an existing app must invalidate its own session before navigating to `/cdn-cgi/access/logout`.

## PHP

Requires PHP 8.1+ with OpenSSL, cURL, and mbstring. The cryptographic dependency is `firebase/php-jwt` 7.2+, selected because 6.x is affected by a security advisory.

```php
$verifier = new \CfAccess\AccessVerifier([
    'teamDomain' => getenv('CF_TEAM_DOMAIN'),
    'audience' => getenv('CF_ACCESS_AUD'),
    'cacheDirectory' => '/private/writable/cf-access-cache',
]);
$identity = $verifier->authenticateRequest($requestHeaders);
```

The application resolves the verified `(issuer, subject)` to its own local account, assigns roles/permissions, manages sessions and CSRF, and implements logout. The PHP package owns no account database, filesystem homes, or framework adapter.

PHP v0.3.0 removes the former FileGator-specific APIs and migration commands. The integrated [FileGator fork](https://github.com/harristong88/filegator) owns those responsibilities; see [migration notes](docs/filegator.md). Node and Python identity APIs are unchanged. The Express account store remains an example owned by the example app.

## Verification behavior

Both packages require RS256, the configured team issuer and application audience, `type=app`, nonempty email/subject, and integer `exp`, `iat`, and `nbf`. Clock tolerance is zero. Service tokens and organization tokens are rejected by this human-login API.

Keys come only from the configured `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`. Default cache lifetime is ten minutes, timeout five seconds, and unknown-key refresh cooldown thirty seconds. Fresh cached keys work offline; expired or unavailable keys fail closed. No refresh occurs for bad signatures, expired tokens, or audience errors. There is no one-use replay cache: browsers legitimately reuse an Access token.

Core errors expose a safe diagnostic code and HTTP status; HTTP adapters return generic 401/403/503 responses. Logs receive only `{code, status}`, never tokens or claims. Node timing options are milliseconds (`cacheMaxAge`, `timeoutDuration`, `cooldownDuration`); PHP options are seconds (`cacheTtl`, `timeout`, `cooldown`). An audience list accepts **any** explicitly configured audience.

## Distribution and verification

See [distribution](docs/distribution.md), [testing and live acceptance](docs/testing.md), and [security and compatibility notes](docs/security.md).

```bash
npm run check
composer install
composer test
```

CI covers Node 22.12/24 and PHP 8.1/8.3/8.5, without requiring FileGator. Shared signed fixtures are test-only and do not contain real Cloudflare credentials.

Cloudflare documentation: [token validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [claims and subject semantics](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/), and [logout behavior](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/).

## Python / ASGI

Python 3.12+ is supported by the separate native package in `python/`. Install an
immutable release commit, without copying this repository into your application:

```bash
pip install 'cf-access-auth @ git+https://github.com/harristong88/cf-access-auth.git@FULL_RELEASE_COMMIT#subdirectory=python'
```

```python
from cf_access_auth import AccessVerifier

verifier = AccessVerifier(team_domain=team_domain, audience=app_aud)
identity = await verifier.authenticate_request(request.scope["headers"])
# Resolve (identity.issuer, identity.subject) to your existing local account.
# Check local permissions and CSRF separately; never trust an email header.
```

Create one verifier per application process and call `await verifier.aclose()` on
shutdown. Python timing options are seconds: `cache_ttl=600`, `timeout=5`,
`cooldown=30`. Unknown-key requests share a refresh; outages fail closed when no
fresh matching key is available. The frozen identity has `issuer`, `subject`,
`email`, and `expires_at`. `AccessError` exposes `code` and `status`; an optional
`on_diagnostic` callback receives only those safe fields. Use raw ASGI header
pairs to reject duplicate assertions. The package owns no accounts or sessions.

Run `pip install './python[test]'` then `cd python && python -m pytest`.
