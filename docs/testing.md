# Testing and acceptance

## Automated checks

```bash
npm ci
npm run check
composer install
composer test
```

Node tests cover the common signed fixtures, header ambiguity, key caching/rotation/outages, safe diagnostics, account linking/tombstones, cross-process first-login races, and Express request handling. PHP adds persistent-worker coordination, migration rollback/dry-runs, home path checks, and FileGator class integration when `FILEGATOR_ROOT` is supplied.

The fixtures are signed with generated test keys and expire in 2100. They are **not Cloudflare credentials**. Regenerate them deliberately with `npm run fixtures` and commit the common JSON fixture; tests do not fetch Cloudflare keys or require production secrets.

## Pinned FileGator HTTP/browser scenario

With PHP/Composer and Node installed:

```bash
node scripts/prepare-filegator.mjs
FILEGATOR_ROOT="$PWD/.artifacts/filegator" composer test
npx playwright install chromium
CF_TEAM_DOMAIN=https://fixture.cloudflareaccess.com \
CF_ACCESS_AUD=test-audience CF_ADMIN_EMAILS=alice@example.com \
CF_CSRF_KEY=test-only-csrf \
php -d display_errors=0 -S 127.0.0.1:8088 -t .artifacts/filegator/dist
```

In another terminal:

```bash
node scripts/filegator.e2e.mjs
```

The preparation script creates an isolated pinned checkout and refuses to overwrite existing installations. Choose another empty directory with `FILEGATOR_ROOT`. The HTTP test uses `FILEGATOR_URL` when the port differs. The fixture config deliberately injects test keys: **never deploy it or expose it through a tunnel**. The production configuration example has no test transport.

The scenario covers browser startup without passwords, uploads/downloads, private-home isolation, admin creation without passwords, changed-identity CSRF rejection, session regeneration, batch/archive and chunk isolation, forbidden password changes, and browser navigation to the edge logout URL. It simulates only the logout endpoint; live revocation and Google login are verified separately.

On a machine without PHP, Docker's `composer:2` image can run the suites:

```bash
docker run --rm -v "$PWD:/work" -w /work composer:2 composer install
docker run --rm -v "$PWD:/work" -w /work composer:2 composer test
```

For actual FileGator testing, mount its checkout and this package at their installed paths, provide the test environment, and map its port to **127.0.0.1**. CI automates the full native-runtime flow.

## Live Cloudflare acceptance checklist

- Set the real team domain and the specific AUD for each example/app. Confirm protected policies cover every application/API path and origin access remains restricted to the tunnel.
- With an approved Google identity, open the app from a fresh browser profile. You should reach the app without entering a local password.
- Open the other app: Cloudflare may reuse its organization session, subject to your Access session/policy settings. There should be no app-managed login form.
- Add a second ordinary approved identity. Confirm its local role is `user`, its FileGator home differs, and it cannot read the first person's files or administer accounts.
- Link an existing user by email and verify its old home, permissions, and role remain intact. Confirm bootstrap emails do not promote that linked user.
- Disable/delete a local user. It must receive 403 even though Access still admits it. Removing admission in Cloudflare must block it at the edge as well.
- Test origin/LAN requests without a token and with spoofed email headers: protected handlers must reject them. A token for a different app must fail audience validation.
- Change local permissions and verify the next request respects them. Try an old local password and password-change endpoint; neither may establish authentication.
- Click Logout. The local session must clear before navigation to Cloudflare logout. Verify subsequent protected navigation goes through Access again; Google may reuse its own session.
- Test a verification outage: a fresh cached key can continue verification until its TTL; a cold/expired cache must return 503 and never fall back to passwords.

## Observability

Keep diagnostic codes in your normal application logs. Investigate `INVALID_TOKEN`/`INVALID_AUDIENCE` when standing up an app, and `JWKS_UNAVAILABLE` during connectivity incidents. Synchronize host clocks. Do not log headers, tokens, raw claims, or identity objects. No new monitoring service is required.
