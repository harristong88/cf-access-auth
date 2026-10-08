# FileGator installation and migration

Supported baseline: FileGator **v7.16.5**, commit `967618f7dc4af195b449aebe7dc735675f4d6193`. The adapter uses upstream `AuthInterface`; the patch handles UI, HTTP errors, password controls, and upload/session isolation. Port the patch manually when your fork differs; do not force-apply it to an unknown version.

## Install

1. Back up your FileGator tree, `configuration.php`, `private/users.json`, and repository files. Stop writes while migrating accounts. Keep the origin restricted to the tunnel throughout.
2. Install `cf-access/auth` using the Composer instructions in [distribution](distribution.md). Ensure the PHP extensions listed in the README are available.
3. From your FileGator checkout, apply the patch:

   ```bash
   git apply --check /path/to/cf-access-auth/patches/filegator-7.16.5.patch
   git apply /path/to/cf-access-auth/patches/filegator-7.16.5.patch
   ```

4. Copy `examples/filegator/configuration.php` into the FileGator root. Merge any existing storage, frontend, or security settings deliberately. This v1 uses the local storage adapter and default JSON migration source. Authentication must appear **after SessionStorage and before Security/CSRF** in the service array; the provided configuration orders it correctly.
5. Create a private writable cache directory and keep SQLite outside `dist`, with access restricted to the application OS user:

   ```bash
   mkdir -p private/cf-access-cache
   chmod 700 private/cf-access-cache
   ```

6. Set `CF_TEAM_DOMAIN`, `CF_ACCESS_AUD`, `CF_ADMIN_EMAILS`, and a random deployment-specific `CF_CSRF_KEY` in the PHP process/container environment. This app does not parse `.env` files. Retain CSRF protection; use secure cookies at the public HTTPS endpoint. If your web server does not report tunnel HTTPS correctly, explicitly set the session handler's `cookie_secure` to `true` in production.
7. Import accounts before opening the new installation to users, or skip the import for a fresh installation. Provisioned existing accounts never receive bootstrap promotion, including `CF_ADMIN_EMAILS` entries.
8. Rebuild the frontend; old compiled assets retain the old UI:

   ```bash
   CYPRESS_INSTALL_BINARY=0 npm ci --legacy-peer-deps --ignore-scripts
   NODE_OPTIONS=--openssl-legacy-provider npm run build
   ```

9. Serve **only `dist/`** as document root. Restart PHP workers and run the live checklist in [testing](testing.md).

## Migrate existing users

The importer preserves usernames, names, roles, permissions, and home directories. It discards password hashes and skips guest accounts. Usernames that are emails link automatically after normalization. Map other usernames explicitly:

```json
{"old-admin": "owner@example.com", "old-user": "person@example.com"}
```

Use the installed Composer bin proxy:

```bash
vendor/bin/import-users --source=private/users.json --email-map=email-map.json
vendor/bin/import-users --source=private/users.json --email-map=email-map.json --database=private/cf-access.sqlite
vendor/bin/import-users --source=private/users.json --email-map=email-map.json --database=private/cf-access.sqlite --apply
```

Without `--apply`, no persistent database is created or modified. An existing supplied database is opened read-only to check conflicts. Import is all-or-nothing: duplicate normalized emails, existing usernames/emails, invalid roles, permissions, or unsafe homes abort the operation. No import overwrites a current user.

Non-email legacy usernames without a mapping remain unlinked; their owner would receive a new basic account. The importer does not move files. Existing homes are preserved, so existing users can still share folders; privacy isolation applies to newly provisioned users.

## Manage accounts

FileGator admins can list, add, edit, and delete local accounts without passwords. New manually added users must use their Cloudflare email as username. Editing a display username does not change its migration email or external identity binding. Guest accounts are unsupported.

Deletion disables the account rather than erasing its binding or files. Offline commands restore access or explicitly rebind a changed identity:

```bash
vendor/bin/account --database=private/cf-access.sqlite --username=person@example.com --disable
vendor/bin/account --database=private/cf-access.sqlite --username=person@example.com --enable
vendor/bin/account --database=private/cf-access.sqlite --username=person@example.com --relink --issuer=https://yourteam.cloudflareaccess.com --subject=verified-new-subject
```

Relinking replaces the old identity; verify the new subject independently. Administrators should protect their own role and backup access. Admin home-directory selections can intentionally grant access to shared/root files; reviewing those grants remains an application administration responsibility.

## Logout and rollback

Logout clears FileGator's local session and then navigates to `/cdn-cgi/access/logout`. This ends Cloudflare sessions across Access apps, rather than just this FileGator instance. Google may still retain its own session.

For rollback, stop writes, back up the new SQLite database and newly created folders, then restore your pre-change FileGator tree/configuration/users.json and rebuild or restore its previous frontend. Keep Cloudflare protection enabled. Changes made to local roles or users after migration are not synchronized back to `users.json`; preserve or reconcile them before reverting. Newly uploaded files remain in storage and are not removed by rollback.
