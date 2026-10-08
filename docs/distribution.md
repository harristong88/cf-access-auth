# Distribution

The root contains both `package.json` and `composer.json`, so each ecosystem can install directly from the same Git repository. No package registry is needed. These instructions use placeholder repository URLs: replace them with yours.

## Local or packaged install

```bash
# In this repository
npm ci
npm pack --pack-destination .artifacts
composer install
composer archive --format=zip --dir=.artifacts --file=cf-access-auth-php-0.1.0

# In a Node consumer
npm install /absolute/path/cf-access-auth/.artifacts/cf-access-auth-0.1.0.tgz

# In a PHP consumer: use a local Composer path repository during development
composer config repositories.cf-access path /absolute/path/cf-access-auth
composer require cf-access/auth:@dev
```

Composer's default path installation may use a symlink. Use a mirrored path repository (`options.symlink=false`) when making a standalone deployment. Commit the consumer lockfile, and do not depend on a developer-machine path in production.

To install the ZIP in a clean PHP consumer, define a package repository in its `composer.json`:

```json
{
  "repositories": [{"type": "package", "package": {
    "name": "cf-access/auth", "version": "0.1.0", "type": "library",
    "dist": {"type": "zip", "url": "/absolute/path/cf-access-auth-php-0.1.0.zip"},
    "require": {"php": "^8.1", "ext-curl": "*", "ext-openssl": "*", "ext-pdo_sqlite": "*", "ext-mbstring": "*", "firebase/php-jwt": "^7.2"},
    "autoload": {"psr-4": {"CfAccess\\": "php/src/"}},
    "bin": ["php/bin/import-users", "php/bin/account"]
  }}],
  "require": {"cf-access/auth": "0.1.0"}
}
```

The package repository repeats the ZIP's metadata because Composer does not inspect arbitrary ZIP archives to discover it. Use a VCS repository for simpler long-term distribution.

## Versioned Git install

After you commit and push the repository, create an immutable release tag such as `v0.1.0`. Publishing and tagging are intentionally left to the repository owner.

```bash
# Node consumer
npm install 'git+https://github.com/YOUR-USER/cf-access-auth.git#v0.1.0'

# PHP consumer
composer config repositories.cf-access vcs https://github.com/YOUR-USER/cf-access-auth.git
composer require cf-access/auth:^0.1
```

npm's prepare script compiles TypeScript on Git installation. Use SSH URLs or your Git credential manager for private repositories; do not put access tokens in URLs or files. Consumer upgrades should change a tag/version deliberately and run the app's auth integration checks.

The native packages share a specification and signed fixtures, rather than a running service or a single cross-language binary. Framework glue still differs by app. The Python implementation lives under `python/` and installs using a Git direct reference with `#subdirectory=python`; pin the full immutable release commit. It shares the same signed fixtures and does not require a verifier service.
