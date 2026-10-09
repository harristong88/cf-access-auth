# v0.3.0 validation

The PHP package is identity-only. Its verifier/cache suite runs independently of FileGator and SQLite. Account, migration, home, session, and browser acceptance tests moved into FileGator. See each repository's test commands and CI for reproducible validation. Live Cloudflare acceptance requires deployment configuration and is not implied by passing signed-fixture tests.
