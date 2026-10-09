# FileGator integration after v0.3.0

The PHP identity package no longer owns FileGator adapters, accounts, homes, or migration commands. Install `cf-access/auth` through Composer and implement an application-owned provider using `AccessVerifier::authenticateRequest()`.

The integrated FileGator fork at https://github.com/harristong88/filegator owns that provider and its local account store. Its `docs/external-auth.md` describes installation, migration, administration, rollback, and acceptance testing. Do not apply the old v7.16.5 patch to this fork.

Breaking PHP removals: `CfAccess\FileGator\CloudflareAccess`, `CfAccess\AccountStore`, `CfAccess\HomeProvisioner`, and the Composer `account` / `import-users` commands. Those responsibilities now live in FileGator. Existing applications may remain pinned to earlier releases while migrating. Node and Python identity APIs are unchanged.
