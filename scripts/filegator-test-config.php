<?php
// Test harness only. Never deploy: this replaces the Cloudflare key transport with local fixtures.
$config = require '/fg/cf-access-configuration.php';
// The example resolves paths relative to its own file; rebase them to the isolated fixture checkout.
$auth =& $config['services']['Filegator\\Services\\Auth\\AuthInterface']['config'];
$auth['database'] = '/fg/private/cf-access-test.sqlite';
$auth['cacheDirectory'] = '/fg/private/cf-access-cache';
$auth['storageRoot'] = '/fg/repository';
$auth['fetch'] = static function (): array { return json_decode(file_get_contents('/work/fixtures/tokens.json'), true)['jwks']; };
return $config;
