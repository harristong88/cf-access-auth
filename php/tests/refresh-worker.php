<?php
require dirname(__DIR__, 2) . '/vendor/autoload.php';
use CfAccess\{AccessException, AccessVerifier};
$f = json_decode(file_get_contents(dirname(__DIR__, 2) . '/fixtures/tokens.json'), true, 64, JSON_THROW_ON_ERROR);
$directory = $argv[1];
$fetch = static function () use ($directory) {
    touch($directory . '/refresh-started');
    $deadline = microtime(true) + 6;
    while (!is_file($directory . '/release-refresh')) {
        if (microtime(true) >= $deadline) throw new RuntimeException('refresh release timed out');
        usleep(10000);
    }
    throw new RuntimeException('simulated outage');
};
$v = new AccessVerifier(['teamDomain' => $f['issuer'], 'audience' => $f['audience'],
    'cacheDirectory' => $directory, 'cooldown' => 0, 'fetch' => $fetch]);
try { $v->verifyToken($f['cases']['rotated']['token']); exit(1); }
catch (AccessException $error) { if ($error->status !== 503) exit(1); }
touch($directory . '/refresh-finished');
