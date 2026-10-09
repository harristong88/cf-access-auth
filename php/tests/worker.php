<?php
require dirname(__DIR__, 2) . '/vendor/autoload.php';
use CfAccess\{AccessVerifier};
$f = json_decode(file_get_contents(dirname(__DIR__, 2) . '/fixtures/tokens.json'), true);
$directory = $argv[1];
$v = new AccessVerifier(['teamDomain'=>$f['issuer'], 'audience'=>$f['audience'], 'cacheDirectory'=>$directory,
    'fetch'=>static function () use ($directory, $f) { file_put_contents($directory . '/fetches', "fetch\n", FILE_APPEND | LOCK_EX); usleep(100000); return $f['jwks']; }]);
$i = $v->verifyToken($f['cases']['valid']['token']);
