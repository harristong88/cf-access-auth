<?php
require dirname(__DIR__, 2) . '/vendor/autoload.php';
use CfAccess\{AccessException, AccessVerifier, Identity};
$f = json_decode(file_get_contents(dirname(__DIR__, 2) . '/fixtures/tokens.json'), true, 64, JSON_THROW_ON_ERROR);
$count = 0;
function check(bool $ok, string $message = 'assertion failed'): void { if (!$ok) throw new RuntimeException($message); }
function denied(Closure $fn, int $status = 403): void {
    try { $fn(); } catch (AccessException $e) { check($e->status === $status, 'wrong rejection: ' . $e->reason . '/' . $e->status); return; }
    throw new RuntimeException('Expected AccessException');
}
function test(string $name, Closure $fn): void { global $count; $fn(); $count++; echo "PASS $name\n"; }
function tempdir(): string { $p = sys_get_temp_dir() . '/cf-access-' . bin2hex(random_bytes(8)); mkdir($p, 0700); return $p; }
$base = ['teamDomain' => $f['issuer'], 'audience' => $f['audience']];
foreach ($f['cases'] as $name => $case) {
    if ($name === 'rotated') continue;
    test('shared fixture: ' . $name, function () use ($base, $f, $case) {
        $v = new AccessVerifier($base + ['cacheDirectory' => tempdir(), 'fetch' => static fn () => $f['jwks']]);
        if ($case['status'] === 200) { $i = $v->verifyToken($case['token']); check($i->expiresAt === 4102444800); check(array_keys($i->jsonSerialize()) === ['issuer','subject','email','expiresAt']); }
        else denied(fn () => $v->verifyToken($case['token']), 401);
    });
}
test('header extraction and cookie/email rejection', function () use ($base, $f) {
    $v = new AccessVerifier($base + ['cacheDirectory' => tempdir(), 'fetch' => static fn () => $f['jwks']]);
    $t = $f['cases']['valid']['token'];
    check($v->authenticateRequest(['Cf-Access-Jwt-Assertion' => [$t]])->subject === 'user-1');
    foreach ([[], ['Cookie' => 'CF_Authorization=' . $t], ['Cf-Access-Authenticated-User-Email' => 'Alice@example.com'],
        ['cf-access-jwt-assertion' => [$t, $t]], ['cf-access-jwt-assertion' => $t, 'Cf-Access-Jwt-Assertion' => $t],
        ['cf-access-jwt-assertion' => $t . ', ' . $t]] as $h) denied(fn () => $v->authenticateRequest($h), 401);
});
test('persistent cache, offline warm keys, cooldown, rotation, no refetch for bad signatures', function () use ($base, $f) {
    $calls = 0; $jwks = $f['jwks']; $offline = false; $dir = tempdir();
    $fetch = static function () use (&$calls, &$jwks, &$offline) { $calls++; if ($offline) throw new RuntimeException('offline'); return $jwks; };
    $v = new AccessVerifier($base + ['cacheDirectory' => $dir, 'fetch' => $fetch]);
    $v->verifyToken($f['cases']['valid']['token']); check($calls === 1);
    denied(fn () => $v->verifyToken($f['cases']['tampered']['token']), 401); check($calls === 1);
    denied(fn () => $v->verifyToken($f['cases']['rotated']['token']), 401); check($calls === 1);
    $offline = true;
    (new AccessVerifier($base + ['cacheDirectory' => $dir, 'fetch' => $fetch]))->verifyToken($f['cases']['valid']['token']); check($calls === 1);
    $offline = false; $jwks = $f['rotatedJwks'];
    (new AccessVerifier($base + ['cacheDirectory' => $dir, 'fetch' => $fetch, 'cooldown' => 0]))->verifyToken($f['cases']['rotated']['token']); check($calls === 2);
});
test('expired cache cannot authenticate during outage', function () use ($base, $f) {
    $dir = tempdir(); $offline = false;
    $fetch = static function () use (&$offline, $f) { if ($offline) throw new RuntimeException('offline'); return $f['jwks']; };
    $v = new AccessVerifier($base + ['cacheDirectory' => $dir, 'fetch' => $fetch, 'cacheTtl' => 1, 'cooldown' => 0]);
    $v->verifyToken($f['cases']['valid']['token']); sleep(1); $offline = true;
    denied(fn () => $v->verifyToken($f['cases']['valid']['token']), 503);
});
test('diagnostics cannot affect authentication or reveal claims', function () use ($base, $f) {
    $events = [];
    $v = new AccessVerifier($base + ['cacheDirectory' => tempdir(), 'fetch' => static function () { throw new RuntimeException('offline'); },
        'onDiagnostic' => static function ($event) use (&$events) { $events[] = $event; throw new RuntimeException('logger'); }]);
    denied(fn () => $v->verifyToken($f['cases']['valid']['token']), 503);
    check($events === [['code' => 'JWKS_UNAVAILABLE', 'status' => 503]]);
});
test('concurrent workers coalesce JWKS fetching', function () {
    $directory = tempdir(); $processes = [];
    for ($i = 0; $i < 6; $i++) $processes[] = proc_open([PHP_BINARY, __DIR__ . '/worker.php', $directory], [1=>['pipe','w'],2=>['pipe','w']], $pipes);
    foreach ($processes as $process) check(proc_close($process) === 0, 'worker failed');
    check(count(file($directory . '/fetches')) === 1, 'multiple network fetches');
});
echo "$count PHP checks passed\n";
