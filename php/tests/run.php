<?php
require dirname(__DIR__, 2) . '/vendor/autoload.php';
use CfAccess\{AccessException, AccessVerifier, AccountStore, HomeProvisioner, Identity};
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
$identity = new Identity($f['issuer'], 'subject-1', ' Alice@Example.com ', 4102444800);
$oldUser = ['username'=>'Alice@example.com','name'=>'Alice','role'=>'user','homedir'=>'/old/alice/','permissions'=>'read|download','password'=>'must-not-import'];
test('link by normalized email preserves data and role; subject change requires relink', function () use ($identity, $oldUser) {
    $store = new AccountStore(':memory:', ['alice@example.com']); $store->import([$oldUser], [], false);
    $user = $store->resolve($identity); check($user['role'] === 'user' && $user['homedir'] === '/old/alice/' && $user['permissions'] === 'read|download');
    check(!isset($user['password'])); check($store->resolve($identity)['id'] === $user['id']);
    denied(fn () => $store->resolve(new Identity($identity->issuer, 'changed', $identity->email, $identity->expiresAt)));
    $store->relink($user['username'], $identity->issuer, 'changed');
    check($store->resolve(new Identity($identity->issuer, 'changed', $identity->email, $identity->expiresAt))['id'] === $user['id']);
});
test('new users provision once; administrator bootstrap; disabled/deleted users never recreated', function () use ($identity) {
    $store = new AccountStore(':memory:', ['alice@example.com']); $a = $store->resolve($identity); check($a['role'] === 'admin');
    check($store->resolve($identity)['id'] === $a['id']); check($a['homedir'] === '/users/' . $a['id'] . '/');
    $b = $store->resolve(new Identity($identity->issuer, 'bob', 'bob@example.com', 4102444800)); check($b['role'] === 'user' && $a['id'] !== $b['id']);
    $store->disable($a['username']); denied(fn () => $store->resolve($identity));
    denied(fn () => $store->resolve(new Identity($identity->issuer, 'new-alice', $identity->email, 4102444800)));
    $store->enable($a['username']); check($store->resolve($identity)['id'] === $a['id']);
});
test('import dry-run, email mappings, duplicate detection and atomic rollback', function () use ($oldUser) {
    $store = new AccountStore(':memory:'); $store->import([$oldUser]); check(!$store->all());
    $legacy = array_merge($oldUser, ['username'=>'legacy']); $store->import([$legacy], ['legacy'=>'legacy@example.com'], false);
    check($store->find('legacy')['email'] === 'legacy@example.com');
    foreach ([[$oldUser, array_merge($oldUser, ['username'=>'alice@EXAMPLE.com'])], [$oldUser, $legacy]] as $users) {
        try { $store->import($users, [], false); throw new RuntimeException('Expected collision'); } catch (InvalidArgumentException $e) {}
    }
    check(count($store->all()) === 1); check($store->find('Alice@example.com') === null);
});
test('permissions loaded fresh; username edits preserve binding', function () use ($identity) {
    $store = new AccountStore(':memory:'); $u = $store->resolve($identity);
    $store->update($u['username'], ['username'=>'renamed', 'permissions'=>'read']);
    $u = $store->resolve($identity); check($u['username'] === 'renamed' && $u['permissions'] === 'read');
});
test('private homes reject traversal, symlinks and file collisions', function () {
    $root = tempdir(); $homes = new HomeProvisioner($root); $homes->ensure('/users/abc/'); $homes->ensure('/users/abc/');
    check(is_dir($root . '/users/abc')); denied(fn () => $homes->ensure('/../escape'), 403);
    symlink(sys_get_temp_dir(), $root . '/link'); denied(fn () => $homes->ensure('/link/escape'), 403);
    file_put_contents($root . '/file', 'x'); denied(fn () => $homes->ensure('/file'), 503);
});
test('concurrent worker first login and JWKS fetch coalescing', function () use ($f) {
    $directory = tempdir(); $processes = [];
    for ($i = 0; $i < 6; $i++) $processes[] = proc_open([PHP_BINARY, __DIR__ . '/worker.php', $directory], [1=>['pipe','w'],2=>['pipe','w']], $pipes);
    foreach ($processes as $process) check(proc_close($process) === 0, 'worker failed');
    $calls = file($directory . '/fetches'); check(count($calls) === 1, 'multiple network fetches');
    $store = new AccountStore($directory . '/accounts.sqlite'); check(count($store->all()) === 1, 'duplicate accounts');
});
test('existing database dry-run is read-only and rejects collisions without changing bytes', function () use ($oldUser) {
    $dir = tempdir(); $path = $dir . '/accounts.sqlite';
    $store = new AccountStore($path); $store->import([$oldUser], [], false); unset($store);
    $before = hash_file('sha256', $path);
    $reader = new AccountStore($path, [], true);
    $reader->import([array_merge($oldUser, ['username'=>'new@example.com'])]);
    try { $reader->import([$oldUser]); throw new RuntimeException('Expected collision'); } catch (InvalidArgumentException $e) {}
    unset($reader); check(hash_file('sha256', $path) === $before);
});
if (getenv('FILEGATOR_ROOT')) require __DIR__ . '/filegator.php';
echo "$count PHP checks passed\n";
