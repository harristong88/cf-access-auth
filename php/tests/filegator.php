<?php
require getenv('FILEGATOR_ROOT') . '/vendor/autoload.php';
use CfAccess\FileGator\CloudflareAccess;
use CfAccess\AccessException;
use Filegator\Kernel\Request;
use Filegator\Services\Session\SessionStorageInterface;
final class TestSession implements SessionStorageInterface {
    public array $values = []; public int $invalidations = 0;
    public function set(string $key, $data) { $this->values[$key] = $data; }
    public function get(string $key, $default = null) { return $this->values[$key] ?? $default; }
    public function invalidate() { $this->values = []; $this->invalidations++; }
    public function save() {}
    public function migrate($destroy = false, $lifetime = null): bool { return true; }
}
test('real FileGator interface: sessions, users, permission refresh, password rejection and administration', function () use ($base, $f) {
    $directory = tempdir(); $session = new TestSession();
    $session->values = ['batch_download_archives'=>['old'], 'oldcsrf'=>'old'];
    $config = $base + ['cacheDirectory'=>$directory,'database'=>$directory . '/accounts.sqlite','storageRoot'=>$directory,
        'adminEmails'=>['alice@example.com'], 'fetch'=>static fn () => $f['jwks']];
    $request = new Request(); $request->headers->set('Cf-Access-Jwt-Assertion', $f['cases']['valid']['token']);
    $adapter = new CloudflareAccess($request, $session); $adapter->init($config);
    check($adapter->user()->isAdmin()); check($session->invalidations === 1); check(!isset($session->values['batch_download_archives']));
    $adapter->user(); check($session->invalidations === 1);
    check(!$adapter->authenticate('Alice@example.com','anything')); denied(fn () => $adapter->getGuest());
    $user = $adapter->user(); denied(fn () => $adapter->update($user->getUsername(), $user, 'password'));
    $user->setPermissions(['read']); $adapter->update($user->getUsername(), $user); check($adapter->user()->getPermissions() === ['read']);
    $request2 = new Request(); $request2->headers->set('Cf-Access-Jwt-Assertion', $f['cases']['bob']['token']);
    $bob = new CloudflareAccess($request2, $session); $bob->init($config); check($session->invalidations === 2); check(!$bob->user()->isAdmin());
    denied(fn () => $bob->allUsers()); $bob->forget(); check($session->invalidations === 3);
    $adapter->delete($adapter->user()); denied(fn () => $adapter->user());
});
