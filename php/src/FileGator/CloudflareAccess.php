<?php
namespace CfAccess\FileGator;

use CfAccess\AccessException;
use CfAccess\AccessVerifier;
use CfAccess\AccountStore;
use CfAccess\HomeProvisioner;
use CfAccess\Identity;
use Filegator\Kernel\Request;
use Filegator\Services\Auth\AuthInterface;
use Filegator\Services\Auth\User;
use Filegator\Services\Auth\UsersCollection;
use Filegator\Services\Service;
use Filegator\Services\Session\SessionStorageInterface;

final class CloudflareAccess implements Service, AuthInterface
{
    private AccessVerifier $verifier;
    private AccountStore $accounts;
    private HomeProvisioner $homes;
    private ?Identity $identity = null;
    public function __construct(private Request $request, private SessionStorageInterface $session) {}
    public function init(array $config = [])
    {
        $this->verifier = new AccessVerifier($config);
        $this->accounts = new AccountStore($config['database'], $config['adminEmails'] ?? []);
        $this->homes = new HomeProvisioner($config['storageRoot']);
        // Configure this service after SessionStorage and BEFORE Security/CSRF.
        $this->user();
    }
    public function user(): ?User
    {
        $this->identity ??= $this->verifier->authenticateRequest($this->request->headers->all());
        $account = $this->accounts->resolve($this->identity);
        $this->homes->ensure($account['homedir']);
        $binding = hash('sha256', $this->identity->issuer . "\0" . $this->identity->subject . "\0" . $account['id']);
        if ($this->session->get('cf_access_binding') !== $binding) {
            // Invalidate removes old CSRF/session values and changes ownership of tmp artifacts.
            $this->session->invalidate();
            $this->session->set('cf_access_binding', $binding);
        }
        return $this->map($account);
    }
    public function authenticate($username, $password): bool { return false; }
    public function forget() { $this->session->invalidate(); return true; }
    public function store(User $user) { throw new AccessException('LOCAL_LOGIN_DISABLED', 403); }
    public function getGuest(): User { throw new AccessException('GUEST_DISABLED', 403); }
    public function find($username): ?User { $row = $this->accounts->find($username); return $row ? $this->map($row) : null; }
    public function allUsers(): UsersCollection
    {
        $this->requireAdmin();
        $users = new UsersCollection();
        foreach ($this->accounts->all() as $row) $users->addUser($this->map($row));
        return $users;
    }
    public function add(User $user, $password): User
    {
        $this->requireAdmin();
        if ($password !== '' && $password !== null) throw new AccessException('PASSWORD_DISABLED', 403);
        if (!filter_var($user->getUsername(), FILTER_VALIDATE_EMAIL)) throw new \InvalidArgumentException('Use the Cloudflare email as username for new accounts');
        return $this->map($this->accounts->add($this->fields($user)));
    }
    public function update($username, User $user, $password = ''): User
    {
        $this->requireAdmin();
        if ($password !== '' && $password !== null) throw new AccessException('PASSWORD_DISABLED', 403);
        return $this->map($this->accounts->update($username, $this->fields($user)));
    }
    public function delete(User $user) { $this->requireAdmin(); $this->accounts->disable($user->getUsername()); return true; }
    private function requireAdmin(): void { if (!$this->user()->isAdmin()) throw new AccessException('ADMIN_REQUIRED', 403); }
    private function fields(User $user): array
    {
        return ['username' => $user->getUsername(), 'name' => $user->getName(), 'role' => $user->getRole(),
            'homedir' => $user->getHomeDir(), 'permissions' => $user->getPermissions(true)];
    }
    private function map(array $row): User
    {
        $user = new User(); $user->setUsername($row['username']); $user->setName($row['name']);
        $user->setRole($row['role']); $user->setHomedir($row['homedir']); $user->setPermissions($row['permissions'], true);
        return $user;
    }
}
