<?php
namespace CfAccess;

/** Local accounts remain app-owned. Passwords are deliberately neither imported nor stored. */
final class AccountStore
{
    private \PDO $db;
    private array $admins;
    public const PERMISSIONS = ['read', 'write', 'upload', 'download', 'batchdownload', 'zip'];
    public function __construct(string $path, array $adminEmails = [], private bool $readOnly = false)
    {
        $this->db = new \PDO('sqlite:' . $path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION] + ($readOnly ? [\PDO::SQLITE_ATTR_OPEN_FLAGS => \PDO::SQLITE_OPEN_READONLY] : []));
        if (!$readOnly && $path !== ':memory:') chmod($path, 0600);
        $this->admins = array_map([Identity::class, 'normalizeEmail'], $adminEmails);
        $this->db->exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
        if (!$readOnly) $this->db->exec('
            CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT UNIQUE, name TEXT NOT NULL, role TEXT NOT NULL, permissions TEXT NOT NULL, homedir TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS bindings (issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL UNIQUE REFERENCES users(id), PRIMARY KEY(issuer,subject));');
    }
    private function query(string $sql, array $args = []): \PDOStatement { $s = $this->db->prepare($sql); $s->execute($args); return $s; }
    private function transaction(\Closure $fn): mixed
    {
        $this->db->exec($this->readOnly ? 'BEGIN' : 'BEGIN IMMEDIATE');
        try { $ret = $fn(); $this->db->exec('COMMIT'); return $ret; }
        catch (\Throwable $e) { $this->db->exec('ROLLBACK'); throw $e; }
    }
    public function resolve(Identity $identity): array
    {
        return $this->transaction(function () use ($identity) {
            $user = $this->query('SELECT u.* FROM bindings b JOIN users u ON u.id=b.user_id WHERE b.issuer=? AND b.subject=?', [$identity->issuer, $identity->subject])->fetch(\PDO::FETCH_ASSOC);
            if (!$user) {
                $email = Identity::normalizeEmail($identity->email);
                $users = $this->query('SELECT * FROM users WHERE email=?', [$email])->fetchAll(\PDO::FETCH_ASSOC);
                if (count($users) > 1) throw new AccessException('AMBIGUOUS_EMAIL', 403);
                $user = $users[0] ?? null;
                if ($user && $this->query('SELECT 1 FROM bindings WHERE user_id=?', [$user['id']])->fetch()) throw new AccessException('RELINK_REQUIRED', 403);
                if (!$user) {
                    $id = bin2hex(random_bytes(16));
                    $user = ['id' => $id, 'username' => $email, 'email' => $email, 'name' => $email,
                        'role' => in_array($email, $this->admins, true) ? 'admin' : 'user',
                        'permissions' => implode('|', self::PERMISSIONS), 'homedir' => '/users/' . $id . '/', 'disabled' => 0];
                    $this->insert($user);
                }
                if ($user['disabled']) throw new AccessException('ACCOUNT_DISABLED', 403);
                $this->query('INSERT INTO bindings VALUES(?,?,?)', [$identity->issuer, $identity->subject, $user['id']]);
            }
            if ($user['disabled']) throw new AccessException('ACCOUNT_DISABLED', 403);
            return $user;
        });
    }
    public function find(string $username): ?array
    {
        return $this->query('SELECT * FROM users WHERE username=? AND disabled=0', [$username])->fetch(\PDO::FETCH_ASSOC) ?: null;
    }
    public function all(): array { return $this->query('SELECT * FROM users WHERE disabled=0 ORDER BY username')->fetchAll(\PDO::FETCH_ASSOC); }
    public function add(array $user): array
    {
        return $this->transaction(function () use ($user) {
            $user['id'] = bin2hex(random_bytes(16)); $user['disabled'] = 0;
            $user['email'] = filter_var($user['username'], FILTER_VALIDATE_EMAIL) ? Identity::normalizeEmail($user['username']) : ($user['email'] ?? null);
            $this->insert($user); return $user;
        });
    }
    public function update(string $username, array $user): array
    {
        return $this->transaction(function () use ($username, $user) {
            $old = $this->find($username);
            if (!$old) throw new \InvalidArgumentException('User not found');
            $user = array_merge($old, $user);
            $this->validate($user);
            // Binding and migration email stay stable when a display username is edited.
            $this->query('UPDATE users SET username=?, name=?, role=?, permissions=?, homedir=? WHERE id=?',
                [$user['username'], $user['name'], $user['role'], $user['permissions'], $user['homedir'], $old['id']]);
            return $user;
        });
    }
    public function disable(string $username): void { $this->query('UPDATE users SET disabled=1 WHERE username=?', [$username]); }
    public function enable(string $username): void { $this->query('UPDATE users SET disabled=0 WHERE username=?', [$username]); }
    public function relink(string $username, string $issuer, string $subject): void
    {
        if (!preg_match('#^https://[a-z0-9-]+\.cloudflareaccess\.com$#D', $issuer) || !trim($subject)) throw new \InvalidArgumentException('Invalid identity');
        $this->transaction(function () use ($username, $issuer, $subject) {
            $u = $this->query('SELECT * FROM users WHERE username=?', [$username])->fetch(\PDO::FETCH_ASSOC);
            if (!$u) throw new \InvalidArgumentException('User not found');
            $this->query('DELETE FROM bindings WHERE user_id=?', [$u['id']]);
            $this->query('INSERT INTO bindings VALUES(?,?,?)', [$issuer, $subject, $u['id']]);
        });
    }
    public function import(array $users, array $emailMap = [], bool $dryRun = true): array
    {
        $prepared = []; $emails = []; $names = [];
        foreach ($users as $user) {
            if (($user['role'] ?? '') === 'guest') continue;
            unset($user['password']);
            $name = $user['username'] ?? '';
            $email = $emailMap[$name] ?? (filter_var($name, FILTER_VALIDATE_EMAIL) ? $name : null);
            if ($email !== null && !filter_var($email, FILTER_VALIDATE_EMAIL)) throw new \InvalidArgumentException('Invalid mapped email');
            $email = $email === null ? null : Identity::normalizeEmail($email);
            if (isset($names[$name]) || ($email !== null && isset($emails[$email]))) throw new \InvalidArgumentException('Duplicate username or normalized email');
            $names[$name] = true; if ($email !== null) $emails[$email] = true;
            $user = array_merge($user, ['id' => bin2hex(random_bytes(16)), 'email' => $email, 'disabled' => 0]);
            $this->validate($user);
            $prepared[] = $user;
        }
        $this->transaction(function () use ($prepared, $dryRun) {
            foreach ($prepared as $u) {
                if ($this->query('SELECT 1 FROM users WHERE username=? OR (email IS NOT NULL AND email=?)', [$u['username'], $u['email']])->fetch()) throw new \InvalidArgumentException('Import conflicts with existing account');
                if (!$dryRun) $this->insert($u);
            }
        });
        return array_map(static fn ($u) => ['username' => $u['username'], 'email' => $u['email'], 'role' => $u['role'], 'homedir' => $u['homedir']], $prepared);
    }
    private function insert(array $u): void
    {
        $this->validate($u);
        $this->query('INSERT INTO users(id,username,email,name,role,permissions,homedir,disabled) VALUES(?,?,?,?,?,?,?,?)',
            [$u['id'], $u['username'], $u['email'], $u['name'], $u['role'], $u['permissions'], $u['homedir'], $u['disabled']]);
    }
    private function validate(array $u): void
    {
        foreach (['username','name','role','permissions','homedir'] as $field) if (!isset($u[$field]) || !is_string($u[$field])) throw new \InvalidArgumentException('Invalid account field');
        if (!trim($u['username']) || !in_array($u['role'], ['user','admin'], true) ||
            array_diff(explode('|', $u['permissions']), [...self::PERMISSIONS, 'chmod', '']) ||
            !str_starts_with($u['homedir'], '/') || preg_match('#(^|/)\.\.?(/|$)|[\\\\\x00]#', $u['homedir'])) throw new \InvalidArgumentException('Invalid account role, permissions, or home');
    }
}
