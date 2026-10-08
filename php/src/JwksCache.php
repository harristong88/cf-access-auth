<?php
namespace CfAccess;

/** A single locked cache per issuer; use a private writable directory on local storage. */
final class JwksCache
{
    private string $file;
    private \Closure $fetch;
    public function __construct(private string $issuer, string $directory, private int $ttl = 600, private int $timeout = 5, private int $cooldown = 30, ?\Closure $fetch = null)
    {
        if ($ttl < 1 || $timeout < 1 || $cooldown < 0 || !is_dir($directory) || !is_writable($directory)) throw new \InvalidArgumentException('Invalid JWKS cache settings or directory');
        $this->file = rtrim($directory, '/') . '/' . hash('sha256', $issuer) . '.json';
        $this->fetch = $fetch ?? static function (string $url, int $timeout): array {
            $curl = curl_init($url);
            curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => $timeout,
                CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS]);
            $bytes = 0;
            $body = '';
            curl_setopt($curl, CURLOPT_WRITEFUNCTION, static function ($handle, string $chunk) use (&$body, &$bytes): int {
                $bytes += strlen($chunk);
                if ($bytes > 1048576) return 0;
                $body .= $chunk;
                return strlen($chunk);
            });
            $ok = curl_exec($curl);
            $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            curl_close($curl);
            if ($ok === false || $status !== 200) throw new AccessException('JWKS_UNAVAILABLE', 503);
            return json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        };
    }
    public function key(string $kid): \Firebase\JWT\Key
    {
        $handle = fopen($this->file, 'c+');
        if (!$handle) throw new AccessException('JWKS_CACHE_UNAVAILABLE', 503);
        chmod($this->file, 0600);
        $deadline = microtime(true) + $this->timeout;
        try {
            while (!flock($handle, LOCK_EX | LOCK_NB)) {
                if (microtime(true) >= $deadline) throw new AccessException('JWKS_CACHE_BUSY', 503);
                usleep(10000);
            }
            $raw = stream_get_contents($handle);
            $cache = $raw ? json_decode($raw, true) : [];
            if (!is_array($cache)) $cache = [];
            $now = time();
            $fresh = isset($cache['fetchedAt']) && $now - $cache['fetchedAt'] < $this->ttl;
            if ($fresh && isset($cache['keys'][$kid])) return $this->parse($cache['keys'][$kid]);
            if (isset($cache['attemptedAt']) && $now - $cache['attemptedAt'] < $this->cooldown) {
                throw new AccessException($fresh ? 'UNKNOWN_KEY' : 'JWKS_UNAVAILABLE', $fresh ? 401 : 503);
            }
            $cache['attemptedAt'] = $now;
            $this->write($handle, $cache);
            try {
                $jwks = ($this->fetch)($this->issuer . '/cdn-cgi/access/certs', $this->timeout);
                if (!isset($jwks['keys']) || !is_array($jwks['keys']) || !$jwks['keys']) throw new \UnexpectedValueException('Invalid JWKS');
                $keys = [];
                foreach ($jwks['keys'] as $key) {
                    if (($key['kty'] ?? '') !== 'RSA' || ($key['alg'] ?? 'RS256') !== 'RS256' || ($key['use'] ?? 'sig') !== 'sig' ||
                        !is_string($key['kid'] ?? null) || !$key['kid'] || isset($keys[$key['kid']])) throw new \UnexpectedValueException('Invalid JWKS key');
                    $key['alg'] = 'RS256';
                    $this->parse($key);
                    $keys[$key['kid']] = $key;
                }
                $cache = ['fetchedAt' => time(), 'attemptedAt' => time(), 'keys' => $keys];
                $this->write($handle, $cache);
            } catch (\Throwable $error) {
                // A failed rotation refresh does not invalidate still-fresh, already-known keys.
                throw new AccessException('JWKS_UNAVAILABLE', 503);
            }
            if (!isset($cache['keys'][$kid])) throw new AccessException('UNKNOWN_KEY');
            return $this->parse($cache['keys'][$kid]);
        } finally { flock($handle, LOCK_UN); fclose($handle); }
    }
    private function parse(array $key): \Firebase\JWT\Key { return \Firebase\JWT\JWK::parseKey($key, 'RS256'); }
    private function write($handle, array $cache): void
    {
        $data = json_encode($cache, JSON_THROW_ON_ERROR);
        rewind($handle);
        if (!ftruncate($handle, 0) || fwrite($handle, $data) !== strlen($data) || !fflush($handle)) throw new AccessException('JWKS_CACHE_UNAVAILABLE', 503);
    }
}
