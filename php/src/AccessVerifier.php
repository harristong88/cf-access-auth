<?php
namespace CfAccess;

use Firebase\JWT\JWT;

final class AccessVerifier
{
    private string $issuer;
    private array $audience;
    private JwksCache $cache;
    private ?\Closure $diagnostic;
    public function __construct(array $config)
    {
        $domain = $config['teamDomain'] ?? '';
        if (!is_string($domain) || !preg_match('#^https://[a-z0-9-]+\.cloudflareaccess\.com/?$#D', $domain)) throw new \InvalidArgumentException('Invalid Cloudflare team domain');
        $this->issuer = rtrim($domain, '/');
        $audience = $config['audience'] ?? [];
        $this->audience = is_string($audience) ? [$audience] : $audience;
        if (!$this->audience) throw new \InvalidArgumentException('Audience is required');
        foreach ($this->audience as $aud) if (!is_string($aud) || !$aud || trim($aud) !== $aud) throw new \InvalidArgumentException('Invalid audience');
        $this->cache = new JwksCache($this->issuer, $config['cacheDirectory'], $config['cacheTtl'] ?? 600,
            $config['timeout'] ?? 5, $config['cooldown'] ?? 30, $config['fetch'] ?? null);
        $this->diagnostic = $config['onDiagnostic'] ?? null;
    }
    public function authenticateRequest(array $headers): Identity
    {
        $values = [];
        foreach ($headers as $name => $value) if (strtolower($name) === 'cf-access-jwt-assertion') $values[] = $value;
        // Symfony HeaderBag supplies arrays; exactly one member is acceptable.
        if (count($values) === 1 && is_array($values[0]) && count($values[0]) === 1) $values[0] = array_values($values[0])[0];
        if (count($values) !== 1 || !is_string($values[0])) $this->fail(new AccessException('ASSERTION_HEADER'));
        return $this->verifyToken($values[0]);
    }
    public function verifyToken(string $token): Identity
    {
        try {
            if (strlen($token) > 16384 || !preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/D', $token)) throw new AccessException('MALFORMED_TOKEN');
            $segment = explode('.', $token)[0];
            $header = json_decode(JWT::urlsafeB64Decode($segment), true, 16, JSON_THROW_ON_ERROR);
            if (($header['alg'] ?? '') !== 'RS256' || !is_string($header['kid'] ?? null) || !$header['kid']) throw new AccessException('INVALID_HEADER');
            // Header is untrusted and used only to select a key at the fixed configured endpoint.
            $key = $this->cache->key($header['kid']);
            $claims = JWT::decode($token, $key);
            foreach (['exp', 'iat', 'nbf'] as $field) if (!isset($claims->$field) || !is_int($claims->$field)) throw new AccessException('INVALID_CLAIMS');
            $now = time();
            if ($claims->exp <= $now || $claims->nbf > $now || $claims->iat > $now || $claims->exp <= $claims->iat ||
                ($claims->iss ?? null) !== $this->issuer || ($claims->type ?? null) !== 'app' ||
                !is_string($claims->sub ?? null) || !trim($claims->sub) || !is_string($claims->email ?? null) || !trim($claims->email)) throw new AccessException('INVALID_CLAIMS');
            $aud = $claims->aud ?? null;
            $aud = is_string($aud) ? [$aud] : $aud;
            if (!is_array($aud) || !$aud || array_filter($aud, static fn ($value) => !is_string($value)) || !array_intersect($this->audience, $aud)) throw new AccessException('INVALID_AUDIENCE');
            return new Identity($this->issuer, $claims->sub, trim($claims->email), $claims->exp);
        } catch (AccessException $error) { $this->fail($error); }
        catch (\Throwable $error) { $this->fail(new AccessException('INVALID_TOKEN')); }
    }
    private function fail(AccessException $error): never
    {
        try { if ($this->diagnostic) ($this->diagnostic)(['code' => $error->reason, 'status' => $error->status]); } catch (\Throwable $ignored) {}
        throw $error;
    }
}
