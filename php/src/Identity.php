<?php
namespace CfAccess;

final class Identity implements \JsonSerializable
{
    public function __construct(public readonly string $issuer, public readonly string $subject, public readonly string $email, public readonly int $expiresAt) {}
    public function jsonSerialize(): array { return get_object_vars($this); }
    public static function normalizeEmail(string $email): string { return mb_strtolower(trim($email), 'UTF-8'); }
}
