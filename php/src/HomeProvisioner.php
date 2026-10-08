<?php
namespace CfAccess;

final class HomeProvisioner
{
    private string $root;
    public function __construct(string $root)
    {
        $real = realpath($root);
        if ($real === false || !is_dir($real)) throw new \InvalidArgumentException('Storage root must exist');
        $this->root = $real;
    }
    public function ensure(string $home): void
    {
        if (!str_starts_with($home, '/') || preg_match('#(^|/)\.\.?(/|$)|[\\\\\x00]#', $home)) throw new AccessException('INVALID_HOME', 403);
        $current = $this->root;
        foreach (array_filter(explode('/', $home), static fn ($s) => $s !== '') as $part) {
            $current .= '/' . $part;
            if (is_link($current)) throw new AccessException('UNSAFE_HOME', 403);
            if (!is_dir($current) && !@mkdir($current, 0700) && !is_dir($current)) throw new AccessException('HOME_UNAVAILABLE', 503);
            $real = realpath($current);
            if ($real === false || !str_starts_with($real, $this->root . '/')) throw new AccessException('UNSAFE_HOME', 403);
        }
    }
}
