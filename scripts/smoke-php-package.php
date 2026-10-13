<?php
// Build and install the actual archive; do not load checkout classes.
$root = dirname(__DIR__);
$directory = sys_get_temp_dir() . '/cf-access-composer-consumer-' . bin2hex(random_bytes(8));
mkdir($directory, 0700);
function runPackageCommand(array $command, string $cwd): void {
    $process = proc_open($command, [1=>['pipe','w'],2=>['pipe','w']], $pipes, $cwd);
    if (!is_resource($process)) throw new RuntimeException('Could not start package check');
    $output = stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    if (proc_close($process) !== 0) throw new RuntimeException($output . $errors);
}
function removePackageDirectory(string $path): void {
    foreach (scandir($path) as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $child = $path . '/' . $entry;
        if (is_dir($child) && !is_link($child)) removePackageDirectory($child); else unlink($child);
    }
    rmdir($path);
}
try {
    runPackageCommand(['composer','archive','--format=zip','--dir='.$directory,'--file=library','--no-interaction'], $root);
    mkdir($directory . '/library', 0700); mkdir($directory . '/consumer', 0700);
    $archive = new ZipArchive();
    if ($archive->open($directory . '/library.zip') !== true) throw new RuntimeException('Archive missing');
    $archive->extractTo($directory . '/library'); $archive->close();
    $lock = json_decode(file_get_contents($root . '/composer.lock'), true, 64, JSON_THROW_ON_ERROR);
    $version = $lock['packages'][0]['version'];
    file_put_contents($directory . '/consumer/composer.json', json_encode([
        'name'=>'test/isolated-consumer',
        'repositories'=>[['type'=>'path','url'=>$directory . '/library','options'=>['symlink'=>false,'versions'=>['cf-access/auth'=>'dev-main']]]],
        'require'=>['cf-access/auth'=>'dev-main','firebase/php-jwt'=>$version],
    ], JSON_THROW_ON_ERROR));
    runPackageCommand(['composer','install','--no-dev','--no-interaction','--no-scripts'], $directory . '/consumer');
    $program = <<<'PHP'
require 'vendor/autoload.php';
use CfAccess\{AccessException, AccessVerifier, Identity};
$f = json_decode(file_get_contents($argv[1]), true, 64, JSON_THROW_ON_ERROR);
$cache = sys_get_temp_dir() . '/cf-access-smoke-cache-' . bin2hex(random_bytes(8)); mkdir($cache,0700);
try {
    $v = new AccessVerifier(['teamDomain'=>$f['issuer'],'audience'=>$f['audience'],'cacheDirectory'=>$cache,'fetch'=>static fn () => $f['jwks']]);
    if ($v->verifyToken($f['cases']['valid']['token'])->jsonSerialize() !== $f['cases']['valid']['identity']) throw new RuntimeException('Identity mismatch');
    try { $v->authenticateRequest([]); throw new RuntimeException('Missing assertion accepted'); }
    catch (AccessException $e) { if ($e->status !== 401) throw $e; }
    if (Identity::normalizeEmail(' Alice@Example.com ') !== 'alice@example.com') throw new RuntimeException('Normalization changed');
    if (!str_starts_with((new ReflectionClass(AccessVerifier::class))->getFileName(),getcwd().'/vendor/')) throw new RuntimeException('Loaded checkout classes');
} finally { foreach (glob($cache.'/*') as $file) unlink($file); rmdir($cache); }
PHP;
    runPackageCommand([PHP_BINARY,'-r',$program,$root . '/fixtures/tokens.json'], $directory . '/consumer');
    echo "Packaged Composer consumer passed\n";
} finally {removePackageDirectory($directory);}
