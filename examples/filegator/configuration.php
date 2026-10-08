<?php
// Copy into the patched FileGator root after installing cf-access/auth via Composer.
$config = require __DIR__ . '/configuration_sample.php';
$required = static function (string $name): string {
    $value = getenv($name);
    if (!$value) throw new RuntimeException("Set $name");
    return $value;
};
$auth = ['handler' => '\\CfAccess\\FileGator\\CloudflareAccess', 'config' => [
    'teamDomain' => $required('CF_TEAM_DOMAIN'), 'audience' => explode(',', $required('CF_ACCESS_AUD')),
    'cacheDirectory' => __DIR__ . '/private/cf-access-cache',
    'database' => __DIR__ . '/private/cf-access.sqlite', 'storageRoot' => __DIR__ . '/repository',
    'adminEmails' => array_filter(explode(',', getenv('CF_ADMIN_EMAILS') ?: '')),
    'onDiagnostic' => static function (array $event): void { error_log(json_encode($event)); },
]];
$config['services']['Filegator\\Services\\Security\\Security']['config']['csrf_key'] = $required('CF_CSRF_KEY');
$config['frontend_config']['cloudflare_access'] = true;
$config['frontend_config']['logout_url'] = '/cdn-cgi/access/logout';
// Authentication and session identity changes must happen before CSRF evaluation.
$services = [];
foreach ($config['services'] as $key => $service) {
    if ($key === 'Filegator\\Services\\Auth\\AuthInterface') continue;
    $services[$key] = $service;
    if ($key === 'Filegator\\Services\\Session\\SessionStorageInterface') $services['Filegator\\Services\\Auth\\AuthInterface'] = $auth;
}
$config['services'] = $services;
return $config;
