<?php
declare(strict_types=1);

// Reproducible synthetic interoperability vector; never reads an application key.
// Usage: php this-file.php /path/to/A1/api/vendor > a1-legacy-access-token.json
// Matches f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74 User::generateAccessToken
// and files/api/config/web.php's HS256 / METHOD_FILE configuration.
$vendor = $argv[1];
require $vendor . '/autoload.php';
require $vendor . '/yiisoft/yii2/Yii.php';
$secret = " \t" . 'synthetic-a1-fixture-key-0123456789abcdef' . "\r\n";
$file = tempnam(sys_get_temp_dir(), 'a1-jwt-fixture-');
try {
    file_put_contents($file, $secret);
    $jwt = new \bizley\jwt\Jwt([
        'signer' => \bizley\jwt\Jwt::HS256,
        'signingKey' => ['key' => $file, 'method' => \bizley\jwt\Jwt::METHOD_FILE, 'passphrase' => ''],
    ]);
    $now = new \DateTimeImmutable('2026-10-12T00:00:00.123456Z');
    $builder = $jwt->getBuilder()
        ->issuedBy('https://a1.example.test')
        ->issuedAt($now)
        ->canOnlyBeUsedAfter($now)
        ->expiresAt($now->modify('+3 hour'));
    $token = $builder->withClaim('uid', 42)->getToken($jwt->getConfiguration()->signer(), $jwt->getConfiguration()->signingKey());
    $stringToken = $builder->withClaim('uid', '42')->getToken($jwt->getConfiguration()->signer(), $jwt->getConfiguration()->signingKey());
    echo json_encode([
        'syntheticOnly' => true,
        'sourceRevision' => 'f5bf6667a6fc5bfc65590f13bccd9d8ba0612a74',
        'bizleyVersion' => \Composer\InstalledVersions::getPrettyVersion('bizley/jwt'),
        'lcobucciVersion' => \Composer\InstalledVersions::getPrettyVersion('lcobucci/jwt'),
        'secretBase64' => base64_encode($secret),
        'token' => $token->toString(),
        'stringUidToken' => $stringToken->toString(),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
} finally {
    unlink($file);
}
