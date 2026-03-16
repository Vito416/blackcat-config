<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeConfigValidator;
use PHPUnit\Framework\TestCase;

final class RuntimeConfigValidatorTest extends TestCase
{
    public function testHttpConfigValidatesTrustedProxies(): void
    {
        $repo = ConfigRepository::fromArray([
            'http' => [
                'trusted_proxies' => [
                    '127.0.0.1',
                    '10.0.0.0/8',
                    '::1',
                    '2001:db8::/32',
                ],
            ],
        ]);

        RuntimeConfigValidator::assertHttpConfig($repo);
        self::assertTrue(true);
    }

    public function testHttpConfigRejectsInvalidTrustedProxy(): void
    {
        $repo = ConfigRepository::fromArray([
            'http' => [
                'trusted_proxies' => [
                    'not-an-ip',
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertHttpConfig($repo);
    }

    public function testHttpConfigValidatesAllowedHosts(): void
    {
        $repo = ConfigRepository::fromArray([
            'http' => [
                'allowed_hosts' => [
                    'localhost',
                    '127.0.0.1',
                    'Example.COM:443',
                    '*.example.com',
                    '[::1]:443',
                ],
            ],
        ]);

        RuntimeConfigValidator::assertHttpConfig($repo);
        self::assertTrue(true);
    }

    public function testHttpConfigRejectsUrlInAllowedHosts(): void
    {
        $repo = ConfigRepository::fromArray([
            'http' => [
                'allowed_hosts' => [
                    'https://example.com',
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertHttpConfig($repo);
    }

    public function testDbConfigRequiresAgentSocketPathWhenTrustKernelIsConfigured(): void
    {
        $repo = ConfigRepository::fromArray([
            'trust' => [
                'web3' => [],
            ],
            'db' => [],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertDbConfig($repo);
    }

    public function testDbConfigRejectsInlineCredentialsInTrustKernelDeployments(): void
    {
        $repo = ConfigRepository::fromArray([
            'trust' => [
                'web3' => [],
            ],
            'db' => [
                'agent' => [
                    'socket_path' => '/tmp/blackcat-db-agent.sock',
                ],
                'dsn' => 'mysql:host=127.0.0.1;dbname=test',
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertDbConfig($repo);
    }

    public function testCryptoConfigAllowsAgentModeWithKeysDir(): void
    {
        $repo = ConfigRepository::fromArray([
            'crypto' => [
                'keys_dir' => '/etc/blackcat/keys',
                'agent' => [
                    'socket_path' => '/tmp/blackcat-secrets-agent.sock',
                ],
            ],
        ]);

        RuntimeConfigValidator::assertCryptoConfig($repo);
        self::assertTrue(true);
    }

    public function testCryptoConfigRequiresKeysDir(): void
    {
        $repo = ConfigRepository::fromArray(['crypto' => []]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertCryptoConfig($repo);
    }

    public function testCryptoConfigValidatesKeysDirAndManifest(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $keysDir = $this->makeTmpDir(0700);
        $manifest = $keysDir . '/manifest.json';
        file_put_contents($manifest, "{\n  \"slots\": {}\n}\n");
        @chmod($manifest, 0644); // public-readable allowed for manifest policy

        try {
            $repo = ConfigRepository::fromArray([
                'crypto' => [
                    'keys_dir' => $keysDir,
                    'manifest' => $manifest,
                ],
            ]);

            RuntimeConfigValidator::assertCryptoConfig($repo);
            self::assertTrue(true);
        } finally {
            @unlink($manifest);
            @rmdir($keysDir);
        }
    }

    public function testCryptoConfigResolvesPathsRelativeToConfigFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $keysDir = $base . '/keys';
        if (!mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Cannot create keys dir: ' . $keysDir);
        }
        @chmod($keysDir, 0700);

        $manifestAbs = $keysDir . '/manifest.json';
        file_put_contents($manifestAbs, "{\n  \"slots\": {}\n}\n");
        @chmod($manifestAbs, 0644);

        $configPath = $base . '/config.runtime.json';
        $configJson = json_encode([
            'crypto' => [
                'keys_dir' => 'keys',
                'manifest' => 'keys/manifest.json',
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (!is_string($configJson)) {
            self::fail('Unable to encode JSON.');
        }
        file_put_contents($configPath, $configJson . "\n");
        @chmod($configPath, 0600);

        try {
            $repo = ConfigRepository::fromJsonFile($configPath);
            RuntimeConfigValidator::assertCryptoConfig($repo);
            self::assertTrue(true);
        } finally {
            @unlink($configPath);
            @unlink($manifestAbs);
            @rmdir($keysDir);
            @rmdir($base);
        }
    }

    public function testObservabilityConfigRequiresStorageDir(): void
    {
        $repo = ConfigRepository::fromArray(['observability' => []]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertObservabilityConfig($repo);
    }

    public function testObservabilityConfigValidatesStorageDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $storageDir = $this->makeTmpDir(0700);
        try {
            $repo = ConfigRepository::fromArray([
                'observability' => [
                    'storage_dir' => $storageDir,
                    'service' => 'blackcat-app',
                ],
            ]);

            RuntimeConfigValidator::assertObservabilityConfig($repo);
            self::assertTrue(true);
        } finally {
            @rmdir($storageDir);
        }
    }

    public function testObservabilityConfigRejectsSymlinkStorageDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\' || !function_exists('symlink')) {
            self::markTestSkipped('Symlink test not supported on this platform.');
        }

        $base = $this->makeTmpDir(0700);
        $target = $base . '/target';
        $link = $base . '/storage';
        if (!mkdir($target, 0700, true) && !is_dir($target)) {
            self::fail('Cannot create target dir: ' . $target);
        }
        @chmod($target, 0700);

        try {
            if (!@symlink($target, $link)) {
                self::markTestSkipped('Unable to create symlink (permissions).');
            }

            $repo = ConfigRepository::fromArray([
                'observability' => [
                    'storage_dir' => $link,
                ],
            ]);

            $this->expectException(SecurityException::class);
            RuntimeConfigValidator::assertObservabilityConfig($repo);
        } finally {
            @unlink($link);
            @rmdir($target);
            @rmdir($base);
        }
    }

    public function testTrustKernelValidatorIsNoOpWhenNotConfigured(): void
    {
        $repo = ConfigRepository::fromArray(['crypto' => ['keys_dir' => '/tmp']]);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
        self::assertTrue(true);
    }

    public function testTrustKernelConfigRequiresChainIdWhenTrustPresent(): void
    {
        $repo = ConfigRepository::fromArray(['trust' => ['web3' => []]]);
        $this->expectException(\RuntimeException::class);
        RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
    }

    public function testTrustKernelConfigValidatesBasicFields(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $outboxDir = $base . '/outbox';
        $rootDir = $base . '/root';
        if (!mkdir($outboxDir, 0700, true) && !is_dir($outboxDir)) {
            self::fail('Cannot create outbox dir: ' . $outboxDir);
        }
        if (!mkdir($rootDir, 0700, true) && !is_dir($rootDir)) {
            self::fail('Cannot create root dir: ' . $rootDir);
        }

        $manifestPath = $base . '/integrity.manifest.json';
        file_put_contents($manifestPath, json_encode([
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => [
                'README.md' => '0x' . str_repeat('11', 32),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        @chmod($manifestPath, 0644);

        try {
            $repo = ConfigRepository::fromArray([
                'trust' => [
                    'integrity' => [
                        'root_dir' => $rootDir,
                        'manifest' => $manifestPath,
                    ],
                    'web3' => [
                        'chain_id' => 4207,
                        'rpc_endpoints' => [
                            'https://rpc.layeredge.io',
                        ],
                        'rpc_quorum' => 1,
                        'max_stale_sec' => 180,
                        'mode' => 'root_uri',
                        'contracts' => [
                            'instance_controller' => '0x1111111111111111111111111111111111111111',
                            'release_registry' => '0x2222222222222222222222222222222222222222',
                            'instance_factory' => '0x3333333333333333333333333333333333333333',
                        ],
                        'tx_outbox_dir' => $outboxDir,
                    ],
                ],
            ]);

            RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
            self::assertTrue(true);
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
            @rmdir($outboxDir);
            @rmdir($base);
        }
    }

    public function testTrustKernelConfigAllowsLargeIntegrityManifestFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $rootDir = $base . '/root';
        if (!mkdir($rootDir, 0700, true) && !is_dir($rootDir)) {
            self::fail('Cannot create root dir: ' . $rootDir);
        }

        $manifestPath = $base . '/integrity.manifest.json';
        $payload = [
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => [
                'README.md' => '0x' . str_repeat('11', 32),
            ],
            'padding' => str_repeat('a', (1024 * 1024) + 32),
        ];
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            self::fail('Unable to encode JSON.');
        }
        file_put_contents($manifestPath, $json . "\n");
        @chmod($manifestPath, 0644);

        try {
            $repo = ConfigRepository::fromArray([
                'trust' => [
                    'integrity' => [
                        'root_dir' => $rootDir,
                        'manifest' => $manifestPath,
                    ],
                    'web3' => [
                        'chain_id' => 4207,
                        'rpc_endpoints' => [
                            'https://rpc.layeredge.io',
                        ],
                        'rpc_quorum' => 1,
                        'contracts' => [
                            'instance_controller' => '0x1111111111111111111111111111111111111111',
                        ],
                    ],
                ],
            ]);

            RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
            self::assertTrue(true);
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
            @rmdir($base);
        }
    }

    public function testTrustKernelConfigRejectsNonTlsRpcEndpoint(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $rootDir = $base . '/root';
        if (!mkdir($rootDir, 0700, true) && !is_dir($rootDir)) {
            self::fail('Cannot create root dir: ' . $rootDir);
        }
        $manifestPath = $base . '/integrity.manifest.json';
        file_put_contents($manifestPath, json_encode([
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => [
                'README.md' => '0x' . str_repeat('11', 32),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        @chmod($manifestPath, 0644);

        $repo = ConfigRepository::fromArray([
            'trust' => [
                'integrity' => [
                    'root_dir' => $rootDir,
                    'manifest' => $manifestPath,
                ],
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => ['http://rpc.layeredge.io'],
                    'rpc_quorum' => 1,
                    'contracts' => [
                        'instance_controller' => '0x1111111111111111111111111111111111111111',
                    ],
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        try {
            RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
            @rmdir($base);
        }
    }

    public function testTrustKernelConfigRejectsQuorumAboveEndpointsCount(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $rootDir = $base . '/root';
        if (!mkdir($rootDir, 0700, true) && !is_dir($rootDir)) {
            self::fail('Cannot create root dir: ' . $rootDir);
        }
        $manifestPath = $base . '/integrity.manifest.json';
        file_put_contents($manifestPath, json_encode([
            'schema_version' => 1,
            'type' => 'blackcat.integrity.manifest',
            'files' => [
                'README.md' => '0x' . str_repeat('11', 32),
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        @chmod($manifestPath, 0644);

        $repo = ConfigRepository::fromArray([
            'trust' => [
                'integrity' => [
                    'root_dir' => $rootDir,
                    'manifest' => $manifestPath,
                ],
                'web3' => [
                    'chain_id' => 4207,
                    'rpc_endpoints' => [
                        'https://rpc.layeredge.io',
                        'https://rpc.layeredge.io',
                    ],
                    'rpc_quorum' => 3,
                    'contracts' => [
                        'instance_controller' => '0x1111111111111111111111111111111111111111',
                    ],
                ],
            ],
        ]);

        $this->expectException(\RuntimeException::class);
        try {
            RuntimeConfigValidator::assertTrustKernelWeb3Config($repo);
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
            @rmdir($base);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-keys-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
