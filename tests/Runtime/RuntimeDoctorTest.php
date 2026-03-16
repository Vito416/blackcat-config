<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\ConfigRepository;
use BlackCat\Config\Runtime\RuntimeDoctor;
use PHPUnit\Framework\TestCase;

final class RuntimeDoctorTest extends TestCase
{
    public function testDoctorWarnsWhenTrustKernelIsNotConfigured(): void
    {
        $repo = ConfigRepository::fromArray([]);

        $res = RuntimeDoctor::inspect($repo);

        self::assertTrue($res['ok']);
        self::assertFalse($res['ok_strict']);
        self::assertSame('compat', $res['tier']);
        self::assertTrue($this->hasFindingCode($res['findings'], 'trust_kernel_not_configured'));
    }

    public function testDoctorReportsRecommendedTrustKernelHardening(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX filesystem required.');
        }

        $rootDir = $this->makeTmpDir(0755);
        $manifestPath = $rootDir . '/integrity.manifest.json';
        file_put_contents($manifestPath, "{\n  \"schema_version\": 1,\n  \"type\": \"blackcat.integrity.manifest\",\n  \"files\": {\"a.txt\": \"0x" . str_repeat("00", 32) . "\"}\n}\n");
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
                        'rpc_endpoints' => ['https://rpc.layeredge.io'],
                        'rpc_quorum' => 1,
                        'mode' => 'full',
                        'contracts' => [
                            'instance_controller' => '0x1111111111111111111111111111111111111111',
                        ],
                    ],
                ],
            ]);

            $res = RuntimeDoctor::inspect($repo);

            self::assertTrue($res['ok'], 'doctor should not report hard errors for recommended posture warnings');
            self::assertFalse($res['ok_strict']);
            self::assertSame('medium', $res['tier']);
            self::assertTrue($this->hasFindingCode($res['findings'], 'rpc_quorum_insecure_for_strict'));
            self::assertTrue($this->hasFindingCode($res['findings'], 'crypto_agent_missing'));
            self::assertTrue($this->hasFindingCode($res['findings'], 'tx_outbox_not_configured'));
        } finally {
            @unlink($manifestPath);
            @rmdir($rootDir);
        }
    }

    public function testDoctorErrorsWhenKeysDirIsInsideDocumentRoot(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX filesystem required.');
        }

        $docRoot = $this->makeTmpDir(0700);
        $keysDir = $docRoot . '/keys';
        if (!mkdir($keysDir, 0700, true) && !is_dir($keysDir)) {
            self::fail('Cannot create keys dir: ' . $keysDir);
        }
        @chmod($keysDir, 0700);

        $oldDocRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
        $_SERVER['DOCUMENT_ROOT'] = $docRoot;

        try {
            $repo = ConfigRepository::fromArray([
                'crypto' => [
                    'keys_dir' => $keysDir,
                ],
            ]);

            $res = RuntimeDoctor::inspect($repo);
            self::assertFalse($res['ok']);
            self::assertTrue($this->hasFindingCode($res['findings'], 'path_inside_document_root'));
        } finally {
            if ($oldDocRoot !== null) {
                $_SERVER['DOCUMENT_ROOT'] = $oldDocRoot;
            } else {
                unset($_SERVER['DOCUMENT_ROOT']);
            }
            @rmdir($keysDir);
            @rmdir($docRoot);
        }
    }

    /**
     * @param list<array{code:string}> $findings
     */
    private function hasFindingCode(array $findings, string $code): bool
    {
        foreach ($findings as $f) {
            if ($f['code'] === $code) {
                return true;
            }
        }
        return false;
    }

    private function makeTmpDir(int $mode): string
    {
        $base = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $base . '/blackcat-config-doctor-' . bin2hex(random_bytes(6));
        mkdir($dir, $mode, true);
        @chmod($dir, $mode);
        return $dir;
    }
}
