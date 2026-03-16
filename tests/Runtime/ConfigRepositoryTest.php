<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Runtime\ConfigRepository;
use PHPUnit\Framework\TestCase;

final class ConfigRepositoryTest extends TestCase
{
    public function testDotNotationLookup(): void
    {
        $repo = ConfigRepository::fromArray([
            'db' => [
                'dsn' => 'mysql:host=localhost',
            ],
            'feature' => [
                'flags' => [
                    'a' => true,
                ],
            ],
        ]);

        self::assertSame('mysql:host=localhost', $repo->get('db.dsn'));
        self::assertSame(true, $repo->get('feature.flags.a'));
        self::assertSame(null, $repo->get('missing.key'));
        self::assertSame('x', $repo->get('missing.key', 'x'));
    }

    public function testRequireStringThrowsWhenMissing(): void
    {
        $repo = ConfigRepository::fromArray(['db' => []]);
        $this->expectException(\RuntimeException::class);
        $repo->requireString('db.dsn');
    }

    public function testFromJsonFileRejectsRuntimeConfigUnderDocumentRoot(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX-only filesystem test.');
        }

        $base = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-config-docroot-' . bin2hex(random_bytes(6));
        if (!mkdir($base, 0700, true) && !is_dir($base)) {
            self::fail('Cannot create temp dir: ' . $base);
        }
        @chmod($base, 0700);

        $path = $base . '/config.runtime.json';
        file_put_contents($path, "{}\n");
        @chmod($path, 0600);

        $old = $_SERVER['DOCUMENT_ROOT'] ?? null;
        $_SERVER['DOCUMENT_ROOT'] = $base;

        try {
            $this->expectException(SecurityException::class);
            ConfigRepository::fromJsonFile($path);
        } finally {
            if ($old !== null) {
                $_SERVER['DOCUMENT_ROOT'] = $old;
            } else {
                unset($_SERVER['DOCUMENT_ROOT']);
            }
            @unlink($path);
            @rmdir($base);
        }
    }

    public function testResolvePathRejectsTraversalSegments(): void
    {
        $repo = ConfigRepository::fromArray([]);
        $this->expectException(\RuntimeException::class);
        $repo->resolvePath('../secrets');
    }

    public function testFromJsonFileRejectsRelativePath(): void
    {
        $base = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-config-rel-' . bin2hex(random_bytes(6));
        if (!mkdir($base, 0700, true) && !is_dir($base)) {
            self::fail('Cannot create temp dir: ' . $base);
        }
        @chmod($base, 0700);

        $path = $base . '/config.runtime.json';
        file_put_contents($path, "{}\n");
        @chmod($path, 0600);

        $oldCwd = getcwd();
        try {
            chdir($base);
            $this->expectException(SecurityException::class);
            ConfigRepository::fromJsonFile('config.runtime.json');
        } finally {
            if (is_string($oldCwd) && $oldCwd !== '') {
                @chdir($oldCwd);
            }
            @unlink($path);
            @rmdir($base);
        }
    }
}
