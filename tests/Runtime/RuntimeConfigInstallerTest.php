<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\RuntimeConfigInstaller;
use PHPUnit\Framework\TestCase;

final class RuntimeConfigInstallerTest extends TestCase
{
    public function testDefaultWritePathsIncludeDocumentRootParentCandidates(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX-only document root candidates.');
        }

        $base = $this->makeTmpDir(0700);
        $docRoot = $base . '/public';
        mkdir($docRoot, 0755, true);
        @chmod($docRoot, 0755);

        $prevDocRoot = $_SERVER['DOCUMENT_ROOT'] ?? null;
        $prevContextDocRoot = $_SERVER['CONTEXT_DOCUMENT_ROOT'] ?? null;

        $_SERVER['DOCUMENT_ROOT'] = $docRoot;
        unset($_SERVER['CONTEXT_DOCUMENT_ROOT']);

        try {
            $paths = RuntimeConfigInstaller::defaultWritePaths();

            self::assertContains($base . '/config.runtime.json', $paths);
            self::assertContains($base . '/.blackcat/config.runtime.json', $paths);
            self::assertContains($base . '/.config/blackcat/config.runtime.json', $paths);
        } finally {
            if ($prevDocRoot !== null) {
                $_SERVER['DOCUMENT_ROOT'] = $prevDocRoot;
            } else {
                unset($_SERVER['DOCUMENT_ROOT']);
            }
            if ($prevContextDocRoot !== null) {
                $_SERVER['CONTEXT_DOCUMENT_ROOT'] = $prevContextDocRoot;
            } else {
                unset($_SERVER['CONTEXT_DOCUMENT_ROOT']);
            }
            @rmdir($docRoot);
            @rmdir($base);
        }
    }

    public function testRecommendWritePathSkipsInsecureDirAndUsesNext(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $badDir = $base . '/bad';
        $goodDir = $base . '/good';

        mkdir($badDir, 0777, true);
        @chmod($badDir, 0777);

        mkdir($goodDir, 0700, true);
        @chmod($goodDir, 0700);

        $badPath = $badDir . '/config.runtime.json';
        $goodPath = $goodDir . '/config.runtime.json';

        try {
            $rec = RuntimeConfigInstaller::recommendWritePath([$badPath, $goodPath]);
            self::assertSame($goodPath, $rec['path']);
            self::assertArrayHasKey($badPath, $rec['rejected']);
        } finally {
            @unlink($badPath);
            @unlink($goodPath);
            @rmdir($badDir);
            @rmdir($goodDir);
            @rmdir($base);
        }
    }

    public function testIsLikelyWindowsMountPathDetectsWslDrives(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('WSL detection is POSIX-only.');
        }

        self::assertTrue(RuntimeConfigInstaller::isLikelyWindowsMountPath('/mnt/c/Users/jaine/.blackcat/config.runtime.json'));
        self::assertTrue(RuntimeConfigInstaller::isLikelyWindowsMountPath('/mnt/D/blackcat/config.runtime.json'));
        self::assertFalse(RuntimeConfigInstaller::isLikelyWindowsMountPath('/home/jaine/.config/blackcat/config.runtime.json'));
    }

    public function testInitSkipsInsecureCandidateAndUsesNext(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $badDir = $base . '/bad';
        $goodDir = $base . '/good';

        mkdir($badDir, 0777, true);
        @chmod($badDir, 0777);

        mkdir($goodDir, 0700, true);
        @chmod($goodDir, 0700);

        $badPath = $badDir . '/config.runtime.json';
        $goodPath = $goodDir . '/config.runtime.json';

        try {
            $res = RuntimeConfigInstaller::init(['hello' => 'world'], null, false, [$badPath, $goodPath]);
            self::assertSame($goodPath, $res['path']);
            self::assertTrue($res['created']);
            self::assertFileExists($goodPath);
            self::assertFalse(file_exists($badPath), 'Rejected candidate must not leave runtime config on disk.');

            $mode = fileperms($goodPath);
            self::assertIsInt($mode);
            self::assertSame(0600, $mode & 0777);
        } finally {
            @unlink($badPath);
            @unlink($goodPath);
            @rmdir($badDir);
            @rmdir($goodDir);
            @rmdir($base);
        }
    }

    public function testInitDoesNotLeaveFileOnDiskWhenAllCandidatesRejected(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $base = $this->makeTmpDir(0700);
        $badDir = $base . '/bad';

        mkdir($badDir, 0777, true);
        @chmod($badDir, 0777);

        $badPath = $badDir . '/config.runtime.json';

        try {
            try {
                RuntimeConfigInstaller::init(['hello' => 'world'], $badPath, false);
                self::fail('Expected init() to fail for insecure path.');
            } catch (\RuntimeException) {
                self::assertFalse(file_exists($badPath), 'Rejected explicit path must not leave runtime config on disk.');
            }
        } finally {
            @unlink($badPath);
            @rmdir($badDir);
            @rmdir($base);
        }
    }

    public function testInitIsIdempotentWhenFileAlreadySecure(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.runtime.json';

        try {
            $first = RuntimeConfigInstaller::init(['a' => 1], $path, false);
            self::assertSame($path, $first['path']);
            self::assertTrue($first['created']);

            $second = RuntimeConfigInstaller::init(['a' => 2], $path, false);
            self::assertSame($path, $second['path']);
            self::assertFalse($second['created']);

            $raw = file_get_contents($path);
            self::assertIsString($raw);
            self::assertStringContainsString('"a": 1', $raw);
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testInitRejectsRelativePath(): void
    {
        $this->expectException(\RuntimeException::class);
        RuntimeConfigInstaller::init(['a' => 1], '.blackcat/config.runtime.json', false);
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-installer-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
