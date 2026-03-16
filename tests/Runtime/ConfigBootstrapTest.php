<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Runtime;

use BlackCat\Config\Runtime\ConfigBootstrap;
use PHPUnit\Framework\TestCase;

final class ConfigBootstrapTest extends TestCase
{
    public function testDefaultJsonPathsIncludeDocumentRootParentCandidates(): void
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
            $paths = ConfigBootstrap::defaultJsonPaths();

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

    public function testTryLoadReturnsNullWhenNoFilesExist(): void
    {
        $repo = ConfigBootstrap::tryLoadFirstAvailableJsonFile([
            '/this/path/should/not/exist-' . bin2hex(random_bytes(4)) . '.json',
        ]);

        self::assertNull($repo);
    }

    public function testLoadReturnsRepoFromFirstExistingSecureFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{\n  \"db\": {\"dsn\": \"mysql:host=localhost;dbname=test\"}\n}\n");
        chmod($path, 0600);

        try {
            $repo = ConfigBootstrap::loadFirstAvailableJsonFile([
                '/does/not/exist-' . bin2hex(random_bytes(4)) . '.json',
                $path,
            ]);

            self::assertSame('mysql:host=localhost;dbname=test', $repo->requireString('db.dsn'));
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testLoadSkipsRejectedFilesAndUsesNextCandidate(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $bad = $dir . '/bad.json';
        file_put_contents($bad, "{\n  \"db\": {\"dsn\": \"bad\"}\n}\n");
        chmod($bad, 0644); // rejected (world-readable)

        $good = $dir . '/good.json';
        file_put_contents($good, "{\n  \"db\": {\"dsn\": \"mysql:host=localhost;dbname=test\"}\n}\n");
        chmod($good, 0600);

        try {
            $repo = ConfigBootstrap::loadFirstAvailableJsonFile([$bad, $good]);
            self::assertSame('mysql:host=localhost;dbname=test', $repo->requireString('db.dsn'));
        } finally {
            @unlink($bad);
            @unlink($good);
            @rmdir($dir);
        }
    }

    public function testLoadReportsRejectedFilesWhenNoneAreUsable(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $bad = $dir . '/bad.json';
        file_put_contents($bad, "{\n  \"db\": {\"dsn\": \"bad\"}\n}\n");
        chmod($bad, 0644);

        try {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessage('Rejected files:');
            ConfigBootstrap::loadFirstAvailableJsonFile([$bad]);
        } finally {
            @unlink($bad);
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-bootstrap-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
