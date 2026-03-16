<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\ConfigFilePolicy;
use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Security\SecureFile;
use BlackCat\Config\Security\SecureFsTestOverrides;
use PHPUnit\Framework\TestCase;

final class SecureFileTest extends TestCase
{
    public function testAcceptsStrictSecureJsonFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0600);

        try {
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
            self::assertTrue(true);
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testRejectsWorldReadableFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0644);

        try {
            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testRejectsWorldWritableFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0602);

        try {
            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testRejectsGroupWritableFile(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0660);

        try {
            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testRejectsWorldWritableDirectory(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0777);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0600);

        try {
            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
        } finally {
            @unlink($path);
            @rmdir($dir);
        }
    }

    public function testRejectsSymlinkByDefault(): void
    {
        if (DIRECTORY_SEPARATOR === '\\' || !function_exists('symlink')) {
            self::markTestSkipped('Symlink test not supported on this platform.');
        }

        $dir = $this->makeTmpDir(0700);
        $target = $dir . '/target.json';
        $link = $dir . '/config.json';
        file_put_contents($target, "{}\n");
        chmod($target, 0600);

        try {
            if (!@symlink($target, $link)) {
                self::markTestSkipped('Unable to create symlink (permissions).');
            }

            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($link, ConfigFilePolicy::strict());
        } finally {
            @unlink($link);
            @unlink($target);
            @rmdir($dir);
        }
    }

    public function testRejectsSymlinkParentDirectory(): void
    {
        if (DIRECTORY_SEPARATOR === '\\' || !function_exists('symlink')) {
            self::markTestSkipped('Symlink test not supported on this platform.');
        }

        $base = $this->makeTmpDir(0700);
        $realDir = $base . '/real';
        if (!mkdir($realDir, 0700, true) && !is_dir($realDir)) {
            self::fail('Cannot create dir: ' . $realDir);
        }
        @chmod($realDir, 0700);

        $target = $realDir . '/config.json';
        file_put_contents($target, "{}\n");
        @chmod($target, 0600);

        $linkDir = $base . '/link';

        try {
            if (!@symlink($realDir, $linkDir)) {
                self::markTestSkipped('Unable to create symlink (permissions).');
            }

            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($linkDir . '/config.json', ConfigFilePolicy::strict());
        } finally {
            @unlink($linkDir);
            @unlink($target);
            @rmdir($realDir);
            @rmdir($base);
        }
    }

    public function testRejectsUnexpectedOwnerWhenRunningAsRoot(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        $path = $dir . '/config.json';
        file_put_contents($path, "{}\n");
        chmod($path, 0600);

        try {
            SecureFsTestOverrides::enable();
            SecureFsTestOverrides::forceEuid(0);
            SecureFsTestOverrides::forceOwner($path, 12345);

            $this->expectException(SecurityException::class);
            SecureFile::assertSecureReadableFile($path, ConfigFilePolicy::strict());
        } finally {
            SecureFsTestOverrides::disable();
            @unlink($path);
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-sec-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
