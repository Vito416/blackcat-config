<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\ConfigDirPolicy;
use BlackCat\Config\Security\SecurityException;
use BlackCat\Config\Security\SecureDir;
use BlackCat\Config\Security\SecureFsTestOverrides;
use PHPUnit\Framework\TestCase;

final class SecureDirTest extends TestCase
{
    public function testAcceptsStrictSecretsDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);
        try {
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
            self::assertTrue(true);
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsWorldReadableExecutableDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0755);
        try {
            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsGroupWritableDir(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0770);
        try {
            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            @rmdir($dir);
        }
    }

    public function testRejectsSymlinkParentDirectory(): void
    {
        if (DIRECTORY_SEPARATOR === '\\' || !function_exists('symlink')) {
            self::markTestSkipped('Symlink test not supported on this platform.');
        }

        $base = $this->makeTmpDir(0700);
        $realParent = $base . '/real';
        $targetDir = $realParent . '/keys';

        if (!mkdir($targetDir, 0700, true) && !is_dir($targetDir)) {
            self::fail('Cannot create dir: ' . $targetDir);
        }
        @chmod($realParent, 0700);
        @chmod($targetDir, 0700);

        $linkParent = $base . '/link';

        try {
            if (!@symlink($realParent, $linkParent)) {
                self::markTestSkipped('Unable to create symlink (permissions).');
            }

            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($linkParent . '/keys', ConfigDirPolicy::secretsDir());
        } finally {
            @unlink($linkParent);
            @rmdir($targetDir);
            @rmdir($realParent);
            @rmdir($base);
        }
    }

    public function testRejectsUnexpectedOwnerWhenRunningAsRoot(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            self::markTestSkipped('POSIX permissions required.');
        }

        $dir = $this->makeTmpDir(0700);

        try {
            SecureFsTestOverrides::enable();
            SecureFsTestOverrides::forceEuid(0);
            SecureFsTestOverrides::forceOwner($dir, 12345);

            $this->expectException(SecurityException::class);
            SecureDir::assertSecureReadableDir($dir, ConfigDirPolicy::secretsDir());
        } finally {
            SecureFsTestOverrides::disable();
            @rmdir($dir);
        }
    }

    private function makeTmpDir(int $mode): string
    {
        $tmpBase = rtrim(sys_get_temp_dir(), '/\\');
        $dir = $tmpBase . '/blackcat-config-dir-' . bin2hex(random_bytes(6));
        if (!mkdir($dir, $mode, true) && !is_dir($dir)) {
            self::fail('Cannot create temp dir: ' . $dir);
        }
        @chmod($dir, $mode);
        return $dir;
    }
}
