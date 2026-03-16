<?php

declare(strict_types=1);

namespace BlackCat\Config\Security;

/**
 * Test-only namespace overrides for POSIX ownership checks.
 *
 * This allows us to simulate "running as root" behavior in unit tests without
 * requiring real root privileges or chown().
 */
final class SecureFsTestOverrides
{
    private static bool $enabled = false;

    private static ?int $forcedEuid = null;

    /** @var array<string,int> */
    private static array $forcedOwners = [];

    public static function enable(): void
    {
        self::$enabled = true;
    }

    public static function disable(): void
    {
        self::$enabled = false;
        self::$forcedEuid = null;
        self::$forcedOwners = [];
    }

    public static function forceEuid(?int $euid): void
    {
        self::$forcedEuid = $euid;
    }

    public static function forceOwner(string $path, int $owner): void
    {
        self::$forcedOwners[$path] = $owner;
    }

    public static function getForcedEuid(): ?int
    {
        if (!self::$enabled) {
            return null;
        }
        return self::$forcedEuid;
    }

    public static function getForcedOwner(string $path): ?int
    {
        if (!self::$enabled) {
            return null;
        }
        return self::$forcedOwners[$path] ?? null;
    }
}

function posix_geteuid(): int
{
    $forced = SecureFsTestOverrides::getForcedEuid();
    if ($forced !== null) {
        return $forced;
    }

    if (!\function_exists('\\posix_geteuid')) {
        // Best-effort fallback for environments without ext-posix.
        return -1;
    }

    return \posix_geteuid();
}

function fileowner(string $path): int|false
{
    $forced = SecureFsTestOverrides::getForcedOwner($path);
    if ($forced !== null) {
        return $forced;
    }

    return \fileowner($path);
}

