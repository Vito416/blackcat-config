<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests;

use BlackCat\Config\Config\ProfileConfig;
use BlackCat\Config\Security\SecurityChecklist;
use PHPUnit\Framework\TestCase;

final class ProfileConfigTest extends TestCase
{
    public function testAllProfilesPassSecurityChecklist(): void
    {
        $config = ProfileConfig::fromFile(__DIR__ . '/../config/profiles.php');
        self::assertNotSame([], $config->profiles());

        $security = new SecurityChecklist();

        foreach ($config->profiles() as $profile) {
            $issues = $security->validate($profile);

            self::assertSame(
                [],
                $issues,
                $profile->name() . ': ' . implode('; ', $issues)
            );
        }
    }
}
