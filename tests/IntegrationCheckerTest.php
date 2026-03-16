<?php
declare(strict_types=1);

namespace BlackCat\Config\Tests;

use BlackCat\Config\Integration\IntegrationChecker;
use BlackCat\Config\Profile\ConfigProfile;
use PHPUnit\Framework\TestCase;

final class IntegrationCheckerTest extends TestCase
{
    public function testReportsMissingIntegrationsAndIgnoresExternalReferences(): void
    {
        $tmpDir = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-config-' . bin2hex(random_bytes(6));
        if (!mkdir($tmpDir, 0770, true) && !is_dir($tmpDir)) {
            self::fail('Cannot create temp dir: ' . $tmpDir);
        }

        $script = $tmpDir . '/ok.sh';

        try {
            file_put_contents($script, "#!/bin/sh\necho ok\n");
            @chmod($script, 0755);

            $profile = ConfigProfile::fromArray([
                'name' => 'dev',
                'environment' => 'development',
                'integrations' => [
                    'ok' => $script,
                    'missing' => 'missing-file',
                    'external' => 'https://example.com/bin',
                ],
            ], $tmpDir);

            $issues = (new IntegrationChecker())->check($profile);

            self::assertSame([
                'Integration missing not found at ' . $tmpDir . '/missing-file',
            ], $issues);
        } finally {
            if (is_file($script)) {
                @unlink($script);
            }
            if (is_dir($tmpDir)) {
                @rmdir($tmpDir);
            }
        }
    }
}

