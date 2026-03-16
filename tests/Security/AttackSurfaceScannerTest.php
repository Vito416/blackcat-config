<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\AttackSurfaceScanner;
use PHPUnit\Framework\TestCase;

final class AttackSurfaceScannerTest extends TestCase
{
    public function testFindsEvalAndAssert(): void
    {
        $base = rtrim(sys_get_temp_dir(), "/\\") . '/blackcat_attack_scan_' . bin2hex(random_bytes(8));
        if (!mkdir($base, 0700, true) && !is_dir($base)) {
            self::fail('Unable to create temp dir: ' . $base);
        }

        $a = $base . '/a.php';
        $b = $base . '/b.php';

        file_put_contents($a, "<?php\neval('phpinfo();');\n");
        file_put_contents($b, "<?php\nassert(\$x);\n");

        try {
            $res = AttackSurfaceScanner::scan($base, ['max_files' => 50]);
            $findings = $res['findings'];

            $rules = array_map(static fn (array $f): string => $f['rule'], $findings);
            self::assertContains(AttackSurfaceScanner::RULE_EVAL, $rules);
            self::assertContains(AttackSurfaceScanner::RULE_ASSERT, $rules);

            $eval = array_values(array_filter($findings, static fn (array $f): bool => $f['rule'] === AttackSurfaceScanner::RULE_EVAL));
            self::assertNotEmpty($eval);
            self::assertSame('error', $eval[0]['severity'] ?? null);
        } finally {
            @unlink($a);
            @unlink($b);
            @rmdir($base);
        }
    }
}
