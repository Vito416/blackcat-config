<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\SourceCodePolicyScanner;
use PHPUnit\Framework\TestCase;

final class SourceCodePolicyScannerTest extends TestCase
{
    public function testScanFindsRawPdoAndKeyFileReadsButSkipsVendor(): void
    {
        $root = rtrim(sys_get_temp_dir(), "/\\") . DIRECTORY_SEPARATOR . 'blackcat-config-scan-' . bin2hex(random_bytes(8));
        self::assertTrue(@mkdir($root, 0700, true) || is_dir($root));

        $src = $root . DIRECTORY_SEPARATOR . 'src';
        self::assertTrue(@mkdir($src, 0700, true) || is_dir($src));

        $vendor = $root . DIRECTORY_SEPARATOR . 'vendor';
        self::assertTrue(@mkdir($vendor, 0700, true) || is_dir($vendor));

        $bad1 = $src . DIRECTORY_SEPARATOR . 'bad_pdo.php';
        $bad2 = $src . DIRECTORY_SEPARATOR . 'bad_key.php';
        $bad3 = $src . DIRECTORY_SEPARATOR . 'bad_fopen.php';
        $bad4 = $src . DIRECTORY_SEPARATOR . 'bad_getpdo.php';
        $bad5 = $src . DIRECTORY_SEPARATOR . 'bad_mysqli.php';
        $bad6 = $src . DIRECTORY_SEPARATOR . 'bad_pg.php';
        $bad7 = $src . DIRECTORY_SEPARATOR . 'bad_sqlite3.php';
        $vendorBad = $vendor . DIRECTORY_SEPARATOR . 'vendor_bad.php';

        file_put_contents($bad1, "<?php\n\$pdo = new PDO('sqlite::memory:');\n");
        file_put_contents($bad2, "<?php\nfile_get_contents('/tmp/app_salt_v1.key');\n");
        file_put_contents($bad3, "<?php\nfopen('/tmp/app_salt_v1.key', 'rb');\n");
        file_put_contents($bad4, "<?php\n\$db->getPdo()->exec('SELECT 1');\n");
        file_put_contents($bad5, "<?php\n\$db = new mysqli('localhost', 'u', 'p', 'db');\n");
        file_put_contents($bad6, "<?php\npg_connect('host=localhost');\n");
        file_put_contents($bad7, "<?php\n\$db = new SQLite3(':memory:');\n");
        file_put_contents($vendorBad, "<?php\n\$pdo = new PDO('sqlite::memory:');\n");

        try {
            $res = SourceCodePolicyScanner::scan($root);
            $rules = array_map(static fn (array $v): string => $v['rule'], $res['violations']);

            self::assertContains(SourceCodePolicyScanner::RULE_RAW_PDO, $rules);
            self::assertContains(SourceCodePolicyScanner::RULE_RAW_PDO_ACCESS, $rules);
            self::assertContains(SourceCodePolicyScanner::RULE_RAW_MYSQLI, $rules);
            self::assertContains(SourceCodePolicyScanner::RULE_RAW_PG_CONNECT, $rules);
            self::assertContains(SourceCodePolicyScanner::RULE_RAW_SQLITE3, $rules);
            self::assertContains(SourceCodePolicyScanner::RULE_KEY_FILE_READ, $rules);

            $files = array_map(static fn (array $v): string => str_replace('\\', '/', $v['file']), $res['violations']);
            foreach ($files as $f) {
                self::assertStringNotContainsString('/vendor/', $f);
            }
        } finally {
            self::rmTree($root);
        }
    }

    private static function rmTree(string $path): void
    {
        if ($path === '' || $path === DIRECTORY_SEPARATOR) {
            return;
        }
        if (!file_exists($path)) {
            return;
        }
        if (is_file($path) || is_link($path)) {
            @unlink($path);
            return;
        }
        $items = @scandir($path);
        if (!is_array($items)) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            self::rmTree($path . DIRECTORY_SEPARATOR . $item);
        }
        @rmdir($path);
    }
}
