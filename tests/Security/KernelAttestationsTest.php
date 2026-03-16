<?php

declare(strict_types=1);

namespace BlackCat\Config\Tests\Security;

use BlackCat\Config\Security\KernelAttestations;
use PHPUnit\Framework\TestCase;

final class KernelAttestationsTest extends TestCase
{
    public function testAttestationKeysAreDeterministic(): void
    {
        self::assertSame(
            '0x' . hash('sha256', 'blackcat.runtime_config.canonical_sha256.v1'),
            KernelAttestations::runtimeConfigAttestationKeyV1(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.composer.lock.canonical_sha256.v1'),
            KernelAttestations::composerLockAttestationKeyV1(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.php.fingerprint.canonical_sha256.v1'),
            KernelAttestations::phpFingerprintAttestationKeyV1(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.php.fingerprint.canonical_sha256.v2'),
            KernelAttestations::phpFingerprintAttestationKeyV2(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.image.digest.sha256.v1'),
            KernelAttestations::imageDigestAttestationKeyV1(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.http.allowed_hosts.canonical_sha256.v1'),
            KernelAttestations::httpAllowedHostsAttestationKeyV1(),
        );

        self::assertSame(
            '0x' . hash('sha256', 'blackcat.hosting.cgi_fix_pathinfo.probe.canonical_sha256.v1'),
            KernelAttestations::cgiFixPathInfoProbeAttestationKeyV1(),
        );
    }

    public function testImageDigestAcceptsSha256Prefix(): void
    {
        $hex = str_repeat('aa', 32);

        self::assertSame('0x' . $hex, KernelAttestations::imageDigestAttestationValueV1('sha256:' . $hex));
        self::assertSame('0x' . $hex, KernelAttestations::imageDigestAttestationValueV1('0x' . strtoupper($hex)));
        self::assertSame('0x' . $hex, KernelAttestations::imageDigestAttestationValueV1($hex));
    }

    public function testImageDigestRejectsInvalidValues(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KernelAttestations::imageDigestAttestationValueV1('sha256:not-hex');
    }

    public function testPhpFingerprintPayloadAndValueAreWellFormed(): void
    {
        $payload = KernelAttestations::phpFingerprintPayloadV2();

        self::assertSame(2, $payload['schema_version']);
        self::assertSame('blackcat.php.fingerprint', $payload['type']);
        self::assertSame(PHP_VERSION, $payload['php_version']);
        self::assertIsArray($payload['extensions']);

        $value = KernelAttestations::phpFingerprintAttestationValueV2($payload);
        self::assertMatchesRegularExpression('/^0x[a-f0-9]{64}$/', $value);
    }

    public function testHttpAllowedHostsAttestationNormalizesHostsAndHashesPayload(): void
    {
        $raw = [
            'Example.COM',
            '*.Example.com',
            'example.com:443',
            'localhost',
            '127.0.0.1:80',
            '[::1]:443',
        ];

        $payload = KernelAttestations::httpAllowedHostsPayloadV1($raw);
        self::assertSame(1, $payload['schema_version']);
        self::assertSame('blackcat.http.allowed_hosts', $payload['type']);
        self::assertSame(['*.example.com', '127.0.0.1', '::1', 'example.com', 'localhost'], $payload['hosts']);

        $value = KernelAttestations::httpAllowedHostsAttestationValueV1($raw);
        self::assertMatchesRegularExpression('/^0x[a-f0-9]{64}$/', $value);
    }

    public function testHttpAllowedHostsAttestationRejectsUrls(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        KernelAttestations::httpAllowedHostsPayloadV1(['https://example.com']);
    }

    public function testCgiFixPathInfoProbeNoExecAttestationIsWellFormed(): void
    {
        $payload = KernelAttestations::cgiFixPathInfoProbeNoExecPayloadV1();
        self::assertSame(1, $payload['schema_version']);
        self::assertSame('blackcat.hosting.cgi_fix_pathinfo.probe', $payload['type']);
        self::assertSame('no_exec', $payload['result']);

        $value = KernelAttestations::cgiFixPathInfoProbeNoExecAttestationValueV1();
        self::assertMatchesRegularExpression('/^0x[a-f0-9]{64}$/', $value);
    }
}
