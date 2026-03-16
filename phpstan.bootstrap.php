<?php
declare(strict_types=1);

$autoloadCandidates = [
    __DIR__ . '/vendor/autoload.php',
    __DIR__ . '/src/autoload.php',
];

foreach ($autoloadCandidates as $candidate) {
    if (is_file($candidate)) {
        require $candidate;
        return;
    }
}

throw new RuntimeException('Cannot find an autoloader; run composer install.');

