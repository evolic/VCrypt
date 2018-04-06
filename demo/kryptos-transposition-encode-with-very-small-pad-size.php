<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\KryptosTranspositionCipher;

$data   = 'SLOWLYDESPARATLYSLOWLY' .
          '?!@#';

$options = array(
    'key' => 'KRYPTOS',
    'pad-size' => 9,
);

$cipher = new KryptosTranspositionCipher($options);

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
echo $encoded = $cipher->encode($data);
echo '</pre>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
echo $decoded = $cipher->decode($encoded);
echo '</pre>' . PHP_EOL;

if ($decoded === $data) {
    echo 'Text successfully decoded' . PHP_EOL;
} else {
    echo 'Text unsuccessfully decoded' . PHP_EOL;
}
