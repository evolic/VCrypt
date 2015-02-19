<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\KryptosTranspositionCipher;

$firephp = \FirePHP::getInstance(true);
$firephp->info('FirePHP is on');

$data   = 'SLOWLYDESPARATLYSLOWLY?'/*THEREMAINSOFPASSAGEDEBRISTHAT'*/;

$options = array(
    'key' => 'KRYPTOS',
    'pad-size' => 16,
);

KryptosTranspositionCipher::setDebug(true);
$cipher = new KryptosTranspositionCipher($options);

echo '<strong>original: "' . $data . '"</strong>' . PHP_EOL;

echo '<br>' . PHP_EOL;
echo '<strong>Encoding:</strong>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
$encoded = $cipher->encode($data);;
echo '<strong>encoded: "' . $encoded . '"</strong>' . PHP_EOL;
echo '</pre>' . PHP_EOL;

echo '<br>' . PHP_EOL;
echo '<strong>Decoding:</strong>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
$decoded = $cipher->decode($encoded);
echo '<strong>decoded: "' . $decoded . '"</strong>' . PHP_EOL;
echo '</pre>' . PHP_EOL;

if ($decoded === $data) {
    echo 'Text successfully decoded' . PHP_EOL;
} else {
    echo 'Text unsuccessfully decoded' . PHP_EOL;
}
