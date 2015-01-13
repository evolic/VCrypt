<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\KryptosTranspositionCipher;
use VCrypt\Common\Output;

$firephp = \FirePHP::getInstance(true);
$firephp->info('FirePHP is on');

$data   = 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUM' .
          'BEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHAN'/*D' .
          'S'*/;

$options = array(
    'key' => 'KRYPTOS',
    'pad-size' => 16,
);

KryptosTranspositionCipher::setDebug(true);
Output::$firephp = true;
$cipher = new KryptosTranspositionCipher($options);

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
echo $cipher->encode($data);
echo '</pre>' . PHP_EOL;
