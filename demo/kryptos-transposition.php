<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\KryptosTranspositionCipher;

$firephp = \FirePHP::getInstance(true);
$firephp->info('FirePHP is on');

$data   = 'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUM' .
          'BEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHAND' .
          'SIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENING' .
          'THEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCA' .
          'PINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDET' .
          'AILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ';

$options = array(
    'key' => 'KRYPTOS',
    'pad-size' => 86,
);

KryptosTranspositionCipher::setDebug(true);
$cipher = new KryptosTranspositionCipher($options);

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
echo $cipher->encode($data);
echo '</pre>' . PHP_EOL;
