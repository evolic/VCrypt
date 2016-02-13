
<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\VigenereCipher;
use VCrypt\Common\Output;

$firephp = \FirePHP::getInstance(true);
$firephp->info('FirePHP is on');

$table = __DIR__ . '/../tests/_files/tableau-kryptos.txt';

$key    = 'fea42FEA4oDea45Bea4';
$data   = 'c1Ab2dfe4oFc6bD54';
$output = '3e3e3bc77FB2fe1FA';

$cipher = new VigenereCipher();
$cipher->setKey($key);
$cipher->loadTable($table);

$reflectionProperty  = new \ReflectionProperty('VCrypt\Cipher\VigenereCipher', 'table');
$reflectionProperty->setAccessible(true);

$outputDebugger = new Output();

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
$outputDebugger->printTableau($reflectionProperty->getValue($cipher), 4); // prints lines with Vigenere table
echo '</pre>' . PHP_EOL;
