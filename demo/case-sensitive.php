<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\VigenereCipher;
use VCrypt\Common\Output;

$array = array(1, 'a' => 2, 'B' => 3, 'A' => 4);
$tests = array(0, 'a', 'b', 'c', 5);

foreach ($tests as $test) {
  if (array_key_exists($test, $array)) {
    echo $test . ' exists in table<br>';
  } else {
    echo $test . ' not exists in table<br>';
  }
}

echo $array['a'] . '<br>' . PHP_EOL;
echo $array['A'] . '<br>' . PHP_EOL;

$table = __DIR__ . '/../tests/_files/tableau-case-sensitive.txt';

$key    = 'fea42FEA4oDea45Bea4';
$data   = 'c1Ab2dfe4oFc6bD54';
$output = '3e3e3bc77FB2fe1FA';

$cipher = new VigenereCipher();
$cipher->setCaseSensitive(true);
$cipher->setKey($key);
$cipher->loadTable($table);

$reflectionProperty  = new \ReflectionProperty(VigenereCipher::class, 'table');
$reflectionProperty->setAccessible(true);

$outputDebugger = new Output();

$encoded = $cipher->encode($data);

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
$outputDebugger->printTableau($reflectionProperty->getValue($cipher), 4); // prints lines with Vigenere table
echo '</pre>' . PHP_EOL;

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo $key . '<br>' . PHP_EOL;
echo $data . '<br>' . PHP_EOL;
echo $output . '<br>' . PHP_EOL;
echo $encoded . '<br>' . PHP_EOL;
