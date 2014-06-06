<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset=utf-8>
  <title>Vigenère cipher - testing utf8 support</title>
</head>
<body>
<?php

require_once __DIR__ . '/../tests/_autoload.php';

use VCrypt\Cipher\VigenereCipher;

$firephp = \FirePHP::getInstance(true);
$firephp->info('FirePHP is on');

$array = array(1, 'a' => 2, 'B' => 3, 'A' => 4, 'ą' => 5, 'è' => 6, 'ę' => 7, 'Ç' => 8, 'ø' => 9, 'ó' => 10);
$tests = array(0, 'a', 'b', 'c', 5, 'è', 'ę', 'ó', 'ø');

foreach ($tests as $test) {
  if (array_key_exists($test, $array)) {
    echo $test . ' exists in table<br>';
  } else {
    echo $test . ' not exists in table<br>';
  }
}

echo $array['a'] . '<br>' . PHP_EOL;
echo $array['A'] . '<br>' . PHP_EOL;

$table = __DIR__ . '/../tests/_files/tableau-utf8.txt';

$key    = 'fea42øÇż4óDea45èea4';
$data   = 'c1żb2dfe4óøc6bD54dc15FEAR';
$output = '3e3e3bc77øè2fe1øżøffèFEAR';

$cipher = new VigenereCipher();
$cipher->setCaseSensitive(true);
$cipher->setKey($key);
$cipher->loadTable($table);

$encoded = $cipher->encode($data);

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo '<pre>' . PHP_EOL;
$cipher->printTable();
echo '</pre>' . PHP_EOL;

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;

echo $key . '<br>' . PHP_EOL;
echo $data . '<br>' . PHP_EOL;
echo $output . '<br>' . PHP_EOL;
echo $encoded . '<br>' . PHP_EOL;

echo '<br>' . PHP_EOL;
echo '<br>' . PHP_EOL;



$key       = 'fea42øÇż4óDea45èea4';
$encrypted = '3e3e3bc77øè2fe1øżFEAR';
$decrypted = 'c1żb2dfe4óøc6bD54FEAR';

// always set case sensitive first!
$options = array('case-sensitive' => true);

$cipher = new Vigenere($options);
$cipher->loadTable($table);

$decodedKey = $cipher->readKey($encrypted, $decrypted);

echo $encrypted . '<br>' . PHP_EOL;
echo $decrypted . '<br>' . PHP_EOL;
echo $key . '<br>' . PHP_EOL;
echo $decodedKey . '<br>' . PHP_EOL;
?>
</body>
</html>
