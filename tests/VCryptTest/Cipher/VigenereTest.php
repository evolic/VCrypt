<?php
/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCryptTest\Cipher;

use VCrypt\Cipher\VigenereCipher;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

/**
 * @group      Vigenere
 *
  *@author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      April 26, 2014
 * @copyright  (C) 2014 Tomasz Kuter Loculus Evolution
 */
class VigenereTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->table = __DIR__ . '/../../_files/tableau-vigenere.txt';
    }

    // Vigenère cipher encoding tests
    public function provideEncodeUsingVigenereTableData()
    {
        return array(
            array('ATTACKATDAWN', 'LXFOPVEFRNHR'),
        );
    }

    /**
     * @dataProvider provideEncodeUsingVigenereTableData
     */
    public function testEncodeUsingVigenereTable($data, $printText)
    {
        $key = 'LEMON';
        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);

        $encoded = $cipher->encode($data);
        $this->assertEquals($printText, $encoded);
    }

    // Vigenère cipher decoding tests
    public function provideDecodeUsingVigenereTableData()
    {
        return array(
            array('LXFOPVEFRNHR', 'ATTACKATDAWN'),
        );
    }

    /**
     * @dataProvider provideDecodeUsingVigenereTableData
     */
    public function testDncodeUsingVigenereTable($data, $printText)
    {
        $key = 'LEMON';
        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);

        $decoded = $cipher->decode($data);
        $this->assertEquals($printText, $decoded);
    }

    public function testReadingKeyFromEncodedAndDecodedPhrases()
    {
        $key = 'LEMON';
        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);

        $decrypted = 'ATTACKATDAWN';
        $encrypted = 'LXFOPVEFRNHR';

        $decodedKey = $cipher->readKey($encrypted, $decrypted);
        $this->assertEquals($key, $decodedKey);
    }

    public function testPhrasesLengthMismatch()
    {
        $key = 'LEMON';
        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);

        $decrypted = 'ATTACKATDAWNX';
        $encrypted = 'LXFOPVEFRNHR';

        $this->setExpectedException(
            '\Exception',
            'Texts cannot be processed because of strings length mismatch!'
        );
        $cipher->readKey($encrypted, $decrypted);
    }

    public function testPrintTextingVigenereTable()
    {
        $stub = $this->getMock('Output', array('printText'));

        $table = array(
            " ABCDEFGHIJKLMNOPQRSTUVWXYZ" . PHP_EOL,
            "AABCDEFGHIJKLMNOPQRSTUVWXYZA" . PHP_EOL,
            "BBCDEFGHIJKLMNOPQRSTUVWXYZAB" . PHP_EOL,
            "CCDEFGHIJKLMNOPQRSTUVWXYZABC" . PHP_EOL,
            "DDEFGHIJKLMNOPQRSTUVWXYZABCD" . PHP_EOL,
            "EEFGHIJKLMNOPQRSTUVWXYZABCDE" . PHP_EOL,
            "FFGHIJKLMNOPQRSTUVWXYZABCDEF" . PHP_EOL,
            "GGHIJKLMNOPQRSTUVWXYZABCDEFG" . PHP_EOL,
            "HHIJKLMNOPQRSTUVWXYZABCDEFGH" . PHP_EOL,
            "IIJKLMNOPQRSTUVWXYZABCDEFGHI" . PHP_EOL,
            "JJKLMNOPQRSTUVWXYZABCDEFGHIJ" . PHP_EOL,
            "KKLMNOPQRSTUVWXYZABCDEFGHIJK" . PHP_EOL,
            "LLMNOPQRSTUVWXYZABCDEFGHIJKL" . PHP_EOL,
            "MMNOPQRSTUVWXYZABCDEFGHIJKLM" . PHP_EOL,
            "NNOPQRSTUVWXYZABCDEFGHIJKLMN" . PHP_EOL,
            "OOPQRSTUVWXYZABCDEFGHIJKLMNO" . PHP_EOL,
            "PPQRSTUVWXYZABCDEFGHIJKLMNOP" . PHP_EOL,
            "QQRSTUVWXYZABCDEFGHIJKLMNOPQ" . PHP_EOL,
            "RRSTUVWXYZABCDEFGHIJKLMNOPQR" . PHP_EOL,
            "SSTUVWXYZABCDEFGHIJKLMNOPQRS" . PHP_EOL,
            "TTUVWXYZABCDEFGHIJKLMNOPQRST" . PHP_EOL,
            "UUVWXYZABCDEFGHIJKLMNOPQRSTU" . PHP_EOL,
            "VVWXYZABCDEFGHIJKLMNOPQRSTUV" . PHP_EOL,
            "WWXYZABCDEFGHIJKLMNOPQRSTUVW" . PHP_EOL,
            "XXYZABCDEFGHIJKLMNOPQRSTUVWX" . PHP_EOL,
            "YYZABCDEFGHIJKLMNOPQRSTUVWXY" . PHP_EOL,
            "ZZABCDEFGHIJKLMNOPQRSTUVWXYZ" . PHP_EOL
        );

        foreach ($table as $idx => $line) {
            $stub->expects( $this->at( $idx ) )->method('printText')->with( $line );
        }

        $key = 'LEMON';

        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);
        $cipher->printTable(false, $stub); // prints lines with Vigenere table
    }
}
