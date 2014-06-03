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
            "  | ABCD EFGH IJKL MNOP QRST UVWX YZ" . PHP_EOL,
            "A | ABCD EFGH IJKL MNOP QRST UVWX YZA" . PHP_EOL,
            "B | BCDE FGHI JKLM NOPQ RSTU VWXY ZAB" . PHP_EOL,
            "C | CDEF GHIJ KLMN OPQR STUV WXYZ ABC" . PHP_EOL,
            "D | DEFG HIJK LMNO PQRS TUVW XYZA BCD" . PHP_EOL,
            "E | EFGH IJKL MNOP QRST UVWX YZAB CDE" . PHP_EOL,
            "F | FGHI JKLM NOPQ RSTU VWXY ZABC DEF" . PHP_EOL,
            "G | GHIJ KLMN OPQR STUV WXYZ ABCD EFG" . PHP_EOL,
            "H | HIJK LMNO PQRS TUVW XYZA BCDE FGH" . PHP_EOL,
            "I | IJKL MNOP QRST UVWX YZAB CDEF GHI" . PHP_EOL,
            "J | JKLM NOPQ RSTU VWXY ZABC DEFG HIJ" . PHP_EOL,
            "K | KLMN OPQR STUV WXYZ ABCD EFGH IJK" . PHP_EOL,
            "L | LMNO PQRS TUVW XYZA BCDE FGHI JKL" . PHP_EOL,
            "M | MNOP QRST UVWX YZAB CDEF GHIJ KLM" . PHP_EOL,
            "N | NOPQ RSTU VWXY ZABC DEFG HIJK LMN" . PHP_EOL,
            "O | OPQR STUV WXYZ ABCD EFGH IJKL MNO" . PHP_EOL,
            "P | PQRS TUVW XYZA BCDE FGHI JKLM NOP" . PHP_EOL,
            "Q | QRST UVWX YZAB CDEF GHIJ KLMN OPQ" . PHP_EOL,
            "R | RSTU VWXY ZABC DEFG HIJK LMNO PQR" . PHP_EOL,
            "S | STUV WXYZ ABCD EFGH IJKL MNOP QRS" . PHP_EOL,
            "T | TUVW XYZA BCDE FGHI JKLM NOPQ RST" . PHP_EOL,
            "U | UVWX YZAB CDEF GHIJ KLMN OPQR STU" . PHP_EOL,
            "V | VWXY ZABC DEFG HIJK LMNO PQRS TUV" . PHP_EOL,
            "W | WXYZ ABCD EFGH IJKL MNOP QRST UVW" . PHP_EOL,
            "X | XYZA BCDE FGHI JKLM NOPQ RSTU VWX" . PHP_EOL,
            "Y | YZAB CDEF GHIJ KLMN OPQR STUV WXY" . PHP_EOL,
            "Z | ZABC DEFG HIJK LMNO PQRS TUVW XYZ" . PHP_EOL
        );

        foreach ($table as $idx => $line) {
            $stub->expects( $this->at( $idx ) )->method('printText')->with( $line );
        }

        $key = 'LEMON';

        $options = array('key' => $key);
        $cipher  = new VigenereCipher($options);
        $cipher->loadTable($this->table);
        $cipher->printTable(4, $stub); // prints lines with Vigenere table
    }
}
