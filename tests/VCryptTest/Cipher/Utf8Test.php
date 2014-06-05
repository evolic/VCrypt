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
 * @since      May 13, 2014
 * @copyright  (C) 2014 Tomasz Kuter Loculus Evolution
 */
class Utf8Test extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->table = __DIR__ . '/../../_files/tableau-utf8.txt';
    }

    // Vigenère cipher encoding tests
    public function provideEncodeUsingUtf8TableData()
    {
        return array(
            array(
                'fea42øÇż4óDea45èea4',
                'c1żb2dfe4óøc6bD54dc15FEAR',
                '3e3e3bc77øè2fe1øżøffèFEAR'
            ),
        );
    }

    /**
     * @dataProvider provideEncodeUsingUtf8TableData
     */
    public function testEncodeUsingUtf8Table($key, $data, $output)
    {
        // always set case sensitive first!
        $options = array('case-sensitive' => true);

        $cipher = new VigenereCipher($options);
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $encoded = $cipher->encode($data);
        $this->assertEquals($output, $encoded);
    }

    // Vigenère cipher decoding keys tests
    public function provideReadingKeyFromEncodedAndDecodedPhrasesUsingUtf8TableData()
    {
        return array(
            array(
                'fea42øÇż4óDea45èea4',
                'c1żb2dfe4óøc6bD54dc15FEAR',
                '3e3e3bc77øè2fe1øżøffèFEAR'
            ),
        );
    }

    /**
     * @dataProvider provideReadingKeyFromEncodedAndDecodedPhrasesUsingUtf8TableData
     */
    public function testReadingKeyFromEncodedAndDecodedPhrasesUsingUtf8TableData($key, $decrypted, $encrypted)
    {
        // always set case sensitive first!
        $options = array('case-sensitive' => true);

        $cipher = new VigenereCipher($options);
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $decodedKey = $cipher->readKey($encrypted, $decrypted);
        $this->assertEquals($key, $decodedKey);
    }
}
