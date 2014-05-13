<?php
/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCryptTest\VCrypt;

use VCrypt\Vigenere;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

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
        $this->table = __DIR__ . '/../_files/tableau-utf8.txt';
    }

    // Vigenère cipher encoding tests
    public function provideEncodeUsingUtf8TableData()
    {
        return array(
            array(
                'fea42øÇż4óDea45èea4',
                'c1żb2dfe4óøc6bD54',
                '3e3e3bc77øè2fe1øż'
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
        $cipher = new Vigenere($options);
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $encoded = $cipher->encode($data);
        $this->assertEquals($output, $encoded);
    }
}
