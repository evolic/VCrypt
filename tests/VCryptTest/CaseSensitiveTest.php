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
class CaseSensitiveTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->table = __DIR__ . '/../_files/tableau-case-sensitive.txt';
    }

    // Vigenère cipher encoding tests
    public function provideEncodeUsingCaseSensitiveTableData()
    {
        return array(
            array(
                'fea42FEA4oDea45Bea4',
                'c1Ab2dfe4oFc6bD54',
                '3e3e3bc77FB2fe1FA'
            ),
        );
    }

    /**
     * @dataProvider provideEncodeUsingCaseSensitiveTableData
     */
    public function testEncodeUsingCaseSensitiveTable($key, $data, $output)
    {
        $cipher = new Vigenere();
        // always set case sensitive first!
        $cipher->setCaseSensitive(true);
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $encoded = $cipher->encode($data);
        $this->assertEquals($output, $encoded);
    }
}
