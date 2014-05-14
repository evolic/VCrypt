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
class KryptosTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->table = __DIR__ . '/../../_files/tableau-kryptos.txt';
    }

    // Vigenère cipher encoding tests
    public function provideEncodeUsingKryptosTableData()
    {
        return array(
            array(
                'PALIMPSEST',
                'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION',
                'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD'
            ),
            array(
                'ABSCISSA',
                'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE?THEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS?THEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATION?ONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST',
                'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGE'
            ),
        );
    }

    /**
     * @dataProvider provideEncodeUsingKryptosTableData
     */
    public function testEncodeUsingKryptosTable($key, $data, $output)
    {
        $cipher = new VigenereCipher();
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $encoded = $cipher->encode($data);
        $this->assertEquals($output, $encoded);
    }

    // Vigenère cipher decoding tests
    public function provideDecodeUsingKryptosTableData()
    {
        return array(
            array(
                'PALIMPSEST',
                'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD',
                'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION'
            ),
            array(
                'ABSCISSA',
                'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGE',
                'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE?THEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS?THEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATION?ONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST'
            ),
        );
    }

    /**
     * @dataProvider provideDecodeUsingKryptosTableData
     */
    public function testDncodeUsingVigenereTable($key, $data, $output)
    {
        $cipher = new VigenereCipher();
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $decoded = $cipher->decode($data);
        $this->assertEquals($output, $decoded);
    }

    // Vigenère cipher decoding keys tests
    public function provideReadingKeyFromEncodedAndDecodedPhrasesUsingKryptosTableData()
    {
        return array(
            array(
                'PALIMPSEST',
                'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION',
                'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD'
            ),
            array(
                'ABSCISSA',
                'ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE?THEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHIS?THEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWSTHEEXACTLOCATION?ONLYWWTHISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWEST',
                'VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK?DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH?DWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKFFHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGE'
            ),
        );
    }

    /**
     * @dataProvider provideReadingKeyFromEncodedAndDecodedPhrasesUsingKryptosTableData
     */
    public function testReadingKeyFromEncodedAndDecodedPhrasesUsingKryptosTableData($key, $decrypted, $encrypted)
    {
        $cipher = new VigenereCipher();
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $decodedKey = $cipher->readKey($encrypted, $decrypted);
        $this->assertEquals($key, $decodedKey);
    }

    public function testPhrasesLengthMismatch()
    {
        $key = 'PALIMPSEST';
        $cipher = new VigenereCipher();
        $cipher->setKey($key);
        $cipher->loadTable($this->table);

        $decrypted = 'BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION?';
        $encrypted = 'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD';

        $this->setExpectedException(
            '\Exception',
            'Texts cannot be processed because of strings length mismatch!'
        );
        $cipher->readKey($encrypted, $decrypted);
    }
}
