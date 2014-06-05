<?php
/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCryptTest\Cipher;

use VCrypt\Cipher\KryptosTranspositionCipher;


/**
 * @group      Vigenere
 *
  *@author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      April 26, 2014
 * @copyright  (C) 2014 Tomasz Kuter Loculus Evolution
 */
class KryptosTranspositionCipherTest extends \PHPUnit_Framework_TestCase
{
    public function testStringBackward()
    {
        $originalText = 'KRYPTOS';
        $backwardText = 'SOTPYRK';

        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'backward');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();

        $output = $reflectionMethod->invokeArgs($cipher, array($originalText));
        $this->assertEquals($backwardText, $output);
    }


    public function provideTextTranspositionData()
    {
        return array(
            array('?QGNIHT', array('?','H','N','Q','T','I','G')),
            array('EHTDESU', array('E','S','D','H','U','E','T')),
            array('LS', array('L','','','S','','','')),
        );
    }

    /**
     * @dataProvider provideTextTranspositionData
     */
    public function testTextTransposition($source, $transposed)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'transpose');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();
        $cipher->setKey('KRYPTOS');

        $output = $reflectionMethod->invokeArgs($cipher, array($source));
        $this->assertEquals($transposed, $output);
    }

    /**
     * @dataProvider provideTextTranspositionData
     * @expectedException VCrypt\Exception\KeyNotSetException
     */
    public function testThrowingExceptionForTextTranspositionWithoutSettingTheKey($source, $transposed)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'transpose');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();

        $output = $reflectionMethod->invokeArgs($cipher, array($source));
    }

    public function provideTextTranspositionWithTooLongData()
    {
        return array(
            array('?QGNIHT!', array('?','H','N','Q','T','I','G', '!')),
        );
    }

    /**
     * @dataProvider provideTextTranspositionWithTooLongData
     * @expectedException VCrypt\Exception\InvalidTranspositionSourceTextException
     */
    public function testThrowingExceptionForTextTranspositionWithTooLongData($source, $transposed)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'transpose');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();
        $cipher->setKey('KRYPTOS');

        $output = $reflectionMethod->invokeArgs($cipher, array($source));
    }


    public function provideTextPaddingData()
    {
      return array(
          array(
              '?QGNIHTYNAEESUOYNACXTSIMEHTMORFDEGREMENIHTIWMOOREHTFOSLIATEDYLTNESERPTUBREKCILFOTEMALFEHTDESUACREBMAHCEHTMORFGNIPACSERIATOHEHTNIDEREEPDNAELDNACEHTDETRESNIIELTTILAELOHEHTGNINEDIWNEHTDNARENROCDNAHTFELREPPUEHTNIHCAERBYNITAEDAMISDNAHGNILBMERTHTIWDEVOMERSAWYAWROODEHTFOTRAPREWOLEHTDEREBMUCNETAHTSIRBEDEGASSAPFOSNIAMEREHTYLWOLSYLTARAPSEDYLWOLS',
              array(
                  '?QGNIHTYNAEESUOYNACXTSIMEHTMORFDEGREMENIHTIWMOOREHTFOSLIATEDYLTNESERPTUBREKCILFOTEMALF',
                  'EHTDESUACREBMAHCEHTMORFGNIPACSERIATOHEHTNIDEREEPDNAELDNACEHTDETRESNIIELTTILAELOHEHTGNI',
                  'NEDIWNEHTDNARENROCDNAHTFELREPPUEHTNIHCAERBYNITAEDAMISDNAHGNILBMERTHTIWDEVOMERSAWYAWROO',
                  'DEHTFOTRAPREWOLEHTDEREBMUCNETAHTSIRBEDEGASSAPFOSNIAMEREHTYLWOLSYLTARAPSEDYLWOLS',
              )
          ),
      );
    }

    /**
     * @dataProvider provideTextPaddingData
     */
    public function testTextPadding($source, $padded)
    {
      $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'padText');
      $reflectionMethod->setAccessible(true);

      $cipher = new KryptosTranspositionCipher();
      $cipher->setPadSize(86);

      $output = $reflectionMethod->invokeArgs($cipher, array($source));
      $this->assertEquals($padded, $output);
    }


    public function provideTextSlicingData()
    {
        return array(
            array(
                array(
                    '?QGNIHTYNAEESUOYNACXTSIMEHTMORFDEGREMENIHTIWMOOREHTFOSLIATEDYLTNESERPTUBREKCILFOTEMALF',
                    'EHTDESUACREBMAHCEHTMORFGNIPACSERIATOHEHTNIDEREEPDNAELDNACEHTDETRESNIIELTTILAELOHEHTGNI',
                    'NEDIWNEHTDNARENROCDNAHTFELREPPUEHTNIHCAERBYNITAEDAMISDNAHGNILBMERTHTIWDEVOMERSAWYAWROO',
                    'DEHTFOTRAPREWOLEHTDEREBMUCNETAHTSIRBEDEGASSAPFOSNIAMEREHTYLWOLSYLTARAPSEDYLWOLS',
                ),
                array(
                    array(
                        '?QGNIHT',
                        'EHTDESU',
                        'NEDIWNE',
                        'DEHTFOT',
                    ),
                    array(
                        'YNAEESU',
                        'ACREBMA',
                        'HTDNARE',
                        'RAPREWO',
                    ),
                    array(
                        'OYNACXT',
                        'HCEHTMO',
                        'NROCDNA',
                        'LEHTDER',
                    ),
                    array(
                        'SIMEHTM',
                        'RFGNIPA',
                        'HTFELRE',
                        'EBMUCNE',
                    ),
                    array(
                        'ORFDEGR',
                        'CSERIAT',
                        'PPUEHTN',
                        'TAHTSIR',
                    ),
                    array(
                        'EMENIHT',
                        'OHEHTNI',
                        'IHCAERB',
                        'BEDEGAS',
                    ),
                    array(
                        'IWMOORE',
                        'DEREEPD',
                        'YNITAED',
                        'SAPFOSN',
                    ),
                    array(
                        'HTFOSLI',
                        'NAELDNA',
                        'AMISDNA',
                        'IAMEREH',
                    ),
                    array(
                        'ATEDYLT',
                        'CEHTDET',
                        'HGNILBM',
                        'TYLWOLS',
                    ),
                    array(
                        'NESERPT',
                        'RESNIIE',
                        'ERTHTIW',
                        'YLTARAP',
                    ),
                    array(
                        'UBREKCI',
                        'LTTILAE',
                        'DEVOMER',
                        'SEDYLWO',
                    ),
                    array(
                        'LFOTEMA',
                        'LOHEHTG',
                        'SAWYAWR',
                        'LS',
                    ),
                    array(
                        'LF',
                        'NI',
                        'OO',
                    ),
                ),
            ),
        );
    }

    /**
     * @dataProvider provideTextSlicingData
     */
    public function testTextSlicing($textInRows, $columns)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'slicePad');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();
        $cipher->setKey('KRYPTOS');
        $cipher->setPadSize(86);

        $output = $reflectionMethod->invokeArgs($cipher, array($textInRows));
        $this->assertEquals($columns, $output);
    }


    public function provideColumnTranspositionData()
    {
        return array(
            array(
                array(
                    array(
                        '?QGNIHT',
                        'EHTDESU',
                        'NEDIWNE',
                        'DEHTFOT',
                    ),
                    array(
                        'YNAEESU',
                        'ACREBMA',
                        'HTDNARE',
                        'RAPREWO',
                    ),
                )
                ,
                array(
                    array('?','H','N','Q','T','I','G'),
                    array('E','S','D','H','U','E','T'),
                    array('N','N','I','E','E','W','D'),
                    array('D','O','T','E','T','F','H'),
                    array('Y','S','E','N','U','E','A'),
                    array('A','M','E','C','A','B','R'),
                    array('H','R','N','T','E','A','D'),
                    array('R','W','R','A','O','E','P')
                )
            ),
        );
    }

    /**
     * @dataProvider provideColumnTranspositionData
     */
    public function testColumnTransposition($columns, $encrypted)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'transposeColumns');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();
        $cipher->setKey('KRYPTOS');

        $output = $reflectionMethod->invokeArgs($cipher, array($columns));
        $this->assertEquals($encrypted, $output);
    }


    public function provideColumnDownwardData()
    {
      return array(
          array(
              array(
                    array('?','H','N','Q','T','I','G'),
                    array('E','S','D','H','U','E','T'),
                    array('N','N','I','E','E','W','D'),
                    array('D','O','T','E','T','F','H'),
                    array('Y','S','E','N','U','E','A'),
                    array('A','M','E','C','A','B','R'),
                    array('H','R','N','T','E','A','D'),
                    array('R','W','R','A','O','E','P')
              )
              ,
              '?ENDYAHR' . 'HSNOSMRW' . 'NDITEENR' . 'QHEENCTA' .
              'TUETUAEO' . 'IEWFEBAE' . 'GTDHARDP'
          ),
      );
    }

    /**
     * @dataProvider provideColumnDownwardData
     */
    public function testColumnDownwardn($column, $text)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'downward');
        $reflectionMethod->setAccessible(true);

        $cipher = new KryptosTranspositionCipher();
        $cipher->setKey('KRYPTOS');

        $output = $reflectionMethod->invokeArgs($cipher, array($column));
        $this->assertEquals($text, $output);
    }


    public function provideEncryptionData()
    {
        return array(
            array(
                'SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUM' .
                'BEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHAND' .
                'SIMADEATINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENING' .
                'THEHOLEALITTLEIINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCA' .
                'PINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDET' .
                'AILSOFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ?'
                ,
                '?ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNO' .
                'HSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTW' .
                'NDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEY' .
                'QHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIO' .
                'TUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGR' .
                'IEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHA' .
                'GTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW'
            ),
        );
    }

    /**
     * @dataProvider provideEncryptionData
     */
    public function testEncryption($source, $encrypted)
    {
        $reflectionMethod  = new \ReflectionMethod('VCrypt\Cipher\KryptosTranspositionCipher', 'encode');
        $reflectionMethod->setAccessible(true);

        $options = array(
            'key' => 'KRYPTOS',
            'pad-size' => 86,
        );

        $cipher = new KryptosTranspositionCipher($options);

        $output = $reflectionMethod->invokeArgs($cipher, array($source));
        $this->assertEquals($encrypted, $output);
    }
}
