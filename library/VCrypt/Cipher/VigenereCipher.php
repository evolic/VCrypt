<?php

/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCrypt\Cipher;


use VCrypt\Common\Output;

/**
 * Vigenère cipher class
 *
 * @author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      December 28, 2011
 * @copyright  (C) 2011-2014 Tomasz Kuter Loculus Evolution
 * @see http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
 */
class VigenereCipher
{
    /**
     * Exception code thrown while getting the encryption key from encrypted and decrypted text
     *
     * @var string
     */
    const EXCEPTION_CODE_STRINGS_LENGTH_MISMATCH = '0001';


    /**
     * Tableou Mapping
     *
     * @var array
     */
    protected $mapping = array();

    /**
     * Tableou
     *
     * @var array
     */
    protected $table = array();

    /**
     * Secret Key
     * @var string
     */
    protected $key;

    /**
     * Specifies if cipher is case sensitive
     * @var bool
     */
    protected $caseSensitive = false;


    /**
     * Constructor
     *
     * @param array $options
     * @return void
     */
    public function __construct($options = array())
    {
        $this->reset();

        if (array_key_exists('case-sensitive', $options)) {
            $this->setCaseSensitive((bool) $options['case-sensitive']);
        }
        if (array_key_exists('key', $options)) {
            $this->setKey($options['key']);
        }
    }

    /**
     * Resets data
     *
     * @return void
     */
    protected function reset()
    {
        $this->mapping = array();
        $this->table = array();
    }


    /**
     * Loads Vigenère table, known as the tabula recta
     * Table is used for encryption and decryption
     *
     * @param string $file Path to file contains tabula recta
     * @return void
     */
    public function loadTable($file)
    {
        $handle = @fopen($file, "r");

        if ($handle) {
            $this->reset();

            $idx = 0;

            while (!feof($handle)) {
                $buffer = rtrim(fgets($handle, 4096));

                if ($idx == 0) {
                    for ($i=0; $i<mb_strlen($buffer, 'utf-8'); $i++) {
                        $char = mb_substr($buffer, $i, 1, 'utf-8');
                        if (!array_key_exists($char, $this->mapping)) {
                            $this->mapping[$char] = $i;
                        }
                        $this->table[$i] = array();
                        $this->table[0][$i] = $char;
                    }
                } else {
                    $char = mb_substr($buffer, 0, 1, 'utf-8');
                    $col = $this->mapping[$char];
                    for ($i=0; $i<mb_strlen($buffer, 'utf-8'); $i++) {
                        $this->table[$col][$i] = mb_substr($buffer, $i, 1, 'utf-8');
                    }
                }

                $idx++;
            }
            fclose($handle);
        }
    }

    /**
     * Prints Vigenère table, known as the tabula recta
     * Function mostly for the debugging purpose
     *
     * @return void
     */
    public function printTable($printWithSpaces = false, $output = null)
    {
        $space = $printWithSpaces ? ' ' : '';

        if (!isset($output)) {
            $output = new Output();
        }

        foreach ($this->table as $col => $rows) {
            $line = '';

            foreach ($rows as $row => $char) {
                $line .= $space . $char;
            }

            $line .=  PHP_EOL;

            $output->printText($line);
        }

        $output->printText(PHP_EOL);
    }

    /**
     * Sets a secret key
     *
     * @param string $key Secret key used for data encryption
     * @return Vigenere
     */
    public function setKey($key)
    {
        if ($this->getCaseSensitive()) {
            $this->key = $key;
        } else {
            $this->key = mb_strtoupper($key, 'utf-8');
        }

        return $this;
    }

    /**
     * Sets if cipher is case sensitive or not
     *
     * @param bool $caseSensitive
     * @return Vigenere
     */
    public function setCaseSensitive($caseSensitive)
    {
        $this->caseSensitive = $caseSensitive;
        return $this;
    }

    /**
     * Gets if cipher is case sensitive or not
     *
     * @return bool
     */
    public function getCaseSensitive()
    {
        return $this->caseSensitive;
    }

    /**
     * Encodes text
     *
     * @param string $text Plain text
     * @param string $key Secret key used for data encryption
     * @return string Encrypted text
     */
    public function encode($text, $key = null)
    {
        if (!isset($key)) {
            $key = $this->key;
        }

        $encoded = '';

        $limit = mb_strlen($key, 'utf-8');
        $j = 0;

        for ($i=0; $i<mb_strlen($text, 'utf-8'); $i++) {
            $ch1 = mb_substr($text, $i, 1, 'utf-8');
            if (!$this->getCaseSensitive()) {
                $ch1 = mb_strtoupper($ch1, 'utf-8');
            }

            if (array_key_exists($ch1, $this->mapping)) {
                $col = $this->mapping[$ch1];

                $ch2 = mb_substr($key, $j, 1, 'utf-8');
                if (!$this->getCaseSensitive()) {
                    $ch2 = mb_strtoupper($ch2, 'utf-8');
                }

                $row = $this->mapping[$ch2];
                $encoded .= $this->table[$col][$row];
            } else {
                $ch = mb_substr($text, $i, 1, 'utf-8');

                if ($this->getCaseSensitive()) {
                    $encoded .= $ch;
                } else {
                    $encoded .= mb_strtoupper($ch, 'utf-8');
                }

                // key is not used for characters not present in the table
                continue;
            }

            $j++;

            if ($j == $limit) {
                $j = $j % $limit;
            }
        }

        return $encoded;
    }

    /**
     * Decodes text
     *
     * @param string $text Encrypted text
     * @return string Decrypted text
     */
    public function decode($text)
    {
        return $this->encode($text, $this->invert());
    }

    /**
     * Gets secret key used for text decoding
     * Internal function
     *
     * @param string $text Encrypted text
     * @return string
     */
    protected function invert()
    {
        $key = '';

        $limit = count($this->mapping) - 1;
        $minus = -2;
        $up = 2;
        $offset = 0;

        // get reverse key
        for ($i=0; $i<mb_strlen($this->key, 'utf-8'); $i++) {
            if ($this->getCaseSensitive()) {
                $kch = mb_substr($this->key, $i, 1, 'utf-8');
            } else {
                $kch = mb_strtoupper(mb_substr($this->key, $i, 1, 'utf-8'), 'utf-8');
            }
            $pos = $this->mapping[$kch] + $offset;
            $nr = ($limit - $pos + $up) % $limit;
            $key .= $this->table[0][$nr];
        }

        return $key;
    }

    /**
     * Reads the key
     *
     * @param string $encrypted Encrypted text
     * @param string $decrypted Decrypted text
     * @throws Exception
     * @return string
     */
    public function readKey($encrypted, $decrypted)
    {
        if (($elen = mb_strlen($encrypted, 'utf-8')) !== ($dlen = mb_strlen($decrypted, 'utf-8'))) {
            throw new \Exception(
                'Texts cannot be processed because of strings length mismatch!',
                self::EXCEPTION_CODE_STRINGS_LENGTH_MISMATCH
            );
        }

        $key = '';

        for ($i=0; $i<$elen; $i++) {
            $ech = mb_substr($encrypted, $i, 1, 'utf-8');
            $dch = mb_substr($decrypted, $i, 1, 'utf-8');

            if (!$this->getCaseSensitive()) {
                $ech = mb_strtoupper($ech, 'utf-8');
                $dch = mb_strtoupper($dch, 'utf-8');
            }

            if (array_key_exists($dch, $this->mapping)) {
                $col = $this->mapping[$dch];

                for ($row=0; $row<count($this->table[$col]); $row++) {
                    if ($this->table[$col][$row] === $ech) {
                        $key .= $this->table[$row][0];
                        break;
                    }
                }
            } else {
                // key is not used for characters not present in the table
                continue;
            }
        }


        return $this->sieveKey($key);
    }

    /**
     * Sieves specified text to find repeating pattern - an encription key
     *
     * @param string $text
     * @return string
     */
    protected function sieveKey($text)
    {
        $key = '';
        $keyLength = 1;
        $textLength = mb_strlen($text, 'utf-8');

        do {
            $valid = true;
            $idx = 0;

            $key = mb_substr($text, 0, $keyLength, 'utf-8');

            do {
                $string = mb_substr($text, $idx, $keyLength, 'utf-8');
                $stringLength = mb_strlen($string, 'utf-8');

                if ($keyLength === $stringLength && $key !== $string) {
                    $valid = false;
                    break;
                } else if ($keyLength !== $stringLength && mb_substr($key, 0, $stringLength, 'utf-8') !== $string) {
                    // last string can be shorter than the key
                    $valid = false;
                    break;
                } else {
                    $idx += $keyLength;
                }
            }
            while ($idx < $textLength);

            $keyLength++;

            if ($valid) {
                break;
            }
        }
        while (true);

        return $key;
    }
}
