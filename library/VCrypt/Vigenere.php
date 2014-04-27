<?php

/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCrypt;

/**
 * Vigenère cipher class
 *
 * @author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      December 28, 2011
 * @copyright  (C) 2011-2014 Tomasz Kuter Loculus Evolution
 * @see http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
 */
class Vigenere
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
     * Constructor
     *
     * @param string $key
     * @return void
     */
    public function __construct($key)
    {
        $this->reset();
        $this->setKey($key);
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
                    for ($i=0; $i<strlen($buffer); $i++) {
                        $char = $buffer[$i];
                        if (!array_key_exists($char, $this->mapping)) {
                            $this->mapping[$char] = $i;
                        }
                        $this->table[$i] = array();
                        $this->table[0][$i] = $char;
                    }
                } else {
                    $char = $buffer[0];
                    $col = $this->mapping[$char];
                    for ($i=0; $i<strlen($buffer); $i++) {
                        $this->table[$col][$i] = $buffer[$i];
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
     * @return Kryptos
     */
    public function setKey($key)
    {
        $this->key = strtoupper($key);
        return $this;
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

        $limit = strlen($key);
        $j = 0;

        for ($i=0; $i<strlen($text); $i++) {
            $ch = strtoupper($text[$i]);

            if (array_key_exists($ch, $this->mapping)) {
                $col = $this->mapping[$ch];
                $row = $this->mapping[$key[$j]];
                $encoded .= $this->table[$col][$row];
            } else {
                $encoded .= strtoupper($text[$i]);
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
        for ($i=0; $i<strlen($this->key); $i++) {
            $kch = strtoupper($this->key[$i]);
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
        if (($elen = strlen($encrypted)) !== ($dlen = strlen($decrypted))) {
            throw new \Exception(
                'Texts cannot be processed because of strings length mismatch!',
                self::EXCEPTION_CODE_STRINGS_LENGTH_MISMATCH
            );
        }

        $key = '';
        for ($i=0; $i<$elen; $i++) {
            $ech = strtoupper($encrypted[$i]);
            $dch = strtoupper($decrypted[$i]);
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
        $textLength = strlen($text);

        do {
            $valid = true;
            $idx = 0;

            $key = substr($text, 0, $keyLength);

            do {
                $string = substr($text, $idx, $keyLength);
                $stringLength = strlen($string);

                if ($keyLength === $stringLength && $key !== $string) {
                    $valid = false;
                    break;
                } else if ($keyLength !== $stringLength && substr($key, 0, $stringLength) !== $string) {
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
