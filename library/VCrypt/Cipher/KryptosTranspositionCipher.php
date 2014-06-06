<?php

/**
 * Kryptos transposition cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://tomaszkuter.com/license/new-bsd New BSD License
 */

namespace VCrypt\Cipher;


use VCrypt\Common\Output;
use VCrypt\Exception\InvalidTranspositionSourceTextException;
use VCrypt\Exception\KeyNotSetException;
use VCrypt\Exception\InvalidPadSizeException;

/**
 * Kryptos transposition cipher class
 *
 * @author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      June 5, 2014
 * @copyright  (C) 2014 Tomasz Kuter Loculus Evolution
 * @see http://math.ucsd.edu/~crypto/Projects/KarlWang/index2.html
 */
class KryptosTranspositionCipher
{
    /**
     * Enable debug mode
     *
     * @var boolean
     */
    static protected $debug = false;


    /**
     * Secret Key
     * @var string
     */
    protected $key;

    /**
     * Secret Key length
     * @var int
     */
    protected $keyLength = 0;

    /**
     * Specifies pad size for the Kryptos cipher
     * @var int
     */
    protected $padSize = 86;


    protected $transpositionTable = array();

    /**
     * Instance of the object printing data
     *
     * @var Output
     */
    protected $output;


    /**
     * Constructor
     *
     * @param array $options
     * @return void
     */
    public function __construct($options = array())
    {
        $this->reset();

        if (array_key_exists('key', $options)) {
            $this->setKey($options['key']);
        }
        if (array_key_exists('pad-size', $options)) {
            $this->setPadSize($options['pad-size']);
        }
    }


    /**
     * Enable/Disable debug mode
     */
    public static function setDebug($debug)
    {
       self::$debug = $debug;
    }


    /**
     * Resets data
     *
     * @return void
     */
    protected function reset()
    {
      $this->transpositionTable = array();
    }

    protected function backward($text)
    {
        $length = mb_strlen($text, 'utf-8');
        $string = '';

        for ($i = $length - 1; $i>=0; $i--) {
            $string .= mb_substr($text, $i, 1, 'utf-8');
        }

        return $string;
    }


    /**
     * Builds transposition table based on the key
     *
     * @throws KeyNotSetException
     */
    protected function buildTranspositionTable()
    {
        $key        = $this->key;
        $keyAsArray = array();

        for ($i=0; $i<$this->keyLength; $i++) {
            $keyAsArray[] = mb_substr($key, $i, 1, 'utf-8');
        }

        $keyAsArraySorted = $keyAsArray;
        sort($keyAsArraySorted);

        for ($i=0; $i<$this->keyLength; $i++) {
            $char = $keyAsArray[$i];

            for ($j=0; $j<$this->keyLength; $j++) {
                if ($char === $keyAsArraySorted[$j]) {
                    $this->transpositionTable[$i] = $j;
                    continue;
                }
            }
        }
    }

    /**
     * Transposes specified text and returns it as an array
     *
     * @param string $text
     * @throws InvalidTranspositionSourceTextException
     * @return array
     */
    protected function transpose($text)
    {
        $textLength = mb_strlen($text, 'utf-8');

        if (!isset($this->key)) {
            throw new KeyNotSetException('You must set key first');
        }
        if ($textLength > $this->keyLength) {
            throw new InvalidTranspositionSourceTextException(
                'Cannot transpose provided text with specified key. Text is too long!'
            );
        }

        if (empty($this->transpositionTable)) {
            $this->buildTranspositionTable();
        }

        $output = array();

        // fill the array with empty values
        for ($i=0; $i<$this->keyLength; $i++) {
            $output[$i] = '';
        }

        for ($i=0; $i<$textLength; $i++) {
            $j = $this->transpositionTable[$i];
            $output[$j] = mb_substr($text, $i, 1, 'utf-8');
        }

        ksort($output);

        return $output;
    }

    /**
     * Pads specified text (slice it into the rows with fixed length)
     *
     * @param string $text
     * @return array
     */
    protected function padText($text)
    {
        $textInRows = array();
        $textLength = mb_strlen($text, 'utf-8');

        $skip = 0;

        do {
            $row = mb_substr($text, $skip, $this->padSize, 'utf-8');
            $textInRows[] = $row;
            $skip += $this->padSize;
        }
        while ($skip < $textLength);

        return $textInRows;
    }

    /**
     * Slices specified text provided in rows into the columns
     *
     * @param array $textInRows
     * @return array
     */
    protected function slicePad($textInRows)
    {
        $columns = array();

        foreach ($textInRows as $row) {
            $rowLength = mb_strlen($row, 'utf-8');

            $skip = 0;
            $idx  = 0;

            do {
                $slice = mb_substr($row, $skip, $this->keyLength, 'utf-8');
                $columns[$idx][] = $slice;

                $skip += $this->keyLength;
                $idx++;
            }
            while ($skip < $rowLength);
        }

        if (self::$debug && !is_null($this->output)) {
            $this->output->printColumns($columns, $this->keyLength, $this->output);
        }

        return $columns;
    }

    protected function transposeColumns($columns)
    {
        $transposedColumn = array();

        foreach ($columns as $column)
        {
            foreach ($column as $row) {
                $transposedColumn[] = $this->transpose($row);
            }
        }

        if (self::$debug && !is_null($this->output)) {
            $this->output->printSingleColumn($transposedColumn, 4, $this->output);
        }

        // validate possibility of the decryption
        $chars = 0;
        $idx   = 1;

        foreach ($transposedColumn as $row) {
            $charsInTheRow = 0;

            foreach ($row as $char) {
                if ($char == '') {
                    continue;
                }

                $charsInTheRow++;
            }

            var_dump(array($chars, $charsInTheRow));

            if (!$chars || $charsInTheRow <= $chars) {
                $chars = $charsInTheRow;
            } else {
                throw new InvalidPadSizeException(
                    sprintf(
                        'Specified pad size: %d is not valid for specified text (rows: %d and %d). Decryption won\'t be possible. Try to decrease or increase pad size!',
                        $this->padSize,
                        $idx - 1,
                        $idx
                    )
                );
            }

            $idx++;
        }

        return $transposedColumn;
    }

    protected function downward($column)
    {
        $text      = '';

        for ($i = 0; $i<$this->keyLength; $i++) {
            foreach ($column as $row) {
                // character can be empt string
                $char = $row[$i];
                $text .= $char;
            }
        }

        return $text;
    }

    /**
     * Encodes provided text
     *
     * @param string $text
     * @param Output $output
     * @return string
     */
    public function encode($text, $output = null)
    {
        if (!isset($output)) {
            $output = new Output();
        }
        $this->output = $output;

        $invertedText     = $this->backward($text);
        $paddedTextInRows = $this->padText($invertedText);
        $columns          = $this->slicePad($paddedTextInRows);
        $transposedColumn = $this->transposeColumns($columns);

        $encrypted        = $this->downward($transposedColumn);

        return $encrypted;
    }


    /**
     * Sets a secret key
     *
     * @param string $key Secret key used for data encryption
     * @return VigenereCipher
     */
    public function setKey($key)
    {
        $this->key = $key;

        // set key length to save time and cpu
        $this->keyLength = mb_strlen($key, 'utf-8');

        return $this;
    }

    /**
     * Sets cipher pad size
     *
     * @param int $padSize
     * @return KryptosTranspositionCipher
     */
    public function setPadSize($padSize)
    {
        $this->padSize = $padSize;
        return $this;
    }
}
