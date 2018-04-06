<?php

/**
 * Kryptos transposition cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @link      http://math.ucsd.edu/~crypto/Projects/KarlWang/index2.html Detailed cipher description
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://tomaszkuter.com/license/new-bsd New BSD License
 */

namespace VCrypt\Cipher;

use VCrypt\Exception\InvalidTranspositionSourceTextException;
use VCrypt\Exception\InvalidUndoTranspositionException;
use VCrypt\Exception\KeyNotSetException;
use VCrypt\Exception\InvalidPadSizeException;
use VCrypt\Exception\PadSizeNotSetException;

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

    /**
     * Specifies auto-correction mode if pad size is not valid for text provided to encode
     * @var bool
     */
    protected $autoCorrectionForPadSizeMismatchWithProvidedText = false;

    /**
     * Specifies auto-correction mode if pad size is not valid for text provided to encode
     * @var int
     */
    protected $autoCorrectionCount = 0;

    /**
     * Specifies how many cipher was unable to decode encrypted text during encoding process (auto-test)
     * @var int
     */
    protected $failedDecodingCount = 0;

    /**
     * Specifies if InvalidPadSizeException should be skipped inside validatePossibilityOfTheDecryption() method
     * @var bool
     */
    protected $paddingSimulation = false;


    protected $transpositionTable = array();


    /**
     * Constructor
     *
     * @param array $options
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

        if (array_key_exists('auto-correction', $options)) {
            $this->setAutoCorrection($options['auto-correction']);
        }
    }


    /**
     * Resets data
     */
    protected function reset()
    {
        $this->transpositionTable = array();
    }

    /**
     * Backwards text
     *
     * @param  string  $text
     * @return string
     */
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
     */
    protected function buildTranspositionTable()
    {
        $key        = $this->key;
        $keyAsArray = array();

        for ($i=0; $i<$this->keyLength; $i++) {
            $keyAsArray[] = mb_substr($key, $i, 1, 'utf-8');
        }

        $keyAsOrderedArray = $keyAsArray;
        sort($keyAsOrderedArray);

        for ($i=0; $i<$this->keyLength; $i++) {
            $char = $keyAsArray[$i];

            for ($j=0; $j<$this->keyLength; $j++) {
                if ($char === $keyAsOrderedArray[$j]) {
                    $this->transpositionTable[$i] = $j;
                    continue;
                }
            }
        }
    }

    /**
     * Transposes specified text and returns it as an array
     *
     * @param  string  $text
     * @throws KeyNotSetException
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
     * Reverts text as it was before transposition of the specified array
     *
     * @param  string  $text
     * @param  array  $transposedColumnLengths
     * @return array
     * @throws InvalidUndoTranspositionException
     */
    protected function splitInputIntoRows($text, $transposedColumnLengths)
    {
        $columns = array();
        $textLength = mb_strlen($text, 'utf-8');

        $skip = 0;

        for ($i=0; $i<$this->keyLength; $i++) {
            $columns[] = mb_substr($text, $skip, $transposedColumnLengths[$i], 'utf-8');
            $skip += $transposedColumnLengths[$i];
        }

        if ($skip !== $textLength) {
            throw new InvalidUndoTranspositionException();
        }

        return $columns;
    }

    /**
     * Reorders columns over the rows
     *
     * @param  array  $rows
     * @return array
     */
    protected function reorderColumns($rows)
    {
        $reorderedRows = array();

        foreach ($this->transpositionTable as $idx) {
            $reorderedRows[] = $rows[$idx];
        }

        return $reorderedRows;
    }

    /**
     * Pads specified text (slice it into the rows with fixed length)
     *
     * @param  string  $text
     * @throws PadSizeNotSetException
     * @return array
     */
    protected function padText($text)
    {
        $textInRows = array();
        $textLength = mb_strlen($text, 'utf-8');

        $skip = 0;

        if (!isset($this->padSize)) {
            throw new PadSizeNotSetException('You must set pad size first');
        }

        do {
            $row = mb_substr($text, $skip, $this->padSize, 'utf-8');
            $textInRows[] = $row;

            $skip += $this->padSize;
        } while ($skip < $textLength);

        return $textInRows;
    }

    /**
     * Slices specified text provided in rows into the columns
     *
     * @param  array  $textInRows
     * @param  int  $sliceSize
     * @return array
     */
    protected function slicePad($textInRows, $sliceSize)
    {
        $columns = array();

        foreach ($textInRows as $row) {
            $rowLength = mb_strlen($row, 'utf-8');

            $skip = 0;
            $idx  = 0;

            do {
                $slice = mb_substr($row, $skip, $sliceSize, 'utf-8');
                $columns[$idx][] = $slice;

                $skip += $sliceSize;
                $idx++;
            } while ($skip < $rowLength);
        }

        return $columns;
    }

    /**
     * Transposes columns provided as the array
     *
     * @param  array  $columns
     * @return array
     * @throws InvalidPadSizeException
     * @throws InvalidTranspositionSourceTextException
     * @throws KeyNotSetException
     */
    protected function transposeColumns($columns)
    {
        $transposedColumn = array();

        foreach ($columns as $column) {
            foreach ($column as $row) {
                $transposedColumn[] = $this->transpose($row);
            }
        }

        $this->validatePossibilityOfTheDecryption($transposedColumn);

        return $transposedColumn;
    }

    /**
     * Validates possibility of the decryption for given text and pad size
     *
     * @param  array  $transposedColumn
     * @throws InvalidPadSizeException
     */
    protected function validatePossibilityOfTheDecryption($transposedColumn)
    {
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

            // @todo add description!
            if (!$chars || $charsInTheRow <= $chars) {
                $chars = $charsInTheRow;
            } else {
                if (!$this->paddingSimulation) {
                    throw new InvalidPadSizeException(
                        sprintf(
                            'Specified pad size: %d is not valid for specified text (rows: %d and %d).' .
                            'Decryption won\'t be possible. Try to decrease or increase pad size!',
                            $this->padSize,
                            $idx - 1,
                            $idx
                        )
                    );
                }
            }

            $idx++;
        }
    }

    /**
     * Concatenates string downward over the rows in the column
     *
     * @param  array  $column
     * @return string
     */
    protected function downward($column)
    {
        $text = '';

        for ($i = 0; $i<$this->keyLength; $i++) {
            foreach ($column as $row) {
                // character can be empty string
                $char = $row[$i];
                $text .= $char;
            }
        }

        return $text;
    }

    /**
     * Encodes provided text
     *
     * @param  string  $text
     * @return string
     * @throws InvalidPadSizeException
     * @throws InvalidTranspositionSourceTextException
     * @throws KeyNotSetException
     * @throws PadSizeNotSetException
     */
    public function encode($text)
    {
        $this->autoCorrectionCount = 0;
        $this->failedDecodingCount = 0;

        if (!$this->autoCorrectionForPadSizeMismatchWithProvidedText) {
            $invertedText     = $this->backward($text);
            $paddedTextInRows = $this->padText($invertedText);
            $columns          = $this->slicePad($paddedTextInRows, $this->keyLength);
            $transposedColumn = $this->transposeColumns($columns);

            $encrypted        = $this->downward($transposedColumn);

            return $encrypted;
        } else {
            $source = $text;
            $sourceLength = mb_strlen($source, 'utf-8');

            do {
                try {
                    $invertedText     = $this->backward($text);
                    $paddedTextInRows = $this->padText($invertedText);
                    $columns          = $this->slicePad($paddedTextInRows, $this->keyLength);
                    $transposedColumn = $this->transposeColumns($columns);

                    $encrypted        = $this->downward($transposedColumn);

                    return $encrypted;
                } catch (InvalidPadSizeException $e) {
                    $char = mb_substr($source, mt_rand(0, $sourceLength - 1), 1, 'utf-8');
                    $text .=  $char;

                    $this->autoCorrectionCount++;
                } catch (InvalidUndoTranspositionException $e) {
                    $source = $text;
                    $sourceLength = mb_strlen($source, 'utf-8');

                    $char = mb_substr($source, mt_rand(0, $sourceLength - 1), 1, 'utf-8');
                    $text .=  $char;

                    $this->autoCorrectionCount = 0;
                    $this->failedDecodingCount++;
                }
            } while (true);
        }
    }

    /**
     * Gets transposed column lengths
     * E.g. [51, 47, 47, 51, 47, 47, 47]
     *
     * @param  array  $transposedColumn
     * @return array
     * @throws KeyNotSetException
     * @throws PadSizeNotSetException
     */
    protected function getTransposedColumnLengths($transposedColumn)
    {
        if (!isset($this->key)) {
            throw new KeyNotSetException('You must set key first');
        }
        if (!isset($this->padSize)) {
            throw new PadSizeNotSetException('You must set pad size first');
        }

        if (empty($this->transpositionTable)) {
            $this->buildTranspositionTable();
        }

        $transposedColumnLengths = array();
        $transposedColumnLength  = count($transposedColumn);

        for ($i=0; $i<$this->keyLength; $i++) {
            for ($j=$transposedColumnLength-1; $j>0; $j--) {
                if ($transposedColumn[$j][$i] !== '') {
                    $transposedColumnLengths[] = $j + 1;
                    break;
                }
            }
        }

        return $transposedColumnLengths;
    }

    /**
     * Decodes given text
     *
     * @param  string  $text
     * @return string
     * @throws InvalidPadSizeException
     * @throws InvalidUndoTranspositionException
     * @throws KeyNotSetException
     * @throws PadSizeNotSetException
     */
    public function decode($text)
    {
        $textLength = mb_strlen($text, 'utf-8');

        list($columns, $transposedColumn) = $this->tryPaddingAndTransposing($text);

        $transposedColumnLengths = $this->getTransposedColumnLengths($transposedColumn);
        $splitTextInRows         = $this->splitInputIntoRows($text, $transposedColumnLengths);
        $reorderedRows           = $this->reorderColumns($splitTextInRows);

        // chop rows into columns according to slice size
        $rowsCount = (int) ceil($textLength / $this->padSize);

        $textPaddedInRows = $this->undoSlicePad($reorderedRows, $columns);
        $invertedText     = $this->undoPadText($textPaddedInRows, $rowsCount);

        $decrypted             = $this->backward($invertedText);

        return $decrypted;
    }

    /**
     * Tries padding and transposing given text
     *
     * @param  string  $text
     * @return array
     * @throws InvalidPadSizeException
     * @throws InvalidTranspositionSourceTextException
     * @throws KeyNotSetException
     * @throws PadSizeNotSetException
     */
    protected function tryPaddingAndTransposing($text)
    {
        // turning on simulation mode
        $this->paddingSimulation = true;

        $paddedTextInRows = $this->padText($text);
        $columns          = $this->slicePad($paddedTextInRows, $this->keyLength);
        $transposedColumn = $this->transposeColumns($columns);

        // turning off simulation mode
        $this->paddingSimulation = false;

        return array($columns, $transposedColumn);
    }

    /**
     * Undoes padding according slice size and text length from the rows sliced into columns
     *
     * @param  array  $reorderedRows
     * @param  array  $columns
     * @return array
     */
    protected function undoSlicePad($reorderedRows, $columns)
    {
        $textPaddedInRows = array();

        $j = 0;
        foreach ($columns as $column) {
            $paddedColumn = array();

            for ($i=0; $i<count($column); $i++) {
                $text = '';

                foreach ($reorderedRows as $reorderedRow) {
                    // @todo Place for optimisation
                    $rowLength = mb_strlen($reorderedRow, 'utf-8');

                    if ($j >= $rowLength) {
                        $char = '';
                    } else {
                        $char = mb_substr($reorderedRow, $j, 1, 'utf-8');
                    }

                    $text .= $char;
                }

                $paddedColumn[] = $text;

                $j++;
            }

            $textPaddedInRows[] = $paddedColumn;
        }

        return $textPaddedInRows;
    }

    /**
     * Undoes text padding
     *
     * @param  array  $textPaddedInRows
     * @param  int  $rowsCount
     * @return string
     */
    protected function undoPadText($textPaddedInRows, $rowsCount)
    {
        $text = '';

        for ($i=0; $i<$rowsCount; $i++) {
            foreach ($textPaddedInRows as $column) {
                $columnLength = count($column);

                if ($i < $columnLength) {
                    $text .= $column[$i];
                }
            }
        }

        return $text;
    }

    /**
     * Sets a secret key
     *
     * @param  string  $key Secret key used for data encryption
     * @return KryptosTranspositionCipher
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

    /**
     * Sets auto-correction mode if pad size is not valid for text provided to encode
     *
     * @param bool $autoCorrection
     * @return KryptosTranspositionCipher
     */
    public function setAutoCorrection($autoCorrection)
    {
        $this->autoCorrectionForPadSizeMismatchWithProvidedText = $autoCorrection;

        return $this;
    }

    /**
     * Returns how many auto-correction was applied to encoded text
     *
     * @return int counter
     */
    public function getAutoCorrectionCount()
    {
        return $this->autoCorrectionCount;
    }

    /**
     * Returns number of failed decoding
     *
     * @return int counter
     */
    public function getFailedDecodingCount()
    {
        return $this->failedDecodingCount;
    }
}
