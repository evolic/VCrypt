<?php
namespace VCrypt\Cipher;

use VCrypt\Common\Output;
use VCrypt\Exception\InvalidPadSizeException;
use VCrypt\Exception\PadSizeNotSetException;

/**
 * Class KryptosTranspositionCipherDebugger
 *
 * @package VCrypt\Cipher
 */
class KryptosTranspositionCipherDebugger extends KryptosTranspositionCipher
{
    /**
     * Instance of the object printing data
     *
     * @var Output
     */
    protected $output;


    /**
     * Constructor
     *
     * @param  array  $options
     * @param  Output  $output
     */
    public function __construct($options = array(), $output = null)
    {
        parent::__construct($options);

        if (is_null($output)) {
            $output = new Output();
        }

        $this->output = $output;
    }


    /**
     * Backwards text
     *
     * @param string $text
     * @return string
     */
    protected function backward($text)
    {
        $string = parent::backward($text);

        $this->output->printText('0 | ');
        $this->output->printText($string);
        $this->output->printText(PHP_EOL . PHP_EOL);

        return $string;
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
        $columns = parent::slicePad($textInRows, $sliceSize);

        $this->output->printColumns($columns);

        return $columns;
    }

    /**
     * Transposes columns provided as the array
     *
     * @param  array  $columns
     * @throws InvalidPadSizeException
     * @return array
     */
    protected function transposeColumns($columns)
    {
        $transposedColumn  = array();
        $transposedColumns = array();

        foreach ($columns as $column) {
            $transposedRows = array();

            foreach ($column as $row) {
                $transposedRow = $this->transpose($row);
                $transposedColumn[] = $transposedRow;

                $transposedRows[] = implode('', $transposedRow);
            }

            $transposedColumns[] = $transposedRows;
        }

        $this->output->printColumns($transposedColumns, $this->keyLength);

        $this->output->printSingleColumn($transposedColumn, 4, $this->output);

        $this->validatePossibilityOfTheDecryption($transposedColumn);

        return $transposedColumn;
    }

    /**
     * @param  string  $text
     * @throws PadSizeNotSetException
     */
    protected function tryPaddingAndTransposing($text)
    {
        $this->output->printText('0 | Started padding and transposing simulation');
        $this->output->printText(PHP_EOL . PHP_EOL);

        list($columns, $transposedColumn) = parent::tryPaddingAndTransposing($text);

        $this->output->printText('0 | Ended padding and transposing simulation');
        $this->output->printText(PHP_EOL . PHP_EOL);

        return array($columns, $transposedColumn);
    }
}