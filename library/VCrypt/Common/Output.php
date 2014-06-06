<?php

/**
 * Vigenère cipher (http://vcrypt.tomaszkuter.com/)
 *
 * @link      http://github.com/loculus/vcrypt for the canonical source repository
 * @copyright Copyright (c) 2014 Tomasz Kuter (http://www.tomaszkuter.com)
 * @license   http://framework.zend.com/license/new-bsd New BSD License
 */

namespace VCrypt\Common;

/**
 * Class used to output text to the stdout
 * It is easy to mock it and check it's output.
 *
 * @author     Tomasz Kuter <me@tomaszkuter.com>
 * @since      April 27, 2014
 * @copyright  (C) 2014 Tomasz Kuter Loculus Evolution
 */
class Output
{
  /**
   * Prints Trithemius' tableau, known as the tabula recta
   * Function mostly for the debugging purpose
   *
   * @see http://en.wikipedia.org/wiki/Tabula_recta
   * @see http://rumkin.com/tools/cipher/vigenere-keyed.php Show tableau
   *
   * @param array $tableau       Trithemius' tableau as an array
   * @param int   $charsInColumn Number of characters in the single column
   */
    public function printTableau($tableau, $charsInColumn = 4)
    {
        $idx = 0;

        foreach ($tableau as $col => $rows) {
            $line = '';

            $chars = -1;

            foreach ($rows as $row => $char) {
                if ($chars === 0) {
                  $line .= ' |';
                }
                if ($chars % $charsInColumn === 0) {
                    $line .= ' ';
                }

                $line .= $char;
                $chars++;
            }

            $line .=  PHP_EOL;

            $this->printText($line);

            $idx++;
        }

        $this->printText(PHP_EOL);
    }

    /**
     * Prints single, transposed column
     *
     * @param array $transposedColumn Transposed column
     * @param int   $charsInColumn    Number of characters in the single column
     */
    public function printSingleColumn($transposedColumn, $charsInColumn = 4)
    {
        $lines  = count($transposedColumn);
        $digits = ceil(log10($lines));

        for ($i=0; $i<$lines; $i++) {
            $line = '';
            $row  = $transposedColumn[$i];

            $line = ' ' . $this->getLineNumber($i+1, $digits) . ' | ';

            $chars = 0;

            foreach ($row as $columnNumber => $char) {
                // convert empty chars into spaces
                if ($char == '') {
                    $char = ' ';
                }

                if ($chars && $chars % $charsInColumn === 0) {
                    $line .= ' ';
                }

                $line .= $char;
                $chars++;
            }

            $line .=  PHP_EOL;

            $this->printText($line);
        }

        $this->printText(PHP_EOL);
    }

    /**
     * Prints text divided into columns
     *
     * @param array $columns       Text divided into columns
     * @param int   $charsInColumn Number of characters in the single column
     */
    public function printColumns($columns, $charsInColumn = 4)
    {
        $lines  = count($columns[0]);
        $digits = ceil(log10($lines));

        for ($i=0; $i<$lines; $i++) {
            $line = ' ' . $this->getLineNumber($i+1, $digits) . ' | ';

            foreach ($columns as $j => $column) {
                if ($j) {
                    $line .= ' ';
                }

                if (array_key_exists($i, $column)) {
                    $line .= $column[$i];
                }
            }

            $line .=  PHP_EOL;

            $this->printText($line);
        }

        $this->printText(PHP_EOL);
    }

    /**
     * Returns line number with some spaces at the beginning.
     * Spaces and line number must be a string with a length specified in $digits param
     *
     * @param  int    $line   Number of the line
     * @param  int    $digits Number of digits, filled with spaces for lower numbers
     * @return string
     */
    public function getLineNumber($line, $digits)
    {
        $spaces     = $digits - strlen((string) $line);
        $lineNumber = '';

        for ($i=0; $i<$spaces; $i++) {
            $lineNumber .= ' ';
        }

        $lineNumber .= $line;

        return $lineNumber;
    }

    /**
     * Low level method, which prints text into stdout
     *
     * @param string $text Text, which will be printed
     */
    public function printText($text)
    {
        echo $text;
    }
}
