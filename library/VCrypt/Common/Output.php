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
   * @param array $tableau
   * @param int  $charsInColumn
   * @param Output $output
   * @return void
   */
    public function printTableau($tableau, $charsInColumn = 4, $output = null)
    {
        if (!isset($output)) {
            $output = $this;
        }

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

            $output->printText($line);

            $idx++;
        }

        $output->printText(PHP_EOL);
    }

    public function printText($text)
    {
        echo $text;
    }
}
