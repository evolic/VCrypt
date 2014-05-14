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
    public function printText($text)
    {
        echo $text;
    }
}
