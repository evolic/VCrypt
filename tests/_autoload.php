<?php
/**
 * Setup autoloading
 */

include_once __DIR__ . '/../vendor/autoload.php';

$loader = new Zend\Loader\StandardAutoloader(
    array(
        Zend\Loader\StandardAutoloader::LOAD_NS => array(
            'VCryptTest' => __DIR__ . '/VCryptTest',
        ),
    )
);
$loader->register();
