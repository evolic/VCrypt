<?php
$finder = Symfony\CS\Finder\DefaultFinder::create()
    ->filter(function (SplFileInfo $file) {
        if (strstr($file->getPath(), 'compatibility')) {
            return false;
        }
    })
    ->in(__DIR__ . '/library')
    ;
$config = Symfony\CS\Config\Config::create();
$config->level(null);
$config->fixers(
    array(
      // borrowed from Zend Framework 2
        'indentation',
        'linefeed',
        'trailing_spaces',
        'short_tag',
        'visibility',
        'php_closing_tag',
        'braces',
        'function_declaration',
        'psr0',
        'elseif',
        'eof_ending',
        'unused_use',
      // my own
        'return',
        'controls_spaces',
    )
);
$config->finder($finder);
return $config;
