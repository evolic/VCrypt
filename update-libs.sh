#!/bin/bash

#############################################################################
# Loculus Evolution
#
# LICENSE
#
# This source file is subject to the new BSD license that is bundled
# with this package in the file LICENSE.txt.
# It is also available through the world-wide-web at this URL:
# http://framework.zend.com/license/new-bsd
# If you did not receive a copy of the license and are unable to
# obtain it through the world-wide-web, please send an email
# to license@zend.com so we can send you a copy immediately.
#
# Loculus
# Copyright (c) 2013 Tomasz Kuter [Poland] (http://evolic.eu5.org)
# http://framework.zend.com/license/new-bsd     New BSD License
#############################################################################

# find php: pear first, command -v second, straight up php lastly
if test "@php_bin@" != '@'php_bin'@'; then
    PHP_BIN="@php_bin@"
elif command -v php 1>/dev/null 2>/dev/null; then
    PHP_BIN=`command -v php`
else
    PHP_BIN=php
fi

# find zf.php: pear first, same directory 2nd, 
if test "@php_dir@" != '@'php_dir'@'; then
    PHP_DIR="@php_dir@"
else
    SELF_LINK="$0"
    SELF_LINK_TMP="$(readlink "$SELF_LINK")"
    while test -n "$SELF_LINK_TMP"; do
        SELF_LINK="$SELF_LINK_TMP"
        SELF_LINK_TMP="$(readlink "$SELF_LINK")"
    done
    PHP_DIR="$(dirname "$SELF_LINK")"
fi

# Add some space between program's executions
echo "" >> composer.log

# Write current datetime to log file
timestamp=`date "+%F %R:%S"`
echo "$timestamp" >> composer.log

# Log Composer activity to log file
# It is important to know and keep in some place information about used version of libraries.
# After doing updates and running unit tests it will be easier to return to the last good working environment.
php composer.phar update >> composer.log

