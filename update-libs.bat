@ECHO off
REM Loculus Evolution
REM
REM LICENSE
REM
REM This source file is subject to the new BSD license that is bundled
REM with this package in the file LICENSE.txt.
REM It is also available through the world-wide-web at this URL:
REM http://framework.zend.com/license/new-bsd
REM If you did not receive a copy of the license and are unable to
REM obtain it through the world-wide-web, please send an email
REM to license@zend.com so we can send you a copy immediately.
REM
REM Loculus
REM Copyright (c) 2013 Tomasz Kuter [Poland] (http://evolic.eu5.org)
REM http://framework.zend.com/license/new-bsd     New BSD License

REM Add some space between program's executions
ECHO. >> composer.log

REM Write current datetime to log file
SET timestamp=%date% %time:~0,2%:%time:~3,2%:%time:~6,2%
ECHO %timestamp% >> composer.log

REM Log Composer activity to log file
REM It is important to know and keep in some place information about used version of libraries.
REM After doing updates and running unit tests it will be easier to return to the last good working environment.
php composer.phar update >> composer.log

