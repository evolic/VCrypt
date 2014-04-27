<?php
/**
 * Deserializes PHP_CodeCoverage objects from the files passed on the command line,
 * combines them into a single coverage object and creates an HTML report of the
 * combined coverage.
 */

if ($argc <= 2) {
  die("Usage: php generate-coverage-report.php cov-file1 cov-file2 ...");
}

// Init the Composer autoloader
require realpath(dirname(__FILE__)) . '/../vendor/autoload.php';

foreach (array_slice($argv, 1) as $filename) {
  // See PHP_CodeCoverage_Report_PHP::process
  // @var PHP_CodeCoverage
  $cov = unserialize(file_get_contents($filename));
  if (isset($codeCoverage)) {
    $codeCoverage->filter()->addFilesToWhitelist($cov->filter()->getWhitelist());
    $codeCoverage->merge($cov);
  } else {
    $codeCoverage = $cov;
  }
}

print "\nGenerating code coverage report in HTML format ...";

// Based on PHPUnit_TextUI_TestRunner::doRun
$writer = new PHP_CodeCoverage_Report_HTML(
  'UTF-8',
  false, // 'reportHighlight'
  35, // 'reportLowUpperBound'
  70, // 'reportHighLowerBound'
  sprintf(
    ' and <a href="http://phpunit.de/">PHPUnit %s</a>',
    PHPUnit_Runner_Version::id()
      )
  );

$writer->process($codeCoverage, 'coverage');

print " done\n";
print "See coverage/index.html\n";