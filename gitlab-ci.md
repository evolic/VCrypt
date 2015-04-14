GitLab CI job

```shell
curl -sS https://getcomposer.org/installer | php
php composer.phar --version

rm composer.lock

sudo apt-get install parallel
php composer.phar install --dev --prefer-source

mkdir -p build/coverage

vendor/bin/php-cs-fixer fix -v --dry-run --config-file ./.php_cs
php tests/run-tests.php --clover ../build/logs/clover.xml
```