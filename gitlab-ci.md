GitLab CI job

```shell
rm composer.lock

sudo apt-get install parallel
composer install --dev --prefer-source

mkdir -p build/coverage

vendor/bin/php-cs-fixer fix -v --dry-run --config-file ./.php_cs
php tests/run-tests.php --clover ../build/logs/clover.xml
```