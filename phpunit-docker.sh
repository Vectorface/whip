#!/bin/sh
command -v docker >/dev/null 2>&1 || { echo >&2 "Docker is required to run the test suite against multiple versions of PHP. Please just use ./vendor/bin/phpunit."; exit 1; }

for phpVersion in 5.3 5.4 5.5 5.6
do
	docker run -v "$(pwd)":/opt/whip -i -t -w /opt/whip debian7-php${phpVersion} /opt/whip/vendor/bin/phpunit
done