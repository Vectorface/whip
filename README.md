# Whip

[![Build Status](https://travis-ci.org/Vectorface/whip.svg?branch=master)](https://travis-ci.org/Vectorface/whip)
[![Code Coverage](https://scrutinizer-ci.com/g/Vectorface/whip/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/Vectorface/whip/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Vectorface/whip/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Vectorface/whip/?branch=master)
[![Latest Stable Version](https://poser.pugx.org/vectorface/whip/v/stable.svg)](https://packagist.org/packages/vectorface/whip)
[![License](https://poser.pugx.org/vectorface/whip/license.svg)](https://packagist.org/packages/vectorface/whip)

Whip (stands for Which Ip) is a lightweight class for returning a client's IP address in PHP.

## The Problem

It may seem trivial to simply pull the client's IP address from
`$_SERVER['REMOTE_ADDR']` but this address is not always accurate. For example,
if your web servers are behind a reverse proxy like Varnish, the IP address
listed will be that of your proxy and not the client.

Many solutions propose checking multiple headers but those headers can be
spoofed as well and we want to present a final solution anyone can deploy.

## Installing Whip.

Simply run the following [composer](https://getcomposer.org/) command:

```shell
$ composer require vectorface/whip
```

## Using Whip

Add the required `use` statement to your class

```php
use Vectorface\Whip\Whip;
```

To fetch an IP address using every implemented method, you can simply do

```php
$whip = new Whip();
$clientAddress = $whip->getValidIpAddress();
```

The class will attempt every method to retrieve the client's IP address
starting with very specific use cases and falling back to more general use
cases.

Note, that the method `Whip::getValidIpAddress` will return `false` if no
valid IP address could be determined, so it is important to check for errors.

```php
$whip = new Whip();
if (false === ($clientAddress = $whip->getValidIpAddress())) {
    // handle the error
}
```

To fetch an IP address using a specific method, you can pass a bitmask of
enabled methods to the constructor. Here is an example of looking up the IP
address using CloudFlare's custom HTTP header, and falling back to
`$_SERVER['REMOTE_ADDR']` otherwise.

```php
$whip = new Whip(Whip::CLOUDFLARE_HEADERS | Whip::REMOTE_ADDR);
$clientAddress = $whip->getValidIpAddress();
```

This method works, but there is the problem that the custom HTTP header can
easily be spoofed if your sites accept traffic not from CloudFlare. To prevent
this, Whip allows you to specify a whitelist of IP addresses (or address ranges)
that you accept per method.

## Using Whip Behind a Trusted Proxy

A common use case is to deploy a trusted proxy (nginx, varnish, and many others)
in front of an application server. To forward the correct client IP, the trusted
proxy should be configured to inject a header for Whip to read with the custom
headers method.

If the trusted proxy is configured to send a X-My-Client-IP header, Whip
could be used as follows:

```php
$whip = new Whip(
    Whip::CUSTOM_HEADERS,
    [Whip::CUSTOM_HEADERS => [ // Whitelist your proxies.
        Whip::IPV4 => ['10.0.0.2', '10.0.0.3']
    ]]
);
$whip->addCustomHeader('HTTP_X_MY_CLIENT_IP');
$ip = $whip->getValidIpAddress();
```

## Using the CloudFlare IP Range Whitelist

As a common example, Whip can accept a whitelist of IP ranges for CloudFlare
when using their custom header and fall back to `$_SERVER['REMOTE_ADDR']` if the
custom header was not found or if the source IP address does match any in the
whitelist.

```php
$whip = new Whip(
    Whip::CLOUDFLARE_HEADERS | Whip::REMOTE_ADDR,
    [
        Whip::CLOUDFLARE_HEADERS => [
            Whip::IPV4 => [
                '199.27.128.0/21',
                '173.245.48.0/20',
                '103.21.244.0/22',
                '103.22.200.0/22',
                '103.31.4.0/22',
                '141.101.64.0/18',
                '108.162.192.0/18',
                '190.93.240.0/20',
                '188.114.96.0/20',
                '197.234.240.0/22',
                '198.41.128.0/17',
                '162.158.0.0/15',
                '104.16.0.0/12'
            ],
            Whip::IPV6 => [
                '2400:cb00::/32',
                '2606:4700::/32',
                '2803:f800::/32',
                '2405:b500::/32',
                '2405:8100::/32'
            ]
        ]
    ]
);
$clientAddress = $whip->getValidIpAddress();
```

Please be sure to use the actual list of IP ranges from CloudFlare for
[IPv4](https://www.cloudflare.com/ips-v4) and
[IPv6](https://www.cloudflare.com/ips-v6).

## List of Methods

The individual methods are stored as integer constants on the `Whip` class.
To combine methods, use the bitwise OR operator `|`. The current methods are:

- `Whip::REMOTE_ADDR` - Uses the standard `$_SERVER['REMOTE_ADDR']`.
- `Whip::PROXY_HEADERS` - Uses any of the following values:
    - `$_SERVER['HTTP_CLIENT_IP']`
    - `$_SERVER['HTTP_X_FORWARDED_FOR']`
    - `$_SERVER['HTTP_X_FORWARDED']`
    - `$_SERVER['HTTP_X_CLUSTER_CLIENT_IP']`
    - `$_SERVER['HTTP_FORWARDED_FOR']`
    - `$_SERVER['HTTP_FORWARDED']`
    - `$_SERVER['HTTP_X_REAL_IP']`
- `Whip::CLOUDFLARE_HEADERS` - Uses the CloudFlare provided HTTP header
  "CF-Connecting-IP".
- `Whip::INCAPSULA_HEADERS` - Use the Incapsula provided HTTP header
  "Incap-Client-IP".
- `Whip::CUSTOM_HEADERS` - Uses a custom list of HTTP headers passed into
  `Whip::addCustomHeader`.

Please note that the proxy headers method can be susceptible to client spoofing
because it extracts addresses from several possible HTTP headers. This means
that using the proxy headers method is not appropriate where trust is required,
like in the context of authentication.

## Using a Custom Header

Whip can also allow you to specify a custom header to use. For example, you may
configure your own proxy to send a unique obfuscated header internally that
would be hard to spoof. In this example, we assume Varnish is run locally and
we use a custom HTTP header "X-SECRET-REAL-IP" (and fall back to
`$_SERVER['REMOTE_ADDR']` if the custom header doesn't work).

```php
$whip = new Whip(
    Whip::CUSTOM_HEADERS | Whip::REMOTE_ADDR,
    [
        Whip::CUSTOM_HEADERS => [
            Whip::IPV4 => [
                '127.0.0.1'
            ],
            Whip::IPV6 => [
                '::1'
            ]
        ]
    ]
);
$whip->addCustomHeader('X-SECRET-REAL-IP');
$clientAddress = $whip->getValidIpAddress();
```

## Valid IP Ranges

For IPv4, Whip accepts three types of IP ranges:

- Asterisk wildcard (192.168.\*)
- Dashed range (192.168.0.0-192.168.255.255)
- CIDR bitmask notation (192.168.0.0/16)

For IPv6, Whip only accepts the CIDR bitmask notation (fc00::/7).

Furthermore, you can specify a list of exact IP addresses instead of a list of
ranges.

## IP Range Filtering

Whip can also be used to provide simple IP range matching. For example,

```php
$range = new Vectorface\Whip\IpRange\Ipv4Range('10.0.*');
if ($range->containsIp($ipv4Address)) {
    // handle the IP address being within the range
}

$range = new Vectorface\Whip\IpRange\Ipv6Range('::1/32');
if ($range->containsIp($ipv6Address)) {
    // handle the IP address being within the range
}
```

## PSR-7 Requests, and Others

Whip supports using [PSR-7 (http-message)](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md) request instances in place of the `$_SERVER` superglobal. For example,

```php
// Get a Psr\Http\Message\ServerRequestInterface implementation from somewhere.
$request = ServerRequestFactory::fromGlobals();

// You can pass the request in the constructor.
$whip = new Whip(Whip::REMOTE_ADDR, [], $request);

// ... or set the request as the source of data.
$whip->setSource($request);

// ... or pass it to any function accepting a source argument.
$ip = $whip->getValidIpAddress($request);
```

Other request formats can be supported via a RequestAdapter (src/Request/RequestAdapter) implementation.
