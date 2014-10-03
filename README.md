# WhichIp

WhichIp (Whip) is a lightweight class for returning a client's IP address in PHP.

## The Problem

It may seem trivial to simply pull the client's IP address from
`$_SERVER['REMOTE_ADDR']` but this address is not always accurate. For example,
if your web servers are behind a reverse proxy like Varnish, the IP address
listed will be that of your proxy and not the client.

Many solutions propose checking multiple headers but those headers can be
spoofed as well and we want to present a final solution anyone can deploy.

## Installing Whip.

Simply add Whip to your composer.json `require` field like so:

    "require": {
        "vectorface/whip": "~0.1.0"
    }

## Using Whip

Add the required `use` statement to your class

    use VectorFace\WhichIp\WhichIp;

To fetch an IP address using every implemented method, you can simply do

    $whip = new WhichIp();
    $clientAddress = $whip->getValidIpAddress();

The class will attempt every method to retrieve the client's IP address
starting with very specific use cases and falling back to more general use
cases.

Note, that the method `WhichIp::getValidIpAddress` will return `false` if no
valid IP address could be determined, so it is important to check for errors.

    $whip = new WhichIp();
    if (false === ($clientAddress = $whip->getValidIpAddress())) {
        // handle the error
    }

To fetch an IP address using a specific method, you can pass a bitmask of
enabled methods to the constructor. Here is an example of looking up the IP
address using CloudFlare's custom HTTP header, and falling back to
`$_SERVER['REMOTE_ADDR']` otherwise.

    $whip = new WhichIp(WhichIp::CLOUDFLARE_HEADERS | WhichIp::REMOTE_ADDR);
    $clientAddress = $whip->getValidIpAddress();

This method works, but there is the problem that the custom HTTP header can
easily be spoofed if your sites accept traffic not from CloudFlare. To prevent
this, Whip allows you to specify a whitelist of IP addresses (or address ranges)
that you accept per method.

## Using the CloudFlare IP Range Whitelist

As a common example, Whip can accept a whitelist of IP ranges for CloudFlare
when using their custom header and fall back to `$_SERVER['REMOTE_ADDR']` if the
custom header was not found or if the source IP address does match any in the
whitelist.

    $whip = new WhichIp(
        WhichIp::CLOUDFLARE_HEADERS | WhichIp::REMOTE_ADDR,
        [
            WhichIp::CLOUDFLARE_HEADERS => [
                WhichIp::IPV4 => [
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
                WhichIp::IPV6 => [
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

Please be sure to use the actual list of IP ranges from CloudFlare for
[IPv4](https://www.cloudflare.com/ips-v4) and
[IPv6](https://www.cloudflare.com/ips-v6).

## List of Methods

The individual methods are stored as integer constants on the `WhichIp` class.
To combine methods, use the bitwise OR operator `|`. The current methods are:

- `WhichIp::REMOTE_ADDR` - Uses the standard `$_SERVER['REMOTE_ADDR']`.
- `WhichIp::PROXY_HEADERS` - Uses any of the following values:
    - `$_SERVER['HTTP_CLIENT_IP']`
    - `$_SERVER['HTTP_X_FORWARDED_FOR']`
    - `$_SERVER['HTTP_X_FORWARDED']`
    - `$_SERVER['HTTP_X_CLUSTER_CLIENT_IP']`
    - `$_SERVER['HTTP_FORWARDED_FOR']`
    - `$_SERVER['HTTP_FORWARDED']`
- `WhichIp::CLOUDFLARE_HEADERS` - Uses the CloudFlare provided HTTP header
  "CF-Connecting-IP".
- `WhichIp::INCAPSULA_HEADERS` - Use the Incapsula provided HTTP header
  "Incap-Client-IP".
- `WhichIp::CUSTOM_HEADERS` - Uses a custom list of HTTP headers passed into
  `WhichIp::addCustomHeader`.

## Using a Custom Header

Whip can also allow you to specify a custom header to use. For example, you may
configure your own proxy to send a unique obfuscated header internally that
would be hard to spoof. In this example, we assume Varnish is run locally and
we use a custom HTTP header "X-SECRET-REAL-IP" (and fall back to
`$_SERVER['REMOTE_ADDR']` if the custom header doesn't work).

    $whip = new WhichIp(
        WhichIp::CUSTOM_HEADERS | WhichIp::REMOTE_ADDR,
        [
            WhichIp::CUSTOM_HEADERS => [
                WhichIp::IPV4 => [
                    '127.0.0.1'
                ],
                WhichIp::IPV6 => [
                    '::1'
                ]
            ]
        ]
    );
    $whip->addCustomHeader('X-SECRET-REAL-IP');
    $clientAddress = $whip->getValidIpAddress();

## Valid IP Ranges

For IPv4, Whip accepts three types of IP ranges:

- Asterisk wildcard (192.168.*)
- Dashed range (192.168.0.0-192.168.255.255)
- CIDR bitmask notation (192.168.0.0/16)

For IPv6, Whip only accepts the CIDR bitmask notation (fc00::/7).

Furthermore, you can specify a list of exact IP addresses instead of a list of
ranges.