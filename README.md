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
        "vectorface/whip": "dev-master"
    }

## Using Whip

Add the required `use` statement to your class

    use VectorFace\WhichIp\WhichIp;

To fetch an IP address using every known method, you can simply do

    $whip = new WhichIp();
    $clientAddress = $whip->getValidIpAddress();

The class will attempt every known method to retrieve the client's IP address
starting with very specific use cases and falling back to more general use cases.

To fetch an IP address using a very specific method, you can specify a bitmask
of enabled methods to the constructor. Here is an example of looking up the IP
using CloudFlare's custom HTTP header, and falling back to REMOTE_ADDR otherwise.

    $whip = new WhichIp(WhichIp::CLOUDFLARE_HEADERS | WhichIp::REMOTE_ADDR);
    $clientAddress = $whip->getValidIpAddress();

This method looks great, but there is the problem that the custom HTTP header
can easily be spoofed if your sites accept traffic not from CloudFlare. WhichIp
also allows you to specify a whitelist of IP ranges to accept custom headers.

For example, here is how we could use CloudFlare with a whitelist of IP ranges
and fall back to REMOTE_ADDR if the custom header was not found.

    $whip = new WhichIp(
        WhichIp::CLOUD_FLARE_HEADERS | WhichIp::REMOTE_ADDR,
        [
            WhichIp::CLOUD_FLARE_HEADERS => [
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
                ]
            ]
        ]
    );
    $clientAddress = $whip->getValidIpAddress();

The IP address in the CloudFlare header will only be returned if the traffic
actually originated from CloudFlare. Please note an up to date list of IPs
can be found at https://www.cloudflare.com/ips-v4.

And the same solution if you offer IPv6:

    $whip = new WhichIp(
        WhichIp::CLOUD_FLARE_HEADERS | WhichIp::REMOTE_ADDR,
        [
            WhichIp::CLOUD_FLARE_HEADERS => [
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