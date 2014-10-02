<?php

namespace VectorFace\IpLookup;

/**
 * A class for accurately looking up a client's IP address.
 * This class checks a call time configurable list of headers in the $_SERVER
 * superglobal to determine the client's IP address.
 * @copyright VectorFace, Inc 2014
 * @author Daniel Bruce <dbruce@vectorface.com>
 */
class IpLookup
{
    /** An instance of the IpLookup class */
    private static $instance;

    /** Indicates all header methods will be used. */
    const ALL_METHODS        = 255;
    /** Indicates the REMOTE_ADDR method will be used. */
    const REMOTE_ADDR        = 1;
    /** Indicates a set of possible proxy headers will be used. */
    const PROXY_METHODS      = 2;
    /** Indicates any CloudFlare specific headers will be used. */
    const CLOUDFLARE_HEADERS = 4;
    /** Indicates any Incapsula specific headers will be used. */
    const INCAPSULA_HEADERS  = 8;
    /** Indicates custom listed headers will be used. */
    const CUSTOM_HEADERS     = 128;

    /** The whitelist key for IPv4 addresses */
    const IPV4 = 'ipv4';
    /** The whitelist key for IPv6 addresses */
    const IPV6 = 'ipv6';

    /** Quick lookup table to map hex digits to 4-character binary representation. */
    private static $hexMaps = [
        '0' => '0000',
        '1' => '0001',
        '2' => '0010',
        '3' => '0011',
        '4' => '0100',
        '5' => '0101',
        '6' => '0110',
        '7' => '0111',
        '8' => '1000',
        '9' => '1001',
        'A' => '1010',
        'B' => '1011',
        'C' => '1100',
        'D' => '1101',
        'E' => '1110',
        'F' => '1111'
    ];

    /** The array of mapped header strings. */
    private static $headers = [
        self::CUSTOM_HEADERS => [],
        self::INCAPSULA_HEADERS => [
            'HTTP_INCAP_CLIENT_IP'
        ],
        self::CLOUDFLARE_HEADERS => [
            'HTTP_CF_CONNECTING_IP'
        ],
        self::PROXY_METHODS => [
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED'
        ],
        self::REMOTE_ADDR => [
            'REMOTE_ADDR'
        ],
    ];

    /** the bitmask of enabled methods */
    private $enabled;
    /** an array of whitelisted IPs to allow per method */
    private $whitelists;

    /**
     * Constructor for the class.
     */
    public function __construct($enabled = self::ALL_METHODS, $whitelists = [])
    {
        $this->enabled = (int)$enabled;
        $this->whitelist = is_array($whitelists) ? $whitelists : [];
    }

    /**
     * Adds a custom header to the list.
     * @param string $header The custom header to add.
     * @return IpLookup Returns $this.
     */
    public function addCustomHeader($header)
    {
        self::$headers[self::CUSTOM_HEADERS][] = $header;
        return $this;
    }

    /**
     * Returns the IP address of the client using the given methods.
     * @param int $enabled (optional) The enabled methods. If not specified, the
     *        class will attempt all known methods. The methods will be
     *        attempted in order from most specific to most generic.
     * @return string Returns the IP address as a string or false if no
     *         IP address could be found.
     */
    public function getIpAddress()
    {
        $localAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : false;
        foreach (self::$headers as $key => $headers) {
            if (!($key & $this->enabled)) {
                continue;
            } else if ($localAddress && isset($this->whitelist[$key]) && is_array($this->whitelist[$key])) {
                if (!$this->isIpWhitelisted($this->whitelist[$key], $localAddress)) {
                    continue;
                }
            }
            foreach ($headers as $header) {
                if (!empty($_SERVER[$header])) {
                    return trim(end(explode(',', $_SERVER[$header])));
                }
            }
        }
        return false;
    }

    /**
     * Returns the valid IP address or throws an exception if the IP address
     * attempted was invalid.
     * @return mixed Returns the IP address (as a string) of the client or false
     *         if no valid IP address was found.
     */
    public function getValidIpAddress()
    {
        $ipAddress = $this->getIpAddress();
        if (false === $ipAddress || false === @inet_pton($ipAddress)) {
            return false;
        }
        return $ipAddress;
    }

    /**
     * Returns whether or not the given IP address falls within any of the
     * whitelisted IP ranges.
     * @param array $whitelist The array of whitelisted IP address ranges.
     * @param string $ipAddress The IP address to match against.
     * @return bool Returns true if the IP is listed in the whitelist and false
     *         otherwise.
     */
    private function isIpWhitelisted($whitelist, $ipAddress)
    {
        if (filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            if (empty($whitelist[self::IPV4])) {
                return false;
            }
            $ipLong = ip2long($ipAddress);
            // handle IPv4 range notations
            foreach ($whitelist[self::IPV4] as $range) {
                list($lower, $upper) = $this->getIpv4Range($range);
                if ($lower <= $ipLong && $upper >= $ipLong) {
                    return true;
                }
            }
            return false;
        } else {
            if (empty($whitelist[self::IPV6])) {
                return false;
            }
            // handle IPv6 CIDR notation only
            foreach ($whitelist[self::IPV6] as $range) {
                list($network, $mask) = explode('/', $range);
                $binaryNetwork = $this->convertToBinaryString($network);
                $binaryAddress = $this->convertToBinaryString($ipAddress);
                if(substr($binaryNetwork, 0, $mask) === substr($binaryAddress, 0, $mask)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Converts an IPv6 address to a binary string.
     * @param string $address The IPv6 address in standard notation.
     * @return string Returns the address as a string of bits.
     */
    private function convertToBinaryString($address)
    {
        $binaryString = '';
        $hexString = strtoupper(bin2hex(inet_pton($address)));
        foreach (str_split($hexString) as $char) {
            $binaryString .= self::$hexMaps[$char];
        }
        return $binaryString;
    }

    /**
     * Returns an array with two elements, namely the minimum and maximum
     * integer value mapping to the IP range listed.
     * @param string $range The IP address range as a string.
     * @return array An array with two integers, the minimum and maximum values
     *         of the range.
     */
    private function getIpv4Range($range)
    {
        if (strpos($range, '/') !== false) {
            // support CIDR notation
            list ($address, $mask) = explode('/', $range);
            $longAddress = ip2long($address);
            return [
                $longAddress & (((1 << $mask) - 1) << (32 - $mask)),
                $longAddress | ((1 << (32 - $mask))-1)
            ];
        } else if (strpos($range, '-') !== false) {
            // support for IP ranges like '10.0.0.0-10.0.0.255'
            return array_map('ip2long', explode('-', $range));
        } else if (($pos = strpos($range, '*')) !== false) {
            // support for IP ranges like '10.0.*'
            $prefix = substr($range, 0, $pos-1);
            $parts = explode('.', $prefix);
            return [
                ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 0)))),
                ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 255))))
            ];
        } else {
            // assume we have a single address
            $longAddress = ip2long($range);
            return [$longAddress, $longAddress];
        }
    }
}
