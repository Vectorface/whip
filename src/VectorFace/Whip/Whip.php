<?php

/*
The MIT License (MIT)

Copyright (c) 2014 VectorFace, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

namespace VectorFace\Whip;

use \Exception;

/**
 * A class for accurately looking up a client's IP address.
 * This class checks a call time configurable list of headers in the $_SERVER
 * superglobal to determine the client's IP address.
 * @copyright VectorFace, Inc 2014
 * @author Daniel Bruce <dbruce@vectorface.com>
 * @author Cory Darby <ckdarby@vectorface.com>
 */
class Whip
{

    /** Indicates all header methods will be used. */
    const ALL_METHODS        = 255;
    /** Indicates the REMOTE_ADDR method will be used. */
    const REMOTE_ADDR        = 1;
    /** Indicates a set of possible proxy headers will be used. */
    const PROXY_HEADERS      = 2;
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

    /** The array of mapped header strings. */
    private static $headers = array(
        self::CUSTOM_HEADERS     => array(),
        self::INCAPSULA_HEADERS  => array(
            'HTTP_INCAP_CLIENT_IP'
        ),
        self::CLOUDFLARE_HEADERS => array(
            'HTTP_CF_CONNECTING_IP'
        ),
        self::PROXY_HEADERS      => array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'HTTP_X_REAL_IP',
        ),
        self::REMOTE_ADDR        => array(
            'REMOTE_ADDR'
        ),
    );

    /** the bitmask of enabled methods */
    private $enabled;

    /** an array of whitelisted IPs to allow per method */
    private $whitelist;

    /** an array holding the source of addresses we will check */
    private $source;

    /**
     * Constructor for the class.
     */
    public function __construct($enabled = self::ALL_METHODS, $whitelists = array())
    {
        $this->enabled   = (int) $enabled;
        $this->whitelist = is_array($whitelists) ? $whitelists : array();
        $this->source    = $_SERVER;
    }

    /**
     * Adds a custom header to the list.
     * @param string $header The custom header to add.
     * @return Whip Returns $this.
     */
    public function addCustomHeader($header)
    {
        self::$headers[self::CUSTOM_HEADERS][] = $header;
        return $this;
    }

    /**
     * Sets the source array to use to lookup the addresses. If not specified,
     * the class will fallback to $_SERVER.
     * @param array $source The source array.
     * @return Whip Returns $this.
     */
    public function setSource(array $source)
    {
        $this->source = $source;
        return $this;
    }

    /**
     * Returns the IP address of the client using the given methods.
     * @param array $source (optional) The source array. By default, the class
     *        will use the value passed to Whip::setSource or fallback to
     *        $_SERVER.
     * @return string Returns the IP address as a string or false if no
     *         IP address could be found.
     */
    public function getIpAddress($source = null)
    {
        $source = is_array($source) ? $source : $this->source;
        $localAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : false;
        foreach (self::$headers as $key => $headers) {
            if (!($key & $this->enabled) // Skip this header if not enabled
                    // skip this header if the IP address is in the whilelist
                    || ($localAddress && isset($this->whitelist[$key])
                    && is_array($this->whitelist[$key])
                    && !$this->isIpWhitelisted($this->whitelist[$key], $localAddress))) {
                continue;
            }
            return $this->extractAddressFromHeaders($source, $headers);
        }
        return false;
    }

    /**
     * Returns the valid IP address or false if no valid IP address was found.
     * @param array $source (optional) The source array. By default, the class
     *        will use the value passed to Whip::setSource or fallback to
     *        $_SERVER.
     * @return mixed Returns the IP address (as a string) of the client or false
     *         if no valid IP address was found.
     */
    public function getValidIpAddress($source = null)
    {
        $ipAddress = $this->getIpAddress($source);
        if (false === $ipAddress || false === @inet_pton($ipAddress)) {
            return false;
        }
        return $ipAddress;
    }

    /**
     * Finds the first element in $headers that is present in $_SERVER and
     * returns the IP address mapped to that value.
     * If the IP address is a list of comma separated values, the last value
     * in the list will be returned.
     * If no IP address is found, we return false.
     * @param array $source  The source array to pull the data from.
     * @param array $headers The list of headers to check.
     * @return mixed Returns the IP address as a string or false if no IP
     *         IP address was found.
     */
    private function extractAddressFromHeaders($source, $headers)
    {
        foreach ($headers as $header) {
            if (empty($source[$header])) {
                continue;
            }
            $list = explode(',', $source[$header]);
            return trim(end($list));
        }
        return false;
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
            return $this->isIp4Whitelisted($whitelist, $ipAddress);
        }
        return $this->isIp6Whitelisted($whitelist, $ipAddress);
    }

    /**
     * Returns whether or not an IPv4 address is in the given whitelist of
     * IPs and ranges.
     * @param array $whitelist The array of whitelisted IPs and addresses.
     * @param string $ipAddress An IPv4 address.
     * @return bool Returns true if the address is in the whitelist and false
     *         otherwise.
     */
    private function isIp4Whitelisted($whitelist, $ipAddress)
    {
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
            return array(
                $longAddress & (((1 << $mask) - 1) << (32 - $mask)),
                $longAddress | ((1 << (32 - $mask)) - 1)
            );
        } elseif (strpos($range, '-') !== false) {
            // support for IP ranges like '10.0.0.0-10.0.0.255'
            return array_map('ip2long', explode('-', $range));
        } elseif (($pos = strpos($range, '*')) !== false) {
            // support for IP ranges like '10.0.*'
            $prefix = substr($range, 0, $pos - 1);
            $parts  = explode('.', $prefix);
            return array(
                ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 0)))),
                ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 255))))
            );
        } else {
            // assume we have a single address
            $longAddress = ip2long($range);
            return array($longAddress, $longAddress);
        }
    }

    /**
     * Returns whether or not an IPv6 address is in the given whitelist of
     * IPs and ranges.
     * @param array $whitelist The array of whitelisted IPs and addresses.
     * @param string $ipAddress An IPv6 address.
     * @return bool Returns true if the address is in the whitelist and false
     *         otherwise.
     */
    private function isIp6Whitelisted($whitelist, $ipAddress)
    {
        if (empty($whitelist[self::IPV6])) {
            return false;
        }
        // handle IPv6 CIDR notation only
        foreach ($whitelist[self::IPV6] as $range) {
            list($network, $mask) = explode('/', $range);
            $binaryNetwork = $this->convertToBinaryString($network);
            $binaryAddress = $this->convertToBinaryString($ipAddress);
            if (substr($binaryNetwork, 0, $mask) === substr($binaryAddress, 0, $mask)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Converts an IPv6 address to a binary string.
     * @param string $address The IPv6 address in standard notation.
     * @return string Returns the address as a string of bits.
     */
    private function convertToBinaryString($address)
    {
        return implode(
            '',
            array_map(
                array(__CLASS__, 'hexToBinary'),
                str_split(bin2hex(inet_pton($address)))
            )
        );
    }
    /**
     * Converts a hexadecimal character to a 4-digit binary string.
     * @param string $hex The hexadecimal character.
     * @return string Returns a 4-digit binary string.
     */
    private static function hexToBinary($hex)
    {
        return str_pad(base_convert($hex, 16, 2), 4, '0', STR_PAD_LEFT);
    }
}
