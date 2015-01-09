<?php

/*
The MIT License (MIT)

Copyright (c) 2015 VectorFace, Inc.

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
use VectorFace\Whip\IpRange\IpWhitelist;

/**
 * A class for accurately looking up a client's IP address.
 * This class checks a call time configurable list of headers in the $_SERVER
 * superglobal to determine the client's IP address.
 * @copyright VectorFace, Inc 2015
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

    /** the array of IP whitelist ranges to check against */
    private $whitelist;

    /** an array holding the source of addresses we will check */
    private $source;

    /**
     * Constructor for the class.
     * @param int $enabled The bitmask of enabled headers.
     * @param array $whitelists The array of IP ranges to be whitelisted.
     */
    public function __construct($enabled = self::ALL_METHODS, array $whitelists = array())
    {
        $this->enabled   = (int) $enabled;
        $this->source    = $_SERVER;
        $this->whitelist = array();
        foreach ($whitelists as $header => $ipRanges) {
            $this->whitelist[$header] = new IpWhitelist($ipRanges);
        }
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
            if (!($key & $this->enabled) || !$this->isIpWhitelisted($key, $localAddress)) {
                // skip this header if not enabled or if the local address
                // is not whitelisted
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
     * @return string|false Returns the IP address (as a string) of the client or false
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
     * @return string|false Returns the IP address as a string or false if no IP
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
     * Returns whether or not the given IP address is whitelisted for the given
     * source key.
     * @param string $key The source key.
     * @param string $ipAddress The IP address.
     * @return boolean Returns true if the IP address is whitelisted and false
     *         otherwise. Returns true if the source does not have a whitelist
     *         specified.
     */
    private function isIpWhitelisted($key, $ipAddress)
    {
        if (!isset($this->whitelist[$key])) {
            return true;
        }
        return $this->whitelist[$key]->isIpWhitelisted($ipAddress);
    }
}
