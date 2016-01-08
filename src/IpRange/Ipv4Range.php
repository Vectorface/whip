<?php

/*
The MIT License (MIT)

Copyright (c) 2015 Vectorface, Inc.

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

namespace Vectorface\Whip\IpRange;

/**
 * A class representing an IPv4 address range.
 * @copyright Vectorface, Inc 2015
 * @author Daniel Bruce <dbruce1126@gmail.com>
 */
class Ipv4Range implements IpRange
{

    /** the lower value of the range (as a long integer) */
    private $lowerInt;
    /** the upper value of the range (as a long integer) */
    private $upperInt;

    /**
     * Constructor for the class.
     * @param string $range A valid IPv4 range as a string. Supported range styles:
     *        - CIDR notation (127.0.0.1/24)
     *        - hyphen notation (127.0.0.1-127.0.0.255)
     *        - wildcard notation (127.0.0.*)
     *        - a single specific IP address (127.0.0.1)
     */
    public function __construct($range)
    {
        $this->computeLowerAndUpperBounds($range);
    }

    /**
     * Returns the lower value of the IPv4 range as a long integer.
     * @return int The lower value of the IPv4 range.
     */
    public function getLowerInt()
    {
        return $this->lowerInt;
    }

    /**
     * Returns the upper value of the IPv4 range as a long integer.
     * @return int The upper value of the IPv4 range.
     */
    public function getUpperInt()
    {
        return $this->upperInt;
    }

    /**
     * Returns whether or not a given IP address falls within this range.
     * @param string $ipAddress The given IP address.
     * @return boolean Returns true if the IP address falls within the range
     *         and false otherwise.
     */
    public function containsIp($ipAddress)
    {
        $ipLong = ip2long($ipAddress);
        return ($this->getLowerInt() <= $ipLong) && ($this->getUpperInt() >= $ipLong);
    }

    /**
     * Computes the lower and upper bounds of the IPv4 range by parsing the
     * range string.
     * @param string $range The IPv4 range as a string.
     */
    private function computeLowerAndUpperBounds($range)
    {
        if (strpos($range, '/') !== false) {
            // support CIDR notation
            list($this->lowerInt, $this->upperInt) = $this->parseCidrRange($range);
        } elseif (strpos($range, '-') !== false) {
            // support for IP ranges like '10.0.0.0-10.0.0.255'
            list($this->lowerInt, $this->upperInt) = $this->parseHyphenRange($range);
        } elseif (($pos = strpos($range, '*')) !== false) {
            // support for IP ranges like '10.0.*'
            list($this->lowerInt, $this->upperInt) = $this->parseWildcardRange($range, $pos);
        } else {
            // assume we have a single address
            $this->lowerInt = ip2long($range);
            $this->upperInt = $this->lowerInt;
        }
    }

    /**
     * Parses a CIDR notation range.
     * @param string $range The CIDR range.
     * @return array Returns an array with the first element being the lower
     *         bound of the range and second element being the upper bound.
     */
    private function parseCidrRange($range)
    {
        list($address, $mask) = explode('/', $range);
        $longAddress = ip2long($address);
        return array(
            $longAddress & (((1 << $mask) - 1) << (32 - $mask)),
            $longAddress | ((1 << (32 - $mask)) - 1)
        );
    }

    /**
     * Parses a hyphen notation range.
     * @param string $range The hyphen notation range.
     * @return array Returns an array with the first element being the lower
     *         bound of the range and second element being the upper bound.
     */
    private function parseHyphenRange($range)
    {
        return array_map('ip2long', explode('-', $range));
    }

    /**
     * Parses a wildcard notation range.
     * @param string $range The wildcard notation range.
     * @param int $pos The integer position of the wildcard within the range string.
     * @return array Returns an array with the first element being the lower
     *         bound of the range and second element being the upper bound.
     */
    private function parseWildcardRange($range, $pos)
    {
        $prefix = substr($range, 0, $pos - 1);
        $parts  = explode('.', $prefix);
        $partsCount = 4 - count($parts);
        return array(
            ip2long(implode('.', array_merge($parts, array_fill(0, $partsCount, 0)))),
            ip2long(implode('.', array_merge($parts, array_fill(0, $partsCount, 255))))
        );
    }
}
