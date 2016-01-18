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

namespace VectorFace\Whip\IpRange;

/**
 * A class representing an IPv6 address range.
 * @copyright VectorFace, Inc 2015
 * @author Daniel Bruce <dbruce1126@gmail.com>
 */
class Ipv6Range implements IpRange
{

    /** The size of the IPv6 range mask. */
    private $mask;

    /** The binary substring of the range minus the mask. */
    private $rangeSubstring;

    /**
     * Constructor for the class.
     * @param string $range The IPv6 range as a string. Supported range styles:
     *        - CIDR notation (2400:cb00::/32)
     *        - a specific IP address (::1)
     */
    public function __construct($range)
    {
        $this->extractNetworkAndMaskFromRange($range);
    }

    /**
     * Returns whether or not a given IP address falls within this range.
     * @param string $ipAddress The given IP address.
     * @return boolean Returns true if the IP address falls within the range
     *         and false otherwise.
     */
    public function containsIp($ipAddress)
    {
        // if the mask is false this means we have a full IP address as a
        // range so compare against the whole string
        if (false === $this->mask) {
            return ($this->rangeSubstring === $this->convertToBinaryString($ipAddress));
        }

        // remove the masked part of the address
        $ipAddressSubstring = substr(
            $this->convertToBinaryString($ipAddress),
            0,
            $this->mask
        );
        return ($this->rangeSubstring === $ipAddressSubstring);
    }

    /**
     * Extracts the mask and binary string substring of the range to compare
     * against incoming IP addresses.
     * @param string $range The IPv6 range as a string.
     */
    private function extractNetworkAndMaskFromRange($range)
    {
        if (false !== strpos($range, '/')) {
            // handle the CIDR notation
            list($network, $this->mask) = explode('/', $range);
            // store a substring of the binary representation of the range
            // minus the masked part
            $this->rangeSubstring = substr(
                $this->convertToBinaryString($network),
                0,
                $this->mask
            );
        } else {
            // handle a single IP address
            $this->rangeSubstring = $this->convertToBinaryString($range);
            $this->mask = false;
        }
    }

    /**
     * Converts an IPv6 address to a binary string.
     * @param string $address The IPv6 address in standard notation.
     * @return string Returns the address as a string of bits.
     */
    private function convertToBinaryString($address)
    {
        return implode('', array_map(
            array(__CLASS__, 'hexToBinary'),
            str_split(bin2hex(inet_pton($address)))
        ));
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
