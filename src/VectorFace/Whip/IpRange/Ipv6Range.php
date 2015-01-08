<?php

namespace VectorFace\Whip\IpRange;

class Ipv6Range extends IpRange
{

    private $mask;
    private $rangeSubstring;

    public function __construct($range)
    {
        $this->extractNetworkAndMaskFromRange($range);
    }

    public function containsIp($ipAddress)
    {
        if (false === $this->mask) {
            return ($this->rangeSubstring === $ipAddress);
        }

        $ipAddressSubstring = substr(
            $this->convertToBinaryString($ipAddress),
            0,
            $this->mask
        );
        return ($this->rangeSubstring === $ipAddressSubstring);
    }

    private function extractNetworkAndMaskFromRange($range)
    {
        if (false !== strpos($range, '/')) {
            list($network, $this->mask) = explode('/', $range);
            $this->rangeSubstring = substr(
                $this->convertToBinaryString($network),
                0,
                $this->mask
            );
        } else {
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
