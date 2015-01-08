<?php

namespace VectorFace\Whip\IpRange;

class Ipv4Range extends IpRange
{

    private $lowerInt;
    private $upperInt;

    public function __construct($range)
    {
        $this->computeLowerAndUpperBounds($range);
    }

    public function getLowerInt()
    {
        return $this->lowerInt;
    }

    public function getUpperInt()
    {
        return $this->upperInt;
    }

    public function containsIp($ipAddress)
    {
        $ipLong = ip2long($ipAddress);
        return ($this->getLowerInt() <= $ipLong) && ($this->getUpperInt() >= $ipLong);
    }

    private function computeLowerAndUpperBounds($range)
    {
        if (strpos($range, '/') !== false) {
            // support CIDR notation
            list ($address, $mask) = explode('/', $range);
            $longAddress = ip2long($address);
            $this->lowerInt = $longAddress & (((1 << $mask) - 1) << (32 - $mask));
            $this->upperInt = $longAddress | ((1 << (32 - $mask)) - 1);
            return;
        } elseif (strpos($range, '-') !== false) {
            // support for IP ranges like '10.0.0.0-10.0.0.255'
            $map = array_map('ip2long', explode('-', $range));
            $this->lowerInt = $map[0];
            $this->upperInt = $map[1];
            return;
        } elseif (($pos = strpos($range, '*')) !== false) {
            // support for IP ranges like '10.0.*'
            $prefix = substr($range, 0, $pos - 1);
            $parts  = explode('.', $prefix);
            $this->lowerInt = ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 0))));
            $this->upperInt = ip2long(implode('.', array_merge($parts, array_fill(0, 4 - count($parts), 255))));
            return;
        }
        // assume we have a single address
        $this->lowerInt = ip2long($range);
        $this->upperInt = $this->lowerInt;
    }
}
