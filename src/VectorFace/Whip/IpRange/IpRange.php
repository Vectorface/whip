<?php

namespace VectorFace\Whip\IpRange;

abstract class IpRange
{
    abstract public function containsIp($ipAddress);
}
