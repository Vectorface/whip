<?php

namespace VectorFace\Whip\IpRange;

class IpWhitelist
{
    /** The whitelist key for IPv4 addresses */
    const IPV4 = 'ipv4';

    /** The whitelist key for IPv6 addresses */
    const IPV6 = 'ipv6';

    private $ipv4Whitelist;
    private $ipv6Whitelist;

    public function __construct(array $whitelists)
    {
        $this->ipv4Whitelist = $this->constructWhiteListForKey(
            $whitelists,
            self::IPV4,
            function ($range) {
                return new Ipv4Range($range);
            }
        );
        $this->ipv6Whitelist = $this->constructWhiteListForKey(
            $whitelists,
            self::IPV6,
            function ($range) {
                return new Ipv6Range($range);
            }
        );
    }

    public function isIpWhitelisted($ipAddress)
    {
        $isIpv4Address = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        return $this->isIpInWhitelist(
            ($isIpv4Address) ? $this->ipv4Whitelist : $this->ipv6Whitelist,
            $ipAddress
        );
    }

    private function constructWhiteListForKey($whitelist, $key, $callback)
    {
        if (isset($whitelist[$key]) && is_array($whitelist[$key])) {
            return array_map($callback, array_values($whitelist[$key]));
        } else {
            return array();
        }
    }

    private function isIpInWhitelist($whitelist, $ipAddress)
    {
        foreach ($whitelist as $ipRange) {
            if ($ipRange->containsIp($ipAddress)) {
                return true;
            }
        }
        return false;
    }
}
