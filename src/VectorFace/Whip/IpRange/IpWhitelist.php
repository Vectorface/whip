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
        $this->ipv4Whitelist = array();
        if (isset($whitelists[self::IPV4]) && is_array($whitelists[self::IPV4])) {
            $this->ipv4Whitelist = array_map(function($range) {
                return new Ipv4Range($range);
            }, array_values($whitelists[self::IPV4]));
        }
        $this->ipv6Whitelist = array();
        if (isset($whitelists[self::IPV6]) && is_array($whitelists[self::IPV6])) {
            $this->ipv6Whitelist = array_map(function($range) {
                return new Ipv6Range($range);
            }, array_values($whitelists[self::IPV6]));
        }
    }

    public function isIpWhitelisted($ipAddress)
    {
        $isIpv4Address = filter_var($ipAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        return $this->isIpInWhitelist(
            ($isIpv4Address) ? $this->ipv4Whitelist : $this->ipv6Whitelist,
            $ipAddress
        );
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
