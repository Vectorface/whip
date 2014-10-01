<?php

namespace VectorFace\IpLookupTests;

use PHPUnit_Framework_TestCase;
use VectorFace\IpLookup\IpLookup;

/**
 * Test class for testing IpLookup.
 * @backupGlobals enabled
 * @copyright VectorFace, Inc 2014
 * @author Daniel Bruce <dbruce@vectorface.com>
 */
class IpLookupTest extends PHPUnit_Framework_TestCase
{
    /**
     * Tests that we get back 127.0.0.1 when there is no superglobal information
     * at all.
     */
    public function testEmptySuperglobal()
    {
        $_SERVER = [];
        $lookup = new IpLookup();
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we get back 127.0.0.1 where there is no superglobal information
     * and when we specify a bitmask for the enabled headers.
     */
    public function testNoAddresFoundDueToBitmask()
    {
        $_SERVER = ['REMOTE_ADDR' => '127.0.0.1'];
        $lookup = new IpLookup(IpLookup::PROXY_METHODS);
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests the standard REMOTE_ADDR method.
     */
    public function testRemoteAddrMethod()
    {
        $_SERVER = ['REMOTE_ADDR' => '24.24.24.24'];
        $lookup = new IpLookup(IpLookup::REMOTE_ADDR);
        $this->assertEquals('24.24.24.24', $lookup->getValidIpAddress());
    }

    /**
     * Tests that an invalid IPv4 address returns false.
     */
    public function testInvalidIPv4Address()
    {
        $_SERVER = ['REMOTE_ADDR' => '127.0.0.01'];
        $lookup = new IpLookup(IpLookup::REMOTE_ADDR);
        $this->assertTrue(false === $lookup->getValidIpAddress());
    }

    /**
     * Tests a valid IPv6 address.
     */
    public function testValidIPv6Address()
    {
        $_SERVER = ['REMOTE_ADDR' => '::1'];
        $lookup = new IpLookup(IpLookup::REMOTE_ADDR);
        $this->assertEquals('::1', $lookup->getValidIpAddress());
    }

    /**
     * Tests that we accept whitelisted proxy methods when the IP matches.
     */
    public function testValidWhitelistedProxyMethod()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        ];
        $lookup = new IpLookup(
            IpLookup::PROXY_METHODS,
            [
                IpLookup::PROXY_METHODS => [
                    '127.0.0.1',
                    '::1'
                ]
            ]
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * dashed range notation.
     */
    public function testValidWhitelistedProxyMethodWithDashNotation()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        ];
        $lookup = new IpLookup(
            IpLookup::PROXY_METHODS,
            [
                IpLookup::PROXY_METHODS => [
                    '127.0.0.0-127.0.255.255',
                    '::1'
                ]
            ]
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * wildcard asterix notation.
     */
    public function testValidWhitelistedProxyMethodWithWildcardNotation()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        ];
        $lookup = new IpLookup(
            IpLookup::PROXY_METHODS,
            [
                IpLookup::PROXY_METHODS => [
                    '127.0.*',
                    '::1'
                ]
            ]
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * CIDR address notation.
     */
    public function testValidWhitelistedProxyMethodWithCIDRdNotation()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        ];
        $lookup = new IpLookup(
            IpLookup::PROXY_METHODS,
            [
                IpLookup::PROXY_METHODS => [
                    '127.0.0.0/24',
                    '::1'
                ]
            ]
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we get false if there is a valid IP in a proxy header but
     * we reject it due to REMOTE_ADDR not being in the whitelist.
     */
    public function testValidIpRejectedDueToWhitelist()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '24.24.24.24',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        ];
        $lookup = new IpLookup(
            IpLookup::PROXY_METHODS,
            [
                IpLookup::PROXY_METHODS => [
                    '127.0.0.1',
                    '::1'
                ]
            ]
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }
}
