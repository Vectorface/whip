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
namespace VectorFace\WhichIpTests;

use PHPUnit_Framework_TestCase;
use VectorFace\WhichIp\WhichIp;

/**
 * Test class for testing WhichIp.
 * @backupGlobals enabled
 * @copyright VectorFace, Inc 2014
 * @author Daniel Bruce <dbruce@vectorface.com>
 */
class WhichIpTest extends PHPUnit_Framework_TestCase
{
    /**
     * Tests that we get back 127.0.0.1 when there is no superglobal information
     * at all.
     */
    public function testEmptySuperglobal()
    {
        $_SERVER = [];
        $lookup = new WhichIp();
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we get back 127.0.0.1 where there is no superglobal information
     * and when we specify a bitmask for the enabled headers.
     */
    public function testNoAddresFoundDueToBitmask()
    {
        $_SERVER = ['REMOTE_ADDR' => '127.0.0.1'];
        $lookup = new WhichIp(WhichIp::PROXY_METHODS);
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests the standard REMOTE_ADDR method.
     */
    public function testRemoteAddrMethod()
    {
        $_SERVER = ['REMOTE_ADDR' => '24.24.24.24'];
        $lookup = new WhichIp(WhichIp::REMOTE_ADDR);
        $this->assertEquals('24.24.24.24', $lookup->getValidIpAddress());
    }

    /**
     * Tests that an invalid IPv4 address returns false.
     */
    public function testInvalidIPv4Address()
    {
        $_SERVER = ['REMOTE_ADDR' => '127.0.0.01'];
        $lookup = new WhichIp(WhichIp::REMOTE_ADDR);
        $this->assertTrue(false === $lookup->getValidIpAddress());
    }

    /**
     * Tests a valid IPv6 address.
     */
    public function testValidIPv6Address()
    {
        $_SERVER = ['REMOTE_ADDR' => '::1'];
        $lookup = new WhichIp(WhichIp::REMOTE_ADDR);
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
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.0.1'
                    ],
                    WhichIp::IPV6 => [
                        '::1'
                    ]
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
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.0.0-127.0.255.255',
                    ],
                    WhichIp::IPV6 => [
                        '::1'
                    ]
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
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.*'
                    ],
                    WhichIp::IPV6 => [
                        '::1'
                    ]
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
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.0.0/24'
                    ],
                    WhichIp::IPV6 => [
                        '::1'
                    ]
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
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.0.1/24'
                    ],
                    WhichIp::IPV6 => [
                        '::1'
                    ]
                ]
            ]
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressRejectedDueToWhitelist()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        ];
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV6 => [
                        '2400:cb00::/32'
                    ]
                ]
            ]
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressFoundInWhitelist()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        ];
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV6 => [
                        '::1/32'
                    ]
                ]
            ]
        );
        $this->assertEquals('::1', $lookup->getIpAddress());
    }

    /**
     * Test that an IPv4 address is rejected because the whitelist is empty for
     * IPv4.
     */
    public function testIPv4AddressRejectedDueToEmptyWhitelist()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '24.24.24.24'
        ];
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV6 => [
                        '::1/32'
                    ]
                ]
            ]
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Test that an IPv6 address is rejected because the whitelist is empty for
     * IPv6.
     */
    public function testIPv6AddressRejectedDueToEmptyWhitelist()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        ];
        $lookup = new WhichIp(
            WhichIp::PROXY_METHODS,
            [
                WhichIp::PROXY_METHODS => [
                    WhichIp::IPV4 => [
                        '127.0.0.0/24'
                    ]
                ]
            ]
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Test a custom header with a whitelisted IP.
     */
    public function testCustomHeader()
    {
        $_SERVER = [
            'REMOTE_ADDR' => '127.0.0.1',
            'X_REAL_IP' => '32.32.32.32'
        ];
        $lookup = new WhichIp(
            WhichIp::CUSTOM_HEADERS | WhichIp::REMOTE_ADDR,
            [
                WhichIp::CUSTOM_HEADERS => [
                    WhichIp::IPV4 => [
                        '127.0.0.1',
                        '::1'
                    ]
                ]
            ]
        );
        $this->assertEquals(
            '32.32.32.32',
            $lookup->addCustomHeader('X_REAL_IP')->getIpAddress()
        );
    }
}
