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
namespace VectorFace\WhipTests;

use PHPUnit_Framework_TestCase;
use VectorFace\Whip\Whip;

/**
 * Test class for testing Whip.
 * @backupGlobals enabled
 * @copyright VectorFace, Inc 2014
 * @author Daniel Bruce <dbruce@vectorface.com>
 */
class WhipTest extends PHPUnit_Framework_TestCase
{
    /**
     * Tests that we get back 127.0.0.1 when there is no superglobal information
     * at all.
     */
    public function testEmptySuperglobal()
    {
        $_SERVER = array();
        $lookup = new Whip();
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we get false when no valid IP address could be found.
     */
    public function testNoAddresFoundDueToBitmask()
    {
        $_SERVER = array('REMOTE_ADDR' => '127.0.0.1');
        $lookup = new Whip(Whip::PROXY_HEADERS);
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests the standard REMOTE_ADDR method.
     */
    public function testRemoteAddrMethod()
    {
        $_SERVER = array('REMOTE_ADDR' => '24.24.24.24');
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertEquals('24.24.24.24', $lookup->getValidIpAddress());
    }

    /**
     * Tests that an invalid IPv4 address returns false.
     */
    public function testInvalidIPv4Address()
    {
        $_SERVER = array('REMOTE_ADDR' => '127.0.0.01');
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertTrue(false === $lookup->getValidIpAddress());
    }

    /**
     * Tests a valid IPv6 address.
     */
    public function testValidIPv6Address()
    {
        $_SERVER = array('REMOTE_ADDR' => '::1');
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertEquals('::1', $lookup->getValidIpAddress());
    }

    /**
     * Tests that we accept whitelisted proxy methods when the IP matches, even
     * if the IP listed is a comma separated list.
     */
    public function testValidWhitelistedProxyMethod()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '192.168.1.1,32.32.32.32'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.1'
                    ),
                    Whip::IPV6 => array(
                        '::1'
                    )
                )
            )
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * dashed range notation.
     */
    public function testValidWhitelistedProxyMethodWithDashNotation()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.0-127.0.255.255',
                    ),
                    Whip::IPV6 => array(
                        '::1'
                    )
                )
            )
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * wildcard asterix notation.
     */
    public function testValidWhitelistedProxyMethodWithWildcardNotation()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.*'
                    ),
                    Whip::IPV6 => array(
                        '::1'
                    )
                )
            )
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * CIDR address notation.
     */
    public function testValidWhitelistedProxyMethodWithCIDRdNotation()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.0/24'
                    ),
                    Whip::IPV6 => array(
                        '::1'
                    )
                )
            )
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we get false if there is a valid IP in a proxy header but
     * we reject it due to REMOTE_ADDR not being in the whitelist.
     */
    public function testValidIpRejectedDueToWhitelist()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '24.24.24.24',
            'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.1/24'
                    ),
                    Whip::IPV6 => array(
                        '::1'
                    )
                )
            )
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressRejectedDueToWhitelist()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '2400:cb00::/32'
                    )
                )
            )
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressFoundInWhitelist()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '::1/32'
                    )
                )
            )
        );
        $this->assertEquals('::1', $lookup->getIpAddress());
    }

    /**
     * Test that an IPv4 address is rejected because the whitelist is empty for
     * IPv4.
     */
    public function testIPv4AddressRejectedDueToEmptyWhitelist()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '24.24.24.24'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '::1/32'
                    )
                )
            )
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Test that an IPv6 address is rejected because the whitelist is empty for
     * IPv6.
     */
    public function testIPv6AddressRejectedDueToEmptyWhitelist()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '::1',
            'HTTP_X_FORWARDED_FOR' => '::1'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.0/24'
                    )
                )
            )
        );
        $this->assertTrue(false === $lookup->getIpAddress());
    }

    /**
     * Test a custom header with a whitelisted IP.
     */
    public function testCustomHeader()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_CUSTOM_SECRET_HEADER' => '32.32.32.32'
        );
        $lookup = new Whip(
            Whip::CUSTOM_HEADERS | Whip::REMOTE_ADDR,
            array(
                Whip::CUSTOM_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.1',
                        '::1'
                    )
                )
            )
        );
        $this->assertEquals(
            '32.32.32.32',
            $lookup->addCustomHeader('HTTP_CUSTOM_SECRET_HEADER')->getIpAddress()
        );
    }

    /**
     * Test HTTP_X_REAL_IP header.
     */
    public function testHttpXRealIpHeader()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_REAL_IP' => '24.24.24.24'
        );
        $lookup = new Whip(
            Whip::PROXY_HEADERS | Whip::REMOTE_ADDR
        );
        $this->assertEquals('24.24.24.24', $lookup->getIpAddress());
    }

    /**
     * Tests that if we specify the source array, it overrides any values found
     * in the $_SERVER array.
     */
    public function testSourceArrayOverridesServerSuperglobal()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1'
        );
        $source = array(
            'REMOTE_ADDR' => '24.24.24.24'
        );
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertNotEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
        $this->assertEquals($source['REMOTE_ADDR'], $lookup->getIpAddress($source));
    }

    /**
     * Tests that if we specify the source array through Whip::setSource, the
     * class will override any values found in $_SERVER.
     */
    public function testSetSourceArrayOverridesServerSuperglobal()
    {
        $_SERVER = array(
            'REMOTE_ADDR' => '127.0.0.1'
        );
        $source = array(
            'REMOTE_ADDR' => '24.24.24.24'
        );
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertNotEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
        $lookup->setSource($source);
        $this->assertEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
    }

    /**
     * Tests that an exception is thrown if we try to call Whip::setSource with
     * a parameter that is not an array.
     * @expectedException \Exception
     * @expectedExceptionMessage Source must be an array.
     */
    public function testSetSourceOnlyAcceptsArray()
    {
        $lookup = new Whip();
        $lookup->setSource(null);
    }
}
