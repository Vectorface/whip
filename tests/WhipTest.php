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
namespace Vectorface\WhipTests;

use PHPUnit\Framework\TestCase;
use Vectorface\Whip\Whip;

/**
 * Test class for testing Whip.
 * @backupGlobals enabled
 * @copyright Vectorface, Inc 2015
 * @author Daniel Bruce <dbruce@vectorface.com>
 */
class WhipTest extends TestCase
{
    /**
     * Tests that an invalid source format is rejected.
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidSource()
    {
        new Whip(Whip::REMOTE_ADDR, array(), new \stdClass());
    }
    /**
     * Tests that we get back the right IP when there using superglobals.
     */
    public function testSuperglobal()
    {
        $_SERVER = array('REMOTE_ADDR' => '24.24.24.24');
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $this->assertEquals('24.24.24.24', $lookup->getValidIpAddress());
    }

    /**
     * Tests that we get back 127.0.0.1 when there is no superglobal information
     * at all.
     */
    public function testEmptySuperglobal()
    {
        $_SERVER = array();
        $lookup = new Whip();
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Helper to get a mocked PSR-7 instance.
     *
     * @param string $remoteAddr The remote address to mock.
     * @param string[][] $headers The headers, in the format expected by Psr-7.
     */
    private function getHttpMessageMock($remoteAddr, array $headers = array())
    {
        $stub = $this->getMockBuilder("Psr\Http\Message\ServerRequestInterface")
            ->getMock();

        $stub->method('getServerParams')
            ->willReturn(array('REMOTE_ADDR' => $remoteAddr));
        $stub->method('getHeaders')
            ->willReturn($headers);

        return $stub;
    }
    /**
     * Tests that we can use a PSR-7 ServerRequestInterface compatible class.
     */
    public function testPsr7Request()
    {
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.1'
                    )
                )
            ),
            $this->getHttpMessageMock("127.0.0.1", array('X-Forwarded-For' => array('32.32.32.32,192.168.1.1')))
        );

        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Tests that we get false when no valid IP address could be found.
     */
    public function testNoAddresFoundDueToBitmask()
    {
        $lookup = new Whip(Whip::PROXY_HEADERS);
        $lookup->setSource(array('REMOTE_ADDR' => '127.0.0.1'));
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Tests the standard REMOTE_ADDR method.
     */
    public function testRemoteAddrMethod()
    {
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $lookup->setSource(array('REMOTE_ADDR' => '24.24.24.24'));
        $this->assertEquals('24.24.24.24', $lookup->getValidIpAddress());
    }

    /**
     * Tests that an invalid IPv4 address returns false.
     */
    public function testInvalidIPv4Address()
    {
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $lookup->setSource(array('REMOTE_ADDR' => '127.0.0.256'));
        $this->assertFalse($lookup->getValidIpAddress());
    }

    /**
     * Tests a valid IPv6 address.
     */
    public function testValidIPv6Address()
    {
        $lookup = new Whip(Whip::REMOTE_ADDR);
        $lookup->setSource(array('REMOTE_ADDR' => '::1'));
        $this->assertEquals('::1', $lookup->getValidIpAddress());
    }

    /**
     * Tests that we accept whitelisted proxy methods when the IP matches, even
     * if the IP listed is a comma separated list.
     *
     * @dataProvider proxyMethodWhitelistProvider
     */
    public function testValidWhitelistedProxyMethod($remoteAddr)
    {
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array('127.0.0.1'),
                    Whip::IPV6 => array('::1')
                )
            ),
            array(
                'REMOTE_ADDR' => $remoteAddr,
                'HTTP_X_FORWARDED_FOR' => '32.32.32.32,192.168.1.1'
            )
        );
        $this->assertEquals('32.32.32.32', $lookup->getIpAddress());
    }

    /**
     * Repeats the above test twice for ipv4 and ipv6
     */
    public function proxyMethodWhitelistProvider()
    {
        return array(
            array('127.0.0.1'),
            array('::1'),
        );
    }

    /**
     * Tests that we accept proxy method based on a whitelisted IP using the
     * dashed range notation.
     */
    public function testValidWhitelistedProxyMethodWithDashNotation()
    {
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
            ),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
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
            ),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
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
            ),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
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
            ),
            array(
                'REMOTE_ADDR' => '24.24.24.24',
                'HTTP_X_FORWARDED_FOR' => '32.32.32.32'
            )
        );
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressRejectedDueToWhitelist()
    {
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '2400:cb00::/32'
                    )
                )
            ),
            array(
                'REMOTE_ADDR' => '::1',
                'HTTP_X_FORWARDED_FOR' => '::1'
            )
        );
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Tests that we reject a proxy listed IPv6 address that does not fall within
     * the allowed subnet.
     */
    public function testIPv6AddressFoundInWhitelist()
    {
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '::1/32'
                    )
                )
            ),
            array(
                'REMOTE_ADDR' => '::1',
                'HTTP_X_FORWARDED_FOR' => '::1'
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
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV6 => array(
                        '::1/32'
                    )
                )
            ),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_FORWARDED_FOR' => '24.24.24.24'
            )
        );
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Test that an IPv6 address is rejected because the whitelist is empty for
     * IPv6.
     */
    public function testIPv6AddressRejectedDueToEmptyWhitelist()
    {
        $lookup = new Whip(
            Whip::PROXY_HEADERS,
            array(
                Whip::PROXY_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.0/24'
                    )
                )
            ),
            array(
                'REMOTE_ADDR' => '::1',
                'HTTP_X_FORWARDED_FOR' => '::1'
            )
        );
        $this->assertFalse($lookup->getIpAddress());
    }

    /**
     * Test a custom header with a whitelisted IP.
     */
    public function testCustomHeader()
    {
        $lookup = new Whip(
            Whip::CUSTOM_HEADERS | Whip::REMOTE_ADDR,
            array(
                Whip::CUSTOM_HEADERS => array(
                    Whip::IPV4 => array(
                        '127.0.0.1',
                        '::1'
                    )
                )
            ),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_CUSTOM_SECRET_HEADER' => '32.32.32.32'
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
        $lookup = new Whip(
            Whip::PROXY_HEADERS | Whip::REMOTE_ADDR,
            array(),
            array(
                'REMOTE_ADDR' => '127.0.0.1',
                'HTTP_X_REAL_IP' => '24.24.24.24'
            )
        );
        $this->assertEquals('24.24.24.24', $lookup->getIpAddress());
    }

    /**
     * Tests that if we specify the source array, it overrides any values found
     * in the $_SERVER array.
     */
    public function testSourceArrayOverridesServerSuperglobal()
    {
        $source = array(
            'REMOTE_ADDR' => '24.24.24.24'
        );
        $lookup = new Whip(Whip::REMOTE_ADDR, array(), array('REMOTE_ADDR' => '127.0.0.1'));
        $this->assertNotEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
        $this->assertEquals($source['REMOTE_ADDR'], $lookup->getIpAddress($source));
    }

    /**
     * Tests that if we specify the source array through Whip::setSource, the
     * class will override any values found in $_SERVER.
     */
    public function testSetSourceArrayOverridesServerSuperglobal()
    {
        $source = array(
            'REMOTE_ADDR' => '24.24.24.24'
        );
        $lookup = new Whip(Whip::REMOTE_ADDR, array(), array('REMOTE_ADDR' => '127.0.0.1'));
        $this->assertNotEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
        $lookup->setSource($source);
        $this->assertEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
    }

    /**
     * Tests that we fallback to REMOTE_ADDR if the custom header was not found
     */
    public function testFallbackToRemoteAddr()
    {
        $source = array(
            'REMOTE_ADDR' => '24.24.24.24'
        );
        $lookup = new Whip(Whip::PROXY_HEADERS | Whip::REMOTE_ADDR, array(), $source);
        $this->assertEquals($source['REMOTE_ADDR'], $lookup->getIpAddress());
    }
}
