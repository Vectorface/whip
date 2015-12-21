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

namespace Vectorface\Whip\Request;

/**
 * Provide IP address data from the $_SERVER superglobal.
 */
class SuperglobalRequestAdapter implements RequestAdapter
{
    /**
     * The $_SERVER-style array that serves as the source of data.
     *
     * @var string[]
     */
    private $server;

    /**
     * A formatted version of the HTTP headers: ["header" => "value", ...]
     *
     * @var string[]
     */
    private $headers;

    /**
     * Create a new adapter for a superglobal $_SERVER-style array.
     *
     * @param string[] $server An array in a format like PHP's $_SERVER var.
     */
    public function __construct(array $server)
    {
        $this->server = $server;
    }

    public function getRemoteAddr()
    {
        return isset($this->server['REMOTE_ADDR']) ? $this->server['REMOTE_ADDR'] : null;
    }

    public function getHeaders()
    {
        if (!isset($this->headers)) {
            $this->headers = $this->serverToHeaders($this->server);
        }
        return $this->headers;
    }

    /**
     * Convert from $_SERVER-style format to normal header names.
     *
     * @param string[] $server The $_SERVER-style array.
     * @return string[] Array of headers with lowercased keys.
     */
    private static function serverToHeaders(array $server)
    {
        $headers = array();
        foreach ($server as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $key = strtolower(str_replace("_", '-', substr($key, 5)));
                $headers[$key] = $value;
            }
        }
        return $headers;
    }
}
