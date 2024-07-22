<?php

namespace Vectorface\Whip\Request;

use Symfony\Component\HttpFoundation\Request;

class SymfonyRequestAdapter implements RequestAdapter
{
    public function __construct(private Request $request)
    {
    }
    /**
     * @inheritDoc
     */
    public function getRemoteAddr(): ?string
    {
        return $this->request->getClientIp();
    }

    /**
     * @inheritDoc
     */
    public function getHeaders(): array
    {
        $headers = [];
        foreach ($this->request->headers->all() as $key => $value) {
            $headers[$key] = implode(',', $value);
        }
        return $headers;
    }
}