<?php

declare(strict_types=1);

namespace App\Classes\Meli;

/**
 * @param string $url
 * @param string $method
 * @param bool $with_authorization_token
 */
class EndPointReturn
{
    public function __construct(
        public string $url,
        public string $method,
        public bool $with_authorization_token
    ) {
    }
}
