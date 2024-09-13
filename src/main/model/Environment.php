<?php
/*
 *
 * Copyright (c) 2024 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

namespace Ebay\Api\Client\Auth\OAuth2\Model;

use Ebay\Api\Client\Auth\OAuth2\Trait\Enum;

enum Environment: string {
    use Enum;
    case PRODUCTION = 'api.ebay.com';
    case SANDBOX = 'api.sandbox.ebay.com';

    public function getWebEndpoint(): string {
        return match($this) {
            self::PRODUCTION => 'https://auth.ebay.com/oauth2/authorize',
            self::SANDBOX => 'https://auth.sandbox.ebay.com/oauth2/authorize',
        };
    }

    public function getApiEndpoint(): string {
        return match($this) {
            self::PRODUCTION => 'https://api.ebay.com/identity/v1/oauth2/token',
            self::SANDBOX => 'https://api.sandbox.ebay.com/identity/v1/oauth2/token',
        };
    }
}
