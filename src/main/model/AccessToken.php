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

use Ebay\Api\Client\Auth\OAuth2\Model\TokenType;

use DateTime;

class AccessToken {
    private string $token;
    private DateTime $expiresOn;
    private TokenType $tokenType;

    public function getToken(): string {
        return $this->token;
    }

    public function setToken(string $token): void {
        $this->token = $token;
    }

    public function getExpiresOn(): DateTime {
        return $this->expiresOn;
    }

    public function setExpiresOn(DateTime $expiresOn): void {
        $this->expiresOn = $expiresOn;
    }

    public function setTokenType(TokenType $tokenType): void {
        $this->tokenType = $tokenType;
    }

    public function getTokenType(): TokenType {
        return $this->tokenType;
    }

    public function __toString(): string {
        return sprintf(
            "AccessToken{token='%s', expiresOn='%s'}",
            $this->token,
            $this->expiresOn->format('Y-m-d H:i:s')
        );
    }
}
