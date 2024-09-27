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

use JsonSerializable;
use Ebay\Api\Client\Auth\OAuth2\Model\AccessToken;

class OAuthResponse implements JsonSerializable
{
    private ?AccessToken $accessToken;
    private ?RefreshToken $refreshToken;
    private ?string $errorMessage;

    public function __construct(
        ?AccessToken $accessToken = null,
        ?RefreshToken $refreshToken = null,
        ?string $errorMessage = null
    ) {
        $this->accessToken = $accessToken;
        $this->refreshToken = $refreshToken;
        $this->errorMessage = $errorMessage;
    }

    public function getAccessToken(): AccessToken
    {
        return $this->accessToken;
    }

    public function setAccessToken(AccessToken $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function getRefreshToken(): RefreshToken
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(RefreshToken $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }

    public function setErrorMessage(string $errorMessage): void
    {
        $this->errorMessage = $errorMessage;
    }

    public function __toString(): string
    {
        return sprintf(
            "OAuthResponse{accessToken=%s, refreshToken=%s, errorMessage='%s'}",
            $this->accessToken,
            $this->refreshToken,
            $this->errorMessage
        );
    }

    public function jsonSerialize(): array
    {
        return [
            'accessToken' => $this->accessToken,
            'refreshToken' => $this->refreshToken,
            'errorMessage' => $this->errorMessage
        ];
    }
}
