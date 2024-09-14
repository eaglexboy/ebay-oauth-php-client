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

class TokenResponse
{
    private string $accessToken;
    private string $tokenType;
    private int $expiresIn;
    private string $refreshToken;
    private int $refreshTokenExpiresIn;

    public function __construct(
        string $accessToken,
        string $tokenType,
        int $expiresIn,
        string $refreshToken,
        int $refreshTokenExpiresIn
    ) {
        $this->accessToken = $accessToken;
        $this->tokenType = $tokenType;
        $this->expiresIn = $expiresIn;
        $this->refreshToken = $refreshToken;
        $this->refreshTokenExpiresIn = $refreshTokenExpiresIn;
    }

    public static function createFromJson(string $json): TokenResponse
    {
        $data = json_decode($json, true);
        return new TokenResponse(
            $data['access_token'],
            $data['token_type'],
            $data['expires_in'],
            $data['refresh_token'],
            $data['refresh_token_expires_in']
        );
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    public function getTokenType(): string
    {
        return $this->tokenType;
    }

    public function setTokenType(string $tokenType): void
    {
        $this->tokenType = $tokenType;
    }

    public function getExpiresIn(): int
    {
        return $this->expiresIn;
    }

    public function setExpiresIn(int $expiresIn): void
    {
        $this->expiresIn = $expiresIn;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): void
    {
        $this->refreshToken = $refreshToken;
    }

    public function getRefreshTokenExpiresIn(): int
    {
        return $this->refreshTokenExpiresIn;
    }

    public function setRefreshTokenExpiresIn(int $refreshTokenExpiresIn): void
    {
        $this->refreshTokenExpiresIn = $refreshTokenExpiresIn;
    }
}
