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

namespace Ebay\Api\Client\Auth\OAuth2;

use DateTime;
use Ebay\Api\Client\Auth\OAuth2\Model\AccessToken;
use Ebay\Api\Client\Auth\OAuth2\Model\OAuthResponse;
use Ebay\Api\Client\Auth\OAuth2\Model\RefreshToken;
use Ebay\Api\Client\Auth\OAuth2\Model\TokenResponse;
use Ebay\Api\Client\Auth\OAuth2\Model\TokenType;
use Symfony\Contracts\HttpClient\ResponseInterface;

class OAuth2Util
{
    public static function parseApplicationToken(string $tokenString): OAuthResponse
    {
        $tokenResponse = TokenResponse::createFromJson($tokenString);
        $token = new AccessToken();
        $token->setTokenType(TokenType::APPLICATION);
        $token->setToken($tokenResponse->getAccessToken());
        $token->setExpiresOn(self::generateExpiration($tokenResponse->getExpiresIn()));
        $oauthResponse = new OAuthResponse($token, null);
        return $oauthResponse;
    }

    private static function generateExpiration(int $expiresIn): DateTime
    {
        return (new DateTime())->add(new \DateInterval('PT' . $expiresIn . 'S'));
    }

    /**
     * @param array<string> $scopes
     */
    public static function buildScopeForRequest(array $scopes): ?string
    {
        $scopeList = null;
        if (!empty($scopes)) {
            $scopeList = implode('+', $scopes);
        }
        return $scopeList;
    }

    public static function parseUserToken(string $tokenString): OAuthResponse
    {
        $tokenResponse = TokenResponse::createFromJson($tokenString);
        $accessToken = new AccessToken();
        $accessToken->setTokenType(TokenType::USER);
        $accessToken->setToken($tokenResponse->getAccessToken());
        $accessToken->setExpiresOn(self::generateExpiration($tokenResponse->getExpiresIn()));

        $refreshToken = new RefreshToken();
        $refreshToken->setToken($tokenResponse->getRefreshToken());
        $refreshToken->setExpiresOn(
            self::generateExpiration($tokenResponse->getRefreshTokenExpiresIn())
        );

        return new OAuthResponse($accessToken, $refreshToken);
    }

    public static function handleError(ResponseInterface $response): OAuthResponse
    {
        $errorMessage = $response->getContent(false);
        return new OAuthResponse(null, null, $errorMessage);
    }
}
