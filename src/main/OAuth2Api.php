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

 require 'vendor/autoload.php';

use DateTime;
use Exception;
use Ebay\Api\Client\Auth\OAuth2\CredentialUtil;
use Ebay\Api\Client\Auth\OAuth2\CredentialType;
use Ebay\Api\Client\Auth\OAuth2\Model\OAuthResponse;
use Ebay\Api\Client\Auth\OAuth2\Model\Environment;
use Ebay\Api\Client\Auth\OAuth2\Model\RefreshToken;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Exception\ClientException;
use Symfony\Component\HttpClient\Exception\ServerException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
 
class OAuth2Api {
    private static Logger $logger;
    // Array<Environment, TimedCacheValue>
    private static array $appAccessTokenMap = [];
    private HttpClientInterface $client;

    /**
     * @param resource|string $stream If a missing path can't be created, an
     *                                UnexpectedValueException will be thrown on first write
     * @param HttpClientInterface $client The HTTP client to use for making network calls
     * @param Level $level The minimum logging level at which this handler will be triggered
     */
    public function __construct($stream, ?HttpClientInterface $client = null, ?Level $level = Level::Debug) {
        if(!isset(self::$logger)){
            self::$logger = new Logger('OAuth2Api');
        }
        if(!isset(self::$logger)){
            self::$logger->pushHandler(new StreamHandler($stream, $level));
        }

        $this->client = isset($client) ? $client : HttpClient::create();
    }

    /**
     * @param Environment $environment The environment for which the token is to be generated
     * @param array<string> $scopes The scopes for which the token is to be generated
     */
    public function getApplicationToken(Environment $environment, array $scopes): OAuthResponse {
        $appAccessToken = self::$appAccessTokenMap[$environment];

        if (isset($appAccessToken) && $appAccessToken->getValue() !== null) {
            self::$logger->debug('application access token returned from cache');
            return $appAccessToken->getValue();
        }

        $scope = OAuth2Util::buildScopeForRequest($scopes) ?? '';
        $credentials = CredentialUtil::getCredentials($environment);

        $requestData = [
            'grant_type' => 'client_credentials',
            'scope' => $scope
        ];

        try {
            $response = $this->client->request('POST', $environment->getApiEndpoint(), [
                'headers' => [
                    'Authorization' => $this->buildAuthorization($credentials),
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ],
                'body' => http_build_query($requestData)
            ]);

            if ($response->getStatusCode() === 200) {
                self::$logger->debug('Network call to generate new token is successful');
                $oAuthResponse = OAuth2Util::parseApplicationToken($response->getContent());
                $accessToken = $oAuthResponse->getAccessToken();
                self::$appAccessTokenMap[$environment] = new TimedCacheValue($oAuthResponse, $accessToken->getExpiresOn());
                return $oAuthResponse;
            } else {
                return OAuth2Util::handleError($response);
            }
        } catch (ClientException | ServerException $e) {
            self::$logger->error('HTTP request failed: ' . $e->getMessage());
            throw new Exception('HTTP request failed: ' . $e->getMessage());
        }
    }

    private function buildAuthorization(Credentials $credentials) {
        $authString = $credentials->get(CredentialType::APP_ID) . ':' . $credentials->get(CredentialType::CERT_ID);
        return 'Basic ' . base64_encode($authString);
    }

    public function generateUserAuthorizationUrl(Environment $environment, array $scopes, string $state = null) {
        $credentials = CredentialUtil::getCredentials($environment);

        if(!isset($credentials)){
            self::$logger->error('Credentials for '. $environment->name . ' is not found.');
            throw new Exception('Credentials for '. $environment->name . ' is not found.');
        }

        $scope = OAuth2Util::buildScopeForRequest($scopes) ?? '';

        $data = [
            'client_id' => $credentials->get(CredentialType::APP_ID),
            'response_type' => 'code',
            'redirect_uri' => $credentials->get(CredentialType::REDIRECT_URI),
            'scope' => $scope,
            'auth_type' => 'oauth'
        ];

        if(isset($state)){
            $data['state'] = $state;
        }

        $url = $environment->getWebEndpoint() . '?' . http_build_query($data);

        self::$logger->debug('authorize_url=' . $url);
        return $url;
    }

    public function exchangeCodeForAccessToken(Environment $environment, string $code) {
        $credentials = CredentialUtil::getCredentials($environment);

        $requestData = [
            'grant_type' => 'authorization_code',
            'redirect_uri' => $credentials->get(CredentialType::REDIRECT_URI),
            'code' => $code
        ];

        try {
            $response = $this->client->request('POST', $environment->getApiEndpoint(), [
                'headers' => [
                    'Authorization' => $this->buildAuthorization($credentials),
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ],
                'body' => http_build_query($requestData)
            ]);

            if ($response->getStatusCode() === 200) {
                return OAuth2Util::parseUserToken($response->getContent());
            } else {
                return OAuth2Util::handleError($response);
            }
        } catch (ClientException | ServerException $e) {
            self::$logger->error('HTTP request failed: ' . $e->getMessage());
            throw new Exception('HTTP request failed: ' . $e->getMessage());
        }
    }

    public function getAccessToken(Environment $environment, RefreshToken $refreshToken, array $scopes) {
        $credentials = CredentialUtil::getCredentials($environment);
        $scope = OAuth2Util::buildScopeForRequest($scopes);

        $requestData = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'scope' => $scope
        ];

        try {
            $response = $this->client->request('POST', $environment->getApiEndpoint(), [
                'headers' => [
                    'Authorization' => $this->buildAuthorization($credentials),
                    'Content-Type' => 'application/x-www-form-urlencoded'
                ],
                'body' => http_build_query($requestData)
            ]);

            if ($response->getStatusCode() === 200) {
                return OAuth2Util::parseUserToken($response->getContent());
            } else {
                return OAuth2Util::handleError($response);
            }
        } catch (ClientException | ServerException $e) {
            self::$logger->error('HTTP request failed: ' . $e->getMessage());
            throw new Exception('HTTP request failed: ' . $e->getMessage());
        }
    }

    public function generateIdTokenUrl(Environment $environment, string $state = null, string $nonce) {
        $credentials = CredentialUtil::getCredentials($environment);

        $data = [
            'client_id' => $credentials->get(CredentialType::APP_ID),
            'response_type' => 'id_token',
            'redirect_uri' => $credentials->get(CredentialType::REDIRECT_URI),
            'nonce' => $nonce,
        ];

        if(isset($state)){
            $data['state'] = $state;
        }

        $url = $environment->getWebEndpoint() . '?' . http_build_query($data);

        self::$logger->debug('id_token_url=' . $url);
        return $url;
    }
}

class TimedCacheValue {
    private OAuthResponse $value;
    private DateTime $expiresAt;

    public function __construct(OAuthResponse $value, DateTime $expiresAt) {
        $this->value = $value;
        $this->expiresAt = clone $expiresAt;
        //Setting a buffer of 5 minutes for refresh
        $this->expiresAt->modify('-5 minutes');
    }

    public function getValue() {
        if (new DateTime() < $this->expiresAt) {
            return $this->value;
        }

        //Since the value is expired, return null
        return null;
    }
}