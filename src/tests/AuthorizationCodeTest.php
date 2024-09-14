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

namespace Ebay\Api\Client\Auth\OAuth2\Tests;

use Ebay\Api\Client\Auth\OAuth2\CredentialType;
use Ebay\Api\Client\Auth\OAuth2\CredentialUtil;
use Ebay\Api\Client\Auth\OAuth2\OAuth2Api;
use Ebay\Api\Client\Auth\OAuth2\Model\Environment;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class AuthorizationCodeTest extends TestCase
{
    private static bool $fromFile = true;
    private static $scopeList = [
        "https://api.ebay.com/oauth/api_scope",
        "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly"
    ];

    //NOTE: Change this env to Environment::PRODUCTION to run this test in PRODUCTION
    private static $executionEnv = Environment::SANDBOX;

    public static function setUpBeforeClass(): void
    {
        CredentialLoaderTestUtil::setLogger();
        CredentialLoaderTestUtil::commonLoadCredentials(self::$executionEnv, self::$fromFile);
        self::assertNotnull(CredentialLoaderTestUtil::$CRED_USERNAME, "Please check if test-config.yaml is setup correctly");
        self::assertNotnull(CredentialLoaderTestUtil::$CRED_PASSWORD, "Please check if test-config.yaml is setup correctly");
        self::$fromFile = false;
    }

    public function testConfigLoadYamlFile()
    {
        if (!CredentialLoaderTestUtil::$isAppCredentialsLoaded) {
            fwrite(
                STDERR,
                "Please check if ebay-config.yaml is setup correctly for app credentials\n"
            );
            return;
        }

        $credentialHelperStr = CredentialUtil::dump();
        $this->printDetailedLog($credentialHelperStr);
        $this->assertStringContainsString(CredentialType::APP_ID->value, $credentialHelperStr);
        $this->assertStringContainsString(CredentialType::DEV_ID->value, $credentialHelperStr);
        $this->assertStringContainsString(CredentialType::CERT_ID->value, $credentialHelperStr);
        $this->assertStringContainsString(CredentialType::REDIRECT_URI->value, $credentialHelperStr);
    }

    public function testExchangeAuthorizationCode()
    {
        if (!CredentialLoaderTestUtil::$isAppCredentialsLoaded) {
            fwrite(
                STDERR,
                "Please check if ebay-config.yaml is setup correctly for app credentials\n"
            );
            return;
        }
        if (!CredentialLoaderTestUtil::$isUserCredentialsLoaded) {
            fwrite(
                STDERR,
                "Please check if test-config.yaml is setup correctly for user credentials\n"
            );
            return;
        }

        $redirectResponse = new MockResponse('', [
            'http_code' => 302,
            'headers' => ['Location' => 'https://localhost:8080?code=12345&thisIsNotAValidCode']
        ]);

        // Step 2: Create a mock response for the final destination
        $mockResponse = new MockResponse('Final destination content', [
            'http_code' => 200
        ]);

        $authorizationCode = $this->getAuthorizationCode([$redirectResponse, $mockResponse]);
        $this->assertNotnull($authorizationCode);


        $mockResponse = new MockResponse(
            json_encode([
                'access_token' => 'ACCESS TOKEN',
                'token_type' => 'TOKEN TYPE',
                'expires_in' => 1234567890,
                'refresh_token' => 'REFRESH TOKEN',
                'refresh_token_expires_in' => 1234567890
            ]),
            [
                'http_code' => 200,
                'headers' => ['Content-Type' => 'application/json']
            ]);

        $auth2Api = new OAuth2Api('src/test/test.log', new MockHttpClient($mockResponse));
        $oauth2Response = $auth2Api->exchangeCodeForAccessToken(
            self::$executionEnv,
            $authorizationCode
        );
        $this->assertNotnull($oauth2Response);

        $this->assertNotnull($oauth2Response->getRefreshToken());
        $this->assertNotnull($oauth2Response->getAccessToken());
        $this->assertnull($oauth2Response->getErrorMessage());
        CredentialLoaderTestUtil::printDetailedLog("Token Exchange Completed\n" . $oauth2Response);
    }

    public function testExchangeRefreshForAccessToken()
    {
        if (!CredentialLoaderTestUtil::$isAppCredentialsLoaded) {
            fwrite(STDERR, "Please check if ebay-config.yaml is setup correctly for app credentials\n");
            return;
        }
        if (!CredentialLoaderTestUtil::$isUserCredentialsLoaded) {
            fwrite(STDERR, "Please check if test-config.yaml is setup correctly for user credentials\n");
            return;
        }

        $redirectResponse = new MockResponse('', [
            'http_code' => 302,
            'headers' => ['Location' => 'https://localhost:8080?code=12345&thisIsNotAValidCode']
        ]);

        $mockResponse = new MockResponse('Final destination content', [
            'http_code' => 200
        ]);
        

        $refreshToken = null;
        $authorizationCode = $this->getAuthorizationCode([$redirectResponse, $mockResponse]);
        if ($authorizationCode != null) {
            $mockResponse = new MockResponse(
                json_encode([
                    'access_token' => 'ACCESS TOKEN',
                    'token_type' => 'TOKEN TYPE',
                    'expires_in' => 1234567890,
                    'refresh_token' => 'REFRESH TOKEN',
                    'refresh_token_expires_in' => 1234567890
                ]),
                [
                    'http_code' => 200,
                    'headers' => ['Content-Type' => 'application/json']
                ]
            );

            $oauth2Api = new OAuth2Api('test_log.log', new MockHttpClient($mockResponse));
            $oauth2Response = $oauth2Api->exchangeCodeForAccessToken(self::$executionEnv, $authorizationCode);
            $this->assertTrue($oauth2Response->getRefreshToken() !== null);
            $refreshToken = $oauth2Response->getRefreshToken();
        }

        $this->assertNotnull($refreshToken);

        $mockResponse = new MockResponse(
            json_encode([
                'access_token' => 'TOKEN ACCESS',
                'token_type' => 'TOKEN TYPE',
                'expires_in' => 1234567890,
                'refresh_token' => 'TOKEN REFRESH',
                'refresh_token_expires_in' => 1234567890
            ]),
            [
                'http_code' => 200,
                'headers' => ['Content-Type' => 'application/json']
            ]
        );

        $oauth2Api = new OAuth2Api('test_log.log', new MockHttpClient($mockResponse));
        $accessTokenResponse = $oauth2Api->getAccessToken(self::$executionEnv, $refreshToken, self::$scopeList);
        $this->assertNotnull($accessTokenResponse);

        $this->assertNotnull($accessTokenResponse->getAccessToken());
        $this->assertnull($accessTokenResponse->getErrorMessage());
        $this->assertEquals('TOKEN ACCESS', $accessTokenResponse->getAccessToken()->getToken());

        $this->assertNotnull($accessTokenResponse->getRefreshToken());
        $this->assertEquals('TOKEN REFRESH', $accessTokenResponse->getRefreshToken()->getToken());

        $this->printDetailedLog("\nRefresh To Access Completed\n" . json_encode($accessTokenResponse));
    }

    private function getAuthorizationResponseUrl(/*MockResponse*/ array $mockResponse)
    {
        $client = new MockHttpClient($mockResponse);
        $auth2Api = new OAuth2Api('test_log.log');
        $authorizeUrl = $auth2Api->generateUserAuthorizationUrl(self::$executionEnv, self::$scopeList, 'current-page');
        
        $response = $client->request('GET', $authorizeUrl, [
            'max_redirects' => 20
        ]);

        // Blocking call to get the final data.
        $response->getContent(false);        
        $statusCode = $response->getStatusCode();
        $isRedirect = $statusCode === 302;

        while($isRedirect){
            $redirectUrl = $response->getInfo('headers')['Location'] ?? $response->getInfo('redirect_url');
            $response = $client->request('GET', $redirectUrl, [
                'max_redirects' => 20
            ]);

            // Blocking call to get the final data.
            $response->getContent(false);   
            $statusCode = $response->getStatusCode();
            $isRedirect = $statusCode === 302;
        }

        $url = $response->getInfo('url') ?? $response->getRequestUrl();
        return $url;
    }

    private function getAuthorizationCode(array $response = null) {

        $url = $this->getAuthorizationResponseUrl($response);
        $codeIndex = strpos($url, "code=");
        $authorizationCode = null;
        if ($codeIndex > 0) {
            preg_match("/code=(.*?)&/", $url, $matches);
            if (isset($matches[1])) {
                $authorizationCode = $matches[1];
            }
        }
        return $authorizationCode;
    }

    public function testGenerateAuthorizationUrlSandbox()
    {
        if (!CredentialLoaderTestUtil::$isAppCredentialsLoaded) {
            fwrite(STDERR, "Please check if ebay-config.yaml is setup correctly for app credentials\n");
            return;
        }

        $oauth2Api = new OAuth2Api('test_log.log');
        $authorizationUrl = $oauth2Api->generateUserAuthorizationUrl(Environment::SANDBOX, self::$scopeList, 'current-page');
        $this->printDetailedLog($authorizationUrl);
        $this->assertNotnull($authorizationUrl);
    }

    public function testGenerateAuthorizationUrlProduction()
    {
        if (!CredentialLoaderTestUtil::$isAppCredentialsLoaded) {
            fwrite(STDERR, "Please check if ebay-config.yaml is setup correctly for app credentials\n");
            return;
        }

        $oauth2Api = new OAuth2Api('test_log.log');
        $authorizationUrl = $oauth2Api->generateUserAuthorizationUrl(Environment::PRODUCTION, self::$scopeList, 'current-page');
        $this->printDetailedLog($authorizationUrl);
        $this->assertNotnull($authorizationUrl);
    }

    private function printDetailedLog($message)
    {
        echo $message . PHP_EOL;
    }
}
