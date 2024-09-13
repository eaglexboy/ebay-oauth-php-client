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

use Ebay\Api\Client\Auth\OAuth2\Model\Environment;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Exception\ClientException;
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
        $this->assertStringContainsString("APP_ID", $credentialHelperStr);
        $this->assertStringContainsString("DEV_ID", $credentialHelperStr);
        $this->assertStringContainsString("CERT_ID", $credentialHelperStr);
        $this->assertStringContainsString("REDIRECT_URI", $credentialHelperStr);
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

        $mockResponse =
            MockResponse::fromRequest(
                'GET',
                'https://localhost:8080?code=12345',
                [],
                new MockResponse('Bogus Response')
            );

        $authorizationCode = $this->getAuthorizationCode($mockResponse);
        $this->assertNotnull($authorizationCode);

        $auth2Api = new OAuth2Api('src/test/test.log', new MockHttpClient([
            'access_token' => 'ACCESS TOKEN',
            'token_type' => 'TOKEN TYPE',
            'expires_in' => 1234567890,
            'refresh_token' => 'REFRESH TOKEN',
            'refresh_token_expires_in' => 1234567890
        ]));
        $oauth2Response = $auth2Api->exchangeCodeForAccessToken(
            self::$executionEnv,
            $authorizationCode
        );
        $this->assertNotnull($oauth2Response);

        $this->assertTrue($oauth2Response->getRefreshToken() !== null);
        $this->assertNotnull($oauth2Response->getRefreshToken());

        $this->assertTrue($oauth2Response->getAccessToken() !== null);
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

        $mockResponse =
            MockResponse::fromRequest(
                'GET',
                'https://localhost:8080?code=12345',
                [],
                new MockResponse('Bogus Response')
            );

        $refreshToken = null;
        $authorizationCode = $this->getAuthorizationCode($mockResponse);
        if ($authorizationCode != null) {
            $oauth2Api = new OAuth2Api('test_log.log', new MockHttpClient([
                'access_token' => 'ACCESS TOKEN',
                'token_type' => 'TOKEN TYPE',
                'expires_in' => 1234567890,
                'refresh_token' => 'REFRESH TOKEN',
                'refresh_token_expires_in' => 1234567890
            ]));
            $oauth2Response = $oauth2Api->exchangeCodeForAccessToken(self::$executionEnv, $authorizationCode);
            $this->assertTrue($oauth2Response->getRefreshToken() !== null);
            $refreshToken = $oauth2Response->getRefreshToken();
        }

        $this->assertNotnull($refreshToken);

        $oauth2Api = new OAuth2Api('test_log.log', new MockHttpClient([
            'access_token' => 'TOKEN ACCESS',
            'token_type' => 'TOKEN TYPE',
            'expires_in' => 1234567890,
            'refresh_token' => 'TOKEN REFRESH',
            'refresh_token_expires_in' => 1234567890
        ]));
        $accessTokenResponse = $oauth2Api->getAccessToken(self::$executionEnv, $refreshToken, self::$scopeList);
        $this->assertNotnull($accessTokenResponse);

        $this->assertTrue($accessTokenResponse->getAccessToken() !== null);
        $this->assertNotnull($accessTokenResponse->getAccessToken());
        $this->assertnull($accessTokenResponse->getErrorMessage());
        $this->assertEquals('TOKEN ACCESS', $accessTokenResponse->getAccessToken());

        $this->assertTrue($accessTokenResponse->getRefreshToken() !== null);
        $this->assertnull($accessTokenResponse->getRefreshToken());
        $this->assertEquals('TOKEN REFRESH', $accessTokenResponse->getRefreshToken());

        $this->printDetailedLog("Refresh To Access Completed\n" . json_encode($accessTokenResponse));
    }

    private function getAuthorizationResponseUrl(MockResponse $response)
    {
        $client = new MockHttpClient($response);
        $auth2Api = new OAuth2Api('test_log.log');
        $authorizeUrl = $auth2Api->generateUserAuthorizationUrl(self::$executionEnv, self::$scopeList, 'current-page');

        $response = $client->request('GET', $authorizeUrl);
        $url = $response->getRequestUrl();
        return $url;
    }

    private function getAuthorizationCode(
        MockResponse $response = new MockResponse('Bogus Response')
    ) {

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
