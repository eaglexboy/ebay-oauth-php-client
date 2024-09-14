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

use Ebay\Api\Client\Auth\OAuth2\CredentialUtil;
use Exception;
use Monolog\Logger;
use Monolog\Level;
use Monolog\Handler\StreamHandler;
use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;

class CredentialLoaderTestUtil
{
    public static $isAppCredentialsLoaded = false;
    public static $isUserCredentialsLoaded = false;

    public static $CRED_USERNAME = null;
    public static $CRED_PASSWORD = null;

    public static function loadAppCredentials()
    {
        $runtimeParam = self::getRuntimeParam('credential_yaml');

        if ($runtimeParam !== null && trim($runtimeParam) !== '') {
            self::printDetailedLog("Using Runtime Parameter: " . $runtimeParam);
            CredentialUtil::load($runtimeParam);
            self::$isAppCredentialsLoaded = true;
        } else {
            //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
            try {
                CredentialUtil::load(file_get_contents('src/test/ebay-config.yaml'));
                self::$isAppCredentialsLoaded = true;
            } catch (Exception $e) {
                echo $e->getMessage();
            }
        }
    }

    public static function loadAppCredentialsFromFile()
    {
        $runtimeParam = self::getRuntimeParam('credential_yaml');

        if ($runtimeParam !== null && trim($runtimeParam) !== '') {
            self::printDetailedLog("Using Runtime Parameter: " . $runtimeParam);
            CredentialUtil::load($runtimeParam);
            self::$isAppCredentialsLoaded = true;
        } else {
            //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
            try {
                CredentialUtil::loadFile('src/tests/ebay-config.yaml');
                self::$isAppCredentialsLoaded = true;
            } catch (Exception $e) {
                echo $e->getMessage();
            }
        }
    }

    public static function loadUserCredentials()
    {
        $runtimeParam = self::getRuntimeParam('usercred_yaml');
        $values = [];

        if ($runtimeParam !== null && trim($runtimeParam) !== '') {
            self::$isUserCredentialsLoaded = true;
            try {
                $values = Yaml::parse($runtimeParam);
            } catch (ParseException $e) {
                echo $e->getMessage();
            }
        } else {
            //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
            try {
                $values = Yaml::parse(file_get_contents(__DIR__.'/test-config.yaml'));
                self::$isUserCredentialsLoaded = true;
            } catch (\Exception $e) {
                echo $e->getMessage();
            }
        }
        return $values;
    }

    private static function getRuntimeParam($varName)
    {
        $propertyValue = getenv($varName);
        if ($propertyValue === false || trim($propertyValue) === '') {
            // Trying from Env Variable instead
            $propertyValue = getenv($varName);
        }
        return $propertyValue;
    }

    public static function commonLoadCredentials($environment, bool $loadFromFile = false)
    {
        //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
        if ($loadFromFile) {
            self::loadAppCredentialsFromFile();
        } else {
            self::loadAppCredentials();
        }

        if (!self::$isAppCredentialsLoaded) {
            echo "Please check if ebay-config.yaml is setup correctly for app credentials";
            return;
        }

        // Loading the test user credentials for Sandbox
        $values = self::loadUserCredentials();
        if (!self::$isUserCredentialsLoaded) {
            echo "Please check if test-config.yaml is setup correctly for app credentials";
            return;
        }

        $userCredentialKey = $environment === 'PRODUCTION' ? 'production-user' : 'sandbox-user';
        if (isset($values[$userCredentialKey]) && is_array($values[$userCredentialKey])) {
            $credValues = $values[$userCredentialKey];
            self::$CRED_USERNAME = $credValues['username'] ?? null;
            self::$CRED_PASSWORD = $credValues['password'] ?? null;
        }
    }

    public static function printDetailedLog($printStmt)
    {
        $runtimeParam = self::getRuntimeParam('detail_log');
        if (filter_var($runtimeParam, FILTER_VALIDATE_BOOLEAN)) {
            echo $printStmt;
        }
    }

    public static function setLogger()
    {
        $logger = new Logger('test');
        $logger->pushHandler(new StreamHandler('php://stdout', Level::Debug));
        CredentialUtil::setLogger($logger);
    }
}

