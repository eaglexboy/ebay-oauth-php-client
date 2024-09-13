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
use Psr\Log\LoggerInterface;
use Symfony\Component\Yaml\Yaml;

class CredentialUtil {
    // Array<Environment, Credentials>
    private static array $envCredentialsMap = [];
    public static LoggerInterface $logger;

    public static function setLogger(LoggerInterface $logger): void {
        self::$logger = $logger;
    }

    public static function load(string $yamlString): void {
        self::$logger->debug("CredentialHelper.loadFile");
        self::_load(Yaml::parse($yamlString));
    }

    public static function loadFile($yamlFile): void {
        self::$logger->debug("CredentialHelper.load");
        self::_load(Yaml::parseFile($yamlFile));
    }

    private static function _load(mixed $values): void {
        self::$logger->debug(var_export($values, true));
        self::iterateYaml($values);
    }

    private static function iterateYaml(mixed $values): void {
        foreach ($values as $key => $value) {
            self::$logger->debug("Key attempted: " . $key);
            $environment = Environment::lookupBy($key);
            if ($environment === null) {
                self::$logger->debug("Env key is incorrect: " . $key);
                continue;
            }

            if (is_array($value)) {
                $credentials = new Credentials($value);
                self::$logger->debug(sprintf("adding for %s - %s", $environment, $credentials->toString()));
                self::$envCredentialsMap[$environment] = $credentials;
            }
        }
    }

    public static function dump(): ?string {
        return var_export(self::$envCredentialsMap, true);
    }

    public static function getCredentials(Environment $environment): ?Credentials {
        return self::$envCredentialsMap[$environment] ?? null;
    }
}
