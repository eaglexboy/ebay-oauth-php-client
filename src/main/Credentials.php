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

class Credentials
{
    // Array<CredentialType, string>
    private array $credentialTypeLookupMap = [];

    public function __construct(array &$map)
    {
        foreach ($map as $key => $value) {
            CredentialUtil::$logger->debug(sprintf("attempting to add credentials \t%s = %s", $key, $value));
            $credentialType = CredentialType::lookupBy($key);
            if ($credentialType !== null) {
                CredentialUtil::$logger->debug("creds added");
                $this->credentialTypeLookupMap[$credentialType->value] = $value;
            }
        }
    }

    public function get(CredentialType $credentialType): ?string
    {
        return $this->credentialTypeLookupMap[$credentialType->value] ?? null;
    }

    public function toString(): string
    {
        return print_r($this->credentialTypeLookupMap, true);
    }
}
