This is a port of the [ebay-oauth-java-client](https://github.com/eBay/ebay-oauth-java-client)

# eBay OAuth Client Library (PHP)

eBay OAuth client library is a simple and easy-to-use library for integrating with eBay OAuth and designed to be used for OAuth 2.0 specification supported by eBay. There are multiple standard clients that can be used with eBay OAuth, such as OpenID Connect client. However, this library in addition to functioning as a simple eBay OAuth client, helps with additional features such as cached App tokens. There are also future enhancements planned to add id_token support, 'login with eBay' support etc.,

## What is OAuth 2.0
[OAuth 2.0](https://tools.ietf.org/html/rfc6749) is the most widely used standard for authentication and authorization for API based access. The complete end to end documentation on how eBay OAuth functions is available at [developer.ebay.com](https://developer.ebay.com/api-docs/static/oauth-tokens.html).

## Supported Languages
This library is created as a PHP project and can be used as a dependency in a PHP based application

## Installation
Install in your project by downloading the repo and extracting in your project or using composer

```
 composer require ebay/ebay-oauth-php-client --repository='{"type":"vcs","url":"https://github.com/eaglexboy/ebay-oauth-php-client"}'
 ```

## Getting Started
All interactions with this library can be performed using `oauth2Api = new OAuth2Api();`

## Library Setup and getting started
1. Ensure you have a config file in your source code of type [YAML](http://yaml.org/). Refer to ebay-config-sample.yaml.
2. This file would hold all your application credentials such as AppId, DevId, and CertId. Refer to [Creating eBay Developer Account](https://developer.ebay.com/api-docs/static/creating-edp-account.html) for details on how to get these credentials.
3. Once the file is created, call `CredentialUtil.loadFile(<your-config-location>);` to load the credentials.
4. It is recommended to load the credentials during startup time (initialization) to prevent runtime delays.
5. Once the credentials are loaded, call any operation on `OAuth2Api`

## Types of Tokens
There are mainly two types of tokens in usage.

### Application Token
An application token contains an application identity which is generated using `client_credentials` grant type. These application tokens are useful for interaction with application specific APIs such as usage statistics etc.,

### User Token
A user token (_access token or refresh token_) contains a user identity and the application's identity. This is usually generated using the `authorization_code` grant type or the `refresh_token` grant type.

## Supported Grant Types for OAuth
All of the regular OAuth 2.0 specifications such as `client_credentials`, `authorization_code`, and `refresh_token` are all supported. Refer to [eBay Developer Portal](https://developer.ebay.com/api-docs/static/oauth-tokens.html)

### Grant Type: Client Credentials
This grant type can be performed by simply using `OAuth2Api.getApplicationToken()`. Read more about this grant type at [oauth-client-credentials-grant](https://developer.ebay.com/api-docs/static/oauth-client-credentials-grant.html)

### Grant Type: Authorization Code
This grant type can be performed by a two step process. Call `OAuth2Api.generateUserAuthorizationUrl()` to get the Authorization URL to redirect the user to. Once the user authenticates and approves the consent, the callback need to be captured by the redirect URL setup by the app and then call `OAuth2Api.exchangeCodeForAccessToken()` to get the refresh and access tokens.

Read more about this grant type at [`oauth-authorization-code-grant`](https://developer.ebay.com/api-docs/static/oauth-authorization-code-grant.html) and [`oauth-auth-code-grant-request`](https://developer.ebay.com/api-docs/static/oauth-auth-code-grant-request.html)

### Grant Type: Refresh Token
This grant type can be performed by simply using `OAuth2Api.getAccessToken()`. Usually access tokens are short lived and if the access token is expired, the caller can use the refresh token to generate a new access token. Read more about it at [Using a refresh token to update a user access token](https://developer.ebay.com/api-docs/static/oauth-auth-code-grant-request.html)

## Contribution
Contributions in terms of patches, features, or comments are always welcome. Refer to [CONTRIBUTING](CONTRIBUTING.md) for guidelines. Submit Github issues for any feature enhancements, bugs, or documentation problems as well as questions and comments.

## Libraries used
- [monolog](https://seldaek.github.io/monolog/)
- symfony
  - [YAML](https://symfony.com/doc/current/components/yaml.html)
  - [HTTP Client](https://symfony.com/doc/current/http_client.html)

## Developers and Contributors
1. [@sengopal](https://github.com/sengopal)
2. [@tanjav](https://github.com/tanjav)
3. [@sonamrks](https://github.com/sonamrks)
4. [@LokeshRishi](https://github.com/LokeshRishi)
5. [Eleazar Castellanos](https://github.com/eaglexboy)


## References
1. https://developer.ebay.com/api-docs/static/oauth-token-types.html
2. https://developer.ebay.com/api-docs/static/oauth-tokens.html
3. https://developer.ebay.com/my/keys

## License
Copyright (c) 2023 eBay Inc.

Use of this source code is governed by a Apache-2.0 license that can be found in the LICENSE file or at https://opensource.org/licenses/Apache-2.0.