# dashboard-kit-addon-sso
[![Packagist Version](https://img.shields.io/packagist/v/rafalmasiarek/dashboard-kit-addon-sso)](https://packagist.org/packages/rafalmasiarek/dashboard-kit-addon-sso)
[![Total Downloads](https://img.shields.io/packagist/dt/rafalmasiarek/dashboard-kit-addon-sso)](https://packagist.org/packages/rafalmasiarek/dashboard-kit-addon-sso)
[![PHP](https://img.shields.io/packagist/php-v/rafalmasiarek/dashboard-kit-addon-sso)](https://packagist.org/packages/rafalmasiarek/dashboard-kit-addon-sso)
[![License](https://img.shields.io/badge/license-BUSL--1.1-red)](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/LICENSE)

OAuth2/OIDC SSO addon for [rafalmasiarek/dashboard-kit](https://github.com/rafalmasiarek/php-dashboard-kit).

Implements the Authorization Code flow with PKCE and RS256-signed JWTs. Exposes standard OpenID Connect protocol endpoints and an admin UI for managing OAuth2 clients.




## Requirements

- PHP 8.2+
- `rafalmasiarek/dashboard-kit: *`
- `firebase/php-jwt: ^6.0`

## Installation

```bash
composer require rafalmasiarek/dashboard-kit-addon-sso
```

## Quick start

```php
use rafalmasiarek\DashboardKitSso\SsoAddon;

$dashboard = Dashboard::create(__DIR__ . '/../', [
    'sso' => [
        'issuer' => 'https://auth.example.com',
    ],
]);

SsoAddon::register($dashboard->getApp(), $dashboard->getContainer());

$dashboard->run();
```

An RSA private key is generated automatically at `{storage_dir}/private.pem` on first boot.

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `issuer` | — | **Required.** Base URL of the authorization server, no trailing slash |
| `access_ttl` | `3600` | Access token lifetime in seconds |
| `refresh_ttl` | `2592000` | Refresh token lifetime in seconds (30 days) |
| `storage_dir` | `{app.root_dir}/storage` | Directory for `private.pem` |

Config can be passed as the third argument to `register()` or via `app.config['sso']` in `Dashboard::create()`.

## Protocol endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Connect discovery document |
| `/oauth/jwks.json` | GET | Public RSA key set (JWKS) |
| `/oauth/authorize` | GET | Authorization endpoint — redirects to login, then back to client |
| `/oauth/token` | POST | Token endpoint — exchanges code for access/refresh tokens |
| `/oauth/userinfo` | GET | Returns claims for the authenticated user |
| `/oauth/revoke` | POST | Revokes an access or refresh token |

## Admin UI

Accessible at `{adminPrefix}/sso/clients`. Requires admin role.

- List, create, and delete OAuth2 clients
- Each client has a `client_id`, optional `client_secret`, and one or more redirect URIs

## Database

All tables are created automatically (`CREATE TABLE IF NOT EXISTS`) on first `register()` call:

- `sso_clients`
- `sso_auth_codes`
- `sso_access_tokens`
- `sso_refresh_tokens`

## Token verification (resource server)

Tokens are RS256-signed JWTs. Verify them using the public key from `/oauth/jwks.json` and any standard JWT library:

```php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

$jwks  = json_decode(file_get_contents('https://auth.example.com/oauth/jwks.json'), true);
$keys  = JWK::parseKeySet($jwks);
$payload = JWT::decode($accessToken, $keys);
```


## Index

### Classes

- [`AuthorizeHandler`](#authorizehandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`DiscoveryHandler`](#discoveryhandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`JwksHandler`](#jwkshandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`RevokeHandler`](#revokehandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`TokenHandler`](#tokenhandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`UserInfoHandler`](#userinfohandler) — `rafalmasiarek\DashboardKitSso\Http`
- [`RsaKeyManager`](#rsakeymanager) — `rafalmasiarek\DashboardKitSso\Keys`
- [`AccessTokenRepository`](#accesstokenrepository) — `rafalmasiarek\DashboardKitSso\Repository`
- [`AuthCodeRepository`](#authcoderepository) — `rafalmasiarek\DashboardKitSso\Repository`
- [`ClientRepository`](#clientrepository) — `rafalmasiarek\DashboardKitSso\Repository`
- [`RefreshTokenRepository`](#refreshtokenrepository) — `rafalmasiarek\DashboardKitSso\Repository`
- [`SsoSchemaProvider`](#ssoschemaprovider) — `rafalmasiarek\DashboardKitSso\Schema`
- [`AuthorizationService`](#authorizationservice) — `rafalmasiarek\DashboardKitSso\Service`
- [`PkceValidator`](#pkcevalidator) — `rafalmasiarek\DashboardKitSso\Service`
- [`TokenService`](#tokenservice) — `rafalmasiarek\DashboardKitSso\Service`
- [`SsoAddon`](#ssoaddon) — `rafalmasiarek\DashboardKitSso`

## `AuthorizeHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\AuthorizeHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/AuthorizeHandler.php#L25)

Handles the OAuth2 authorization endpoint. Validates incoming authorization requests, checks session state, and either redirects unauthenticated users to the login page (storing pending params in session) or issues an authorization code and redirects back to the client. Errors that cannot be redirected (invalid client_id, unregistered redirect_uri) are rendered via the oauth/error.twig template to prevent open-redirect attacks.

**Depends on:** `Twig`, `Auth`, [`AuthorizationService`](#authorizationservice)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#authorizehandler-__construct) | public | — | — |
| [`handle()`](#authorizehandler-handle) | public | `Response` | Handles GET /oauth/authorize. Flow: 1. Extract and validate query parameters. 2. Validate client_id and redirect_uri before any redirect (security boundary). 3. If user is not authenticated, store pending params in session and redirect to /login?from=... 4. If user is authenticated, issue an authorization code and redirect to redirect_uri. |

<details>
<summary><code>__construct()</code></summary>

#### `AuthorizeHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/AuthorizeHandler.php#L40)

```php
public function __construct(Twig $view, Auth $auth, AuthorizationService $authService, string $dashboardPrefix)
```

| Param | Type | Description |
|---|---|---|
| `$view` | `Twig` | Twig renderer for error and consent pages. |
| `$auth` | `Auth` | AuthKit authentication service. |
| `$authService` | [`AuthorizationService`](#authorizationservice) | Authorization flow orchestrator. |
| `$dashboardPrefix` | `string` | URL prefix prepended to /login redirect (e.g. ''). |

</details>

<details>
<summary><code>handle()</code></summary>

#### `AuthorizeHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/AuthorizeHandler.php#L61)

```php
public function handle(Request $request, Response $response): Response
```

Handles GET /oauth/authorize. Flow: 1. Extract and validate query parameters. 2. Validate client_id and redirect_uri before any redirect (security boundary). 3. If user is not authenticated, store pending params in session and redirect to /login?from=... 4. If user is authenticated, issue an authorization code and redirect to redirect_uri.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response`

</details>

## `DiscoveryHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\DiscoveryHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/DiscoveryHandler.php#L19)

Serves the OpenID Connect discovery document. Responds to GET /.well-known/openid-configuration with a JSON object describing the issuer's supported endpoints, algorithms, and capabilities. This is the entry point for OIDC-compliant clients that auto-discover endpoints.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#discoveryhandler-__construct) | public | — | — |
| [`handle()`](#discoveryhandler-handle) | public | `Response` | Handles GET /.well-known/openid-configuration. |

<details>
<summary><code>__construct()</code></summary>

#### `DiscoveryHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/DiscoveryHandler.php#L24)

```php
public function __construct(string $issuer)
```

| Param | Type | Description |
|---|---|---|
| `$issuer` | `string` | Base URL of the authorization server (no trailing slash). |

</details>

<details>
<summary><code>handle()</code></summary>

#### `DiscoveryHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/DiscoveryHandler.php#L35)

```php
public function handle(Request $request, Response $response): Response
```

Handles GET /.well-known/openid-configuration.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request (unused; only GET is expected). |
| `$response` | `Response` | PSR-7 response to write the discovery document into. |

**Returns:** `Response` — JSON response with Content-Type application/json.

</details>

## `JwksHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\JwksHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/JwksHandler.php#L20)

Serves the JSON Web Key Set (JWKS) document. Responds to GET /oauth/jwks.json with the public RSA key in JWK format. External clients and resource servers fetch this endpoint to verify JWT signatures without sharing a secret — no direct coordination needed.

**Depends on:** [`RsaKeyManager`](#rsakeymanager)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#jwkshandler-__construct) | public | — | — |
| [`handle()`](#jwkshandler-handle) | public | `Response` | Handles GET /oauth/jwks.json. |

<details>
<summary><code>__construct()</code></summary>

#### `JwksHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/JwksHandler.php#L25)

```php
public function __construct(RsaKeyManager $keyManager)
```

| Param | Type | Description |
|---|---|---|
| `$keyManager` | [`RsaKeyManager`](#rsakeymanager) | RSA key manager that provides the public key in JWK format. |

</details>

<details>
<summary><code>handle()</code></summary>

#### `JwksHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/JwksHandler.php#L36)

```php
public function handle(Request $request, Response $response): Response
```

Handles GET /oauth/jwks.json.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request (unused). |
| `$response` | `Response` | PSR-7 response to write the JWKS into. |

**Returns:** `Response` — JSON response with Content-Type application/json.

</details>

## `RevokeHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\RevokeHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L27)

Handles the OAuth2 token revocation endpoint (POST /oauth/revoke). Implements RFC 7009: always returns 200 regardless of whether the token was found, to prevent probing for valid tokens. Supports access_token and refresh_token hints. When the hint is absent or ambiguous, tries both. When a refresh token is revoked, the associated access token JTI is also invalidated. When an access token is revoked, any refresh tokens sharing its JTI are also revoked.

**Depends on:** [`TokenService`](#tokenservice), [`AccessTokenRepository`](#accesstokenrepository), [`RefreshTokenRepository`](#refreshtokenrepository)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#revokehandler-__construct) | public | — | — |
| [`handle()`](#revokehandler-handle) | public | `Response` | Handles POST /oauth/revoke. Per RFC 7009 the server MUST return 200 even when the token is unknown or already revoked — the goal is idempotent invalidation, not error reporting. |
| [`revoke()`](#revokehandler-revoke) | private | `void` | Attempts to revoke the token, trying the hinted type first. If the hint is 'refresh_token', tries refresh revocation then falls back to access token revocation. If the hint is 'access_token' or absent, tries access token revocation then falls back to refresh token revocation. |
| [`revokeAccessToken()`](#revokehandler-revokeaccesstoken) | private | `bool` | Decodes the JWT to extract the JTI and revokes the access token record. Also revokes any refresh tokens linked to the same JTI. |
| [`revokeRefreshToken()`](#revokehandler-revokerefreshtoken) | private | `void` | Hashes the token and revokes the matching refresh token record. Also revokes the linked access token JTI when the refresh token is found. |

<details>
<summary><code>__construct()</code></summary>

#### `RevokeHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L34)

```php
public function __construct(TokenService $tokenService, AccessTokenRepository $accessTokens, RefreshTokenRepository $refreshTokens)
```

| Param | Type | Description |
|---|---|---|
| `$tokenService` | [`TokenService`](#tokenservice) | JWT decoder for access token JTI extraction. |
| `$accessTokens` | [`AccessTokenRepository`](#accesstokenrepository) | Access token revocation store. |
| `$refreshTokens` | [`RefreshTokenRepository`](#refreshtokenrepository) | Refresh token revocation store. |

</details>

<details>
<summary><code>handle()</code></summary>

#### `RevokeHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L51)

```php
public function handle(Request $request, Response $response): Response
```

Handles POST /oauth/revoke. Per RFC 7009 the server MUST return 200 even when the token is unknown or already revoked — the goal is idempotent invalidation, not error reporting.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request with form-encoded body. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response` — HTTP 200 with empty body.

</details>

<details>
<summary><code>revoke()</code></summary>

#### `RevokeHandler revoke()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L75)

```php
private function revoke(string $token, string $typeHint): void
```

Attempts to revoke the token, trying the hinted type first. If the hint is 'refresh_token', tries refresh revocation then falls back to access token revocation. If the hint is 'access_token' or absent, tries access token revocation then falls back to refresh token revocation.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | The opaque or JWT token to revoke. |
| `$typeHint` | `string` | 'access_token', 'refresh_token', or '' for auto-detect. |

</details>

<details>
<summary><code>revokeAccessToken()</code></summary>

#### `RevokeHandler revokeAccessToken()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L99)

```php
private function revokeAccessToken(string $token): bool
```

Decodes the JWT to extract the JTI and revokes the access token record. Also revokes any refresh tokens linked to the same JTI.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | Encoded JWT access token. |

**Returns:** `bool` — True when a revocable access token was found.

</details>

<details>
<summary><code>revokeRefreshToken()</code></summary>

#### `RevokeHandler revokeRefreshToken()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/RevokeHandler.php#L127)

```php
private function revokeRefreshToken(string $token): void
```

Hashes the token and revokes the matching refresh token record. Also revokes the linked access token JTI when the refresh token is found.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | Plain-text refresh token. |

</details>

## `TokenHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\TokenHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L26)

Handles the OAuth2 token endpoint (POST /oauth/token). Supports two grant types: authorization_code — exchanges a code + PKCE verifier for a token pair. refresh_token      — rotates a refresh token for a new pair. All error responses follow RFC 6749 Section 5.2: {"error": "...", "error_description": "..."}

**Depends on:** [`AuthCodeRepository`](#authcoderepository), [`PkceValidator`](#pkcevalidator), [`TokenService`](#tokenservice)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#tokenhandler-__construct) | public | — | — |
| [`handle()`](#tokenhandler-handle) | public | `Response` | Handles POST /oauth/token. Reads application/x-www-form-urlencoded body, dispatches to the appropriate grant handler, and returns a JSON token response or error. |
| [`handleAuthorizationCode()`](#tokenhandler-handleauthorizationcode) | private | `Response` | Processes the authorization_code grant. Validates: code existence, PKCE verifier, redirect_uri match, client_id match, user active status. On success: fetches the user row and issues a token pair. |
| [`handleRefreshToken()`](#tokenhandler-handlerefreshtoken) | private | `Response` | Processes the refresh_token grant. Consumes the refresh token via TokenService::refresh(), re-fetches the user to ensure current email and role values are used (never trust stale JWT claims). |
| [`fetchUser()`](#tokenhandler-fetchuser) | private | `array{id: string, email: string, role: string, active: int}\|null` | Fetches a user row by ID. |
| [`errorResponse()`](#tokenhandler-errorresponse) | private | `Response` | Writes a JSON error response following RFC 6749 Section 5.2. |
| [`jsonResponse()`](#tokenhandler-jsonresponse) | private | `Response` | Encodes $data as JSON and writes it to the response body. |

<details>
<summary><code>__construct()</code></summary>

#### `TokenHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L33)

```php
public function __construct(AuthCodeRepository $authCodes, PkceValidator $pkce, TokenService $tokenService)
```

| Param | Type | Description |
|---|---|---|
| `$authCodes` | [`AuthCodeRepository`](#authcoderepository) | Authorization code store. |
| `$pkce` | [`PkceValidator`](#pkcevalidator) | PKCE code verifier validator. |
| `$tokenService` | [`TokenService`](#tokenservice) | Issues and refreshes JWT token pairs. |

</details>

<details>
<summary><code>handle()</code></summary>

#### `TokenHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L50)

```php
public function handle(Request $request, Response $response): Response
```

Handles POST /oauth/token. Reads application/x-www-form-urlencoded body, dispatches to the appropriate grant handler, and returns a JSON token response or error.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response` — JSON response.

</details>

<details>
<summary><code>handleAuthorizationCode()</code></summary>

#### `TokenHandler handleAuthorizationCode()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L72)

```php
private function handleAuthorizationCode(array $body, Response $response): Response
```

Processes the authorization_code grant. Validates: code existence, PKCE verifier, redirect_uri match, client_id match, user active status. On success: fetches the user row and issues a token pair.

| Param | Type | Description |
|---|---|---|
| `$body` | `array<string, mixed>` | Parsed form body. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response`

</details>

<details>
<summary><code>handleRefreshToken()</code></summary>

#### `TokenHandler handleRefreshToken()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L137)

```php
private function handleRefreshToken(array $body, Response $response): Response
```

Processes the refresh_token grant. Consumes the refresh token via TokenService::refresh(), re-fetches the user to ensure current email and role values are used (never trust stale JWT claims).

| Param | Type | Description |
|---|---|---|
| `$body` | `array<string, mixed>` | Parsed form body. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response`

</details>

<details>
<summary><code>fetchUser()</code></summary>

#### `TokenHandler fetchUser()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L186)

```php
private function fetchUser(string $userId): ?array
```

Fetches a user row by ID.

| Param | Type | Description |
|---|---|---|
| `$userId` | `string` | UUID of the user. |

**Returns:** `array{id: string, email: string, role: string, active: int}\|null`

</details>

<details>
<summary><code>errorResponse()</code></summary>

#### `TokenHandler errorResponse()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L200)

```php
private function errorResponse(Response $response, string $error, string $errorDescription, int $status): Response
```

Writes a JSON error response following RFC 6749 Section 5.2.

| Param | Type | Description |
|---|---|---|
| `$response` | `Response` | PSR-7 response. |
| `$error` | `string` | RFC 6749 error code. |
| `$errorDescription` | `string` | Human-readable description. |
| `$status` | `int` | HTTP status code (400 or 401). |

**Returns:** `Response`

</details>

<details>
<summary><code>jsonResponse()</code></summary>

#### `TokenHandler jsonResponse()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/TokenHandler.php#L216)

```php
private function jsonResponse(Response $response, array $data, int $status): Response
```

Encodes $data as JSON and writes it to the response body.

| Param | Type | Description |
|---|---|---|
| `$response` | `Response` | PSR-7 response. |
| `$data` | `array<string, mixed>` | Data to encode. |
| `$status` | `int` | HTTP status code. |

**Returns:** `Response`

</details>

## `UserInfoHandler`

*final class* — `rafalmasiarek\DashboardKitSso\Http\UserInfoHandler` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/UserInfoHandler.php#L22)

Handles the OIDC UserInfo endpoint (GET /oauth/userinfo). Accepts a Bearer access token in the Authorization header, verifies the JWT signature, checks for revocation in the database, then re-fetches the user from the users table to return always-current claims (not cached JWT values).

**Depends on:** [`TokenService`](#tokenservice), [`AccessTokenRepository`](#accesstokenrepository)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#userinfohandler-__construct) | public | — | — |
| [`handle()`](#userinfohandler-handle) | public | `Response` | Handles GET /oauth/userinfo. Validates the Bearer token, checks revocation, fetches the user and returns a JSON object with the claims authorized by the token's scopes. |
| [`errorResponse()`](#userinfohandler-errorresponse) | private | `Response` | Writes a JSON error response with WWW-Authenticate header. |
| [`jsonResponse()`](#userinfohandler-jsonresponse) | private | `Response` | Encodes $data as JSON and writes it to the response body. |

<details>
<summary><code>__construct()</code></summary>

#### `UserInfoHandler __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/UserInfoHandler.php#L28)

```php
public function __construct(TokenService $tokenService, AccessTokenRepository $accessTokens)
```

| Param | Type | Description |
|---|---|---|
| `$tokenService` | [`TokenService`](#tokenservice) | JWT decoder using the RSA public key. |
| `$accessTokens` | [`AccessTokenRepository`](#accesstokenrepository) | Revocation check store. |

</details>

<details>
<summary><code>handle()</code></summary>

#### `UserInfoHandler handle()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/UserInfoHandler.php#L44)

```php
public function handle(Request $request, Response $response): Response
```

Handles GET /oauth/userinfo. Validates the Bearer token, checks revocation, fetches the user and returns a JSON object with the claims authorized by the token's scopes.

| Param | Type | Description |
|---|---|---|
| `$request` | `Request` | Incoming PSR-7 request. |
| `$response` | `Response` | PSR-7 response. |

**Returns:** `Response` — JSON user claims or a 401/403 error.

</details>

<details>
<summary><code>errorResponse()</code></summary>

#### `UserInfoHandler errorResponse()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/UserInfoHandler.php#L113)

```php
private function errorResponse(Response $response, int $status, string $error, string $description): Response
```

Writes a JSON error response with WWW-Authenticate header.

| Param | Type | Description |
|---|---|---|
| `$response` | `Response` | PSR-7 response. |
| `$status` | `int` | HTTP status code. |
| `$error` | `string` | OAuth2 error code. |
| `$description` | `string` | Human-readable error description. |

**Returns:** `Response`

</details>

<details>
<summary><code>jsonResponse()</code></summary>

#### `UserInfoHandler jsonResponse()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Http/UserInfoHandler.php#L129)

```php
private function jsonResponse(Response $response, array $data, int $status): Response
```

Encodes $data as JSON and writes it to the response body.

| Param | Type | Description |
|---|---|---|
| `$response` | `Response` | PSR-7 response. |
| `$data` | `array<string, mixed>` | Data to encode. |
| `$status` | `int` | HTTP status code. |

**Returns:** `Response`

</details>

## `RsaKeyManager`

*final class* — `rafalmasiarek\DashboardKitSso\Keys\RsaKeyManager` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L18)

Manages the RSA-2048 key pair used for JWT signing and JWKS publication. Generates the key pair on first use and persists the private key as a PEM file under {storageDir}/sso/private.pem. Subsequent calls load from file. The directory and file are created with mode 0700/0600 respectively.

**Depends on:** `\OpenSSLAsymmetricKey`

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$privateKeyPath` | `string` | private | Absolute path to the private key PEM file. |
| `$privateKey` | `\OpenSSLAsymmetricKey\|null` | private | In-memory cached private key resource. |
| `$publicKey` | `\OpenSSLAsymmetricKey\|null` | private | In-memory cached public key resource. |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#rsakeymanager-__construct) | public | — | — |
| [`getPrivateKey()`](#rsakeymanager-getprivatekey) | public | `\OpenSSLAsymmetricKey` | Returns the private key resource for JWT signing. Generates and persists the key pair on first call if the PEM file does not exist. |
| [`getPublicKey()`](#rsakeymanager-getpublickey) | public | `\OpenSSLAsymmetricKey` | Returns the public key resource for JWT verification and JWKS extraction. |
| [`getJwks()`](#rsakeymanager-getjwks) | public | `array{keys: array<int, array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>}` | Returns the JWK Set (JWKS) representation of the public key. The returned array is ready to be JSON-encoded and served at /oauth/jwks.json. The RSA modulus (n) and exponent (e) are base64url-encoded without padding. |
| [`generate()`](#rsakeymanager-generate) | private | `void` | Generates the RSA-2048 key pair and writes the private key PEM to disk. Creates the storage directory with mode 0700 if it does not exist. The PEM file is written with mode 0600. |
| [`load()`](#rsakeymanager-load) | private | `void` | Loads the private key from the PEM file on disk. |
| [`ensureKey()`](#rsakeymanager-ensurekey) | private | `void` | Ensures the key pair is available, generating it if the PEM file is missing. |
| [`base64url()`](#rsakeymanager-base64url) | private | `string` | Encodes binary data as base64url without padding. |

<details>
<summary><code>__construct()</code></summary>

#### `RsaKeyManager __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L44)

```php
public function __construct(string $storageDir)
```

| Param | Type | Description |
|---|---|---|
| `$storageDir` | `string` | Absolute path to the application storage root. |

</details>

<details>
<summary><code>getPrivateKey()</code></summary>

#### `RsaKeyManager getPrivateKey()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L58)

```php
public function getPrivateKey(): \OpenSSLAsymmetricKey
```

Returns the private key resource for JWT signing. Generates and persists the key pair on first call if the PEM file does not exist.

**Returns:** `\OpenSSLAsymmetricKey`

| Throws | When |
|---|---|
| `RuntimeException` | When the key cannot be generated or loaded. |

</details>

<details>
<summary><code>getPublicKey()</code></summary>

#### `RsaKeyManager getPublicKey()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L74)

```php
public function getPublicKey(): \OpenSSLAsymmetricKey
```

Returns the public key resource for JWT verification and JWKS extraction.

**Returns:** `\OpenSSLAsymmetricKey`

| Throws | When |
|---|---|
| `RuntimeException` | When the public key cannot be derived. |

</details>

<details>
<summary><code>getJwks()</code></summary>

#### `RsaKeyManager getJwks()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L93)

```php
public function getJwks(): array
```

Returns the JWK Set (JWKS) representation of the public key. The returned array is ready to be JSON-encoded and served at /oauth/jwks.json. The RSA modulus (n) and exponent (e) are base64url-encoded without padding.

**Returns:** `array{keys: array<int, array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>}`

| Throws | When |
|---|---|
| `RuntimeException` | When key details cannot be extracted. |

</details>

<details>
<summary><code>generate()</code></summary>

#### `RsaKeyManager generate()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L127)

```php
private function generate(): void
```

Generates the RSA-2048 key pair and writes the private key PEM to disk. Creates the storage directory with mode 0700 if it does not exist. The PEM file is written with mode 0600.

| Throws | When |
|---|---|
| `RuntimeException` | When key generation or file write fails. |

</details>

<details>
<summary><code>load()</code></summary>

#### `RsaKeyManager load()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L165)

```php
private function load(): void
```

Loads the private key from the PEM file on disk.

| Throws | When |
|---|---|
| `RuntimeException` | When the file cannot be read or parsed. |

</details>

<details>
<summary><code>ensureKey()</code></summary>

#### `RsaKeyManager ensureKey()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L201)

```php
private function ensureKey(): void
```

Ensures the key pair is available, generating it if the PEM file is missing.

</details>

<details>
<summary><code>base64url()</code></summary>

#### `RsaKeyManager base64url()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Keys/RsaKeyManager.php#L220)

```php
private function base64url(string $data): string
```

Encodes binary data as base64url without padding.

| Param | Type | Description |
|---|---|---|
| `$data` | `string` | Raw binary string. |

**Returns:** `string` — URL-safe base64 without trailing '=' characters.

</details>

## `AccessTokenRepository`

*final class* — `rafalmasiarek\DashboardKitSso\Repository\AccessTokenRepository` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L17)

Manages access token metadata in the sso_access_tokens table. The actual access token is a signed JWT; this table tracks its JTI (JWT ID) for revocation checks and admin UI listing. The JWT itself is not stored.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`create()`](#accesstokenrepository-create) | public | `void` | Records an issued access token by JTI. |
| [`find()`](#accesstokenrepository-find) | public | `array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}\|null` | Fetches an access token record by JTI. |
| [`revoke()`](#accesstokenrepository-revoke) | public | `void` | Marks an access token as revoked by setting revoked_at to the current time. |
| [`allByUser()`](#accesstokenrepository-allbyuser) | public | `array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}>` | Returns all non-expired, non-revoked access tokens for a given user. Used by the admin UI to display active sessions. |
| [`allActive()`](#accesstokenrepository-allactive) | public | `array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}>` | Returns all active (non-expired, non-revoked) access tokens across all users. Used by the admin UI token listing. |

<details>
<summary><code>create()</code></summary>

#### `AccessTokenRepository create()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L29)

```php
public function create(string $jti, string $clientId, string $userId, array $scopes, int $ttlSeconds): void
```

Records an issued access token by JTI.

| Param | Type | Description |
|---|---|---|
| `$jti` | `string` | UUID v4 used as the JWT 'jti' claim. |
| `$clientId` | `string` | Client that requested the token. |
| `$userId` | `string` | UUID of the authenticated user. |
| `$scopes` | `string[]` | Scopes granted to this token. |
| `$ttlSeconds` | `int` | Lifetime in seconds; used to compute expires_at. |

</details>

<details>
<summary><code>find()</code></summary>

#### `AccessTokenRepository find()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L47)

```php
public function find(string $jti): ?array
```

Fetches an access token record by JTI.

| Param | Type | Description |
|---|---|---|
| `$jti` | `string` | The JWT ID claim. |

**Returns:** `array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}\|null` — Token row or null when not found.

</details>

<details>
<summary><code>revoke()</code></summary>

#### `AccessTokenRepository revoke()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L58)

```php
public function revoke(string $jti): void
```

Marks an access token as revoked by setting revoked_at to the current time.

| Param | Type | Description |
|---|---|---|
| `$jti` | `string` | The JWT ID of the token to revoke. |

</details>

<details>
<summary><code>allByUser()</code></summary>

#### `AccessTokenRepository allByUser()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L71)

```php
public function allByUser(string $userId): array
```

Returns all non-expired, non-revoked access tokens for a given user. Used by the admin UI to display active sessions.

| Param | Type | Description |
|---|---|---|
| `$userId` | `string` | UUID of the user. |

**Returns:** `array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}>`

</details>

<details>
<summary><code>allActive()</code></summary>

#### `AccessTokenRepository allActive()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AccessTokenRepository.php#L89)

```php
public function allActive(): array
```

Returns all active (non-expired, non-revoked) access tokens across all users. Used by the admin UI token listing.

**Returns:** `array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}>`

</details>

## `AuthCodeRepository`

*final class* — `rafalmasiarek\DashboardKitSso\Repository\AuthCodeRepository` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AuthCodeRepository.php#L17)

Manages short-lived authorization codes in the sso_auth_codes table. Each code is single-use: consume() marks used_at and returns null on any subsequent call, preventing replay attacks.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`create()`](#authcoderepository-create) | public | `void` | Persists a new authorization code. |
| [`consume()`](#authcoderepository-consume) | public | `array{code: string, client_id: string, user_id: string, redirect_uri: string, code_challenge: string, code_challenge_method: string, scopes: string, expires_at: string}\|null` | Atomically marks a code as used and returns its data. Returns null if the code does not exist, has already been used (used_at IS NOT NULL), or has expired. |

<details>
<summary><code>create()</code></summary>

#### `AuthCodeRepository create()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AuthCodeRepository.php#L32)

```php
public function create(string $code, string $clientId, string $userId, string $redirectUri, string $codeChallenge, string $method, array $scopes, int $ttlSeconds): void
```

Persists a new authorization code.

| Param | Type | Description |
|---|---|---|
| `$code` | `string` | Cryptographically random code string. |
| `$clientId` | `string` | The client that initiated the flow. |
| `$userId` | `string` | UUID of the authenticated user. |
| `$redirectUri` | `string` | The redirect URI supplied in the authorization request. |
| `$codeChallenge` | `string` | The PKCE code challenge (base64url-encoded SHA-256 of verifier). |
| `$method` | `string` | Challenge method ('S256' or 'plain'). |
| `$scopes` | `string[]` | Requested scopes. |
| `$ttlSeconds` | `int` | Lifetime of the code in seconds. Default: 600. |

</details>

<details>
<summary><code>consume()</code></summary>

#### `AuthCodeRepository consume()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/AuthCodeRepository.php#L63)

```php
public function consume(string $code): ?array
```

Atomically marks a code as used and returns its data. Returns null if the code does not exist, has already been used (used_at IS NOT NULL), or has expired.

| Param | Type | Description |
|---|---|---|
| `$code` | `string` | The authorization code to consume. |

**Returns:** `array{code: string, client_id: string, user_id: string, redirect_uri: string, code_challenge: string, code_challenge_method: string, scopes: string, expires_at: string}\|null`

</details>

## `ClientRepository`

*final class* — `rafalmasiarek\DashboardKitSso\Repository\ClientRepository` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L18)

Manages OAuth2 client records in the sso_clients table. Clients are identified by a client_id string. Public clients have no secret (client_secret_hash is NULL) and rely solely on PKCE. Confidential clients store a bcrypt hash of their secret.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`find()`](#clientrepository-find) | public | `array{client_id: string, client_secret_hash: string\|null, name: string, redirect_uris: string, is_active: int, created_at: string}\|null` | Fetches a single client row by client_id. |
| [`findAll()`](#clientrepository-findall) | public | `array<int, array{client_id: string, client_secret_hash: string\|null, name: string, redirect_uris: string, is_active: int, created_at: string}>` | Returns all registered clients ordered by created_at descending. |
| [`create()`](#clientrepository-create) | public | `void` | Creates a new OAuth2 client record. When $secret is non-null it is stored as a bcrypt hash. Pass null for public (PKCE-only) clients that authenticate solely via code_verifier. is_active/created_at are left to the schema's own defaults (1 / now). |
| [`syncFromConfig()`](#clientrepository-syncfromconfig) | public | `void` | Upserts a config-declared client. Unlike create(), this keeps client_secret_hash and is_active untouched on update. |
| [`setActive()`](#clientrepository-setactive) | public | `void` | Enables or disables a client without deleting it. |
| [`delete()`](#clientrepository-delete) | public | `void` | Permanently removes a client and all its associated tokens. Note: cascade deletes are not enforced by foreign keys here because the sso_* tables do not cross-reference sso_clients with FK constraints. Callers should revoke tokens separately if required. |
| [`validateRedirectUri()`](#clientrepository-validateredirecturi) | public | `bool` | Checks whether a redirect URI is registered for a given client. Performs an exact string match against every URI stored in redirect_uris. |
| [`getRedirectUris()`](#clientrepository-getredirecturis) | public | `string[]` | Returns the list of allowed redirect URIs for a client. |

<details>
<summary><code>find()</code></summary>

#### `ClientRepository find()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L27)

```php
public function find(string $clientId): ?array
```

Fetches a single client row by client_id.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client identifier. |

**Returns:** `array{client_id: string, client_secret_hash: string\|null, name: string, redirect_uris: string, is_active: int, created_at: string}\|null` — Client row or null when not found.

</details>

<details>
<summary><code>findAll()</code></summary>

#### `ClientRepository findAll()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L37)

```php
public function findAll(): array
```

Returns all registered clients ordered by created_at descending.

**Returns:** `array<int, array{client_id: string, client_secret_hash: string\|null, name: string, redirect_uris: string, is_active: int, created_at: string}>`

</details>

<details>
<summary><code>create()</code></summary>

#### `ClientRepository create()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L55)

```php
public function create(string $clientId, ?string $secret, string $name, array $redirectUris): void
```

Creates a new OAuth2 client record. When $secret is non-null it is stored as a bcrypt hash. Pass null for public (PKCE-only) clients that authenticate solely via code_verifier. is_active/created_at are left to the schema's own defaults (1 / now).

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | Unique client identifier (e.g. 'swagger-ui'). |
| `$secret` | `string\|null` | Plain-text secret to hash; null for public clients. |
| `$name` | `string` | Human-readable display name. |
| `$redirectUris` | `string[]` | Allowed redirect URIs (exact match enforced on use). |

</details>

<details>
<summary><code>syncFromConfig()</code></summary>

#### `ClientRepository syncFromConfig()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L74)

```php
public function syncFromConfig(string $clientId, string $name, array $redirectUris): void
```

Upserts a config-declared client. Unlike create(), this keeps client_secret_hash and is_active untouched on update.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | Unique client identifier (e.g. 'swagger-ui'). |
| `$name` | `string` | Human-readable display name. |
| `$redirectUris` | `string[]` | Allowed redirect URIs (exact match enforced on use). |

</details>

<details>
<summary><code>setActive()</code></summary>

#### `ClientRepository setActive()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L93)

```php
public function setActive(string $clientId, bool $active): void
```

Enables or disables a client without deleting it.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client identifier. |
| `$active` | `bool` | True to enable, false to disable. |

</details>

<details>
<summary><code>delete()</code></summary>

#### `ClientRepository delete()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L108)

```php
public function delete(string $clientId): void
```

Permanently removes a client and all its associated tokens. Note: cascade deletes are not enforced by foreign keys here because the sso_* tables do not cross-reference sso_clients with FK constraints. Callers should revoke tokens separately if required.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client identifier. |

</details>

<details>
<summary><code>validateRedirectUri()</code></summary>

#### `ClientRepository validateRedirectUri()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L122)

```php
public function validateRedirectUri(string $clientId, string $redirectUri): bool
```

Checks whether a redirect URI is registered for a given client. Performs an exact string match against every URI stored in redirect_uris.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client identifier. |
| `$redirectUri` | `string` | The URI to validate. |

**Returns:** `bool` — True when the URI is registered and the client is active.

</details>

<details>
<summary><code>getRedirectUris()</code></summary>

#### `ClientRepository getRedirectUris()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/ClientRepository.php#L145)

```php
public function getRedirectUris(string $clientId): array
```

Returns the list of allowed redirect URIs for a client.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client identifier. |

**Returns:** `string[]` — Empty array when client is not found.

</details>

## `RefreshTokenRepository`

*final class* — `rafalmasiarek\DashboardKitSso\Repository\RefreshTokenRepository` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/RefreshTokenRepository.php#L17)

Manages refresh token records in the sso_refresh_tokens table. Refresh tokens are stored as SHA-256 hashes of the opaque token string. The plain token is only held in memory and returned to the client once.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`create()`](#refreshtokenrepository-create) | public | `void` | Persists a new refresh token. The token string is hashed with SHA-256 before storage. |
| [`consume()`](#refreshtokenrepository-consume) | public | `array{token_hash: string, jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}\|null` | Validates and consumes a refresh token in a single operation. Hashes the plain token, looks it up, checks expiry and revocation status, then marks it as revoked. Returns the token row or null when invalid. |
| [`revokeByJti()`](#refreshtokenrepository-revokebyjti) | public | `void` | Revokes all refresh tokens associated with a given access token JTI. Called when revoking an access token to also invalidate any refresh token that can produce new access tokens from the same grant. |

<details>
<summary><code>create()</code></summary>

#### `RefreshTokenRepository create()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/RefreshTokenRepository.php#L32)

```php
public function create(string $token, string $jti, string $clientId, string $userId, array $scopes, int $ttlSeconds): void
```

Persists a new refresh token. The token string is hashed with SHA-256 before storage.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | Plain-text opaque token (returned to client; not stored). |
| `$jti` | `string` | JTI of the corresponding access token. |
| `$clientId` | `string` | Client that owns this refresh token. |
| `$userId` | `string` | UUID of the authenticated user. |
| `$scopes` | `string[]` | Scopes associated with this refresh token. |
| `$ttlSeconds` | `int` | Lifetime in seconds. |

</details>

<details>
<summary><code>consume()</code></summary>

#### `RefreshTokenRepository consume()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/RefreshTokenRepository.php#L59)

```php
public function consume(string $token): ?array
```

Validates and consumes a refresh token in a single operation. Hashes the plain token, looks it up, checks expiry and revocation status, then marks it as revoked. Returns the token row or null when invalid.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | Plain-text refresh token provided by the client. |

**Returns:** `array{token_hash: string, jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string\|null}\|null`

</details>

<details>
<summary><code>revokeByJti()</code></summary>

#### `RefreshTokenRepository revokeByJti()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Repository/RefreshTokenRepository.php#L89)

```php
public function revokeByJti(string $jti): void
```

Revokes all refresh tokens associated with a given access token JTI. Called when revoking an access token to also invalidate any refresh token that can produce new access tokens from the same grant.

| Param | Type | Description |
|---|---|---|
| `$jti` | `string` | JTI of the access token. |

</details>

## `SsoSchemaProvider`

*final class* — `rafalmasiarek\DashboardKitSso\Schema\SsoSchemaProvider` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Schema/SsoSchemaProvider.php#L22)

Creates the database tables required by the SSO / OAuth2 system. Tables created: sso_clients        - registered OAuth2 clients. sso_auth_codes     - short-lived authorization codes for PKCE flow. sso_access_tokens  - issued JWT access tokens (tracked for revocation). sso_refresh_tokens - long-lived refresh tokens (stored as SHA-256 hashes). Called directly by SsoAddon::register() on every boot; all statements use IF NOT EXISTS.

**Depends on:** `PDO`

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#ssoschemaprovider-__construct) | public | — | — |
| [`createSchema()`](#ssoschemaprovider-createschema) | public | `void` | Runs CREATE TABLE IF NOT EXISTS for all SSO tables. Detects driver via PDO::ATTR_DRIVER_NAME and delegates to the appropriate method. |
| [`createMysql()`](#ssoschemaprovider-createmysql) | private | `void` | Creates all SSO tables for MySQL. |
| [`createSqlite()`](#ssoschemaprovider-createsqlite) | private | `void` | Creates all SSO tables for SQLite. |

<details>
<summary><code>__construct()</code></summary>

#### `SsoSchemaProvider __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Schema/SsoSchemaProvider.php#L27)

```php
public function __construct(PDO $pdo)
```

| Param | Type | Description |
|---|---|---|
| `$pdo` | `PDO` | Database connection used to determine driver and execute DDL. |

</details>

<details>
<summary><code>createSchema()</code></summary>

#### `SsoSchemaProvider createSchema()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Schema/SsoSchemaProvider.php#L38)

```php
public function createSchema(): void
```

Runs CREATE TABLE IF NOT EXISTS for all SSO tables. Detects driver via PDO::ATTR_DRIVER_NAME and delegates to the appropriate method.

</details>

<details>
<summary><code>createMysql()</code></summary>

#### `SsoSchemaProvider createMysql()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Schema/SsoSchemaProvider.php#L54)

```php
private function createMysql(): void
```

Creates all SSO tables for MySQL.

</details>

<details>
<summary><code>createSqlite()</code></summary>

#### `SsoSchemaProvider createSqlite()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Schema/SsoSchemaProvider.php#L117)

```php
private function createSqlite(): void
```

Creates all SSO tables for SQLite.

</details>

## `AuthorizationService`

*final class* — `rafalmasiarek\DashboardKitSso\Service\AuthorizationService` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/AuthorizationService.php#L20)

Orchestrates the OAuth2 authorization code flow. Validates the incoming authorization request against registered client data, generates authorization codes, and determines whether a user is authenticated. Kept deliberately thin so that AuthorizeHandler remains the HTTP boundary.

**Depends on:** [`ClientRepository`](#clientrepository), [`AuthCodeRepository`](#authcoderepository)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#authorizationservice-__construct) | public | — | — |
| [`validateRequest()`](#authorizationservice-validaterequest) | public | `array{error: string, error_description: string}\|null` | Validates the core parameters of an authorization request. Checks: - response_type must be 'code' - code_challenge_method must be 'S256' (plain is not accepted) - client_id must resolve to an active client - redirect_uri must be registered for the client (exact match) Returns an error descriptor on failure, null on success. |
| [`generateCode()`](#authorizationservice-generatecode) | public | `string` | Generates and persists an authorization code for an authenticated user. |
| [`normalizeScopes()`](#authorizationservice-normalizescopes) | public | `string[]` | Normalizes and filters a space-separated scope string. Unknown scopes are silently dropped. If the result is empty or 'openid' is absent, 'openid' is prepended. |

<details>
<summary><code>__construct()</code></summary>

#### `AuthorizationService __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/AuthorizationService.php#L26)

```php
public function __construct(ClientRepository $clients, AuthCodeRepository $authCodes)
```

| Param | Type | Description |
|---|---|---|
| `$clients` | [`ClientRepository`](#clientrepository) | Client registry for validation. |
| `$authCodes` | [`AuthCodeRepository`](#authcoderepository) | Authorization code persistence. |

</details>

<details>
<summary><code>validateRequest()</code></summary>

#### `AuthorizationService validateRequest()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/AuthorizationService.php#L50)

```php
public function validateRequest(string $responseType, string $clientId, string $redirectUri, string $codeChallenge, string $codeChallengeMethod): ?array
```

Validates the core parameters of an authorization request. Checks: - response_type must be 'code' - code_challenge_method must be 'S256' (plain is not accepted) - client_id must resolve to an active client - redirect_uri must be registered for the client (exact match) Returns an error descriptor on failure, null on success.

| Param | Type | Description |
|---|---|---|
| `$responseType` | `string` | Must be 'code'. |
| `$clientId` | `string` | The requesting client. |
| `$redirectUri` | `string` | The redirect URI from the request. |
| `$codeChallenge` | `string` | The PKCE code challenge. |
| `$codeChallengeMethod` | `string` | Must be 'S256'. |

**Returns:** `array{error: string, error_description: string}\|null` — Null on success.

</details>

<details>
<summary><code>generateCode()</code></summary>

#### `AuthorizationService generateCode()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/AuthorizationService.php#L110)

```php
public function generateCode(string $clientId, string $userId, string $redirectUri, string $codeChallenge, string $method, array $scopes): string
```

Generates and persists an authorization code for an authenticated user.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | The client initiating the flow. |
| `$userId` | `string` | UUID of the authenticated user. |
| `$redirectUri` | `string` | Validated redirect URI. |
| `$codeChallenge` | `string` | PKCE challenge value. |
| `$method` | `string` | Challenge method (always 'S256'). |
| `$scopes` | `string[]` | Requested and validated scopes. |

**Returns:** `string` — The generated authorization code.

| Throws | When |
|---|---|
| `\Random\RandomException` | When the system PRNG fails. |

</details>

<details>
<summary><code>normalizeScopes()</code></summary>

#### `AuthorizationService normalizeScopes()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/AuthorizationService.php#L135)

```php
public function normalizeScopes(string $scopeString, array $allowedScopes): array
```

Normalizes and filters a space-separated scope string. Unknown scopes are silently dropped. If the result is empty or 'openid' is absent, 'openid' is prepended.

| Param | Type | Description |
|---|---|---|
| `$scopeString` | `string` | Raw space-separated scope input. |
| `$allowedScopes` | `string[]` | Scopes the server supports (e.g. ['openid', 'profile', 'email']). |

**Returns:** `string[]` — Deduplicated, validated scope list.

</details>

## `PkceValidator`

*final class* — `rafalmasiarek\DashboardKitSso\Service\PkceValidator` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/PkceValidator.php#L15)

Validates PKCE (Proof Key for Code Exchange) code verifiers against stored challenges. Supports the S256 method (RECOMMENDED, RFC 7636) and the plain method (fallback). S256 transforms the verifier as: BASE64URL(SHA256(ASCII(code_verifier))).

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`validate()`](#pkcevalidator-validate) | public | `bool` | Validates a code_verifier against a previously stored code_challenge. For S256: computes base64url(sha256(codeVerifier)) and compares to codeChallenge. For plain: compares codeVerifier directly to codeChallenge. |

<details>
<summary><code>validate()</code></summary>

#### `PkceValidator validate()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/PkceValidator.php#L28)

```php
public function validate(string $codeVerifier, string $codeChallenge, string $method): bool
```

Validates a code_verifier against a previously stored code_challenge. For S256: computes base64url(sha256(codeVerifier)) and compares to codeChallenge. For plain: compares codeVerifier directly to codeChallenge.

| Param | Type | Description |
|---|---|---|
| `$codeVerifier` | `string` | The verifier supplied in the token request (43-128 chars, A-Z a-z 0-9 - . _ ~). |
| `$codeChallenge` | `string` | The challenge stored with the authorization code. |
| `$method` | `string` | Challenge method: 'S256' or 'plain'. |

**Returns:** `bool` — True when the verifier satisfies the challenge.

</details>

## `TokenService`

*final class* — `rafalmasiarek\DashboardKitSso\Service\TokenService` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L21)

Issues and refreshes OAuth2 token pairs (access token + refresh token). Access tokens are RS256-signed JWTs. Refresh tokens are opaque random strings whose SHA-256 hashes are stored in the database.

**Depends on:** [`RsaKeyManager`](#rsakeymanager), [`AccessTokenRepository`](#accesstokenrepository), [`RefreshTokenRepository`](#refreshtokenrepository)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#tokenservice-__construct) | public | — | — |
| [`issueTokenPair()`](#tokenservice-issuetokenpair) | public | `array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}` | Issues a new access token + refresh token pair for an authenticated user. The 'name' claim is included only when the 'profile' scope is present. The 'email' claim is always included. The JTI is a UUID v4 used for revocation tracking. |
| [`refresh()`](#tokenservice-refresh) | public | `array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}\|null` | Rotates a refresh token and issues a fresh token pair. The old refresh token is consumed (revoked) before the new pair is issued. Returns null when the refresh token is invalid, expired, or already used. |
| [`decode()`](#tokenservice-decode) | public | `array<string, mixed>\|null` | Decodes and verifies an RS256 JWT using the public key. Returns the decoded payload as an associative array, or null on failure. |
| [`generateOpaqueToken()`](#tokenservice-generateopaquetoken) | private | `string` | Generates a cryptographically secure URL-safe opaque token. |
| [`uuid4()`](#tokenservice-uuid4) | private | `string` | Generates a version-4 UUID string. |

<details>
<summary><code>__construct()</code></summary>

#### `TokenService __construct()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L31)

```php
public function __construct(RsaKeyManager $keys, AccessTokenRepository $accessTokens, RefreshTokenRepository $refreshTokens, string $issuer, int $accessTtl, int $refreshTtl)
```

| Param | Type | Description |
|---|---|---|
| `$keys` | [`RsaKeyManager`](#rsakeymanager) | RSA key pair manager for JWT signing. |
| `$accessTokens` | [`AccessTokenRepository`](#accesstokenrepository) | Access token persistence. |
| `$refreshTokens` | [`RefreshTokenRepository`](#refreshtokenrepository) | Refresh token persistence. |
| `$issuer` | `string` | Issuer URL placed in the 'iss' JWT claim (no trailing slash). |
| `$accessTtl` | `int` | Access token lifetime in seconds. Default: 3600. |
| `$refreshTtl` | `int` | Refresh token lifetime in seconds. Default: 2592000 (30 days). |

</details>

<details>
<summary><code>issueTokenPair()</code></summary>

#### `TokenService issueTokenPair()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L57)

```php
public function issueTokenPair(string $clientId, string $userId, string $email, string $role, ?string $firstName, ?string $lastName, array $scopes): array
```

Issues a new access token + refresh token pair for an authenticated user. The 'name' claim is included only when the 'profile' scope is present. The 'email' claim is always included. The JTI is a UUID v4 used for revocation tracking.

| Param | Type | Description |
|---|---|---|
| `$clientId` | `string` | Client that requested the tokens. |
| `$userId` | `string` | UUID of the authenticated user. |
| `$email` | `string` | User email address. |
| `$role` | `string` | User role (e.g. 'admin', 'user'). |
| `$firstName` | `string\|null` | User first name; null when not available. |
| `$lastName` | `string\|null` | User last name; null when not available. |
| `$scopes` | `string[]` | Granted OAuth2 scopes. |

**Returns:** `array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}`

</details>

<details>
<summary><code>refresh()</code></summary>

#### `TokenService refresh()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L117)

```php
public function refresh(string $refreshToken, string $clientId, string $email, string $role, ?string $firstName, ?string $lastName): ?array
```

Rotates a refresh token and issues a fresh token pair. The old refresh token is consumed (revoked) before the new pair is issued. Returns null when the refresh token is invalid, expired, or already used.

| Param | Type | Description |
|---|---|---|
| `$refreshToken` | `string` | The opaque refresh token supplied by the client. |
| `$clientId` | `string` | Client ID from the token request (must match stored value). |
| `$email` | `string` | Current user email (re-fetched by caller; do not use JWT claims). |
| `$role` | `string` | Current user role. |
| `$firstName` | `string\|null` | User first name. |
| `$lastName` | `string\|null` | User last name. |

**Returns:** `array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}\|null`

</details>

<details>
<summary><code>decode()</code></summary>

#### `TokenService decode()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L153)

```php
public function decode(string $token): ?array
```

Decodes and verifies an RS256 JWT using the public key. Returns the decoded payload as an associative array, or null on failure.

| Param | Type | Description |
|---|---|---|
| `$token` | `string` | Encoded JWT string. |

**Returns:** `array<string, mixed>\|null` — Decoded claims or null when verification fails.

</details>

<details>
<summary><code>generateOpaqueToken()</code></summary>

#### `TokenService generateOpaqueToken()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L170)

```php
private function generateOpaqueToken(): string
```

Generates a cryptographically secure URL-safe opaque token.

**Returns:** `string` — 43-character base64url string without padding.

| Throws | When |
|---|---|
| `\Random\RandomException` | When the system PRNG fails. |

</details>

<details>
<summary><code>uuid4()</code></summary>

#### `TokenService uuid4()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/Service/TokenService.php#L182)

```php
private function uuid4(): string
```

Generates a version-4 UUID string.

**Returns:** `string` — UUID v4 in the format xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx.

| Throws | When |
|---|---|
| `\Random\RandomException` | When the system PRNG fails. |

</details>

## `SsoAddon`

*final class* — `rafalmasiarek\DashboardKitSso\SsoAddon` · [source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/SsoAddon.php#L38)

Wires the OAuth2/OIDC SSO system into a dashboard-kit application.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`register()`](#ssoaddon-register) | public static | `void` | Registers the SSO addon into the Slim application. Must be called after Dashboard::create() has built the container and registered the Twig view, since this method injects template paths into the already-constructed FilesystemLoader. |
| [`syncConfigClients()`](#ssoaddon-syncconfigclients) | private static | `void` | Syncs config-declared OAuth2 clients into sso_clients on every boot. A redirect_uri starting with '/' is resolved relative to $issuer. |
| [`registerProtocolRoutes()`](#ssoaddon-registerprotocolroutes) | private static | `void` | Registers the public OAuth2 protocol routes. These routes are intentionally outside dashboard-kit's auth middleware because the authorize endpoint handles its own session check internally. |
| [`registerAdminRoutes()`](#ssoaddon-registeradminroutes) | private static | `void` | Registers admin UI routes for SSO client and token management. All routes are protected by AuthMiddleware, CsrfMiddleware, and RoleMiddleware(['admin']). Routes: GET /admin/sso/clients — list clients POST /admin/sso/clients — create client POST /admin/sso/clients/{id}/delete — delete client GET /admin/sso/tokens — list active tokens POST /admin/sso/tokens/{jti}/revoke — revoke token |

<details>
<summary><code>register()</code></summary>

#### `SsoAddon register()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/SsoAddon.php#L52)

```php
public static function register(App $app, ContainerInterface $container, array $config): void
```

Registers the SSO addon into the Slim application. Must be called after Dashboard::create() has built the container and registered the Twig view, since this method injects template paths into the already-constructed FilesystemLoader.

| Param | Type | Description |
|---|---|---|
| `$app` | `App` | Slim application instance. |
| `$container` | `ContainerInterface` | PHP-DI container from Dashboard::create(). |
| `$config` | `array<string, mixed>` | Addon configuration overrides. |

</details>

<details>
<summary><code>syncConfigClients()</code></summary>

#### `SsoAddon syncConfigClients()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/SsoAddon.php#L134)

```php
private static function syncConfigClients(ClientRepository $repo, array $clients, string $issuer): void
```

Syncs config-declared OAuth2 clients into sso_clients on every boot. A redirect_uri starting with '/' is resolved relative to $issuer.

| Param | Type | Description |
|---|---|---|
| `$repo` | [`ClientRepository`](#clientrepository) | Client repository. |
| `$clients` | `array<int, array{client_id: string, name: string, redirect_uris: string[]}>` | Config-declared clients. |
| `$issuer` | `string` | Full issuer base URL (no trailing slash). |

</details>

<details>
<summary><code>registerProtocolRoutes()</code></summary>

#### `SsoAddon registerProtocolRoutes()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/SsoAddon.php#L165)

```php
private static function registerProtocolRoutes(App $app, ContainerInterface $container, string $dashboardPrefix, string $issuer): void
```

Registers the public OAuth2 protocol routes. These routes are intentionally outside dashboard-kit's auth middleware because the authorize endpoint handles its own session check internally.

| Param | Type | Description |
|---|---|---|
| `$app` | `App` | — |
| `$container` | `ContainerInterface` | — |
| `$dashboardPrefix` | `string` | URL prefix (e.g. '' or '/app'). |
| `$issuer` | `string` | Full issuer URL for the discovery document. |

</details>

<details>
<summary><code>registerAdminRoutes()</code></summary>

#### `SsoAddon registerAdminRoutes()`

[source](https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso/blob/main/src/SsoAddon.php#L250)

```php
private static function registerAdminRoutes(App $app, ContainerInterface $container, string $dashboardPrefix): void
```

Registers admin UI routes for SSO client and token management. All routes are protected by AuthMiddleware, CsrfMiddleware, and RoleMiddleware(['admin']). Routes: GET  /admin/sso/clients              — list clients POST /admin/sso/clients              — create client POST /admin/sso/clients/{id}/delete  — delete client GET  /admin/sso/tokens               — list active tokens POST /admin/sso/tokens/{jti}/revoke  — revoke token

| Param | Type | Description |
|---|---|---|
| `$app` | `App` | — |
| `$container` | `ContainerInterface` | — |
| `$dashboardPrefix` | `string` | URL prefix. |

</details>



## License

![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-red)

Business Source License 1.1.

Source available; commercial use restricted until 2099-01-01.


For alternative licensing, contact: https://masiarek.pl/contact/?af_subject=Commercial+license+%E2%80%94+dashboard-kit-addon-sso&af_message=Hello%2C+I+am+interested+in+a+commercial+license+for+dashboard-kit-addon-sso.



See [LICENSE](LICENSE) for full details.
## Authors

- Rafał Masiarek | [website](https://masiarek.pl) | [github](https://github.com/rafalmasiarek)


<!-- references -->

[repo_link]: https://github.com/rafalmasiarek/php-dashboard-kit-addon-sso
