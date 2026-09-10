# dashboard-kit-addon-sso

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

## License

Business Source License 1.1 — see [LICENSE](LICENSE).
For alternative licensing, [contact us](https://masiarek.pl/contact/?af_subject=Commercial+license+%E2%80%94+dashboard-kit-addon-sso&af_message=Hello%2C+I+am+interested+in+a+commercial+license+for+dashboard-kit-addon-sso.).
