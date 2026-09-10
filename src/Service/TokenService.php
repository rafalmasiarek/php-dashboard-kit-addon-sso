<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use rafalmasiarek\DashboardKitSso\Keys\RsaKeyManager;
use rafalmasiarek\DashboardKitSso\Repository\AccessTokenRepository;
use rafalmasiarek\DashboardKitSso\Repository\RefreshTokenRepository;

/**
 * Issues and refreshes OAuth2 token pairs (access token + refresh token).
 *
 * Access tokens are RS256-signed JWTs. Refresh tokens are opaque random strings
 * whose SHA-256 hashes are stored in the database.
 *
 * @package rafalmasiarek\DashboardKitSso\Service
 */
final class TokenService
{
    /**
     * @param RsaKeyManager          $keys          RSA key pair manager for JWT signing.
     * @param AccessTokenRepository  $accessTokens  Access token persistence.
     * @param RefreshTokenRepository $refreshTokens Refresh token persistence.
     * @param string                 $issuer        Issuer URL placed in the 'iss' JWT claim (no trailing slash).
     * @param int                    $accessTtl     Access token lifetime in seconds. Default: 3600.
     * @param int                    $refreshTtl    Refresh token lifetime in seconds. Default: 2592000 (30 days).
     */
    public function __construct(
        private readonly RsaKeyManager          $keys,
        private readonly AccessTokenRepository  $accessTokens,
        private readonly RefreshTokenRepository $refreshTokens,
        private readonly string                 $issuer,
        private readonly int                    $accessTtl  = 3600,
        private readonly int                    $refreshTtl = 2592000,
    ) {
    }

    /**
     * Issues a new access token + refresh token pair for an authenticated user.
     *
     * The 'name' claim is included only when the 'profile' scope is present.
     * The 'email' claim is always included.
     * The JTI is a UUID v4 used for revocation tracking.
     *
     * @param string      $clientId   Client that requested the tokens.
     * @param string      $userId     UUID of the authenticated user.
     * @param string      $email      User email address.
     * @param string      $role       User role (e.g. 'admin', 'user').
     * @param string|null $firstName  User first name; null when not available.
     * @param string|null $lastName   User last name; null when not available.
     * @param string[]    $scopes     Granted OAuth2 scopes.
     * @return array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}
     */
    public function issueTokenPair(
        string $clientId,
        string $userId,
        string $email,
        string $role,
        ?string $firstName,
        ?string $lastName,
        array $scopes,
    ): array {
        $jti = $this->uuid4();
        $iat = time();
        $exp = $iat + $this->accessTtl;

        $payload = [
            'iss'   => $this->issuer,
            'sub'   => $userId,
            'aud'   => $clientId,
            'exp'   => $exp,
            'iat'   => $iat,
            'jti'   => $jti,
            'email' => $email,
            'role'  => $role,
        ];

        if (in_array('profile', $scopes, true)) {
            $name = trim(($firstName ?? '') . ' ' . ($lastName ?? ''));
            if ($name !== '') {
                $payload['name'] = $name;
            }
        }

        $accessToken  = JWT::encode($payload, $this->keys->getPrivateKey(), 'RS256');
        $refreshToken = $this->generateOpaqueToken();

        $this->accessTokens->create($jti, $clientId, $userId, $scopes, $this->accessTtl);
        $this->refreshTokens->create($refreshToken, $jti, $clientId, $userId, $scopes, $this->refreshTtl);

        return [
            'access_token'  => $accessToken,
            'refresh_token' => $refreshToken,
            'expires_in'    => $this->accessTtl,
            'token_type'    => 'Bearer',
            'scope'         => implode(' ', $scopes),
        ];
    }

    /**
     * Rotates a refresh token and issues a fresh token pair.
     *
     * The old refresh token is consumed (revoked) before the new pair is issued.
     * Returns null when the refresh token is invalid, expired, or already used.
     *
     * @param string   $refreshToken The opaque refresh token supplied by the client.
     * @param string   $clientId     Client ID from the token request (must match stored value).
     * @param string   $email        Current user email (re-fetched by caller; do not use JWT claims).
     * @param string   $role         Current user role.
     * @param string|null $firstName User first name.
     * @param string|null $lastName  User last name.
     * @return array{access_token: string, refresh_token: string, expires_in: int, token_type: string, scope: string}|null
     */
    public function refresh(
        string $refreshToken,
        string $clientId,
        string $email,
        string $role,
        ?string $firstName,
        ?string $lastName,
    ): ?array {
        $row = $this->refreshTokens->consume($refreshToken);

        if ($row === null || $row['client_id'] !== $clientId) {
            return null;
        }

        $scopes = json_decode($row['scopes'], true);
        $scopes = is_array($scopes) ? $scopes : [];

        return $this->issueTokenPair(
            $clientId,
            $row['user_id'],
            $email,
            $role,
            $firstName,
            $lastName,
            $scopes,
        );
    }

    /**
     * Decodes and verifies an RS256 JWT using the public key.
     *
     * Returns the decoded payload as an associative array, or null on failure.
     *
     * @param string $token Encoded JWT string.
     * @return array<string, mixed>|null Decoded claims or null when verification fails.
     */
    public function decode(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->keys->getPublicKey(), 'RS256'));
            return (array) $decoded;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Generates a cryptographically secure URL-safe opaque token.
     *
     * @return string 43-character base64url string without padding.
     *
     * @throws \Random\RandomException When the system PRNG fails.
     */
    private function generateOpaqueToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Generates a version-4 UUID string.
     *
     * @return string UUID v4 in the format xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx.
     *
     * @throws \Random\RandomException When the system PRNG fails.
     */
    private function uuid4(): string
    {
        $bytes = random_bytes(16);

        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
