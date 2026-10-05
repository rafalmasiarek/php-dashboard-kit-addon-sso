<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use rafalmasiarek\DashboardKit\Model\Model;

/**
 * Manages refresh token records in the sso_refresh_tokens table.
 *
 * Refresh tokens are stored as SHA-256 hashes of the opaque token string.
 * The plain token is only held in memory and returned to the client once.
 *
 * @package rafalmasiarek\DashboardKitSso\Repository
 */
final class RefreshTokenRepository
{
    /**
     * Persists a new refresh token.
     *
     * The token string is hashed with SHA-256 before storage.
     *
     * @param string   $token      Plain-text opaque token (returned to client; not stored).
     * @param string   $jti        JTI of the corresponding access token.
     * @param string   $clientId   Client that owns this refresh token.
     * @param string   $userId     UUID of the authenticated user.
     * @param string[] $scopes     Scopes associated with this refresh token.
     * @param int      $ttlSeconds Lifetime in seconds.
     * @return void
     */
    public function create(
        string $token,
        string $jti,
        string $clientId,
        string $userId,
        array $scopes,
        int $ttlSeconds,
    ): void {
        Model::on('sso_refresh_tokens')->insert([
            'token_hash' => hash('sha256', $token),
            'jti'        => $jti,
            'client_id'  => $clientId,
            'user_id'    => $userId,
            'scopes'     => json_encode($scopes, JSON_UNESCAPED_UNICODE),
            'expires_at' => Model::getClock()->now()->modify("+{$ttlSeconds} seconds")->format('Y-m-d H:i:s'),
        ]);
    }

    /**
     * Validates and consumes a refresh token in a single operation.
     *
     * Hashes the plain token, looks it up, checks expiry and revocation status,
     * then marks it as revoked. Returns the token row or null when invalid.
     *
     * @param string $token Plain-text refresh token provided by the client.
     * @return array{token_hash: string, jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string|null}|null
     */
    public function consume(string $token): ?array
    {
        $hash = hash('sha256', $token);
        $now  = Model::getClock()->now()->format('Y-m-d H:i:s');

        $row = Model::on('sso_refresh_tokens')
            ->where('token_hash', $hash)
            ->where('revoked_at', null)
            ->where('expires_at', '>', $now)
            ->first();

        if ($row === null) {
            return null;
        }

        // Mark revoked to prevent reuse.
        Model::on('sso_refresh_tokens')->where('token_hash', $hash)->update(['revoked_at' => $now]);

        return $row;
    }

    /**
     * Revokes all refresh tokens associated with a given access token JTI.
     *
     * Called when revoking an access token to also invalidate any refresh token
     * that can produce new access tokens from the same grant.
     *
     * @param string $jti JTI of the access token.
     * @return void
     */
    public function revokeByJti(string $jti): void
    {
        Model::on('sso_refresh_tokens')
            ->where('jti', $jti)
            ->where('revoked_at', null)
            ->update(['revoked_at' => Model::getClock()->now()->format('Y-m-d H:i:s')]);
    }
}
