<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use PDO;

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
     * @param PDO $pdo Database connection.
     */
    public function __construct(private readonly PDO $pdo)
    {
    }

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
        $driver     = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $hash       = hash('sha256', $token);
        $scopesJson = json_encode($scopes, JSON_UNESCAPED_UNICODE);

        if ($driver === 'mysql') {
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_refresh_tokens (token_hash, jti, client_id, user_id, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))"
            );
            $stmt->execute([$hash, $jti, $clientId, $userId, $scopesJson, $ttlSeconds]);
        } else {
            $expiresAt = date('Y-m-d H:i:s', time() + $ttlSeconds);
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_refresh_tokens (token_hash, jti, client_id, user_id, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?)"
            );
            $stmt->execute([$hash, $jti, $clientId, $userId, $scopesJson, $expiresAt]);
        }
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
        $hash   = hash('sha256', $token);
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $now    = $driver === 'mysql' ? 'NOW()' : "datetime('now')";

        $stmt = $this->pdo->prepare(
            "SELECT * FROM sso_refresh_tokens
             WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > {$now}"
        );
        $stmt->execute([$hash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            return null;
        }

        // Mark revoked to prevent reuse.
        $upd = $this->pdo->prepare("UPDATE sso_refresh_tokens SET revoked_at = {$now} WHERE token_hash = ?");
        $upd->execute([$hash]);

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
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $now    = $driver === 'mysql' ? 'NOW()' : "datetime('now')";

        $stmt = $this->pdo->prepare(
            "UPDATE sso_refresh_tokens SET revoked_at = {$now} WHERE jti = ? AND revoked_at IS NULL"
        );
        $stmt->execute([$jti]);
    }
}
