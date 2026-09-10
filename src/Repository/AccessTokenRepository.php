<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use PDO;

/**
 * Manages access token metadata in the sso_access_tokens table.
 *
 * The actual access token is a signed JWT; this table tracks its JTI (JWT ID)
 * for revocation checks and admin UI listing. The JWT itself is not stored.
 *
 * @package rafalmasiarek\DashboardKitSso\Repository
 */
final class AccessTokenRepository
{
    /**
     * @param PDO $pdo Database connection.
     */
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Records an issued access token by JTI.
     *
     * @param string   $jti       UUID v4 used as the JWT 'jti' claim.
     * @param string   $clientId  Client that requested the token.
     * @param string   $userId    UUID of the authenticated user.
     * @param string[] $scopes    Scopes granted to this token.
     * @param int      $ttlSeconds Lifetime in seconds; used to compute expires_at.
     * @return void
     */
    public function create(string $jti, string $clientId, string $userId, array $scopes, int $ttlSeconds): void
    {
        $driver     = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $scopesJson = json_encode($scopes, JSON_UNESCAPED_UNICODE);

        if ($driver === 'mysql') {
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_access_tokens (jti, client_id, user_id, scopes, expires_at)
                 VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))"
            );
            $stmt->execute([$jti, $clientId, $userId, $scopesJson, $ttlSeconds]);
        } else {
            $expiresAt = date('Y-m-d H:i:s', time() + $ttlSeconds);
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_access_tokens (jti, client_id, user_id, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?)"
            );
            $stmt->execute([$jti, $clientId, $userId, $scopesJson, $expiresAt]);
        }
    }

    /**
     * Fetches an access token record by JTI.
     *
     * @param string $jti The JWT ID claim.
     * @return array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string|null}|null
     *         Token row or null when not found.
     */
    public function find(string $jti): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM sso_access_tokens WHERE jti = ?');
        $stmt->execute([$jti]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row !== false ? $row : null;
    }

    /**
     * Marks an access token as revoked by setting revoked_at to the current time.
     *
     * @param string $jti The JWT ID of the token to revoke.
     * @return void
     */
    public function revoke(string $jti): void
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $now    = $driver === 'mysql' ? 'NOW()' : "datetime('now')";

        $stmt = $this->pdo->prepare("UPDATE sso_access_tokens SET revoked_at = {$now} WHERE jti = ?");
        $stmt->execute([$jti]);
    }

    /**
     * Returns all non-expired, non-revoked access tokens for a given user.
     *
     * Used by the admin UI to display active sessions.
     *
     * @param string $userId UUID of the user.
     * @return array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string|null}>
     */
    public function allByUser(string $userId): array
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $now    = $driver === 'mysql' ? 'NOW()' : "datetime('now')";

        $stmt = $this->pdo->prepare(
            "SELECT * FROM sso_access_tokens
             WHERE user_id = ? AND revoked_at IS NULL AND expires_at > {$now}
             ORDER BY expires_at DESC"
        );
        $stmt->execute([$userId]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Returns all active (non-expired, non-revoked) access tokens across all users.
     *
     * Used by the admin UI token listing.
     *
     * @return array<int, array{jti: string, client_id: string, user_id: string, scopes: string, expires_at: string, revoked_at: string|null}>
     */
    public function allActive(): array
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $now    = $driver === 'mysql' ? 'NOW()' : "datetime('now')";

        $stmt = $this->pdo->query(
            "SELECT at.*, u.email
             FROM sso_access_tokens at
             LEFT JOIN users u ON u.id = at.user_id
             WHERE at.revoked_at IS NULL AND at.expires_at > {$now}
             ORDER BY at.expires_at DESC"
        );

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
