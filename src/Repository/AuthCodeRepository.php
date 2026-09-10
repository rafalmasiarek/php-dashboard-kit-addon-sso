<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use PDO;

/**
 * Manages short-lived authorization codes in the sso_auth_codes table.
 *
 * Each code is single-use: consume() marks used_at and returns null on any
 * subsequent call, preventing replay attacks.
 *
 * @package rafalmasiarek\DashboardKitSso\Repository
 */
final class AuthCodeRepository
{
    /**
     * @param PDO $pdo Database connection.
     */
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Persists a new authorization code.
     *
     * @param string   $code          Cryptographically random code string.
     * @param string   $clientId      The client that initiated the flow.
     * @param string   $userId        UUID of the authenticated user.
     * @param string   $redirectUri   The redirect URI supplied in the authorization request.
     * @param string   $codeChallenge The PKCE code challenge (base64url-encoded SHA-256 of verifier).
     * @param string   $method        Challenge method ('S256' or 'plain').
     * @param string[] $scopes        Requested scopes.
     * @param int      $ttlSeconds    Lifetime of the code in seconds. Default: 600.
     * @return void
     */
    public function create(
        string $code,
        string $clientId,
        string $userId,
        string $redirectUri,
        string $codeChallenge,
        string $method,
        array $scopes,
        int $ttlSeconds = 600,
    ): void {
        $driver     = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $scopesJson = json_encode($scopes, JSON_UNESCAPED_UNICODE);

        if ($driver === 'mysql') {
            $expiresExpr = 'DATE_ADD(NOW(), INTERVAL ? SECOND)';
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_auth_codes
                    (code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, {$expiresExpr})"
            );
            $stmt->execute([$code, $clientId, $userId, $redirectUri, $codeChallenge, $method, $scopesJson, $ttlSeconds]);
        } else {
            $expiresAt = date('Y-m-d H:i:s', time() + $ttlSeconds);
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_auth_codes
                    (code, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, scopes, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            );
            $stmt->execute([$code, $clientId, $userId, $redirectUri, $codeChallenge, $method, $scopesJson, $expiresAt]);
        }
    }

    /**
     * Atomically marks a code as used and returns its data.
     *
     * Returns null if the code does not exist, has already been used (used_at IS NOT NULL),
     * or has expired.
     *
     * @param string $code The authorization code to consume.
     * @return array{code: string, client_id: string, user_id: string, redirect_uri: string, code_challenge: string, code_challenge_method: string, scopes: string, expires_at: string}|null
     */
    public function consume(string $code): ?array
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        if ($driver === 'mysql') {
            $nowExpr = 'NOW()';
        } else {
            $nowExpr = "datetime('now')";
        }

        $stmt = $this->pdo->prepare(
            "SELECT * FROM sso_auth_codes
             WHERE code = ? AND used_at IS NULL AND expires_at > {$nowExpr}"
        );
        $stmt->execute([$code]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            return null;
        }

        // Mark as used immediately to prevent replay.
        $upd = $this->pdo->prepare("UPDATE sso_auth_codes SET used_at = {$nowExpr} WHERE code = ?");
        $upd->execute([$code]);

        return $row;
    }
}
