<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use PDO;

/**
 * Manages OAuth2 client records in the sso_clients table.
 *
 * Clients are identified by a client_id string. Public clients have no secret
 * (client_secret_hash is NULL) and rely solely on PKCE. Confidential clients
 * store a bcrypt hash of their secret.
 *
 * @package rafalmasiarek\DashboardKitSso\Repository
 */
final class ClientRepository
{
    /**
     * @param PDO $pdo Database connection.
     */
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Fetches a single client row by client_id.
     *
     * @param string $clientId The client identifier.
     * @return array{client_id: string, client_secret_hash: string|null, name: string, redirect_uris: string, is_active: int, created_at: string}|null
     *         Client row or null when not found.
     */
    public function find(string $clientId): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM sso_clients WHERE client_id = ?');
        $stmt->execute([$clientId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row !== false ? $row : null;
    }

    /**
     * Returns all registered clients ordered by created_at descending.
     *
     * @return array<int, array{client_id: string, client_secret_hash: string|null, name: string, redirect_uris: string, is_active: int, created_at: string}>
     */
    public function findAll(): array
    {
        $stmt = $this->pdo->query('SELECT * FROM sso_clients ORDER BY created_at DESC');

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Creates a new OAuth2 client record.
     *
     * When $secret is non-null it is stored as a bcrypt hash. Pass null for
     * public (PKCE-only) clients that authenticate solely via code_verifier.
     *
     * @param string      $clientId     Unique client identifier (e.g. 'swagger-ui').
     * @param string|null $secret       Plain-text secret to hash; null for public clients.
     * @param string      $name         Human-readable display name.
     * @param string[]    $redirectUris Allowed redirect URIs (exact match enforced on use).
     * @return void
     */
    public function create(string $clientId, ?string $secret, string $name, array $redirectUris): void
    {
        $hash = $secret !== null ? password_hash($secret, PASSWORD_BCRYPT) : null;

        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $urisJson = json_encode($redirectUris, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($driver === 'mysql') {
            $stmt = $this->pdo->prepare(
                'INSERT INTO sso_clients (client_id, client_secret_hash, name, redirect_uris) VALUES (?, ?, ?, ?)'
            );
        } else {
            $stmt = $this->pdo->prepare(
                "INSERT INTO sso_clients (client_id, client_secret_hash, name, redirect_uris, is_active, created_at)
                 VALUES (?, ?, ?, ?, 1, datetime('now'))"
            );
        }

        $stmt->execute([$clientId, $hash, $name, $urisJson]);
    }

    /**
     * Enables or disables a client without deleting it.
     *
     * @param string $clientId The client identifier.
     * @param bool   $active   True to enable, false to disable.
     * @return void
     */
    public function setActive(string $clientId, bool $active): void
    {
        $stmt = $this->pdo->prepare('UPDATE sso_clients SET is_active = ? WHERE client_id = ?');
        $stmt->execute([$active ? 1 : 0, $clientId]);
    }

    /**
     * Permanently removes a client and all its associated tokens.
     *
     * Note: cascade deletes are not enforced by foreign keys here because the
     * sso_* tables do not cross-reference sso_clients with FK constraints.
     * Callers should revoke tokens separately if required.
     *
     * @param string $clientId The client identifier.
     * @return void
     */
    public function delete(string $clientId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM sso_clients WHERE client_id = ?');
        $stmt->execute([$clientId]);
    }

    /**
     * Checks whether a redirect URI is registered for a given client.
     *
     * Performs an exact string match against every URI stored in redirect_uris.
     *
     * @param string $clientId    The client identifier.
     * @param string $redirectUri The URI to validate.
     * @return bool               True when the URI is registered and the client is active.
     */
    public function validateRedirectUri(string $clientId, string $redirectUri): bool
    {
        $client = $this->find($clientId);

        if ($client === null || (int) $client['is_active'] !== 1) {
            return false;
        }

        $uris = json_decode($client['redirect_uris'], true);

        if (!is_array($uris)) {
            return false;
        }

        return in_array($redirectUri, $uris, true);
    }

    /**
     * Returns the list of allowed redirect URIs for a client.
     *
     * @param string $clientId The client identifier.
     * @return string[]        Empty array when client is not found.
     */
    public function getRedirectUris(string $clientId): array
    {
        $client = $this->find($clientId);

        if ($client === null) {
            return [];
        }

        $uris = json_decode($client['redirect_uris'], true);

        return is_array($uris) ? $uris : [];
    }
}
