<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use rafalmasiarek\DashboardKit\Model\Model;

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
     * Fetches a single client row by client_id.
     *
     * @param string $clientId The client identifier.
     * @return array{client_id: string, client_secret_hash: string|null, name: string, redirect_uris: string, is_active: int, created_at: string}|null
     *         Client row or null when not found.
     */
    public function find(string $clientId): ?array
    {
        return Model::on('sso_clients')->where('client_id', $clientId)->first();
    }

    /**
     * Returns all registered clients ordered by created_at descending.
     *
     * @return array<int, array{client_id: string, client_secret_hash: string|null, name: string, redirect_uris: string, is_active: int, created_at: string}>
     */
    public function findAll(): array
    {
        return Model::on('sso_clients')->orderBy('created_at', 'DESC')->get()->toArray();
    }

    /**
     * Creates a new OAuth2 client record.
     *
     * When $secret is non-null it is stored as a bcrypt hash. Pass null for
     * public (PKCE-only) clients that authenticate solely via code_verifier.
     * is_active/created_at are left to the schema's own defaults (1 / now).
     *
     * @param string      $clientId     Unique client identifier (e.g. 'swagger-ui').
     * @param string|null $secret       Plain-text secret to hash; null for public clients.
     * @param string      $name         Human-readable display name.
     * @param string[]    $redirectUris Allowed redirect URIs (exact match enforced on use).
     * @return void
     */
    public function create(string $clientId, ?string $secret, string $name, array $redirectUris): void
    {
        Model::on('sso_clients')->insert([
            'client_id'          => $clientId,
            'client_secret_hash' => $secret !== null ? password_hash($secret, PASSWORD_BCRYPT) : null,
            'name'               => $name,
            'redirect_uris'      => json_encode($redirectUris, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]);
    }

    /**
     * Upserts a config-declared client. Unlike create(), this keeps
     * client_secret_hash and is_active untouched on update.
     *
     * @param string   $clientId     Unique client identifier (e.g. 'swagger-ui').
     * @param string   $name         Human-readable display name.
     * @param string[] $redirectUris Allowed redirect URIs (exact match enforced on use).
     * @return void
     */
    public function syncFromConfig(string $clientId, string $name, array $redirectUris): void
    {
        Model::on('sso_clients')->upsert(
            [
                'client_id'     => $clientId,
                'name'          => $name,
                'redirect_uris' => json_encode($redirectUris, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            ],
            ['client_id'],
        );
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
        Model::on('sso_clients')->where('client_id', $clientId)->update(['is_active' => $active ? 1 : 0]);
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
        Model::on('sso_clients')->where('client_id', $clientId)->forceDelete();
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
