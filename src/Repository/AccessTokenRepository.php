<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use rafalmasiarek\DashboardKit\Model\Model;

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
     * Records an issued access token by JTI.
     *
     * @param string   $jti        UUID v4 used as the JWT 'jti' claim.
     * @param string   $clientId   Client that requested the token.
     * @param string   $userId     UUID of the authenticated user.
     * @param string[] $scopes     Scopes granted to this token.
     * @param int      $ttlSeconds Lifetime in seconds; used to compute expires_at.
     * @return void
     */
    public function create(string $jti, string $clientId, string $userId, array $scopes, int $ttlSeconds): void
    {
        Model::on('sso_access_tokens')->insert([
            'jti'        => $jti,
            'client_id'  => $clientId,
            'user_id'    => $userId,
            'scopes'     => json_encode($scopes, JSON_UNESCAPED_UNICODE),
            'expires_at' => date('Y-m-d H:i:s', time() + $ttlSeconds),
        ]);
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
        return Model::on('sso_access_tokens')->where('jti', $jti)->first();
    }

    /**
     * Marks an access token as revoked by setting revoked_at to the current time.
     *
     * @param string $jti The JWT ID of the token to revoke.
     * @return void
     */
    public function revoke(string $jti): void
    {
        Model::on('sso_access_tokens')->where('jti', $jti)->update(['revoked_at' => date('Y-m-d H:i:s')]);
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
        return Model::on('sso_access_tokens')
            ->where('user_id', $userId)
            ->where('revoked_at', null)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->orderBy('expires_at', 'DESC')
            ->get()
            ->toArray();
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
        return Model::on('sso_access_tokens')
            ->select('sso_access_tokens.*', 'users.email')
            ->leftJoin('users', 'users.id', '=', 'sso_access_tokens.user_id')
            ->where('revoked_at', null)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->orderBy('expires_at', 'DESC')
            ->get()
            ->toArray();
    }
}
