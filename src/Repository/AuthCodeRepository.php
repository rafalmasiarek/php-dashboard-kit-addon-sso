<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Repository;

use rafalmasiarek\DashboardKit\Model\Model;

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
        Model::on('sso_auth_codes')->insert([
            'code'                  => $code,
            'client_id'             => $clientId,
            'user_id'               => $userId,
            'redirect_uri'          => $redirectUri,
            'code_challenge'        => $codeChallenge,
            'code_challenge_method' => $method,
            'scopes'                => json_encode($scopes, JSON_UNESCAPED_UNICODE),
            'expires_at'            => Model::getClock()->now()->modify("+{$ttlSeconds} seconds")->format('Y-m-d H:i:s'),
        ]);
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
        $now = Model::getClock()->now()->format('Y-m-d H:i:s');

        $row = Model::on('sso_auth_codes')
            ->where('code', $code)
            ->where('used_at', null)
            ->where('expires_at', '>', $now)
            ->first();

        if ($row === null) {
            return null;
        }

        // Mark as used immediately to prevent replay.
        Model::on('sso_auth_codes')->where('code', $code)->update(['used_at' => $now]);

        return $row;
    }
}
