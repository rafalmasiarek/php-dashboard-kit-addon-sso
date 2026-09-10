<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Service;

use rafalmasiarek\DashboardKitSso\Repository\AuthCodeRepository;
use rafalmasiarek\DashboardKitSso\Repository\ClientRepository;

/**
 * Orchestrates the OAuth2 authorization code flow.
 *
 * Validates the incoming authorization request against registered client data,
 * generates authorization codes, and determines whether a user is authenticated.
 *
 * Kept deliberately thin so that AuthorizeHandler remains the HTTP boundary.
 *
 * @package rafalmasiarek\DashboardKitSso\Service
 */
final class AuthorizationService
{
    /**
     * @param ClientRepository   $clients   Client registry for validation.
     * @param AuthCodeRepository $authCodes Authorization code persistence.
     */
    public function __construct(
        private readonly ClientRepository   $clients,
        private readonly AuthCodeRepository $authCodes,
    ) {
    }

    /**
     * Validates the core parameters of an authorization request.
     *
     * Checks:
     *   - response_type must be 'code'
     *   - code_challenge_method must be 'S256' (plain is not accepted)
     *   - client_id must resolve to an active client
     *   - redirect_uri must be registered for the client (exact match)
     *
     * Returns an error descriptor on failure, null on success.
     *
     * @param string $responseType         Must be 'code'.
     * @param string $clientId             The requesting client.
     * @param string $redirectUri          The redirect URI from the request.
     * @param string $codeChallenge        The PKCE code challenge.
     * @param string $codeChallengeMethod  Must be 'S256'.
     * @return array{error: string, error_description: string}|null Null on success.
     */
    public function validateRequest(
        string $responseType,
        string $clientId,
        string $redirectUri,
        string $codeChallenge,
        string $codeChallengeMethod,
    ): ?array {
        if ($responseType !== 'code') {
            return [
                'error'             => 'unsupported_response_type',
                'error_description' => 'Only response_type=code is supported.',
            ];
        }

        if ($codeChallengeMethod !== 'S256') {
            return [
                'error'             => 'invalid_request',
                'error_description' => 'Only code_challenge_method=S256 is supported.',
            ];
        }

        if ($codeChallenge === '') {
            return [
                'error'             => 'invalid_request',
                'error_description' => 'code_challenge is required.',
            ];
        }

        $client = $this->clients->find($clientId);

        if ($client === null || (int) $client['is_active'] !== 1) {
            return [
                'error'             => 'invalid_client',
                'error_description' => 'Client not found or inactive.',
            ];
        }

        if (!$this->clients->validateRedirectUri($clientId, $redirectUri)) {
            return [
                'error'             => 'invalid_request',
                'error_description' => 'redirect_uri is not registered for this client.',
            ];
        }

        return null;
    }

    /**
     * Generates and persists an authorization code for an authenticated user.
     *
     * @param string   $clientId      The client initiating the flow.
     * @param string   $userId        UUID of the authenticated user.
     * @param string   $redirectUri   Validated redirect URI.
     * @param string   $codeChallenge PKCE challenge value.
     * @param string   $method        Challenge method (always 'S256').
     * @param string[] $scopes        Requested and validated scopes.
     * @return string                 The generated authorization code.
     *
     * @throws \Random\RandomException When the system PRNG fails.
     */
    public function generateCode(
        string $clientId,
        string $userId,
        string $redirectUri,
        string $codeChallenge,
        string $method,
        array $scopes,
    ): string {
        $code = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        $this->authCodes->create($code, $clientId, $userId, $redirectUri, $codeChallenge, $method, $scopes);

        return $code;
    }

    /**
     * Normalizes and filters a space-separated scope string.
     *
     * Unknown scopes are silently dropped. If the result is empty or 'openid'
     * is absent, 'openid' is prepended.
     *
     * @param string   $scopeString   Raw space-separated scope input.
     * @param string[] $allowedScopes Scopes the server supports (e.g. ['openid', 'profile', 'email']).
     * @return string[]               Deduplicated, validated scope list.
     */
    public function normalizeScopes(string $scopeString, array $allowedScopes): array
    {
        $requested = array_filter(explode(' ', $scopeString));
        $valid     = array_values(array_intersect($requested, $allowedScopes));

        if (!in_array('openid', $valid, true)) {
            array_unshift($valid, 'openid');
        }

        return array_values(array_unique($valid));
    }
}
