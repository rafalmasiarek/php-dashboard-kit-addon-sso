<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Service;

/**
 * Validates PKCE (Proof Key for Code Exchange) code verifiers against stored challenges.
 *
 * Supports the S256 method (RECOMMENDED, RFC 7636) and the plain method (fallback).
 * S256 transforms the verifier as: BASE64URL(SHA256(ASCII(code_verifier))).
 *
 * @package rafalmasiarek\DashboardKitSso\Service
 */
final class PkceValidator
{
    /**
     * Validates a code_verifier against a previously stored code_challenge.
     *
     * For S256: computes base64url(sha256(codeVerifier)) and compares to codeChallenge.
     * For plain: compares codeVerifier directly to codeChallenge.
     *
     * @param string $codeVerifier   The verifier supplied in the token request (43-128 chars, A-Z a-z 0-9 - . _ ~).
     * @param string $codeChallenge  The challenge stored with the authorization code.
     * @param string $method         Challenge method: 'S256' or 'plain'.
     * @return bool                  True when the verifier satisfies the challenge.
     */
    public function validate(string $codeVerifier, string $codeChallenge, string $method): bool
    {
        if ($method === 'S256') {
            $derived = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
            return hash_equals($codeChallenge, $derived);
        }

        // plain — constant-time comparison to prevent timing attacks.
        return hash_equals($codeChallenge, $codeVerifier);
    }
}
