<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use rafalmasiarek\DashboardKitSso\Repository\AccessTokenRepository;
use rafalmasiarek\DashboardKitSso\Repository\RefreshTokenRepository;
use rafalmasiarek\DashboardKitSso\Service\TokenService;

/**
 * Handles the OAuth2 token revocation endpoint (POST /oauth/revoke).
 *
 * Implements RFC 7009: always returns 200 regardless of whether the token
 * was found, to prevent probing for valid tokens. Supports access_token and
 * refresh_token hints. When the hint is absent or ambiguous, tries both.
 *
 * When a refresh token is revoked, the associated access token JTI is also
 * invalidated. When an access token is revoked, any refresh tokens sharing
 * its JTI are also revoked.
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class RevokeHandler
{
    /**
     * @param TokenService          $tokenService  JWT decoder for access token JTI extraction.
     * @param AccessTokenRepository $accessTokens  Access token revocation store.
     * @param RefreshTokenRepository $refreshTokens Refresh token revocation store.
     */
    public function __construct(
        private readonly TokenService           $tokenService,
        private readonly AccessTokenRepository  $accessTokens,
        private readonly RefreshTokenRepository $refreshTokens,
    ) {
    }

    /**
     * Handles POST /oauth/revoke.
     *
     * Per RFC 7009 the server MUST return 200 even when the token is unknown or
     * already revoked — the goal is idempotent invalidation, not error reporting.
     *
     * @param Request  $request  Incoming PSR-7 request with form-encoded body.
     * @param Response $response PSR-7 response.
     * @return Response HTTP 200 with empty body.
     */
    public function handle(Request $request, Response $response): Response
    {
        $body      = (array) ($request->getParsedBody() ?? []);
        $token     = (string) ($body['token']            ?? '');
        $typeHint  = (string) ($body['token_type_hint']  ?? '');

        if ($token !== '') {
            $this->revoke($token, $typeHint);
        }

        return $response->withStatus(200)->withHeader('Content-Type', 'application/json; charset=utf-8');
    }

    /**
     * Attempts to revoke the token, trying the hinted type first.
     *
     * If the hint is 'refresh_token', tries refresh revocation then falls back
     * to access token revocation. If the hint is 'access_token' or absent,
     * tries access token revocation then falls back to refresh token revocation.
     *
     * @param string $token    The opaque or JWT token to revoke.
     * @param string $typeHint 'access_token', 'refresh_token', or '' for auto-detect.
     * @return void
     */
    private function revoke(string $token, string $typeHint): void
    {
        if ($typeHint === 'refresh_token') {
            $this->revokeRefreshToken($token);
            return;
        }

        // Try access token (JWT decode to get JTI).
        if ($this->revokeAccessToken($token)) {
            return;
        }

        // Fall back to refresh token.
        $this->revokeRefreshToken($token);
    }

    /**
     * Decodes the JWT to extract the JTI and revokes the access token record.
     *
     * Also revokes any refresh tokens linked to the same JTI.
     *
     * @param string $token Encoded JWT access token.
     * @return bool True when a revocable access token was found.
     */
    private function revokeAccessToken(string $token): bool
    {
        $payload = $this->tokenService->decode($token);

        if ($payload === null) {
            return false;
        }

        $jti = (string) ($payload['jti'] ?? '');

        if ($jti === '') {
            return false;
        }

        $this->accessTokens->revoke($jti);
        $this->refreshTokens->revokeByJti($jti);

        return true;
    }

    /**
     * Hashes the token and revokes the matching refresh token record.
     *
     * Also revokes the linked access token JTI when the refresh token is found.
     *
     * @param string $token Plain-text refresh token.
     * @return void
     */
    private function revokeRefreshToken(string $token): void
    {
        $row = $this->refreshTokens->consume($token);

        if ($row !== null) {
            $this->accessTokens->revoke($row['jti']);
        }
    }
}
