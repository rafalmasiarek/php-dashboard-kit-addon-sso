<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use rafalmasiarek\DashboardKitSso\Repository\AuthCodeRepository;
use rafalmasiarek\DashboardKitSso\Service\PkceValidator;
use rafalmasiarek\DashboardKitSso\Service\TokenService;

/**
 * Handles the OAuth2 token endpoint (POST /oauth/token).
 *
 * Supports two grant types:
 *   authorization_code — exchanges a code + PKCE verifier for a token pair.
 *   refresh_token      — rotates a refresh token for a new pair.
 *
 * All error responses follow RFC 6749 Section 5.2:
 *   {"error": "...", "error_description": "..."}
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class TokenHandler
{
    /**
     * @param AuthCodeRepository $authCodes    Authorization code store.
     * @param PkceValidator      $pkce         PKCE code verifier validator.
     * @param TokenService       $tokenService Issues and refreshes JWT token pairs.
     * @param PDO                $pdo          Database connection for user lookup.
     */
    public function __construct(
        private readonly AuthCodeRepository $authCodes,
        private readonly PkceValidator      $pkce,
        private readonly TokenService       $tokenService,
        private readonly PDO                $pdo,
    ) {
    }

    /**
     * Handles POST /oauth/token.
     *
     * Reads application/x-www-form-urlencoded body, dispatches to the appropriate
     * grant handler, and returns a JSON token response or error.
     *
     * @param Request  $request  Incoming PSR-7 request.
     * @param Response $response PSR-7 response.
     * @return Response JSON response.
     */
    public function handle(Request $request, Response $response): Response
    {
        $body      = (array) ($request->getParsedBody() ?? []);
        $grantType = (string) ($body['grant_type'] ?? '');

        return match ($grantType) {
            'authorization_code' => $this->handleAuthorizationCode($body, $response),
            'refresh_token'      => $this->handleRefreshToken($body, $response),
            default              => $this->errorResponse($response, 'unsupported_grant_type', 'Unsupported grant_type.', 400),
        };
    }

    /**
     * Processes the authorization_code grant.
     *
     * Validates: code existence, PKCE verifier, redirect_uri match, client_id match, user active status.
     * On success: fetches the user row and issues a token pair.
     *
     * @param array<string, mixed> $body     Parsed form body.
     * @param Response             $response PSR-7 response.
     * @return Response
     */
    private function handleAuthorizationCode(array $body, Response $response): Response
    {
        $code         = (string) ($body['code']          ?? '');
        $clientId     = (string) ($body['client_id']     ?? '');
        $redirectUri  = (string) ($body['redirect_uri']  ?? '');
        $codeVerifier = (string) ($body['code_verifier'] ?? '');

        if ($code === '' || $clientId === '' || $redirectUri === '' || $codeVerifier === '') {
            return $this->errorResponse($response, 'invalid_request', 'Missing required parameters.', 400);
        }

        $authCode = $this->authCodes->consume($code);

        if ($authCode === null) {
            return $this->errorResponse($response, 'invalid_grant', 'Authorization code is invalid, expired, or already used.', 400);
        }

        if ($authCode['client_id'] !== $clientId) {
            return $this->errorResponse($response, 'invalid_grant', 'client_id does not match.', 400);
        }

        if ($authCode['redirect_uri'] !== $redirectUri) {
            return $this->errorResponse($response, 'invalid_grant', 'redirect_uri does not match.', 400);
        }

        if (!$this->pkce->validate($codeVerifier, $authCode['code_challenge'], $authCode['code_challenge_method'])) {
            return $this->errorResponse($response, 'invalid_grant', 'code_verifier is invalid.', 400);
        }

        $user = $this->fetchUser($authCode['user_id']);

        if ($user === null) {
            return $this->errorResponse($response, 'invalid_grant', 'User not found.', 400);
        }

        if ((int) $user['active'] !== 1) {
            return $this->errorResponse($response, 'invalid_grant', 'User account is inactive.', 400);
        }

        $scopes = json_decode($authCode['scopes'], true);
        $scopes = is_array($scopes) ? $scopes : ['openid'];

        $tokenPair = $this->tokenService->issueTokenPair(
            $clientId,
            $user['id'],
            $user['email'],
            $user['role'] ?? 'user',
            null,
            null,
            $scopes,
        );

        return $this->jsonResponse($response, $tokenPair, 200);
    }

    /**
     * Processes the refresh_token grant.
     *
     * Consumes the refresh token via TokenService::refresh(), re-fetches the user
     * to ensure current email and role values are used (never trust stale JWT claims).
     *
     * @param array<string, mixed> $body     Parsed form body.
     * @param Response             $response PSR-7 response.
     * @return Response
     */
    private function handleRefreshToken(array $body, Response $response): Response
    {
        $refreshToken = (string) ($body['refresh_token'] ?? '');
        $clientId     = (string) ($body['client_id']     ?? '');

        if ($refreshToken === '' || $clientId === '') {
            return $this->errorResponse($response, 'invalid_request', 'Missing refresh_token or client_id.', 400);
        }

        // Peek at the stored refresh token record to get user_id before consuming.
        $hash = hash('sha256', $refreshToken);
        $stmt = $this->pdo->prepare(
            'SELECT user_id FROM sso_refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL'
        );
        $stmt->execute([$hash]);
        $rtRow = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($rtRow === false) {
            return $this->errorResponse($response, 'invalid_grant', 'Refresh token is invalid or expired.', 400);
        }

        $user = $this->fetchUser((string) $rtRow['user_id']);

        if ($user === null || (int) $user['active'] !== 1) {
            return $this->errorResponse($response, 'invalid_grant', 'User not found or inactive.', 400);
        }

        $tokenPair = $this->tokenService->refresh(
            $refreshToken,
            $clientId,
            $user['email'],
            $user['role'] ?? 'user',
            null,
            null,
        );

        if ($tokenPair === null) {
            return $this->errorResponse($response, 'invalid_grant', 'Refresh token is invalid, expired, or client mismatch.', 400);
        }

        return $this->jsonResponse($response, $tokenPair, 200);
    }

    /**
     * Fetches a user row by ID.
     *
     * @param string $userId UUID of the user.
     * @return array{id: string, email: string, role: string, active: int}|null
     */
    private function fetchUser(string $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, email, role, active FROM users WHERE id = ?'
        );
        $stmt->execute([$userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row !== false ? $row : null;
    }

    /**
     * Writes a JSON error response following RFC 6749 Section 5.2.
     *
     * @param Response $response         PSR-7 response.
     * @param string   $error            RFC 6749 error code.
     * @param string   $errorDescription Human-readable description.
     * @param int      $status           HTTP status code (400 or 401).
     * @return Response
     */
    private function errorResponse(Response $response, string $error, string $errorDescription, int $status): Response
    {
        return $this->jsonResponse($response, [
            'error'             => $error,
            'error_description' => $errorDescription,
        ], $status);
    }

    /**
     * Encodes $data as JSON and writes it to the response body.
     *
     * @param Response             $response PSR-7 response.
     * @param array<string, mixed> $data     Data to encode.
     * @param int                  $status   HTTP status code.
     * @return Response
     */
    private function jsonResponse(Response $response, array $data, int $status): Response
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $response->getBody()->write((string) $json);

        return $response
            ->withStatus($status)
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
