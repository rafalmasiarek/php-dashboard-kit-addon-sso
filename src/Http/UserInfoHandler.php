<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use rafalmasiarek\DashboardKitSso\Repository\AccessTokenRepository;
use rafalmasiarek\DashboardKitSso\Service\TokenService;

/**
 * Handles the OIDC UserInfo endpoint (GET /oauth/userinfo).
 *
 * Accepts a Bearer access token in the Authorization header, verifies the JWT
 * signature, checks for revocation in the database, then re-fetches the user
 * from the users table to return always-current claims (not cached JWT values).
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class UserInfoHandler
{
    /**
     * @param TokenService          $tokenService  JWT decoder using the RSA public key.
     * @param AccessTokenRepository $accessTokens  Revocation check store.
     * @param PDO                   $pdo           Database connection for live user fetch.
     */
    public function __construct(
        private readonly TokenService          $tokenService,
        private readonly AccessTokenRepository $accessTokens,
        private readonly PDO                   $pdo,
    ) {
    }

    /**
     * Handles GET /oauth/userinfo.
     *
     * Validates the Bearer token, checks revocation, fetches the user and returns
     * a JSON object with the claims authorized by the token's scopes.
     *
     * @param Request  $request  Incoming PSR-7 request.
     * @param Response $response PSR-7 response.
     * @return Response JSON user claims or a 401/403 error.
     */
    public function handle(Request $request, Response $response): Response
    {
        $authorization = $request->getHeaderLine('Authorization');

        if (!str_starts_with($authorization, 'Bearer ')) {
            return $this->errorResponse($response, 401, 'invalid_token', 'Bearer token is required.');
        }

        $token   = substr($authorization, 7);
        $payload = $this->tokenService->decode($token);

        if ($payload === null) {
            return $this->errorResponse($response, 401, 'invalid_token', 'Token is invalid or expired.');
        }

        $jti = (string) ($payload['jti'] ?? '');

        if ($jti === '') {
            return $this->errorResponse($response, 401, 'invalid_token', 'Token is missing JTI claim.');
        }

        $record = $this->accessTokens->find($jti);

        if ($record === null || $record['revoked_at'] !== null) {
            return $this->errorResponse($response, 401, 'invalid_token', 'Token has been revoked.');
        }

        $userId = (string) ($payload['sub'] ?? '');
        $stmt   = $this->pdo->prepare(
            'SELECT id, email, role, first_name, last_name FROM users WHERE id = ? AND active = 1'
        );
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user === false) {
            return $this->errorResponse($response, 403, 'access_denied', 'User not found or inactive.');
        }

        $scopes = json_decode($record['scopes'], true);
        $scopes = is_array($scopes) ? $scopes : [];

        $claims = [
            'sub'   => $user['id'],
            'email' => $user['email'],
            'role'  => $user['role'] ?? 'user',
        ];

        if (in_array('profile', $scopes, true)) {
            $firstName = $user['first_name'] ?? null;
            $lastName  = $user['last_name'] ?? null;
            $name      = trim(($firstName ?? '') . ' ' . ($lastName ?? ''));

            if ($name !== '') {
                $claims['name'] = $name;
            }
        }

        return $this->jsonResponse($response, $claims, 200);
    }

    /**
     * Writes a JSON error response with WWW-Authenticate header.
     *
     * @param Response $response    PSR-7 response.
     * @param int      $status      HTTP status code.
     * @param string   $error       OAuth2 error code.
     * @param string   $description Human-readable error description.
     * @return Response
     */
    private function errorResponse(Response $response, int $status, string $error, string $description): Response
    {
        return $this->jsonResponse($response, [
            'error'             => $error,
            'error_description' => $description,
        ], $status)->withHeader('WWW-Authenticate', 'Bearer error="' . $error . '"');
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
        $json = json_encode($data, JSON_UNESCAPED_UNICODE);
        $response->getBody()->write((string) $json);

        return $response
            ->withStatus($status)
            ->withHeader('Content-Type', 'application/json; charset=utf-8');
    }
}
