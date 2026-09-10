<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use rafalmasiarek\DashboardKitSso\Keys\RsaKeyManager;

/**
 * Serves the JSON Web Key Set (JWKS) document.
 *
 * Responds to GET /oauth/jwks.json with the public RSA key in JWK format.
 * External clients and resource servers fetch this endpoint to verify JWT
 * signatures without sharing a secret — no direct coordination needed.
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class JwksHandler
{
    /**
     * @param RsaKeyManager $keyManager RSA key manager that provides the public key in JWK format.
     */
    public function __construct(private readonly RsaKeyManager $keyManager)
    {
    }

    /**
     * Handles GET /oauth/jwks.json.
     *
     * @param Request  $request  Incoming PSR-7 request (unused).
     * @param Response $response PSR-7 response to write the JWKS into.
     * @return Response JSON response with Content-Type application/json.
     */
    public function handle(Request $request, Response $response): Response
    {
        $jwks = $this->keyManager->getJwks();
        $json = json_encode($jwks, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        $response->getBody()->write((string) $json);

        return $response
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('Cache-Control', 'public, max-age=86400');
    }
}
