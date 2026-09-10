<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Serves the OpenID Connect discovery document.
 *
 * Responds to GET /.well-known/openid-configuration with a JSON object
 * describing the issuer's supported endpoints, algorithms, and capabilities.
 * This is the entry point for OIDC-compliant clients that auto-discover endpoints.
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class DiscoveryHandler
{
    /**
     * @param string $issuer Base URL of the authorization server (no trailing slash).
     */
    public function __construct(private readonly string $issuer)
    {
    }

    /**
     * Handles GET /.well-known/openid-configuration.
     *
     * @param Request  $request  Incoming PSR-7 request (unused; only GET is expected).
     * @param Response $response PSR-7 response to write the discovery document into.
     * @return Response JSON response with Content-Type application/json.
     */
    public function handle(Request $request, Response $response): Response
    {
        $issuer = rtrim($this->issuer, '/');

        $document = [
            'issuer'                                => $issuer,
            'authorization_endpoint'                => $issuer . '/oauth/authorize',
            'token_endpoint'                        => $issuer . '/oauth/token',
            'userinfo_endpoint'                     => $issuer . '/oauth/userinfo',
            'jwks_uri'                              => $issuer . '/oauth/jwks.json',
            'revocation_endpoint'                   => $issuer . '/oauth/revoke',
            'response_types_supported'              => ['code'],
            'grant_types_supported'                 => ['authorization_code', 'refresh_token'],
            'subject_types_supported'               => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported'                      => ['openid', 'profile', 'email'],
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_post'],
            'code_challenge_methods_supported'      => ['S256'],
        ];

        $json = json_encode($document, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);

        $response->getBody()->write((string) $json);

        return $response
            ->withHeader('Content-Type', 'application/json; charset=utf-8')
            ->withHeader('Cache-Control', 'public, max-age=3600');
    }
}
