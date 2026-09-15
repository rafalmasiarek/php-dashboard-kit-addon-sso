<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Http;

use AuthKit\Auth;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use rafalmasiarek\DashboardKitSso\Service\AuthorizationService;
use Slim\Views\Twig;

/**
 * Handles the OAuth2 authorization endpoint.
 *
 * Validates incoming authorization requests, checks session state, and either
 * redirects unauthenticated users to the login page (storing pending params in
 * session) or issues an authorization code and redirects back to the client.
 *
 * Errors that cannot be redirected (invalid client_id, unregistered redirect_uri)
 * are rendered via the oauth/error.twig template to prevent open-redirect attacks.
 *
 * @package rafalmasiarek\DashboardKitSso\Http
 */
final class AuthorizeHandler
{
    /**
     * Supported OIDC scopes. Requests containing unknown scopes have them silently stripped.
     *
     * @var string[]
     */
    private const ALLOWED_SCOPES = ['openid', 'profile', 'email'];

    /**
     * @param Twig                 $view             Twig renderer for error and consent pages.
     * @param Auth                 $auth             AuthKit authentication service.
     * @param AuthorizationService $authService      Authorization flow orchestrator.
     * @param string               $dashboardPrefix  URL prefix prepended to /login redirect (e.g. '').
     */
    public function __construct(
        private readonly Twig                 $view,
        private readonly Auth                 $auth,
        private readonly AuthorizationService $authService,
        private readonly string               $dashboardPrefix = '',
    ) {
    }

    /**
     * Handles GET /oauth/authorize.
     *
     * Flow:
     *   1. Extract and validate query parameters.
     *   2. Validate client_id and redirect_uri before any redirect (security boundary).
     *   3. If user is not authenticated, store pending params in session and redirect to /login?from=...
     *   4. If user is authenticated, issue an authorization code and redirect to redirect_uri.
     *
     * @param Request  $request  Incoming PSR-7 request.
     * @param Response $response PSR-7 response.
     * @return Response
     */
    public function handle(Request $request, Response $response): Response
    {
        $params = $request->getQueryParams();

        $responseType        = (string) ($params['response_type']         ?? '');
        $clientId            = (string) ($params['client_id']             ?? '');
        $redirectUri         = (string) ($params['redirect_uri']          ?? '');
        $codeChallenge       = (string) ($params['code_challenge']        ?? '');
        $codeChallengeMethod = (string) ($params['code_challenge_method'] ?? 'S256');
        $scopeString         = (string) ($params['scope']                 ?? 'openid');
        $state               = (string) ($params['state']                 ?? '');

        // Validate before any redirect — redirect_uri must be trusted.
        $error = $this->authService->validateRequest(
            $responseType,
            $clientId,
            $redirectUri,
            $codeChallenge,
            $codeChallengeMethod,
        );

        if ($error !== null) {
            return $this->view->render($response->withStatus(400), '@sso/error.twig', [
                'title'             => 'Authorization Error',
                'error'             => $error['error'],
                'error_description' => $error['error_description'],
            ]);
        }

        if (!$this->auth->isLoggedIn()) {
            // Store pending OAuth params in session so they survive the login redirect.
            $_SESSION['sso_pending'] = [
                'response_type'         => $responseType,
                'client_id'             => $clientId,
                'redirect_uri'          => $redirectUri,
                'code_challenge'        => $codeChallenge,
                'code_challenge_method' => $codeChallengeMethod,
                'scope'                 => $scopeString,
                'state'                 => $state,
            ];

            $loginUrl = $this->dashboardPrefix . '/login?from=' . urlencode($this->dashboardPrefix . '/oauth/authorize?' . http_build_query($params));

            return $response->withHeader('Location', $loginUrl)->withStatus(302);
        }

        // Clear any leftover pending params now that the user is logged in.
        unset($_SESSION['sso_pending']);

        $user   = $this->auth->getUser();
        $userId = (string) $user->get('id');
        $scopes = $this->authService->normalizeScopes($scopeString, self::ALLOWED_SCOPES);

        $code = $this->authService->generateCode(
            $clientId,
            $userId,
            $redirectUri,
            $codeChallenge,
            $codeChallengeMethod,
            $scopes,
        );

        $callbackParams = ['code' => $code];

        if ($state !== '') {
            $callbackParams['state'] = $state;
        }

        $callbackUrl = $redirectUri . (str_contains($redirectUri, '?') ? '&' : '?') . http_build_query($callbackParams);

        return $response->withHeader('Location', $callbackUrl)->withStatus(302);
    }
}
