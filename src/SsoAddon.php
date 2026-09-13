<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso;

use AuthKit\Auth;
use PDO;
use Psr\Container\ContainerInterface;
use rafalmasiarek\DashboardKit\Flash;
use rafalmasiarek\DashboardKit\Middleware\AuthMiddleware;
use rafalmasiarek\DashboardKit\Middleware\CsrfMiddleware;
use rafalmasiarek\DashboardKit\Middleware\RoleMiddleware;
use rafalmasiarek\DashboardKitSso\Http\AuthorizeHandler;
use rafalmasiarek\DashboardKitSso\Http\DiscoveryHandler;
use rafalmasiarek\DashboardKitSso\Http\JwksHandler;
use rafalmasiarek\DashboardKitSso\Http\RevokeHandler;
use rafalmasiarek\DashboardKitSso\Http\TokenHandler;
use rafalmasiarek\DashboardKitSso\Http\UserInfoHandler;
use rafalmasiarek\DashboardKitSso\Keys\RsaKeyManager;
use rafalmasiarek\DashboardKitSso\Repository\AccessTokenRepository;
use rafalmasiarek\DashboardKitSso\Repository\AuthCodeRepository;
use rafalmasiarek\DashboardKitSso\Repository\ClientRepository;
use rafalmasiarek\DashboardKitSso\Repository\RefreshTokenRepository;
use rafalmasiarek\DashboardKitSso\Schema\SsoSchemaProvider;
use rafalmasiarek\DashboardKitSso\Service\AuthorizationService;
use rafalmasiarek\DashboardKitSso\Service\PkceValidator;
use rafalmasiarek\DashboardKitSso\Service\TokenService;
use Slim\App;
use Slim\Routing\RouteCollectorProxy;
use Twig\Loader\FilesystemLoader;

/**
 * Wires the OAuth2/OIDC SSO system into a dashboard-kit application.
 *
 * @package rafalmasiarek\DashboardKitSso
 */
final class SsoAddon
{
    /**
     * Registers the SSO addon into the Slim application.
     *
     * Must be called after Dashboard::create() has built the container and
     * registered the Twig view, since this method injects template paths into
     * the already-constructed FilesystemLoader.
     *
     * @param App                 $app       Slim application instance.
     * @param ContainerInterface  $container PHP-DI container from Dashboard::create().
     * @param array<string, mixed> $config   Addon configuration overrides.
     * @return void
     */
    public static function register(App $app, ContainerInterface $container, array $config = []): void
    {
        if (!\class_exists(\rafalmasiarek\DashboardKit\Dashboard::class)) {
            throw new \LogicException(
                static::class . ' is a dashboard-kit addon and requires rafalmasiarek/dashboard-kit. '
                . 'Run: composer require rafalmasiarek/dashboard-kit'
            );
        }

        $rootDir    = (string) $container->get('app.root_dir');
        $storageDir = (string) ($config['storage_dir'] ?? $rootDir . '/storage');
        $issuer     = rtrim((string) ($config['issuer'] ?? ''), '/');
        $accessTtl  = (int) ($config['access_ttl']  ?? 3600);
        $refreshTtl = (int) ($config['refresh_ttl'] ?? 2592000);

        // Ensure Auth has created the users table before SSO tries to reference it.
        $container->get(Auth::class);

        $pdo = $container->get(PDO::class);

        // Initialize schema.
        (new SsoSchemaProvider($pdo))->createSchema();

        // Wire repositories into container.
        $container->set(RsaKeyManager::class,           static fn()  => new RsaKeyManager($storageDir));
        $container->set(ClientRepository::class,        static fn()  => new ClientRepository($pdo));
        $container->set(AuthCodeRepository::class,      static fn()  => new AuthCodeRepository($pdo));
        $container->set(AccessTokenRepository::class,   static fn()  => new AccessTokenRepository($pdo));
        $container->set(RefreshTokenRepository::class,  static fn()  => new RefreshTokenRepository($pdo));

        $container->set(PkceValidator::class, static fn() => new PkceValidator());

        $container->set(AuthorizationService::class, static fn(ContainerInterface $c) =>
            new AuthorizationService(
                $c->get(ClientRepository::class),
                $c->get(AuthCodeRepository::class),
            )
        );

        $container->set(TokenService::class, static fn(ContainerInterface $c) =>
            new TokenService(
                $c->get(RsaKeyManager::class),
                $c->get(AccessTokenRepository::class),
                $c->get(RefreshTokenRepository::class),
                $issuer,
                $accessTtl,
                $refreshTtl,
            )
        );

        // Register Twig template namespaces into the already-built loader.
        $view   = $container->get('view');
        $env    = $view->getEnvironment();
        $loader = $env->getLoader();

        if ($loader instanceof FilesystemLoader) {
            $loader->addPath(__DIR__ . '/../templates/oauth',           'sso');
            $loader->addPath(__DIR__ . '/../modules/admin/sso/templates', 'sso-admin');
        }

        // Keep config-declared clients in sync with the current issuer on every boot.
        self::syncConfigClients($container->get(ClientRepository::class), (array) ($config['clients'] ?? []), $issuer);

        $dashboardPrefix = (string) ($container->get('dashboard.url_prefix'));

        // Register protocol routes (no auth — public OAuth2 endpoints).
        self::registerProtocolRoutes($app, $container, $dashboardPrefix, $issuer);

        // Register admin UI routes (admin role required).
        self::registerAdminRoutes($app, $container, $dashboardPrefix);
    }

    /**
     * Syncs config-declared OAuth2 clients into sso_clients on every boot.
     *
     * A redirect_uri starting with '/' is resolved relative to $issuer.
     *
     * @param ClientRepository                                                  $repo     Client repository.
     * @param array<int, array{client_id: string, name: string, redirect_uris: string[]}> $clients Config-declared clients.
     * @param string                                                             $issuer   Full issuer base URL (no trailing slash).
     * @return void
     */
    private static function syncConfigClients(ClientRepository $repo, array $clients, string $issuer): void
    {
        foreach ($clients as $client) {
            $clientId = (string) ($client['client_id'] ?? '');
            $name     = (string) ($client['name'] ?? $clientId);

            if ($clientId === '') {
                continue;
            }

            $redirectUris = array_map(
                static fn($uri) => str_starts_with((string) $uri, '/') ? $issuer . $uri : (string) $uri,
                (array) ($client['redirect_uris'] ?? []),
            );

            $repo->syncFromConfig($clientId, $name, $redirectUris);
        }
    }

    /**
     * Registers the public OAuth2 protocol routes.
     *
     * These routes are intentionally outside dashboard-kit's auth middleware
     * because the authorize endpoint handles its own session check internally.
     *
     * @param App                $app
     * @param ContainerInterface $container
     * @param string             $dashboardPrefix URL prefix (e.g. '' or '/app').
     * @param string             $issuer          Full issuer URL for the discovery document.
     * @return void
     */
    private static function registerProtocolRoutes(App $app, ContainerInterface $container, string $dashboardPrefix, string $issuer): void
    {
        $app->get('/.well-known/openid-configuration', function ($req, $res) use ($container) {
            return $container->get(DiscoveryHandler::class)->handle($req, $res);
        });

        $app->get('/oauth/jwks.json', function ($req, $res) use ($container) {
            return $container->get(JwksHandler::class)->handle($req, $res);
        });

        $app->get('/oauth/authorize', function ($req, $res) use ($container) {
            return $container->get(AuthorizeHandler::class)->handle($req, $res);
        });

        $app->post('/oauth/token', function ($req, $res) use ($container) {
            return $container->get(TokenHandler::class)->handle($req, $res);
        });

        $app->get('/oauth/userinfo', function ($req, $res) use ($container) {
            return $container->get(UserInfoHandler::class)->handle($req, $res);
        });

        $app->post('/oauth/revoke', function ($req, $res) use ($container) {
            return $container->get(RevokeHandler::class)->handle($req, $res);
        });

        // Lazy-wire handlers into container (after all dependencies are registered).
        $container->set(DiscoveryHandler::class, static fn(ContainerInterface $c) =>
            new DiscoveryHandler($issuer)
        );

        $container->set(JwksHandler::class, static fn(ContainerInterface $c) =>
            new JwksHandler($c->get(RsaKeyManager::class))
        );

        $container->set(AuthorizeHandler::class, static fn(ContainerInterface $c) =>
            new AuthorizeHandler(
                $c->get('view'),
                $c->get(Auth::class),
                $c->get(AuthorizationService::class),
                $dashboardPrefix,
            )
        );

        $container->set(TokenHandler::class, static fn(ContainerInterface $c) =>
            new TokenHandler(
                $c->get(AuthCodeRepository::class),
                $c->get(PkceValidator::class),
                $c->get(TokenService::class),
                $c->get(PDO::class),
            )
        );

        $container->set(UserInfoHandler::class, static fn(ContainerInterface $c) =>
            new UserInfoHandler(
                $c->get(TokenService::class),
                $c->get(AccessTokenRepository::class),
                $c->get(PDO::class),
            )
        );

        $container->set(RevokeHandler::class, static fn(ContainerInterface $c) =>
            new RevokeHandler(
                $c->get(TokenService::class),
                $c->get(AccessTokenRepository::class),
                $c->get(RefreshTokenRepository::class),
            )
        );
    }

    /**
     * Registers admin UI routes for SSO client and token management.
     *
     * All routes are protected by AuthMiddleware, CsrfMiddleware, and RoleMiddleware(['admin']).
     *
     * Routes:
     *   GET  /admin/sso/clients              — list clients
     *   POST /admin/sso/clients              — create client
     *   POST /admin/sso/clients/{id}/delete  — delete client
     *   GET  /admin/sso/tokens               — list active tokens
     *   POST /admin/sso/tokens/{jti}/revoke  — revoke token
     *
     * @param App                $app
     * @param ContainerInterface $container
     * @param string             $dashboardPrefix URL prefix.
     * @return void
     */
    private static function registerAdminRoutes(App $app, ContainerInterface $container, string $dashboardPrefix): void
    {
        $app->group('/admin/sso', function (RouteCollectorProxy $group) use ($container, $dashboardPrefix) {

            // --- Client management ---

            $group->get('/clients', function ($req, $res) use ($container) {
                /** @var ClientRepository $repo */
                $repo    = $container->get(ClientRepository::class);
                $clients = $repo->findAll();

                foreach ($clients as &$client) {
                    $client['redirect_uris_list'] = json_decode($client['redirect_uris'], true) ?? [];
                }
                unset($client);

                return $container->get('view')->render($res, '@sso-admin/clients/index.twig', [
                    'title'       => 'SSO Clients',
                    'breadcrumbs' => [['label' => 'SSO Clients']],
                    'clients'     => $clients,
                ]);
            });

            $group->get('/clients/create', function ($req, $res) use ($container) {
                return $container->get('view')->render($res, '@sso-admin/clients/create.twig', [
                    'title'       => 'New SSO Client',
                    'breadcrumbs' => [
                        ['label' => 'SSO Clients', 'url' => $container->get('dashboard.admin_panel_prefix') . '/sso/clients'],
                        ['label' => 'New Client'],
                    ],
                ]);
            });

            $group->post('/clients', function ($req, $res) use ($container, $dashboardPrefix) {
                $body            = (array) $req->getParsedBody();
                $name            = trim((string) ($body['name']            ?? ''));
                $redirectUrisRaw = trim((string) ($body['redirect_uris']   ?? ''));
                $generateSecret  = !empty($body['generate_secret']);

                $flash = $container->get(Flash::class);

                if ($name === '' || $redirectUrisRaw === '') {
                    $flash->add('danger', 'Name and at least one redirect URI are required.');
                    return $res->withHeader('Location', $dashboardPrefix . '/admin/sso/clients/create')->withStatus(302);
                }

                $redirectUris = array_values(array_filter(array_map('trim', explode("\n", $redirectUrisRaw))));

                if ($redirectUris === []) {
                    $flash->add('danger', 'At least one redirect URI is required.');
                    return $res->withHeader('Location', $dashboardPrefix . '/admin/sso/clients/create')->withStatus(302);
                }

                $clientId = bin2hex(random_bytes(12));
                $secret   = $generateSecret ? bin2hex(random_bytes(24)) : null;

                /** @var ClientRepository $repo */
                $repo = $container->get(ClientRepository::class);
                $repo->create($clientId, $secret, $name, $redirectUris);

                $message = "Client '{$name}' created. Client ID: {$clientId}";

                if ($secret !== null) {
                    $message .= " — Client Secret (shown once): {$secret}";
                }

                $flash->add('success', $message);

                return $res->withHeader('Location', $dashboardPrefix . '/admin/sso/clients')->withStatus(302);
            });

            $group->post('/clients/{clientId}/delete', function ($req, $res, $args) use ($container, $dashboardPrefix) {
                $clientId = (string) ($args['clientId'] ?? '');
                $flash    = $container->get(Flash::class);

                if ($clientId !== '') {
                    /** @var ClientRepository $repo */
                    $repo = $container->get(ClientRepository::class);
                    $repo->delete($clientId);
                    $flash->add('success', 'Client deleted.');
                } else {
                    $flash->add('danger', 'Invalid client ID.');
                }

                return $res->withHeader('Location', $dashboardPrefix . '/admin/sso/clients')->withStatus(302);
            });

            // --- Token management ---

            $group->get('/tokens', function ($req, $res) use ($container) {
                /** @var AccessTokenRepository $repo */
                $repo   = $container->get(AccessTokenRepository::class);
                $tokens = $repo->allActive();

                return $container->get('view')->render($res, '@sso-admin/tokens/index.twig', [
                    'title'       => 'Active SSO Tokens',
                    'breadcrumbs' => [['label' => 'SSO Tokens']],
                    'tokens'      => $tokens,
                ]);
            });

            $group->post('/tokens/{jti}/revoke', function ($req, $res, $args) use ($container, $dashboardPrefix) {
                $jti   = (string) ($args['jti'] ?? '');
                $flash = $container->get(Flash::class);

                if ($jti !== '') {
                    /** @var AccessTokenRepository $accessRepo */
                    $accessRepo = $container->get(AccessTokenRepository::class);
                    $accessRepo->revoke($jti);

                    /** @var RefreshTokenRepository $refreshRepo */
                    $refreshRepo = $container->get(RefreshTokenRepository::class);
                    $refreshRepo->revokeByJti($jti);

                    $flash->add('success', 'Token revoked.');
                } else {
                    $flash->add('danger', 'Invalid JTI.');
                }

                return $res->withHeader('Location', $dashboardPrefix . '/admin/sso/tokens')->withStatus(302);
            });

        })
        ->add(new RoleMiddleware($container, ['admin'], $dashboardPrefix))
        ->add(CsrfMiddleware::class)
        ->add(AuthMiddleware::class);
    }
}
