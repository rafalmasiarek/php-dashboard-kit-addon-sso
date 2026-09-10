<?php

declare(strict_types=1);

/**
 * Admin module definition for the SSO plugin.
 *
 * Registers the SSO section in the admin sidebar with links to client management
 * and token listings. Routes are handled directly by SsoAddon::registerAdminRoutes().
 */
return [
    'slug'        => 'sso',
    'title'       => 'SSO',
    'icon'        => '🔑',
    'description' => 'OAuth2/OIDC client and token management.',
    'order'       => 80,
    'path'        => '/admin/sso/clients',
    '_templates_dir' => __DIR__ . '/templates',
];
