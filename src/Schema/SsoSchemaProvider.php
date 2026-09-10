<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Schema;

use PDO;

/**
 * Creates the database tables required by the SSO / OAuth2 system.
 *
 * Tables created:
 *   sso_clients        - registered OAuth2 clients.
 *   sso_auth_codes     - short-lived authorization codes for PKCE flow.
 *   sso_access_tokens  - issued JWT access tokens (tracked for revocation).
 *   sso_refresh_tokens - long-lived refresh tokens (stored as SHA-256 hashes).
 *
 * Called directly by SsoAddon::register() on every boot; all statements use IF NOT EXISTS.
 *
 * @package rafalmasiarek\DashboardKitSso\Schema
 */
final class SsoSchemaProvider
{
    /**
     * @param PDO $pdo Database connection used to determine driver and execute DDL.
     */
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Runs CREATE TABLE IF NOT EXISTS for all SSO tables.
     *
     * Detects driver via PDO::ATTR_DRIVER_NAME and delegates to the appropriate method.
     *
     * @return void
     */
    public function createSchema(): void
    {
        $driver = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);

        if ($driver === 'mysql') {
            $this->createMysql();
        } else {
            $this->createSqlite();
        }
    }

    /**
     * Creates all SSO tables for MySQL.
     *
     * @return void
     */
    private function createMysql(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS `sso_clients` (
                `client_id`          VARCHAR(64)   NOT NULL,
                `client_secret_hash` VARCHAR(255)  NULL,
                `name`               VARCHAR(255)  NOT NULL,
                `redirect_uris`      JSON          NOT NULL,
                `is_active`          TINYINT       NOT NULL DEFAULT 1,
                `created_at`         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (`client_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS `sso_auth_codes` (
                `code`                  VARCHAR(128)  NOT NULL,
                `client_id`             VARCHAR(64)   NOT NULL,
                `user_id`               CHAR(36)      NOT NULL,
                `redirect_uri`          VARCHAR(2048) NOT NULL,
                `code_challenge`        VARCHAR(128)  NOT NULL,
                `code_challenge_method` VARCHAR(10)   NOT NULL DEFAULT 'S256',
                `scopes`                JSON          NOT NULL,
                `expires_at`            DATETIME      NOT NULL,
                `used_at`               DATETIME      NULL,
                PRIMARY KEY (`code`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS `sso_access_tokens` (
                `jti`        VARCHAR(64) NOT NULL,
                `client_id`  VARCHAR(64) NOT NULL,
                `user_id`    CHAR(36)    NOT NULL,
                `scopes`     JSON        NOT NULL,
                `expires_at` DATETIME    NOT NULL,
                `revoked_at` DATETIME    NULL,
                PRIMARY KEY (`jti`),
                INDEX `idx_sso_at_user_id` (`user_id`),
                INDEX `idx_sso_at_expires_at` (`expires_at`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS `sso_refresh_tokens` (
                `token_hash` VARCHAR(64) NOT NULL,
                `jti`        VARCHAR(64) NOT NULL,
                `client_id`  VARCHAR(64) NOT NULL,
                `user_id`    CHAR(36)    NOT NULL,
                `scopes`     JSON        NOT NULL,
                `expires_at` DATETIME    NOT NULL,
                `revoked_at` DATETIME    NULL,
                PRIMARY KEY (`token_hash`),
                INDEX `idx_sso_rt_jti` (`jti`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ");
    }

    /**
     * Creates all SSO tables for SQLite.
     *
     * @return void
     */
    private function createSqlite(): void
    {
        $this->pdo->exec('PRAGMA foreign_keys = ON');

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS sso_clients (
                client_id          TEXT    NOT NULL PRIMARY KEY,
                client_secret_hash TEXT    NULL,
                name               TEXT    NOT NULL,
                redirect_uris      TEXT    NOT NULL,
                is_active          INTEGER NOT NULL DEFAULT 1,
                created_at         TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS sso_auth_codes (
                code                  TEXT NOT NULL PRIMARY KEY,
                client_id             TEXT NOT NULL,
                user_id               TEXT NOT NULL,
                redirect_uri          TEXT NOT NULL,
                code_challenge        TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL DEFAULT 'S256',
                scopes                TEXT NOT NULL,
                expires_at            TEXT NOT NULL,
                used_at               TEXT NULL
            )
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS sso_access_tokens (
                jti        TEXT NOT NULL PRIMARY KEY,
                client_id  TEXT NOT NULL,
                user_id    TEXT NOT NULL,
                scopes     TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT NULL
            )
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS sso_refresh_tokens (
                token_hash TEXT NOT NULL PRIMARY KEY,
                jti        TEXT NOT NULL,
                client_id  TEXT NOT NULL,
                user_id    TEXT NOT NULL,
                scopes     TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT NULL
            )
        ");
    }
}
