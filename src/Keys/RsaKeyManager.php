<?php

declare(strict_types=1);

namespace rafalmasiarek\DashboardKitSso\Keys;

use RuntimeException;

/**
 * Manages the RSA-2048 key pair used for JWT signing and JWKS publication.
 *
 * Generates the key pair on first use and persists the private key as a PEM
 * file under {storageDir}/sso/private.pem. Subsequent calls load from file.
 * The directory and file are created with mode 0700/0600 respectively.
 *
 * @package rafalmasiarek\DashboardKitSso\Keys
 */
final class RsaKeyManager
{
    /**
     * Absolute path to the private key PEM file.
     *
     * @var string
     */
    private string $privateKeyPath;

    /**
     * In-memory cached private key resource.
     *
     * @var \OpenSSLAsymmetricKey|null
     */
    private ?\OpenSSLAsymmetricKey $privateKey = null;

    /**
     * In-memory cached public key resource.
     *
     * @var \OpenSSLAsymmetricKey|null
     */
    private ?\OpenSSLAsymmetricKey $publicKey = null;

    /**
     * @param string $storageDir Absolute path to the application storage root.
     */
    public function __construct(string $storageDir)
    {
        $this->privateKeyPath = rtrim($storageDir, '/') . '/sso/private.pem';
    }

    /**
     * Returns the private key resource for JWT signing.
     *
     * Generates and persists the key pair on first call if the PEM file does not exist.
     *
     * @return \OpenSSLAsymmetricKey
     *
     * @throws RuntimeException When the key cannot be generated or loaded.
     */
    public function getPrivateKey(): \OpenSSLAsymmetricKey
    {
        if ($this->privateKey === null) {
            $this->ensureKey();
        }

        return $this->privateKey;
    }

    /**
     * Returns the public key resource for JWT verification and JWKS extraction.
     *
     * @return \OpenSSLAsymmetricKey
     *
     * @throws RuntimeException When the public key cannot be derived.
     */
    public function getPublicKey(): \OpenSSLAsymmetricKey
    {
        if ($this->publicKey === null) {
            $this->ensureKey();
        }

        return $this->publicKey;
    }

    /**
     * Returns the JWK Set (JWKS) representation of the public key.
     *
     * The returned array is ready to be JSON-encoded and served at /oauth/jwks.json.
     * The RSA modulus (n) and exponent (e) are base64url-encoded without padding.
     *
     * @return array{keys: array<int, array{kty: string, use: string, alg: string, kid: string, n: string, e: string}>}
     *
     * @throws RuntimeException When key details cannot be extracted.
     */
    public function getJwks(): array
    {
        $this->ensureKey();

        $details = openssl_pkey_get_details($this->publicKey);

        if ($details === false || !isset($details['rsa'])) {
            throw new RuntimeException('Failed to extract RSA key details for JWKS.');
        }

        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => '1',
                    'n'   => $this->base64url($details['rsa']['n']),
                    'e'   => $this->base64url($details['rsa']['e']),
                ],
            ],
        ];
    }

    /**
     * Generates the RSA-2048 key pair and writes the private key PEM to disk.
     *
     * Creates the storage directory with mode 0700 if it does not exist.
     * The PEM file is written with mode 0600.
     *
     * @return void
     *
     * @throws RuntimeException When key generation or file write fails.
     */
    private function generate(): void
    {
        $dir = dirname($this->privateKeyPath);

        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException(sprintf('Cannot create SSO key directory: %s', $dir));
        }

        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new RuntimeException('Failed to generate RSA key pair: ' . openssl_error_string());
        }

        openssl_pkey_export($resource, $pem);

        if (file_put_contents($this->privateKeyPath, $pem) === false) {
            throw new RuntimeException(sprintf('Failed to write private key to %s', $this->privateKeyPath));
        }

        chmod($this->privateKeyPath, 0600);

        $this->privateKey = $resource;
        $this->publicKey  = openssl_pkey_get_details($resource)['key']
            ? openssl_pkey_get_public(openssl_pkey_get_details($resource)['key'])
            : throw new RuntimeException('Failed to derive public key after generation.');
    }

    /**
     * Loads the private key from the PEM file on disk.
     *
     * @return void
     *
     * @throws RuntimeException When the file cannot be read or parsed.
     */
    private function load(): void
    {
        $pem = file_get_contents($this->privateKeyPath);

        if ($pem === false) {
            throw new RuntimeException(sprintf('Cannot read private key from %s', $this->privateKeyPath));
        }

        $resource = openssl_pkey_get_private($pem);

        if ($resource === false) {
            throw new RuntimeException('Failed to parse private key PEM: ' . openssl_error_string());
        }

        $this->privateKey = $resource;

        $details = openssl_pkey_get_details($resource);

        if ($details === false) {
            throw new RuntimeException('Failed to get public key from loaded private key.');
        }

        $pub = openssl_pkey_get_public($details['key']);

        if ($pub === false) {
            throw new RuntimeException('Failed to parse public key PEM.');
        }

        $this->publicKey = $pub;
    }

    /**
     * Ensures the key pair is available, generating it if the PEM file is missing.
     *
     * @return void
     */
    private function ensureKey(): void
    {
        if ($this->privateKey !== null) {
            return;
        }

        if (file_exists($this->privateKeyPath)) {
            $this->load();
        } else {
            $this->generate();
        }
    }

    /**
     * Encodes binary data as base64url without padding.
     *
     * @param string $data Raw binary string.
     * @return string      URL-safe base64 without trailing '=' characters.
     */
    private function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
