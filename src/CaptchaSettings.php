<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha;

use Nolviko\Core\Config\Config;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * The CAPTCHA settings (2026-11-26) in one JSON file in the extension's private storage directory. The secret key
 * is sealed with a key derived from the site secret (like the Google sign-in extension) and never shown again; an
 * empty secret field keeps the stored one.
 */
final class CaptchaSettings
{
    public const MODES = ['replace', 'add'];

    private const FILE = '/settings.json';

    private const PREFIX = 'v1.';

    public function __construct(private readonly string $directory, private readonly ?Config $config)
    {
    }

    /**
     * @return array{provider: string, site_key: string, mode: string, threshold: float, sealed: string}
     */
    public function data(): array
    {
        try {
            $raw = is_file($this->directory . self::FILE) ? file_get_contents($this->directory . self::FILE) : false;
            $data = is_string($raw) ? json_decode($raw, true, 4) : [];
        } catch (Throwable) {
            $data = [];
        }
        $data = is_array($data) ? $data : [];
        $provider = is_string($data['provider'] ?? null) && CaptchaProviders::exists($data['provider'])
            ? $data['provider'] : '';

        return [
            'provider' => $provider,
            'site_key' => is_string($data['site_key'] ?? null) ? $data['site_key'] : '',
            'mode' => in_array($data['mode'] ?? null, self::MODES, true) ? $data['mode'] : 'replace',
            'threshold' => is_float($data['threshold'] ?? null) || is_int($data['threshold'] ?? null)
                ? max(0.1, min(0.9, (float) $data['threshold'])) : 0.5,
            'sealed' => is_string($data['secret'] ?? null) ? $data['secret'] : '',
        ];
    }

    /** True when a provider, a site key and a readable secret are set. */
    public function ready(): bool
    {
        $data = $this->data();

        return $data['provider'] !== '' && $data['site_key'] !== '' && $this->secret() !== null;
    }

    public function secret(): ?string
    {
        try {
            return $this->open($this->data()['sealed']);
        } catch (Throwable) {
            return null;
        }
    }

    /** @param string|null $secret Null keeps the stored secret. */
    public function save(
        string $provider,
        string $siteKey,
        #[SensitiveParameter] ?string $secret,
        string $mode,
        float $threshold,
    ): void {
        $current = $this->data();
        $json = json_encode([
            'provider' => $provider,
            'site_key' => $siteKey,
            'secret' => $secret === null ? $current['sealed'] : $this->seal($secret),
            'mode' => $mode,
            'threshold' => round($threshold, 2),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $temporary = $this->directory . '/.settings-' . bin2hex(random_bytes(6)) . '.json';
        if (
            file_put_contents($temporary, $json, LOCK_EX) === false
            || !rename($temporary, $this->directory . self::FILE)
        ) {
            @unlink($temporary);
            throw new RuntimeException('nolviko_captcha_settings_unwritable');
        }
        @chmod($this->directory . self::FILE, 0600);
    }

    public function clear(): void
    {
        @unlink($this->directory . self::FILE);
    }

    private function seal(#[SensitiveParameter] string $secret): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return self::PREFIX . base64_encode($nonce . sodium_crypto_secretbox($secret, $nonce, $this->key()));
    }

    private function open(string $sealed): ?string
    {
        $raw = str_starts_with($sealed, self::PREFIX)
            ? base64_decode(substr($sealed, strlen(self::PREFIX)), true) : false;
        if (!is_string($raw) || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }
        $plain = sodium_crypto_secretbox_open(
            substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->key(),
        );

        return is_string($plain) && $plain !== '' ? $plain : null;
    }

    private function key(): string
    {
        $secret = $this->config?->appSecret->reveal() ?? '';
        if ($secret === '') {
            throw new RuntimeException('nolviko_captcha_settings_unavailable');
        }

        return hash_hkdf('sha256', $secret, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'nolviko captcha secret');
    }
}
