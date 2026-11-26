<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha;

/**
 * The supported CAPTCHA services (2026-11-26) with their script, widget class, response field, verification
 * endpoint and the Content-Security-Policy hosts each one documents. All four share the same `siteverify`
 * protocol (POST secret, response, remoteip; JSON with success, hostname, and for reCAPTCHA v3 a score).
 */
final class CaptchaProviders
{
    public const PROVIDERS = [
        'turnstile' => [
            'script' => 'https://challenges.cloudflare.com/turnstile/v0/api.js',
            'class' => 'cf-turnstile',
            'field' => 'cf-turnstile-response',
            'verify' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            'csp' => ['script-src' => ['https://challenges.cloudflare.com'],
                'frame-src' => ['https://challenges.cloudflare.com'],
                'connect-src' => ['https://challenges.cloudflare.com']],
        ],
        'hcaptcha' => [
            'script' => 'https://js.hcaptcha.com/1/api.js',
            'class' => 'h-captcha',
            'field' => 'h-captcha-response',
            'verify' => 'https://api.hcaptcha.com/siteverify',
            'csp' => ['script-src' => ['https://hcaptcha.com', 'https://*.hcaptcha.com'],
                'frame-src' => ['https://hcaptcha.com', 'https://*.hcaptcha.com'],
                'style-src' => ['https://hcaptcha.com', 'https://*.hcaptcha.com'],
                'connect-src' => ['https://hcaptcha.com', 'https://*.hcaptcha.com']],
        ],
        'recaptcha' => [
            'script' => 'https://www.google.com/recaptcha/api.js',
            'class' => 'g-recaptcha',
            'field' => 'g-recaptcha-response',
            'verify' => 'https://www.google.com/recaptcha/api/siteverify',
            'csp' => ['script-src' => ['https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
                'frame-src' => ['https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/']],
        ],
        'recaptcha_v3' => [
            'script' => 'https://www.google.com/recaptcha/api.js',
            'class' => '',
            'field' => 'g-recaptcha-response',
            'verify' => 'https://www.google.com/recaptcha/api/siteverify',
            'csp' => ['script-src' => ['https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
                'frame-src' => ['https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/']],
        ],
    ];

    /**
     * The providers' published test site keys (always pass, report a placeholder hostname): with them the
     * hostname check is skipped, so the setup can be tried on a local test site.
     */
    public const TEST_KEYS = ['1x00000000000000000000AA', '2x00000000000000000000AB', '3x00000000000000000000FF',
        '10000000-ffff-ffff-ffff-000000000001', '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'];

    public static function exists(string $provider): bool
    {
        return isset(self::PROVIDERS[$provider]);
    }
}
