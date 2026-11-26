<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha;

use Closure;
use Nolviko\Core\View\SafeHtml;
use Nolviko\Modules\Users\Domain\RegistrationChallenge;
use SensitiveParameter;
use Throwable;

/**
 * The registration challenge with an outside CAPTCHA (2026-11-26, extension API 1.4.0). It replaces the built-in
 * challenge or is added to it; until a provider is set up the built-in one runs unchanged. The answer is checked
 * once with the provider's `siteverify` (tokens are single use and expire after a few minutes there); the hostname
 * the provider reports must be this site, and reCAPTCHA v3 must reach the score threshold. A provider that cannot
 * be reached fails closed: the form is refused, never let through.
 */
final class CaptchaChallenge implements RegistrationChallenge
{
    /**
     * @param array{provider: string, site_key: string, mode: string, threshold: float} $settings
     * @param Closure(string, array<string, string>): array{0: int, 1: string} $post URL, fields => status, body.
     * @param Closure(): array{ip: string, host: string, locale: string} $request
     */
    public function __construct(
        private readonly array $settings,
        #[SensitiveParameter] private readonly ?string $secret,
        private readonly RegistrationChallenge $builtIn,
        private readonly string $nonce,
        private readonly Closure $post,
        private readonly Closure $request,
    ) {
    }

    public function present(): ?array
    {
        if (!$this->ready()) {
            return $this->builtIn->present();
        }
        $base = $this->settings['mode'] === 'add' ? ($this->builtIn->present() ?? ['id' => '', 'parameters' => []])
            : ['id' => '', 'parameters' => []];

        return $base + ['widget' => $this->widget()];
    }

    public function passes(array $input): bool
    {
        if (!$this->ready()) {
            return $this->builtIn->passes($input);
        }
        $builtIn = $this->settings['mode'] !== 'add' || $this->builtIn->passes($input);
        $provider = CaptchaProviders::PROVIDERS[$this->settings['provider']];
        $token = is_string($input[$provider['field']] ?? null) ? $input[$provider['field']] : '';
        if (!$builtIn || $token === '' || strlen($token) > 4096) {
            return false;
        }
        $request = ($this->request)();
        try {
            [$status, $body] = ($this->post)($provider['verify'], array_filter([
                'secret' => (string) $this->secret,
                'response' => $token,
                'remoteip' => $request['ip'],
            ], static fn(string $value): bool => $value !== ''));
            $answer = $status === 200 ? json_decode($body, true, 4) : null;
        } catch (Throwable) {
            return false;
        }

        return is_array($answer) && ($answer['success'] ?? false) === true
            && (in_array($this->settings['site_key'], CaptchaProviders::TEST_KEYS, true)
                || self::sameHost($answer['hostname'] ?? null, $request['host']))
            && ($this->settings['provider'] !== 'recaptcha_v3' || ((float) ($answer['score'] ?? 0.0)
                >= $this->settings['threshold'] && in_array($answer['action'] ?? 'register', ['register'], true)));
    }

    private function ready(): bool
    {
        return CaptchaProviders::exists($this->settings['provider']) && $this->settings['site_key'] !== ''
            && $this->secret !== null && $this->secret !== '';
    }

    private function widget(): SafeHtml
    {
        $provider = CaptchaProviders::PROVIDERS[$this->settings['provider']];
        $key = self::e($this->settings['site_key']);
        $nonce = self::e($this->nonce);
        $locale = self::e(substr(($this->request)()['locale'], 0, 5));
        if ($this->settings['provider'] === 'recaptcha_v3') {
            $json = json_encode($this->settings['site_key'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS
                | JSON_HEX_QUOT);

            return new SafeHtml('<input type="hidden" name="g-recaptcha-response" value="" data-captcha-v3>'
                . '<script src="' . $provider['script'] . '?render=' . $key . '" nonce="' . $nonce . '" async defer>'
                . '</script><script nonce="' . $nonce . '">(function(){var f=document.querySelector('
                . '"[data-captcha-v3]").form,done=false;f.addEventListener("submit",function(e){if(done)return;'
                . 'e.preventDefault();grecaptcha.ready(function(){grecaptcha.execute(' . $json
                . ',{action:"register"}).then(function(t){f.querySelector("[data-captcha-v3]").value=t;done=true;'
                . 'f.requestSubmit?f.requestSubmit():f.submit();});});});})();</script>');
        }

        return new SafeHtml('<div class="' . $provider['class'] . '" data-sitekey="' . $key . '"'
            . ($locale === '' ? '' : ' data-language="' . $locale . '"') . '></div><script src="' . $provider['script']
            . ($locale === '' ? '' : '?hl=' . $locale) . '" nonce="' . $nonce . '" async defer></script>');
    }

    private static function sameHost(mixed $reported, string $host): bool
    {
        if (!is_string($reported) || $reported === '') {
            // Turnstile and hCaptcha test keys report no hostname; the token is still single use.
            return true;
        }

        return strtolower($reported) === strtolower($host);
    }

    private static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
