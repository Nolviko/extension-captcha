<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha\Tests;

use Nolviko\Core\Http\CspNonce;
use Nolviko\Modules\Users\Domain\RegistrationChallenge;
use NolvikoExt\Captcha\CaptchaChallenge;
use NolvikoExt\Captcha\CaptchaProviders;
use PHPUnit\Framework\TestCase;

/**
 * Run from the workspace root (not part of the ZIP):
 *   php dev/vendor/bin/phpunit --bootstrap dev/vendor/autoload.php extensions-src/nolviko/captcha/tests
 */
final class CaptchaTest extends TestCase
{
    /** @var list<array{0: string, 1: array<string, string>}> */
    private array $posts = [];

    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__) . '/src/CaptchaProviders.php';
        require_once dirname(__DIR__) . '/src/CaptchaChallenge.php';
    }

    public function testUnconfiguredKeepsTheBuiltInChallenge(): void
    {
        $challenge = $this->challenge(['provider' => ''], null, '{}');

        self::assertSame(['id' => 'q', 'parameters' => []], $challenge->present());
        self::assertTrue($challenge->passes(['answer' => 'ok']));
        self::assertSame([], $this->posts);
    }

    public function testWidgetAndVerification(): void
    {
        $challenge = $this->challenge([], 'secret-key', '{"success":true,"hostname":"forum.test"}');
        $present = $challenge->present();

        self::assertSame('', $present['id']);
        $widget = $present['widget']->html;
        self::assertStringContainsString('<div class="cf-turnstile" data-sitekey="site-key-123"', $widget);
        self::assertStringContainsString('api.js?hl=tr" nonce="N" async defer', $present['widget']->html);
        self::assertFalse($challenge->passes([]));
        self::assertTrue($challenge->passes(['cf-turnstile-response' => 'token']));
        self::assertSame(CaptchaProviders::PROVIDERS['turnstile']['verify'], $this->posts[0][0]);
        self::assertSame(
            ['secret' => 'secret-key', 'response' => 'token', 'remoteip' => '203.0.113.5'],
            $this->posts[0][1]
        );
    }

    public function testRefusesOtherHostsFailuresAndLowScores(): void
    {
        $token = ['cf-turnstile-response' => 't', 'g-recaptcha-response' => 't'];

        self::assertFalse($this->challenge([], 's', '{"success":true,"hostname":"evil.test"}')->passes($token));
        self::assertFalse($this->challenge([], 's', '{"success":false}')->passes($token));
        self::assertFalse($this->challenge([], 's', 'not json', 0)->passes($token));
        self::assertTrue($this->challenge(
            ['site_key' => '1x00000000000000000000AA'],
            's',
            '{"success":true,"hostname":"example.com"}'
        )->passes($token));
        $v3 = ['provider' => 'recaptcha_v3', 'threshold' => 0.5];
        self::assertFalse($this->challenge($v3, 's', '{"success":true,"hostname":"forum.test","score":0.3,'
            . '"action":"register"}')->passes($token));
        self::assertTrue($this->challenge($v3, 's', '{"success":true,"hostname":"forum.test","score":0.7,'
            . '"action":"register"}')->passes($token));
    }

    public function testAddModeNeedsBothAndHostsAreValidCsp(): void
    {
        $add = $this->challenge(['mode' => 'add'], 's', '{"success":true}');

        self::assertSame('q', $add->present()['id']);
        self::assertFalse($add->passes(['cf-turnstile-response' => 't', 'answer' => 'wrong']));
        self::assertTrue($add->passes(['cf-turnstile-response' => 't', 'answer' => 'ok']));
        foreach (CaptchaProviders::PROVIDERS as $provider) {
            foreach ($provider['csp'] as $directive => $sources) {
                foreach ($sources as $source) {
                    self::assertTrue(CspNonce::validSource($directive, $source), $source);
                }
            }
        }
    }

    /** RC1 acceptance (2026-11-27): an unreachable service, a reused answer or a wrong secret never lets anyone in. */
    public function testTimeoutsReusedAnswersAndKeyErrorsAreRefused(): void
    {
        $token = ['cf-turnstile-response' => 't'];
        $timeout = $this->challenge([], 's', '', 200, static function (): array {
            throw new \RuntimeException('timed out');
        });

        self::assertFalse($timeout->passes($token), 'a timeout is a refusal');
        self::assertFalse($this->challenge([], 's', '{"success":false,"error-codes":["timeout-or-duplicate"]}')
            ->passes($token), 'an answer used twice');
        self::assertFalse($this->challenge([], 'wrong', '{"success":false,"error-codes":["invalid-input-secret"]}')
            ->passes($token), 'a wrong secret key');
        self::assertFalse($this->challenge([], 's', '{"success":true}', 503)->passes($token), 'a service error');
        self::assertFalse($this->challenge([], 's', '{"success":"yes"}')->passes($token), 'only true counts');

        $this->posts = [];
        $missing = $this->challenge([], null, '{"success":true}');
        self::assertSame('q', $missing->present()['id'], 'without a secret the built-in challenge stays');
        self::assertFalse($missing->passes($token));
        self::assertSame([], $this->posts, 'and nothing is sent');
    }

    private function challenge(
        array $settings,
        ?string $secret,
        string $body,
        int $status = 200,
        ?\Closure $post = null,
    ): CaptchaChallenge {
        $builtIn = new class implements RegistrationChallenge {
            public function present(): ?array
            {
                return ['id' => 'q', 'parameters' => []];
            }

            public function passes(array $input): bool
            {
                return ($input['answer'] ?? '') === 'ok';
            }
        };

        return new CaptchaChallenge(
            $settings + ['provider' => 'turnstile', 'site_key' => 'site-key-123', 'mode' => 'replace',
                'threshold' => 0.5],
            $secret,
            $builtIn,
            'N',
            $post ?? function (string $url, array $fields) use ($body, $status): array {
                $this->posts[] = [$url, $fields];

                return [$status, $body];
            },
            static fn(): array => ['ip' => '203.0.113.5', 'host' => 'forum.test', 'locale' => 'tr'],
        );
    }
}
