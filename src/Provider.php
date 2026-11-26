<?php

declare(strict_types=1);

/*
 * Nolviko CAPTCHA extension (2026-11-26, PLG-02): Cloudflare Turnstile, hCaptcha or Google reCAPTCHA (v2, v3) on
 * the registration form, replacing or added to the built-in challenge. Off until a provider is set up.
 */

use Doctrine\DBAL\Connection;
use Nolviko\Core\Application\CompositionRoot;
use Nolviko\Core\Config\Config;
use Nolviko\Core\Extensions\ExtensionContext;
use Nolviko\Core\Extensions\ExtensionProvider;
use Nolviko\Core\Http\CspNonce;
use Nolviko\Core\Http\ErrorResponder;
use Nolviko\Core\Http\ThemeRequest;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\RouteDefinition;
use Nolviko\Core\Routing\Router;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Admin\Http\AdminSession;
use Nolviko\Modules\Admin\Infrastructure\DbalAdminAudit;
use Nolviko\Modules\Permissions\Domain\PermissionDefinition;
use Nolviko\Modules\Permissions\Domain\PermissionType;
use Nolviko\Modules\Users\Domain\RegistrationChallenge;
use Nolviko\Modules\Users\Http\RequestSubject;
use NolvikoExt\Captcha\AdminHandler;
use NolvikoExt\Captcha\CaptchaChallenge;
use NolvikoExt\Captcha\CaptchaHttp;
use NolvikoExt\Captcha\CaptchaProviders;
use NolvikoExt\Captcha\CaptchaSettings;

require_once __DIR__ . '/CaptchaProviders.php';
require_once __DIR__ . '/CaptchaSettings.php';
require_once __DIR__ . '/CaptchaHttp.php';
require_once __DIR__ . '/CaptchaChallenge.php';
require_once __DIR__ . '/AdminHandler.php';

return new class implements ExtensionProvider {
    public function register(ExtensionContext $context): void
    {
        $directory = $context->storage();
        $context->service(
            'nolviko.captcha.settings',
            static fn(?Config $config): CaptchaSettings => new CaptchaSettings($directory, $config),
            [CompositionRoot::CONFIG],
        );

        // The provider's hosts are needed only on pages with the widget, but the policy is per site; a file read.
        $provider = (new CaptchaSettings($directory, null))->data()['provider'];
        if ($provider !== '') {
            $context->contentSecurity(CaptchaProviders::PROVIDERS[$provider]['csp']);
        }

        $context->service(
            'nolviko.captcha.challenge',
            static fn(
                CaptchaSettings $settings,
                CspNonce $nonce,
                ThemeRequest $request,
                MessageTranslator $translator,
            ): Closure => static fn(RegistrationChallenge $builtIn): RegistrationChallenge => new CaptchaChallenge(
                $settings->data(),
                $settings->secret(),
                $builtIn,
                $nonce->value,
                CaptchaHttp::post(...),
                static fn(): array => [
                    'ip' => (string) $request->request?->getClientIp(),
                    'host' => (string) $request->request?->getHost(),
                    'locale' => $translator->locale(),
                ],
            ),
            ['nolviko.captcha.settings', CspNonce::class, ThemeRequest::class, MessageTranslator::class],
        );
        $context->registrationChallenge('nolviko.captcha.challenge');

        $context->permission(new PermissionDefinition('nolviko.captcha.manage', PermissionType::Bool, default: true));
        $context->route(
            new RouteDefinition(
                AdminHandler::ROUTE,
                '/ext/nolviko/captcha/admin',
                ['GET', 'POST'],
                requiresHttps: true,
            ),
            'nolviko.captcha.manage',
            static fn(
                MessageTranslator $translator,
                TemplateRenderer $views,
                RequestSubject $subjects,
                AdminSession $admin,
                CsrfTokens $csrf,
                Router $router,
                Session $session,
                Connection $db,
                ErrorResponder $errors,
                CaptchaSettings $settings,
            ): AdminHandler => new AdminHandler(
                $translator,
                $views,
                $subjects,
                $admin,
                $csrf,
                $router,
                $session,
                new DbalAdminAudit($db),
                $errors,
                $settings,
            ),
            [
                MessageTranslator::class, TemplateRenderer::class, RequestSubject::class, AdminSession::class,
                CsrfTokens::class, Router::class, Session::class, Connection::class, ErrorResponder::class,
                'nolviko.captcha.settings',
            ],
        );
        $context->adminPage(AdminHandler::ROUTE);
    }
};
