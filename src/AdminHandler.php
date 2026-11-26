<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha;

use InvalidArgumentException;
use Nolviko\Core\Http\ErrorResponder;
use Nolviko\Core\Http\InstallerPage;
use Nolviko\Core\Http\RouteHandler;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\CoreRoutes;
use Nolviko\Core\Routing\Router;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\View\SafeHtml;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Admin\Http\AdminNavigation;
use Nolviko\Modules\Admin\Http\AdminSession;
use Nolviko\Modules\Admin\Infrastructure\DbalAdminAudit;
use Nolviko\Modules\Users\Http\RequestSubject;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * `/ext/nolviko/captcha/admin` (2026-11-26): choose the CAPTCHA service, paste the site key and the secret key,
 * choose whether it replaces or is added to the built-in challenge. Administrators only, with a password
 * confirmation from the last 15 minutes; every change is audited. The secret is never shown again.
 */
final class AdminHandler implements RouteHandler
{
    public const ROUTE = 'nolviko.captcha.admin';

    private const FLASH = '_nolviko_captcha_notice';

    private const CONSOLES = [
        'turnstile' => 'https://dash.cloudflare.com/?to=/:account/turnstile',
        'hcaptcha' => 'https://dashboard.hcaptcha.com/sites',
        'recaptcha' => 'https://www.google.com/recaptcha/admin/create',
        'recaptcha_v3' => 'https://www.google.com/recaptcha/admin/create',
    ];

    public function __construct(
        private readonly MessageTranslator $translator,
        private readonly TemplateRenderer $views,
        private readonly RequestSubject $subjects,
        private readonly AdminSession $admin,
        private readonly CsrfTokens $csrf,
        private readonly Router $router,
        private readonly Session $session,
        private readonly DbalAdminAudit $audit,
        private readonly ErrorResponder $errors,
        private readonly CaptchaSettings $settings,
    ) {
    }

    public function handle(Request $request, array $parameters): Response
    {
        $subject = $this->subjects->of($request);
        if ($subject->userId === null || !$subject->allows('admin.access')) {
            return $subject->userId === null
                ? InstallerPage::redirect($this->router->generate(CoreRoutes::LOGIN)) : $this->errors->denied();
        }

        $error = null;
        if ($request->isMethod('POST')) {
            if (!$this->admin->isFresh()) {
                $error = $this->text('reauth');
            } else {
                try {
                    $this->save($request->request->all(), (int) $subject->userId);

                    return InstallerPage::redirect($this->router->generate(self::ROUTE));
                } catch (InvalidArgumentException $invalid) {
                    $error = $this->text('error_' . $invalid->getMessage());
                } catch (Throwable) {
                    $error = $this->text('error_failed');
                }
            }
        }

        $notice = $this->session->get(self::FLASH);
        $this->session->remove(self::FLASH);
        $html = $this->views->render('extensions/admin_page.twig', [
            'title' => $this->text('title'),
            'nav' => AdminNavigation::items($this->router, $this->translator, CoreRoutes::ADMIN_EXTENSIONS),
            'body' => new SafeHtml($this->body(is_string($notice) ? $notice : null, $error)),
        ]);

        return new Response($html, $error === null ? 200 : 422, [
            'Content-Type' => 'text/html; charset=UTF-8', 'Cache-Control' => 'no-store, private',
        ]);
    }

    private function save(array $input, int $userId): void
    {
        $field = static fn(string $key): string => trim(is_string($input[$key] ?? null) ? $input[$key] : '');
        if ($field('remove') === '1') {
            $this->settings->clear();
            $this->audit->record($userId, 'nolviko.captcha.removed');
            $this->session->set(self::FLASH, $this->text('removed'));

            return;
        }
        $provider = $field('provider');
        $siteKey = $field('site_key');
        $secret = $field('secret');
        if (!CaptchaProviders::exists($provider)) {
            throw new InvalidArgumentException('provider');
        }
        if (preg_match('/^[A-Za-z0-9_-]{8,120}$/D', $siteKey) !== 1) {
            throw new InvalidArgumentException('site_key');
        }
        if (
            ($secret === '' && $this->settings->secret() === null)
            || ($secret !== '' && preg_match('/^[\x21-\x7E]{8,200}$/D', $secret) !== 1)
        ) {
            throw new InvalidArgumentException('secret');
        }
        $mode = in_array($field('mode'), CaptchaSettings::MODES, true) ? $field('mode') : 'replace';
        $threshold = is_numeric($field('threshold')) ? (float) $field('threshold') : 0.5;
        $this->settings->save(
            $provider,
            $siteKey,
            $secret === '' ? null : $secret,
            $mode,
            max(0.1, min(0.9, $threshold))
        );
        $this->audit->record($userId, 'nolviko.captcha.saved');
        $this->session->set(self::FLASH, $this->text('saved'));
    }

    private function body(?string $notice, ?string $error): string
    {
        $data = $this->settings->data();
        $ready = $this->settings->ready();
        $fresh = $this->admin->isFresh();
        $token = '<input type="hidden" name="' . $this->e(CsrfTokens::FIELD) . '" value="'
            . $this->e($this->csrf->token()) . '">';
        $html = ($notice === null ? '' : '<p role="status">' . $this->e($notice) . '</p>')
            . ($error === null ? '' : '<p role="alert">' . $this->e($error) . '</p>')
            . '<section class="panel panel-pad stack"><p><span class="chip ' . ($ready ? 'chip-new' : 'chip-amber')
            . '">' . $this->e($this->text($ready ? 'status_on' : 'status_off')) . '</span> '
            . $this->e($this->text($ready ? 'status_on_help' : 'status_off_help')) . '</p><p class="meta">'
            . $this->e($this->text('privacy')) . '</p></section>'
            . '<section class="panel panel-pad stack"><h2>' . $this->e($this->text('steps_title'))
            . '</h2><ol class="stack">'
            . '<li>' . $this->e($this->text('step_choose')) . '</li><li>' . $this->e($this->text('step_keys')) . ' ';
        foreach (self::CONSOLES as $provider => $url) {
            if ($provider !== 'recaptcha_v3') {
                $html .= '<a href="' . $this->e($url) . '" rel="noopener noreferrer" target="_blank">'
                    . $this->e($this->text('provider_' . $provider)) . '</a> ';
            }
        }
        $html .= '</li><li>' . $this->e($this->text('step_test')) . '</li></ol></section>'
            . ($fresh ? '' : '<p>' . $this->e($this->text('reauth_hint')) . ' <a href="'
                . $this->e($this->router->generate(CoreRoutes::ADMIN_REAUTH)) . '">'
                . $this->e($this->translator->translate('admin.reauth.title')) . '</a></p>')
            . '<form method="post" action="' . $this->e($this->router->generate(self::ROUTE))
            . '" class="panel panel-pad stack">' . $token . '<p><label for="captcha-provider">'
            . $this->e($this->text('provider')) . '</label><select id="captcha-provider" name="provider">';
        foreach (array_keys(CaptchaProviders::PROVIDERS) as $provider) {
            $html .= '<option value="' . $provider . '"' . ($data['provider'] === $provider ? ' selected' : '') . '>'
                . $this->e($this->text('provider_' . $provider)) . '</option>';
        }
        $html .= '</select></p><p><label for="captcha-site">' . $this->e($this->text('site_key')) . '</label>'
            . '<input id="captcha-site" name="site_key" type="text" maxlength="120" spellcheck="false"'
            . ' autocomplete="off" value="' . $this->e($data['site_key']) . '"></p>'
            . '<p><label for="captcha-secret">' . $this->e($this->text('secret')) . '</label>'
            . '<input id="captcha-secret" name="secret" type="password" maxlength="200" autocomplete="off"'
            . ($this->settings->secret() !== null ? ' placeholder="' . $this->e($this->text('secret_kept')) . '"' : '')
            . '></p><fieldset class="stack"><legend>' . $this->e($this->text('mode')) . '</legend>';
        foreach (CaptchaSettings::MODES as $mode) {
            $html .= '<p><label><input type="radio" name="mode" value="' . $mode . '"'
                . ($data['mode'] === $mode ? ' checked' : '') . '> ' . $this->e($this->text('mode_' . $mode))
                . '</label></p>';
        }

        $html .= '</fieldset><p><label for="captcha-threshold">' . $this->e($this->text('threshold')) . '</label>'
            . '<input id="captcha-threshold" name="threshold" type="number" min="0.1" max="0.9" step="0.1" value="'
            . $this->e((string) $data['threshold']) . '"><span class="hint">' . $this->e($this->text('threshold_help'))
            . '</span></p><p><button type="submit"' . ($fresh ? '' : ' disabled') . '>' . $this->e($this->text('save'))
            . '</button></p></form>';
        if ($data['provider'] !== '') {
            $html .= '<form method="post" action="' . $this->e($this->router->generate(self::ROUTE)) . '">' . $token
                . '<input type="hidden" name="remove" value="1"><button class="btn-d" type="submit"'
                . ($fresh ? '' : ' disabled') . '>' . $this->e($this->text('remove')) . '</button></form>';
        }

        return $html;
    }

    private function text(string $key): string
    {
        return $this->translator->translate('nolviko.captcha.' . $key);
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
