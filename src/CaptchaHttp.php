<?php

declare(strict_types=1);

namespace NolvikoExt\Captcha;

use SensitiveParameter;

/**
 * One HTTPS form POST with verified TLS and a short timeout (2026-11-26), without Composer packages; the
 * same approach as the Google sign-in extension. Redirects are not followed.
 */
final class CaptchaHttp
{
    /**
     * @param array<string, string> $fields
     * @return array{0: int, 1: string} HTTP status (0 when unreachable) and body.
     */
    public static function post(string $url, #[SensitiveParameter] array $fields): array
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n",
                'content' => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
                'timeout' => 8,
                'ignore_errors' => true,
                'follow_location' => 0,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $body = @file_get_contents($url, false, $context, 0, 65536);
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $match) === 1) {
                $status = (int) $match[1];
            }
        }

        return [$status, is_string($body) ? $body : ''];
    }
}
