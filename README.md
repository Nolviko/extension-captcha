# CAPTCHA for Nolviko

Official [Nolviko](https://github.com/Nolviko/nolviko) extension: an outside CAPTCHA on the registration form.
**Admin → Extensions → CAPTCHA**.

## Services

- **Cloudflare Turnstile** (recommended: free, usually invisible, no puzzles, collects the least data)
- **hCaptcha**
- **Google reCAPTCHA v2** (checkbox) and **reCAPTCHA v3** (invisible, with a score threshold)

## Features

- Replaces the built-in challenge, or is asked in addition to it. Until a service is set up the built-in
  challenge (honeypot, fill time, question or proof of work) keeps running unchanged.
- The secret key is sealed with a key derived from the site secret and never shown again.
- Each answer is checked once with the service's `siteverify`: the reported hostname must be this site (skipped
  for the services' published test keys, so you can try it locally), reCAPTCHA v3 must reach the score threshold.
  A service that cannot be reached fails closed — the form is refused, never let through.
- The service's hosts are added to the Content-Security-Policy and its scripts carry the page's nonce.

The core offers one hook for this (registration); sign-in and password reset keep their own rate limits.

### Test keys

| Service | Site key | Secret key |
|---|---|---|
| Turnstile | `1x00000000000000000000AA` | `1x0000000000000000000000000000000AA` |
| hCaptcha | `10000000-ffff-ffff-ffff-000000000001` | `0x0000000000000000000000000000000000000000` |
| reCAPTCHA v2 | `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` | `6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe` |

## Installation

1. Download `nolviko-ext-nolviko-captcha-<version>.zip` and copy its SHA-256.
2. **Admin → Extensions → Upload**, choose the ZIP and confirm. Enable it, open its settings page.

Requires Nolviko with extension API 1.4 or newer.

## Development

```bash
php <nolviko-dev-vendor>/bin/phpunit --bootstrap <nolviko-dev-vendor>/autoload.php tests
```

## License

[Apache License 2.0](LICENSE), like Nolviko itself.
