# webexpose

**A one-command security check for your own website.** Headers, exposed
`.git` / `.env` files, TLS expiry, cookies and CORS, with a grade from A+ to F
and a concrete fix for every problem.

[![CI](https://github.com/tahaSec/webexpose/actions/workflows/ci.yml/badge.svg)](https://github.com/tahaSec/webexpose/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

You deployed your portfolio, your side project or a client's shop. Did the
`.git` folder ship with it? Is `.env` readable at `/.env`? Does the
certificate expire next week? `webexpose` answers that in a few seconds,
with **zero dependencies**, on Linux, macOS and Windows.

```console
$ webexpose http://127.0.0.1:8099
http://127.0.0.1:8099
  final URL: http://127.0.0.1:8099/ (HTTP 200)
  grade:  F   score 0/100

  ✖ CRITICAL [exposure] Git repository exposed (/.git/)
      fix: Block /.git in your web server config and never deploy the .git folder.
  ✖ CRITICAL [exposure] .env file exposed (secrets!)
      fix: Remove .env from the web root and ROTATE every secret inside it.
  ✖ HIGH     [cors] CORS reflects any Origin with credentials
  ✖ HIGH     [https] Site is served over plain HTTP
  ! MEDIUM   [cookies] Cookie 'PHPSESSID': no HttpOnly, no SameSite
      fix: Set-Cookie: PHPSESSID=...; Secure; HttpOnly; SameSite=Lax; Path=/
  ! MEDIUM   [headers] Content-Security-Policy missing
  ! LOW      [disclosure] X-Powered-By header reveals version: PHP/7.2.1
  ...
```

> Try it safely: `python examples/vulnerable_server.py` starts a deliberately
> broken site on `127.0.0.1:8099`.

## What it checks

| Area | Checks |
|------|--------|
| **Exposed files** | `/.git/`, `.env`, `.env.production`, AWS credentials, SSH keys, `.npmrc`, `.htpasswd`, `.svn`, `.DS_Store`, SQL dumps, backup archives, `wp-config.php.bak`, `docker-compose.yml`, `phpinfo.php`, `server-status`, Spring actuator, VS Code `sftp.json` |
| **Headers** | HSTS (and its max-age), CSP (presence and weaknesses such as `unsafe-inline`, `unsafe-eval`, wildcards), clickjacking (XFO / `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| **Disclosure** | Version numbers in `Server`, `X-Powered-By`, `X-AspNet-Version` and similar headers |
| **TLS** | Trusted certificate, days until expiry, TLS 1.0/1.1 still accepted |
| **HTTPS** | HTTP → HTTPS redirect (permanent?) |
| **Cookies** | `Secure`, `HttpOnly`, `SameSite`, with stricter rules for session-looking cookies |
| **CORS** | Arbitrary `Origin` reflected, with or without credentials |
| **security.txt** | Whether `/.well-known/security.txt` exists |

Exposed-file checks **validate the content** (for example `.git/HEAD` must
start with `ref:`), and pages that answer 200 for every URL ("soft 404") are
detected, so you won't get flooded with false positives.

## Install

```bash
pip install git+https://github.com/tahaSec/webexpose
```

## Usage

```bash
webexpose example.com                    # full check
webexpose example.com -v                 # also show what passed
webexpose site1.com site2.com -f markdown > report.md
webexpose example.com -f json
webexpose example.com --no-paths         # headers / TLS / cookies only
webexpose staging.example.com --fail-under B   # exit 1 if grade < B
```

Exit codes: `0` ok, `1` grade below `--fail-under`, `2` target unreachable.

### Monitor your site with GitHub Actions

Catch an expiring certificate or an accidental `.env` deploy every morning:

```yaml
name: site-check
on:
  schedule: [{ cron: "0 6 * * *" }]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: pip install git+https://github.com/tahaSec/webexpose
      - run: webexpose yourdomain.com --fail-under B
```

## Responsible use

Only scan websites **you own or have written permission to test**.
`webexpose` sends about 25 ordinary `GET` requests (with a small delay
between them) and never attempts to exploit anything. It identifies itself
with the `webexpose/<version>` User-Agent.

## Contributing

New probes need a content validator so they stay free of false positives.
Issues and PRs are welcome.

```bash
pip install -e ".[dev]" && pytest
```

---

## Türkçe

`webexpose`, **kendi** sitenizin güvenliğini tek komutla kontrol eder.
Açıkta kalmış `.git` klasörü ve `.env` dosyası, eksik güvenlik başlıkları
(HSTS, CSP), sertifikanın bitmesine kalan gün, cookie ayarları ve hatalı
CORS yapılandırması gibi sorunları bulur. Siteye A+'tan F'ye bir not verir
ve her sorun için düzeltme önerir. Hiçbir ek kütüphane gerektirmez.

```bash
pip install git+https://github.com/tahaSec/webexpose
webexpose siteniz.com
```

Yalnızca sahibi olduğunuz ya da test izniniz bulunan siteleri tarayın.

## License

MIT © Muhammed Taha Özer
