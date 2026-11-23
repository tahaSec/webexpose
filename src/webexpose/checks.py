"""The individual checks. Each returns a list of Finding objects."""

from __future__ import annotations

import datetime as dt
import re
import socket
import ssl
import time
import warnings
from dataclasses import asdict, dataclass
from typing import Callable, List, Optional
from urllib.parse import urljoin, urlparse

from .http import Client, Response

SEVERITY_ORDER = {"pass": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PENALTY = {"pass": 0, "info": 0, "low": 3, "medium": 8, "high": 20, "critical": 40}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

def check_headers(resp: Response) -> List[Finding]:
    out: List[Finding] = []
    is_https = resp.url.lower().startswith("https://")
    h = resp.header

    # HSTS
    hsts = h("Strict-Transport-Security")
    if is_https:
        if not hsts:
            out.append(Finding("headers", "medium", "Strict-Transport-Security missing",
                               "Browsers may be downgraded to HTTP on first visit.",
                               "Strict-Transport-Security: max-age=31536000; includeSubDomains"))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15552000:
                out.append(Finding("headers", "low", "HSTS max-age is short (%d s)" % age,
                                   "Less than 180 days.", "Use max-age=31536000 or more."))
            else:
                out.append(Finding("headers", "pass", "Strict-Transport-Security set", hsts))

    # CSP
    csp = h("Content-Security-Policy")
    if not csp:
        sev = "medium" if not h("Content-Security-Policy-Report-Only") else "low"
        out.append(Finding("headers", sev, "Content-Security-Policy missing",
                           "No browser-side protection against XSS and injected scripts.",
                           "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; "
                           "base-uri 'self'; frame-ancestors 'self'"))
    else:
        weak = []
        script_src = _csp_directive(csp, "script-src") or _csp_directive(csp, "default-src") or ""
        if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'strict-dynamic'" not in script_src:
            weak.append("'unsafe-inline' in script-src")
        if "'unsafe-eval'" in script_src:
            weak.append("'unsafe-eval' in script-src")
        if re.search(r"(^|\s)(\*|https?:|data:)(\s|$)", script_src):
            weak.append("wildcard/scheme source in script-src")
        if not _csp_directive(csp, "object-src") and "'none'" not in (_csp_directive(csp, "default-src") or ""):
            weak.append("no object-src 'none'")
        if weak:
            out.append(Finding("headers", "low", "Content-Security-Policy is weak", "; ".join(weak),
                               "Use nonces or hashes instead of 'unsafe-inline' and avoid wildcards."))
        else:
            out.append(Finding("headers", "pass", "Content-Security-Policy set"))

    # Clickjacking
    xfo = h("X-Frame-Options")
    if not xfo and not _csp_directive(csp, "frame-ancestors"):
        out.append(Finding("headers", "medium", "Clickjacking protection missing",
                           "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                           "Content-Security-Policy: frame-ancestors 'self'  (or X-Frame-Options: DENY)"))
    else:
        out.append(Finding("headers", "pass", "Clickjacking protection set"))

    if h("X-Content-Type-Options").lower().strip() != "nosniff":
        out.append(Finding("headers", "low", "X-Content-Type-Options missing",
                           "Browsers may MIME-sniff responses.", "X-Content-Type-Options: nosniff"))
    else:
        out.append(Finding("headers", "pass", "X-Content-Type-Options: nosniff"))

    rp = h("Referrer-Policy").lower()
    if not rp or "unsafe-url" in rp or rp.strip() == "no-referrer-when-downgrade":
        out.append(Finding("headers", "low", "Referrer-Policy missing or permissive",
                           "Full URLs (with tokens in query strings) may leak to other sites.",
                           "Referrer-Policy: strict-origin-when-cross-origin"))
    else:
        out.append(Finding("headers", "pass", "Referrer-Policy: %s" % rp))

    if not h("Permissions-Policy"):
        out.append(Finding("headers", "info", "Permissions-Policy not set",
                           fix="Permissions-Policy: camera=(), microphone=(), geolocation=()"))

    # Information disclosure
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = h(name)
        if value and re.search(r"\d", value):
            out.append(Finding("disclosure", "low", "%s header reveals version: %s" % (name, value),
                               "Version numbers help attackers pick known exploits.",
                               "Remove the header or strip the version."))
        elif value and name != "Server":
            out.append(Finding("disclosure", "info", "%s header reveals technology: %s" % (name, value),
                               fix="Remove the header."))
    return out


def _csp_directive(csp: str, name: str) -> Optional[str]:
    for part in (csp or "").split(";"):
        tokens = part.strip().split(None, 1)
        if tokens and tokens[0].lower() == name:
            return tokens[1] if len(tokens) > 1 else ""
    return None


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

def check_cookies(resp: Response) -> List[Finding]:
    out: List[Finding] = []
    is_https = resp.url.lower().startswith("https://")
    for raw in resp.set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        samesite = re.search(r";\s*samesite\s*=\s*(\w+)", raw, re.I)
        problems = []
        if is_https and "secure" not in attrs:
            problems.append("no Secure")
        if "httponly" not in attrs:
            problems.append("no HttpOnly")
        if not samesite:
            problems.append("no SameSite")
        elif samesite.group(1).lower() == "none" and "secure" not in attrs:
            problems.append("SameSite=None without Secure")
        if problems:
            looks_sensitive = re.search(r"sess|auth|token|sid|jwt|login|remember", name, re.I)
            out.append(Finding("cookies", "medium" if looks_sensitive else "low",
                               "Cookie '%s': %s" % (name, ", ".join(problems)),
                               fix="Set-Cookie: %s=...; Secure; HttpOnly; SameSite=Lax; Path=/" % name))
        else:
            out.append(Finding("cookies", "pass", "Cookie '%s' has Secure, HttpOnly, SameSite" % name))
    return out


# ---------------------------------------------------------------------------
# HTTPS redirect / TLS
# ---------------------------------------------------------------------------

def check_https_redirect(client: Client, host: str, port: Optional[int] = None) -> List[Finding]:
    url = "http://%s%s/" % (host, ":%d" % port if port else "")
    resp = client.get(url, follow=False, read_body=False)
    if resp.status == 0:
        return [Finding("https", "info", "Plain HTTP is not reachable", resp.error or "")]
    location = resp.header("Location")
    if resp.status in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
        sev = "pass" if resp.status in (301, 308) else "info"
        return [Finding("https", sev, "HTTP redirects to HTTPS (%d)" % resp.status,
                        fix="" if sev == "pass" else "Use a permanent 301/308 redirect.")]
    return [Finding("https", "high", "HTTP does not redirect to HTTPS",
                    "http:// returned %d without an https:// redirect." % resp.status,
                    "Redirect all HTTP traffic to HTTPS with a 301 and enable HSTS.")]


def parse_cert_date(value: str) -> dt.datetime:
    """Parse the notAfter format returned by ssl.getpeercert()."""
    return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=dt.timezone.utc)


def check_tls(host: str, port: int = 443, timeout: float = 10.0,
              now: Optional[dt.datetime] = None) -> List[Finding]:
    out: List[Finding] = []
    now = now or dt.datetime.now(dt.timezone.utc)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return [Finding("tls", "critical", "TLS certificate is not trusted", exc.verify_message or str(exc),
                        "Install a valid certificate (Let's Encrypt is free) that matches the hostname.")]
    except (ssl.SSLError, OSError) as exc:
        return [Finding("tls", "info", "Could not complete a TLS handshake", str(exc))]

    out.append(Finding("tls", "pass", "Negotiated %s" % version))
    expires = parse_cert_date(cert["notAfter"])
    days = (expires - now).days
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    detail = "Expires %s (%d days), issuer: %s" % (
        expires.strftime("%Y-%m-%d"), days, issuer.get("organizationName") or issuer.get("commonName", "?"))
    if days < 0:
        out.append(Finding("tls", "critical", "Certificate has expired", detail, "Renew the certificate."))
    elif days < 14:
        out.append(Finding("tls", "high", "Certificate expires in %d days" % days, detail,
                           "Renew now and automate renewal (certbot, Caddy, your host's auto-renew)."))
    elif days < 30:
        out.append(Finding("tls", "low", "Certificate expires in %d days" % days, detail,
                           "Check that automatic renewal is working."))
    else:
        out.append(Finding("tls", "pass", "Certificate valid for %d more days" % days, detail))

    out.extend(_check_legacy_tls(host, port, timeout))
    return out


def _check_legacy_tls(host: str, port: int, timeout: float) -> List[Finding]:
    accepted = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))
    for name, version in legacy:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = version
                ctx.maximum_version = version
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            continue  # local OpenSSL cannot even offer it; skip silently
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    accepted.append(name)
        except (ssl.SSLError, OSError):
            pass
    if accepted:
        return [Finding("tls", "medium", "Deprecated protocol accepted: %s" % ", ".join(accepted),
                        fix="Disable TLS 1.0/1.1 and allow only TLS 1.2 and 1.3.")]
    return []


# ---------------------------------------------------------------------------
# Exposed files
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Probe:
    path: str
    severity: str
    title: str
    validate: Callable[[bytes], bool]
    fix: str


def _has(*needles: bytes) -> Callable[[bytes], bool]:
    return lambda body: any(n in body for n in needles)


def _regex(pattern: bytes) -> Callable[[bytes], bool]:
    rx = re.compile(pattern, re.M)
    return lambda body: bool(rx.search(body))


PROBES = [
    Probe("/.git/HEAD", "critical", "Git repository exposed (/.git/)",
          _regex(rb"^ref: refs/|^[0-9a-f]{40}\s*$"),
          "Block /.git in your web server config and never deploy the .git folder. "
          "Attackers can download your full source code and history."),
    Probe("/.git/config", "critical", "Git config exposed",
          _has(b"[core]", b"repositoryformatversion"), "Block access to /.git/."),
    Probe("/.env", "critical", ".env file exposed (secrets!)",
          _regex(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S"),
          "Remove .env from the web root and ROTATE every secret inside it."),
    Probe("/.env.production", "critical", ".env.production exposed",
          _regex(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S"), "Remove it from the web root and rotate secrets."),
    Probe("/.aws/credentials", "critical", "AWS credentials exposed",
          _has(b"aws_access_key_id"), "Remove the file and rotate the keys immediately."),
    Probe("/id_rsa", "critical", "SSH private key exposed",
          _has(b"PRIVATE KEY-----"), "Remove the key and revoke it everywhere it is authorised."),
    Probe("/.npmrc", "high", ".npmrc exposed",
          _has(b"_authToken", b"registry="), "Remove it from the web root and rotate tokens."),
    Probe("/.DS_Store", "low", ".DS_Store file exposed (lists directory contents)",
          lambda b: b[:8] == b"\x00\x00\x00\x01Bud1", "Delete .DS_Store files from the deployment."),
    Probe("/.svn/entries", "high", "Subversion metadata exposed",
          _regex(rb"^(dir|\d+)\s*$"), "Block /.svn/ and remove it from the deployment."),
    Probe("/.htpasswd", "high", ".htpasswd exposed (password hashes)",
          _regex(rb"^[\w.-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13}\s*$)"),
          "Move it outside the web root."),
    Probe("/wp-config.php.bak", "critical", "WordPress config backup exposed",
          _has(b"DB_PASSWORD"), "Delete backup files from the web root and rotate the DB password."),
    Probe("/config.php.bak", "high", "PHP config backup exposed",
          _has(b"<?php"), "Delete backup files from the web root."),
    Probe("/backup.zip", "high", "Backup archive exposed",
          lambda b: b[:4] == b"PK\x03\x04", "Remove archives from the web root."),
    Probe("/backup.sql", "critical", "Database dump exposed",
          _has(b"CREATE TABLE", b"INSERT INTO"), "Remove the dump and treat the data as leaked."),
    Probe("/dump.sql", "critical", "Database dump exposed",
          _has(b"CREATE TABLE", b"INSERT INTO"), "Remove the dump and treat the data as leaked."),
    Probe("/docker-compose.yml", "medium", "docker-compose.yml exposed",
          _regex(rb"^services:\s*$"), "Do not serve deployment files."),
    Probe("/phpinfo.php", "medium", "phpinfo() page exposed",
          _has(b"PHP Version", b"phpinfo()"), "Delete phpinfo pages from production."),
    Probe("/server-status", "medium", "Apache server-status exposed",
          _has(b"Apache Server Status"), "Restrict mod_status to localhost."),
    Probe("/actuator/env", "high", "Spring Boot actuator /env exposed",
          _has(b"propertySources", b"activeProfiles"), "Do not expose actuator endpoints publicly."),
    Probe("/.vscode/sftp.json", "critical", "VS Code SFTP config exposed (contains passwords)",
          _has(b'"password"', b'"host"'), "Remove it and change the server password."),
]

SOFT_404_PATH = "/webexpose-%d-does-not-exist.txt"


def check_exposed_files(client: Client, base_url: str, delay: float = 0.2) -> List[Finding]:
    out: List[Finding] = []
    # Detect "soft 404" sites that return 200 + the same page for every path.
    baseline = client.get(urljoin(base_url, SOFT_404_PATH % int(time.time())))
    baseline_body = baseline.body if baseline.status == 200 else None

    for probe in PROBES:
        resp = client.get(urljoin(base_url, probe.path), follow=False)
        if delay:
            time.sleep(delay)
        if resp.status != 200 or not resp.body:
            continue
        if baseline_body is not None and resp.body == baseline_body:
            continue
        if probe.validate(resp.body):
            out.append(Finding("exposure", probe.severity, probe.title,
                               "%s returned %d bytes" % (probe.path, len(resp.body)), probe.fix))
    if not out:
        out.append(Finding("exposure", "pass", "No common sensitive files exposed (%d checked)" % len(PROBES)))

    sec = client.get(urljoin(base_url, "/.well-known/security.txt"), follow=True)
    if sec.status == 200 and b"Contact:" in sec.body:
        out.append(Finding("exposure", "pass", "security.txt present"))
    else:
        out.append(Finding("exposure", "info", "No /.well-known/security.txt",
                           "Researchers have no official way to report vulnerabilities to you.",
                           "Publish one: https://securitytxt.org"))
    return out


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def check_cors(client: Client, url: str) -> List[Finding]:
    evil = "https://webexpose-cors-test.example"
    resp = client.get(url, headers={"Origin": evil}, read_body=False)
    acao = resp.header("Access-Control-Allow-Origin")
    creds = resp.header("Access-Control-Allow-Credentials").lower() == "true"
    if acao == evil and creds:
        return [Finding("cors", "high", "CORS reflects any Origin with credentials",
                        "Any website can read authenticated responses from this origin.",
                        "Only allow a fixed list of trusted origins.")]
    if acao == evil:
        return [Finding("cors", "medium", "CORS reflects arbitrary Origin",
                        fix="Only allow a fixed list of trusted origins.")]
    if acao == "*" and creds:
        return [Finding("cors", "medium", "CORS wildcard with credentials header",
                        fix="Do not combine '*' with Allow-Credentials.")]
    return [Finding("cors", "pass", "CORS does not reflect untrusted origins")]


def target_parts(url: str):
    parsed = urlparse(url if "://" in url else "https://" + url)
    return parsed.scheme or "https", parsed.hostname, parsed.port, \
        "%s://%s" % (parsed.scheme or "https", parsed.netloc)
