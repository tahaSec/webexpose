import datetime as dt
import json
import threading
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from webexpose import checks
from webexpose.checks import check_cookies, check_headers, parse_cert_date
from webexpose.cli import main
from webexpose.http import Client, Response
from webexpose.scanner import Report, scan


def make_resp(headers=None, cookies=(), url="https://example.com/"):
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return Response(url=url, status=200, headers=msg, set_cookies=list(cookies))


def titles(findings, severity=None):
    return {f.title for f in findings if severity is None or f.severity == severity}


GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


# --- headers -------------------------------------------------------------------

def test_good_headers_all_pass():
    found = check_headers(make_resp(GOOD_HEADERS))
    assert all(f.severity == "pass" for f in found), [f.title for f in found if f.severity != "pass"]


def test_missing_headers():
    found = check_headers(make_resp({}))
    t = titles(found)
    assert "Strict-Transport-Security missing" in t
    assert "Content-Security-Policy missing" in t
    assert "Clickjacking protection missing" in t
    assert "X-Content-Type-Options missing" in t


def test_hsts_not_required_on_http():
    found = check_headers(make_resp({}, url="http://example.com/"))
    assert "Strict-Transport-Security missing" not in titles(found)


def test_short_hsts():
    found = check_headers(make_resp({"Strict-Transport-Security": "max-age=300"}))
    assert any(t.startswith("HSTS max-age is short") for t in titles(found))


def test_weak_csp():
    resp = make_resp({"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval' *"})
    f = next(f for f in check_headers(resp) if f.title == "Content-Security-Policy is weak")
    assert "unsafe-inline" in f.detail and "unsafe-eval" in f.detail and "wildcard" in f.detail


def test_csp_nonce_allows_unsafe_inline_fallback():
    resp = make_resp({"Content-Security-Policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'"})
    assert "Content-Security-Policy is weak" not in titles(check_headers(resp))


def test_version_disclosure():
    resp = make_resp({"Server": "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.1"})
    t = titles(check_headers(resp), "low")
    assert any("Server header reveals version" in x for x in t)
    assert any("X-Powered-By header reveals version" in x for x in t)


# --- cookies -------------------------------------------------------------------

def test_insecure_session_cookie():
    found = check_cookies(make_resp(cookies=["PHPSESSID=abc; path=/"]))
    assert found[0].severity == "medium"
    assert "no Secure" in found[0].title and "no HttpOnly" in found[0].title


def test_secure_cookie_passes():
    found = check_cookies(make_resp(cookies=["sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]))
    assert found[0].severity == "pass"


def test_samesite_none_without_secure():
    found = check_cookies(make_resp(cookies=["x=1; HttpOnly; SameSite=None"], url="http://e.com/"))
    assert "SameSite=None without Secure" in found[0].title


# --- TLS helpers / grading ----------------------------------------------------

def test_parse_cert_date():
    d = parse_cert_date("Jan  5 12:00:00 2030 GMT")
    assert d == dt.datetime(2030, 1, 5, 12, 0, tzinfo=dt.timezone.utc)


def test_grade_critical_is_f():
    r = Report(target="x", findings=[checks.Finding("exposure", "critical", "x")])
    assert r.grade == "F"


def test_grade_perfect():
    r = Report(target="x", findings=[checks.Finding("headers", "pass", "ok")])
    assert r.grade == "A+" and r.score == 100


def test_target_parts():
    assert checks.target_parts("example.com")[1] == "example.com"
    assert checks.target_parts("http://127.0.0.1:8080/x")[2] == 8080


# --- end-to-end against a local test server ----------------------------------

ROUTES = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        route = ROUTES.get(self.path.split("?")[0])
        if route is None:
            if ROUTES.get("__soft404__"):
                route = (200, {"Content-Type": "text/html"}, b"<html>home page</html>")
            else:
                route = (404, {}, b"not found")
        status, headers, body = route
        self.send_response(status)
        for k, v in headers.items():
            if k == "Set-Cookie":
                for c in v:
                    self.send_header(k, c)
            else:
                self.send_header(k, v)
        origin = self.headers.get("Origin")
        if origin and ROUTES.get("__reflect_cors__"):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    ROUTES.clear()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()


def test_e2e_exposed_git_and_env(server):
    ROUTES["/"] = (200, {"Server": "nginx/1.18.0", "Set-Cookie": ["session=1; path=/"]}, b"hi")
    ROUTES["/.git/HEAD"] = (200, {}, b"ref: refs/heads/main\n")
    ROUTES["/.env"] = (200, {}, b"APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n")
    ROUTES["__reflect_cors__"] = True
    report = scan(server, client=Client(timeout=5), delay=0)
    t = titles(report.findings)
    assert "Git repository exposed (/.git/)" in t
    assert ".env file exposed (secrets!)" in t
    assert "Site is served over plain HTTP" in t
    assert "CORS reflects any Origin with credentials" in t
    assert report.grade == "F"


def test_e2e_soft_404_no_false_positives(server):
    ROUTES["/"] = (200, {}, b"<html>home page</html>")
    ROUTES["__soft404__"] = True
    report = scan(server, client=Client(timeout=5), delay=0)
    assert not any(f.check == "exposure" and f.severity in ("high", "critical") for f in report.findings)


def test_e2e_html_404_page_does_not_trigger_env_rule(server):
    ROUTES["/"] = (200, {}, b"ok")
    ROUTES["/.env"] = (200, {"Content-Type": "text/html"}, b"<html><body>Welcome</body></html>")
    report = scan(server, client=Client(timeout=5), delay=0)
    assert ".env file exposed (secrets!)" not in titles(report.findings)


def test_cli_json_and_unreachable(server, capsys):
    ROUTES["/"] = (200, dict(GOOD_HEADERS), b"ok")
    assert main([server, "-f", "json", "--delay", "0"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["grade"] in ("A+", "A", "B", "C", "D", "F")
    assert main(["http://127.0.0.1:1", "--timeout", "1"]) == 2


@pytest.fixture()
def tls_server(tmp_path):
    import shutil
    import socket
    import ssl
    import subprocess

    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "5", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    srv.settimeout(10)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], str(crt)
    srv.close()


def test_tls_self_signed_is_untrusted(tls_server):
    port, _ = tls_server
    found = checks.check_tls("localhost", port, timeout=5)
    assert found[0].severity == "critical"
    assert found[0].title == "TLS certificate is not trusted"


def test_tls_expiry_warning(tls_server, monkeypatch):
    import ssl

    port, crt = tls_server
    real = ssl.create_default_context
    monkeypatch.setattr(checks.ssl, "create_default_context", lambda *a, **k: real(cafile=crt))
    found = checks.check_tls("localhost", port, timeout=5)
    assert any(f.title.startswith("Certificate expires in") and f.severity == "high" for f in found), found
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30)
    found = checks.check_tls("localhost", port, timeout=5, now=later)
    assert any(f.title == "Certificate has expired" for f in found)
