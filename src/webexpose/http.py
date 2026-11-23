"""Tiny HTTP client on top of urllib (no third-party dependencies)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Dict, List, Optional

from . import __version__

USER_AGENT = "webexpose/%s (+https://github.com/tahaSec/webexpose)" % __version__
MAX_BODY = 256 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: Message
    body: bytes = b""
    error: Optional[str] = None
    set_cookies: List[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        if self.headers is None:
            return default
        return self.headers.get(name, default) or default

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class Client:
    def __init__(self, timeout: float = 10.0, verify_tls: bool = True):
        self.timeout = timeout
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        https = urllib.request.HTTPSHandler(context=ctx)
        self._follow = urllib.request.build_opener(https)
        self._nofollow = urllib.request.build_opener(https, _NoRedirect())

    def get(self, url: str, follow: bool = True, headers: Optional[Dict[str, str]] = None,
            read_body: bool = True) -> Response:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "*/*")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        opener = self._follow if follow else self._nofollow
        try:
            resp = opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:  # 3xx (no-follow), 4xx, 5xx
            body = b""
            try:
                body = exc.read(MAX_BODY) if read_body else b""
            except Exception:  # pragma: no cover - network edge cases
                pass
            return Response(url=exc.geturl() or url, status=exc.code, headers=exc.headers, body=body,
                            set_cookies=exc.headers.get_all("Set-Cookie") or [] if exc.headers else [])
        except (urllib.error.URLError, OSError, ValueError) as exc:
            reason = getattr(exc, "reason", exc)
            return Response(url=url, status=0, headers=Message(), error=str(reason))
        with resp:
            body = resp.read(MAX_BODY) if read_body else b""
            return Response(url=resp.geturl(), status=resp.status, headers=resp.headers, body=body,
                            set_cookies=resp.headers.get_all("Set-Cookie") or [])
