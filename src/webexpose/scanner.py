"""Run all checks against one target and grade the result."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import List

from . import checks
from .checks import PENALTY, SEVERITY_ORDER, Finding
from .http import Client

GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]


@dataclass
class Report:
    target: str
    final_url: str = ""
    status: int = 0
    scanned_at: str = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"))
    findings: List[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def score(self) -> int:
        return max(0, 100 - sum(PENALTY[f.severity] for f in self.findings))

    @property
    def grade(self) -> str:
        if self.error:
            return "?"
        if any(f.severity == "critical" for f in self.findings):
            return "F"
        return next(g for limit, g in GRADES if self.score >= limit)

    def issues(self) -> List[Finding]:
        return [f for f in self.findings if f.severity not in ("pass",)]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "status": self.status,
            "scanned_at": self.scanned_at,
            "grade": self.grade,
            "score": self.score,
            "error": self.error or None,
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: -SEVERITY_ORDER[f.severity])],
        }


def scan(target: str, client: Client = None, paths: bool = True, tls: bool = True,
         delay: float = 0.2) -> Report:
    client = client or Client()
    scheme, host, port, base = checks.target_parts(target)
    report = Report(target=base)
    if not host:
        report.error = "invalid target: %r" % target
        return report

    resp = client.get(base + "/")
    if resp.status == 0 and scheme == "https":
        # Fall back to http so we can at least report that HTTPS is broken.
        fallback = client.get("http://%s%s/" % (host, ":%d" % port if port else ""))
        if fallback.status:
            report.findings.append(Finding("https", "high", "HTTPS is not available",
                                           resp.error or "", "Enable HTTPS (Let's Encrypt is free)."))
            resp = fallback
    if resp.status == 0:
        report.error = "could not connect: %s" % resp.error
        return report

    report.final_url = resp.url
    report.status = resp.status
    report.findings += checks.check_headers(resp)
    report.findings += checks.check_cookies(resp)
    report.findings += checks.check_cors(client, resp.url)

    if resp.url.startswith("https://"):
        report.findings += checks.check_https_redirect(client, host)
        if tls:
            report.findings += checks.check_tls(host, port or 443, client.timeout)
    elif not any(f.title == "HTTPS is not available" for f in report.findings):
        report.findings.append(Finding("https", "high", "Site is served over plain HTTP",
                                       fix="Enable HTTPS and redirect HTTP to it."))

    if paths:
        base_final = resp.url.split("/", 3)
        root = "/".join(base_final[:3]) + "/"
        report.findings += checks.check_exposed_files(client, root, delay=delay)
    return report
