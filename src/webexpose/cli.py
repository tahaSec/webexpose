"""Command line interface: ``webexpose example.com``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import __version__
from .checks import SEVERITY_ORDER
from .http import Client
from .scanner import Report, scan

C = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m",
     "info": "\033[37m", "pass": "\033[32m", "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m"}
GRADE_COLOR = {"A+": "pass", "A": "pass", "B": "medium", "C": "medium", "D": "high", "F": "critical", "?": "info"}
ICON = {"pass": "✔", "info": "i", "low": "!", "medium": "!", "high": "✖", "critical": "✖"}

NOTICE = ("Only scan websites you own or have written permission to test. "
          "webexpose sends ~25 ordinary GET requests and never tries to exploit anything.")


def _color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


def render_text(report: Report, verbose: bool) -> str:
    c = C if _color() else {k: "" for k in C}
    lines = []
    g = report.grade
    lines.append("%s%s%s" % (c["bold"], report.target, c["reset"]))
    if report.error:
        lines.append("  %s" % report.error)
        return "\n".join(lines)
    lines.append("  final URL: %s (HTTP %d)" % (report.final_url, report.status))
    lines.append("  grade: %s %s %s  score %d/100\n" % (c[GRADE_COLOR[g]], g, c["reset"], report.score))
    shown = report.findings if verbose else [f for f in report.findings if f.severity != "pass"]
    for f in sorted(shown, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check)):
        lines.append("  %s%s %-8s%s [%s] %s" % (c[f.severity], ICON[f.severity], f.severity.upper(),
                                               c["reset"], f.check, f.title))
        if f.detail:
            lines.append("      %s%s%s" % (c["dim"], f.detail, c["reset"]))
        if f.fix and f.severity != "pass":
            lines.append("      fix: %s" % f.fix)
    passed = sum(1 for f in report.findings if f.severity == "pass")
    if not verbose and passed:
        lines.append("  %s%d check(s) passed (use -v to show them)%s" % (c["pass"], passed, c["reset"]))
    return "\n".join(lines)


def render_markdown(reports: List[Report]) -> str:
    out = ["# webexpose report\n"]
    for r in reports:
        out.append("## %s - grade **%s** (%d/100)\n" % (r.target, r.grade, r.score))
        if r.error:
            out.append("Error: %s\n" % r.error)
            continue
        out.append("| Severity | Area | Finding | Fix |\n|---|---|---|---|")
        for f in sorted(r.findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
            out.append("| %s | %s | %s | %s |" % (f.severity, f.check, f.title.replace("|", "\\|"),
                                                 f.fix.replace("|", "\\|")))
        out.append("")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="webexpose",
                                description="Quick security check for your own website.",
                                epilog=NOTICE)
    p.add_argument("targets", nargs="+", help="domain or URL, e.g. example.com or https://example.com")
    p.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("-v", "--verbose", action="store_true", help="also show passed checks")
    p.add_argument("--no-paths", action="store_true", help="skip the exposed-files probes")
    p.add_argument("--no-tls", action="store_true", help="skip certificate / protocol checks")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--delay", type=float, default=0.2, help="seconds between path probes (default 0.2)")
    p.add_argument("--fail-under", default=None, metavar="GRADE",
                   help="exit 1 if any grade is worse than this (e.g. B). Useful in CI.")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


ORDER = ["F", "D", "C", "B", "A", "A+"]


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass
    client = Client(timeout=args.timeout)
    reports = []
    for t in args.targets:
        if args.format == "text":
            print("scanning %s ..." % t, file=sys.stderr)
        reports.append(scan(t, client=client, paths=not args.no_paths, tls=not args.no_tls,
                            delay=args.delay))

    if args.format == "json":
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(render_markdown(reports))
    else:
        print("\n\n".join(render_text(r, args.verbose) for r in reports))

    if any(r.error for r in reports):
        return 2
    if args.fail_under:
        want = args.fail_under.upper()
        if want not in ORDER:
            print("webexpose: unknown grade %r" % args.fail_under, file=sys.stderr)
            return 2
        if any(ORDER.index(r.grade) < ORDER.index(want) for r in reports):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
