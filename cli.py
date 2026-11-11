"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .report import json_report, sarif_report, text_report
from .scanner import scan_path

LEVELS = {"none": 99, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="agentcrypt", description="Scan AI agent configs and code for agent risks and quantum-vulnerable cryptography.")
    p.add_argument("--version", action="version", version=f"agentcrypt-scan {__version__}")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    s.add_argument("--exclude", action="append", default=[], help="skip a directory or relative path (repeatable)")
    s.add_argument("--only", choices=["agent", "crypto"], help="report only one kind of finding")
    s.add_argument("--fail-on", choices=list(LEVELS), default="high")
    a = p.parse_args(argv)
    if a.cmd != "scan":
        p.print_help()
        return 2
    if not Path(a.path).exists():
        print(f"error: path not found: {a.path}", file=sys.stderr)
        return 2
    res = scan_path(a.path, a.exclude)
    if a.only:
        res.findings = [f for f in res.findings if f.kind == a.only]
    out = {"text": text_report, "json": json_report, "sarif": sarif_report}[a.format](res)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"Report written to {a.output}")
    else:
        sys.stdout.write(out)
    threshold = LEVELS[a.fail_on]
    worst = max((LEVELS[f.severity] for f in res.findings), default=-1)
    return 1 if worst >= threshold else 0
