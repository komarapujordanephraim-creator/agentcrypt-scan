"""Text, JSON and SARIF output."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__

DISCLAIMER = (
    "AgentCrypt Scan is pattern-based. It can miss real issues and can flag harmless text. "
    "A clean result does not prove that an agent setup or codebase is safe. Use it as a starting "
    "point for review, not as a substitute for a security assessment."
)
SEV = ["critical", "high", "medium", "low", "info"]


def summarize(res):
    by = Counter(f.severity for f in res.findings)
    kinds = Counter(f.kind for f in res.findings)
    if by["critical"] or by["high"]:
        verdict = "Action needed"
    elif any(f.severity != "info" for f in res.findings):
        verdict = "Review recommended"
    else:
        verdict = "No findings from this rule set"
    return {
        "total": len(res.findings),
        "by_severity": {s: by.get(s, 0) for s in SEV},
        "agent_findings": kinds.get("agent", 0),
        "crypto_findings": kinds.get("crypto", 0),
        "verdict": verdict,
    }


def text_report(res) -> str:
    s = summarize(res)
    lines = [
        f"AgentCrypt Scan {__version__}",
        f"Scanned: {res.root}",
        f"Files scanned: {res.files_scanned} (agent files: {res.agent_files}, MCP configs: {res.mcp_files})   Skipped: {res.files_skipped}",
        f"Findings: {s['total']} (agent: {s['agent_findings']}, crypto: {s['crypto_findings']})   Verdict: {s['verdict']}",
        "",
    ]
    for kind, label in (("agent", "AI agent configuration"), ("crypto", "Cryptography")):
        items = [f for f in res.findings if f.kind == kind]
        if not items:
            continue
        lines.append(f"== {label} ==")
        for f in items:
            lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.title}")
            lines.append(f"    {f.file}:{f.line}")
            lines.append(f"    {f.snippet}")
        lines.append("")
    lines.append(DISCLAIMER)
    return "\n".join(lines) + "\n"


def json_report(res) -> str:
    return json.dumps({
        "tool": "agentcrypt-scan",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(res),
        "disclaimer": DISCLAIMER,
        **res.to_dict(),
    }, indent=2)


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def sarif_report(res) -> str:
    """SARIF 2.1.0, readable by GitHub code scanning."""
    rules, seen = [], set()
    for f in res.findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rules.append({
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.why},
            "help": {"text": f.fix},
            "properties": {"tags": [f.kind, "security"], "severity": f.severity},
        })
    results = [{
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f"{f.title}: {f.snippet}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": f.line},
        }}],
    } for f in res.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentCrypt Scan",
                "version": __version__,
                "informationUri": "https://github.com/komarapujordanephraim-creator/agentcrypt-scan",
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)
