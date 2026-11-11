"""Walk a project, classify files and apply agent and crypto rules."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List

from .agent_rules import AGENT_RULES, INVISIBLE_RULE
from .crypto_rules import RULES as CRYPTO_RULES

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "vendor", "target",
}
TEXT_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rb", ".php",
    ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".swift", ".sh", ".bash", ".yml", ".yaml", ".json",
    ".toml", ".ini", ".conf", ".cfg", ".env", ".tf", ".pem", ".key", ".txt", ".md", ".mdc",
    ".prompt", ".properties", ".xml",
}
MCP_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp_settings.json"}
AGENT_NAMES = {
    "skill.md", "agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules",
    "copilot-instructions.md", "system_prompt.md", "system-prompt.md",
}
TEXT_NAMES = {"dockerfile", "makefile", ".env", "authorized_keys", "known_hosts",
              "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} | MCP_NAMES | AGENT_NAMES
MAX_BYTES = 1_000_000
IGNORE = "agentcrypt: ignore"
SNIP = 160


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    kind: str        # "agent" or "crypto"
    file: str
    line: int
    snippet: str
    why: str
    fix: str


@dataclass
class Result:
    root: str
    files_scanned: int = 0
    agent_files: int = 0
    mcp_files: int = 0
    files_skipped: int = 0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        return d


def classify(rel: str, text: str = "") -> str:
    """Return 'mcp', 'agent' or 'code' for a relative POSIX path."""
    p = rel.lower()
    name = p.rsplit("/", 1)[-1]
    if name in MCP_NAMES or p.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
        return "mcp"
    if name.endswith(".json") and '"mcpservers"' in text.lower():
        return "mcp"
    if name in AGENT_NAMES or name.endswith((".prompt", ".prompt.md")):
        return "agent"
    if "/.cursor/rules/" in "/" + p or "/.github/instructions/" in "/" + p:
        return "agent"
    if ("/skills/" in "/" + p or "/.claude/" in "/" + p) and name.endswith(".md"):
        return "agent"
    return "code"


def _candidate(path: Path) -> bool:
    n = path.name.lower()
    return path.suffix.lower() in TEXT_EXT or n in TEXT_NAMES


def _iter(root: Path, exclude: Iterable[str]):
    if root.is_file():
        yield root, root.name
        return
    ex = [e.strip("/").replace("\\", "/") for e in exclude if e.strip("/")]
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            full = Path(dp) / fn
            rel = full.relative_to(root).as_posix()
            if any(rel == e or rel.startswith(e + "/") or e in rel.split("/") for e in ex):
                continue
            yield full, rel


def _snip(line: str) -> str:
    s = line.strip()
    return s if len(s) <= SNIP else s[: SNIP - 3] + "..."


def scan_text(text: str, rel: str) -> List[Finding]:
    kind = classify(rel, text)
    out: List[Finding] = []
    for no, line in enumerate(text.splitlines(), start=1):
        if IGNORE in line.lower():
            continue
        if kind in ("agent", "mcp"):
            for r in AGENT_RULES:
                if r.scope == "mcp" and kind != "mcp":
                    continue
                if r.pattern.search(line):
                    out.append(Finding(r.rule_id, r.title, r.severity, "agent", rel, no, _snip(line), r.why, r.fix))
            if INVISIBLE_RULE.pattern.search(line):
                shown = INVISIBLE_RULE.pattern.sub(lambda m: "<U+%04X>" % ord(m.group()), line)
                r = INVISIBLE_RULE
                out.append(Finding(r.rule_id, r.title, r.severity, "agent", rel, no, _snip(shown), r.why, r.fix))
        for r in CRYPTO_RULES:
            if r.pattern.search(line):
                out.append(Finding(r.rule_id, r.title, r.severity, "crypto", rel, no, _snip(line), r.why, r.fix))
    if kind == "mcp":
        out.extend(check_mcp_servers(text, rel))
    return out


LAUNCHERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "yarn"}


def _pinned(pkg: str) -> bool:
    if "==" in pkg or pkg.startswith(("./", "/", "file:")):
        return True
    body = pkg[1:] if pkg.startswith("@") else pkg
    return "@" in body


def check_mcp_servers(text: str, rel: str) -> List[Finding]:
    """AG005 for MCP servers started through a package runner without a pinned version."""
    from .agent_rules import AGENT_RULES as _AR
    rule = next(r for r in _AR if r.rule_id == "AG005")
    try:
        data = json.loads(text)
    except ValueError:
        return []
    servers = {}
    if isinstance(data, dict):
        for key in ("mcpServers", "servers"):
            if isinstance(data.get(key), dict):
                servers.update(data[key])
    out = []
    lines = text.splitlines()
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", "")).rsplit("/", 1)[-1].lower()
        args = [str(a) for a in cfg.get("args", []) if isinstance(a, (str, int))]
        if cmd not in LAUNCHERS:
            continue
        pkgs = [a for a in args if not a.startswith("-") and a not in ("dlx", "exec", "run")]
        if not pkgs or _pinned(pkgs[0]):
            continue
        pkg = pkgs[0]
        line_no = next((i + 1 for i, l in enumerate(lines) if '"%s"' % pkg in l), 1)
        out.append(Finding(rule.rule_id, rule.title, rule.severity, "agent", rel, line_no,
                           _snip(f'server "{name}": {cmd} {pkg} (no version pinned)'), rule.why, rule.fix))
    return out


def scan_path(path: str, exclude: Iterable[str] = ()) -> Result:
    root = Path(path).resolve()
    res = Result(root=str(root))
    for full, rel in _iter(root, exclude):
        if not _candidate(full):
            res.files_skipped += 1
            continue
        try:
            if full.stat().st_size > MAX_BYTES:
                res.files_skipped += 1
                continue
            raw = full.read_bytes()
        except OSError:
            res.files_skipped += 1
            continue
        if b"\x00" in raw[:4096]:
            res.files_skipped += 1
            continue
        text = raw.decode("utf-8", errors="replace")
        res.files_scanned += 1
        k = classify(rel, text)
        if k == "agent":
            res.agent_files += 1
        elif k == "mcp":
            res.mcp_files += 1
        res.findings.extend(scan_text(text, rel))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    res.findings.sort(key=lambda f: (order.get(f.severity, 9), f.kind, f.file, f.line))
    return res
