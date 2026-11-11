"""Rules for AI agent configuration files.

These rules look at the files that tell an AI agent what it can do: MCP server
configs, agent skills (SKILL.md), agent instruction files (AGENTS.md,
CLAUDE.md, .cursorrules) and prompt files. They target tool poisoning, hidden
instructions, risky server launches and secrets in config.

Patterns are heuristics. They can miss attacks and can flag harmless text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentRule:
    rule_id: str
    title: str
    severity: str
    pattern: "re.Pattern[str]"
    why: str
    fix: str
    scope: str = "agent"  # "agent" files only, or "mcp" config files only


def _r(rule_id, title, severity, pattern, why, fix, scope="agent"):
    return AgentRule(rule_id, title, severity, re.compile(pattern, re.IGNORECASE), why, fix, scope)


AGENT_RULES = [
    _r(
        "AG001",
        "Hidden or overriding instruction",
        "high",
        r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts)"
        r"|disregard (the |all )?(system|previous) (prompt|instructions)"
        r"|do not (tell|inform|mention (this )?to) the user"
        r"|without (telling|informing|asking) the user"
        r"|<\s*important\s*>|\[\s*system\s*\]\s*:"
        r"|you must (always )?(first )?(read|send|call|run) .{0,40}(before|regardless)",
        "Tool descriptions, skills and instruction files are read by the model as trusted text. "
        "Phrases that override instructions or hide actions from the user are the core of tool poisoning.",
        "Remove the instruction or the tool. Only install skills and MCP servers whose full text you have reviewed.",
    ),
    _r(
        "AG002",
        "Reference to secrets or credential files",
        "high",
        r"~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.env\b|\.npmrc|\.pypirc"
        r"|\.git-credentials|\.kube/config|mcp\.json|claude_desktop_config\.json",
        "An agent file that points the model at credential files can be used to read and leak them.",
        "Agent instructions should never mention credential paths. Restrict file access for the agent.",
    ),
    _r(
        "AG003",
        "Possible data exfiltration step",
        "high",
        r"(curl|wget|invoke-webrequest|fetch)\b.{0,80}(\$\(|`|base64|--data|-d\s|@)"
        r"|send (it|them|the (file|contents|key|token|data)) to https?://"
        r"|(post|upload) .{0,40}to https?://",
        "Instructions that send local data to a URL are a common way to exfiltrate secrets through an agent.",
        "Remove the step. Agents should not send local files or secrets to external URLs.",
    ),
    _r(
        "AG005",
        "MCP server launched from an unpinned package or remote script",
        "medium",
        r"curl\s+[^|]+\|\s*(ba)?sh|iwr\s+[^|]+\|\s*iex",
        "An unpinned package runs whatever version is newest, so a compromised release reaches you silently.",
        "Pin an exact version (for example package@1.4.2) and review updates before upgrading.",
        scope="agent",
    ),
    _r(
        "AG006",
        "Secret value written directly in agent config",
        "critical",
        r"\b(sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
        r"|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})",
        "Config files are often shared, synced or committed. A live key in them can be stolen and used.",
        "Move the key to an environment variable or a secret manager and rotate the exposed key.",
    ),
    _r(
        "AG007",
        "Remote MCP server over plain HTTP",
        "medium",
        r"\"(url|serverUrl|endpoint)\"\s*:\s*\"http://(?!localhost|127\.0\.0\.1|\[::1\])",
        "Traffic to a remote MCP server over HTTP can be read or changed on the network, including tool results.",
        "Use https:// for every remote MCP server.",
        scope="mcp",
    ),
    _r(
        "AG008",
        "Tool calls approved automatically",
        "medium",
        r"\"(autoApprove|alwaysAllow|auto_approve|autoApproveAll)\"\s*:\s*(true|\[\s*\"\*\"|\[\s*\")"
        r"|--dangerously-skip-permissions|\"yolo\"\s*:\s*true",
        "Auto-approval removes the human check, so a poisoned tool result can trigger actions without review.",
        "Keep approval on for tools that write, send, delete or run commands.",
    ),
]

# Invisible characters that can hide instructions from a human reviewer while
# the model still reads them: zero-width characters, bidi controls and the
# Unicode "tag" block (U+E0000 to U+E007F).
INVISIBLE_RE = re.compile(
    "[​‌‍⁠﻿‪-‮⁦-⁩]|[\U000E0000-\U000E007F]"
)

INVISIBLE_RULE = AgentRule(
    "AG004",
    "Invisible or direction-changing characters",
    "high",
    INVISIBLE_RE,
    "Zero-width, bidi and Unicode tag characters can hide text that the model reads but a reviewer does not see.",
    "Delete the characters, then re-read the file. Treat a skill or tool that contained them as untrusted.",
)

ALL_AGENT_RULES = AGENT_RULES + [INVISIBLE_RULE]
