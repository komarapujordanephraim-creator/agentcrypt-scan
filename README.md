# AgentCrypt Scan

One offline scan for two problems that usually need two different tools:

1. **AI agent configuration risks** in MCP server configs, agent skills (`SKILL.md`), instruction files (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`) and prompt files: tool poisoning, hidden instructions, invisible Unicode, secrets in config, unpinned MCP servers, auto-approved tools.
2. **Quantum-vulnerable and weak cryptography** in the same repository: RSA, ECC, Diffie-Hellman, weak hashes, small keys, old TLS and committed private keys (rule set from [QuantumShield](https://github.com/komarapujordanephraim-creator/quantumshield)).

No dependencies. Python 3.8+. Nothing is uploaded anywhere.

## Why one scan

Teams adding AI agents to a codebase now have new trusted text (tool descriptions, skills, prompts) next to old trusted code (keys, TLS, signatures). Both are supply-chain and inventory problems. AgentCrypt Scan reads the repository once and reports both, with SARIF output for GitHub code scanning.

## Quick start

```bash
git clone https://github.com/komarapujordanephraim-creator/agentcrypt-scan.git
cd agentcrypt-scan
python -m agentcrypt_scan scan examples/risky_agent
python -m agentcrypt_scan scan path/to/your/project --format sarif -o agentcrypt.sarif
```

Install as a command: `pip install -e .` then `agentcrypt scan .`

## Example output

Run on the deliberately unsafe demo in `examples/risky_agent` (all keys are fake):

```
Files scanned: 4 (agent files: 1, MCP configs: 1)   Skipped: 0
Findings: 10 (agent: 8, crypto: 2)   Verdict: Action needed

[CRITICAL] AG006 Secret value written directly in agent config   .cursor/mcp.json:6
[HIGH]     AG001 Hidden or overriding instruction                skills/pdf-helper/SKILL.md:7
[HIGH]     AG002 Reference to secrets or credential files        skills/pdf-helper/SKILL.md:7
[HIGH]     AG003 Possible data exfiltration step                 skills/pdf-helper/SKILL.md:8
[HIGH]     AG004 Invisible or direction-changing characters      skills/pdf-helper/SKILL.md:9
           Helpful tip:<U+200B><U+E0049><U+E0047><U+E004E>... keep answers short.
[MEDIUM]   AG005 server "notes": npx notes-mcp-server (no version pinned)
[MEDIUM]   AG007 Remote MCP server over plain HTTP
[MEDIUM]   AG008 Tool calls approved automatically
[HIGH]     QS001 RSA usage                                       src/tokens.py:4
[MEDIUM]   QS005 JWT/token signing with RSA, ECDSA or EdDSA      src/tokens.py:8
```

## Agent rules (v0.1)

| ID | Finding | Severity | Files |
|---|---|---|---|
| AG001 | Hidden or overriding instruction (ignore previous instructions, do not tell the user, `<IMPORTANT>` blocks) | high | agent, MCP |
| AG002 | Reference to credential files (`~/.ssh`, `.env`, `.aws/credentials`, MCP configs) | high | agent, MCP |
| AG003 | Possible data exfiltration (curl/wget with file upload, "send it to https://...") | high | agent, MCP |
| AG004 | Invisible characters: zero-width, bidi controls, Unicode tag block U+E0000-E007F (shown as `<U+XXXX>`) | high | agent, MCP |
| AG005 | MCP server started with `npx`/`uvx`/`bunx` without a pinned version, or `curl ... \| sh` | medium | agent, MCP |
| AG006 | Live-looking secret in config (OpenAI, Anthropic, GitHub, AWS, Slack, Google key formats) | critical | agent, MCP |
| AG007 | Remote MCP server over `http://` (localhost allowed) | medium | MCP |
| AG008 | Tool calls auto-approved (`autoApprove`, `alwaysAllow`, skip-permissions flags) | medium | agent, MCP |

Crypto rules QS001-QS011 and QS100 come from QuantumShield and run on every text file.

Agent rules only run on files recognised as agent files, so a security blog post that quotes "ignore previous instructions" in `docs/` is not flagged.

## Options

| Option | Meaning |
|---|---|
| `--format text\|json\|sarif` | Output format. SARIF 2.1.0 works with GitHub code scanning |
| `-o FILE` | Write the report to a file |
| `--only agent\|crypto` | Report one kind of finding |
| `--exclude NAME` | Skip a directory or path (repeatable) |
| `--fail-on LEVEL` | Exit 1 at this severity or higher. Default `high` |

Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage error. Add `agentcrypt: ignore` on a line you have reviewed.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: komarapujordanephraim-creator/agentcrypt-scan@main
  with:
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: agentcrypt.sarif
```

## Limitations (read this)

- Pattern-based, line by line. It does not run the agent, call MCP servers or follow data flow.
- It can miss attacks written in other words or languages, and it can flag harmless text.
- It reads files in the repository only, not MCP servers fetched at runtime or tool descriptions served by remote servers.
- A clean result does not prove an agent setup or codebase is safe.

## Tests

```bash
python -m unittest discover -s tests -v
```

19 tests cover file classification, every agent rule, the ignore marker, crypto detection, JSON and SARIF shape, and CLI exit codes.

## License

MIT. Copyright (c) 2026 Komarapu Jordan Ephraim.
