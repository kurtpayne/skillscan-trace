# skillscan-trace

[![CI](https://github.com/kurtpayne/skillscan-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/kurtpayne/skillscan-trace/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/skillscan-trace.svg)](https://pypi.org/project/skillscan-trace/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Behavioral execution engine for MCP-based AI agent skills.**

skillscan-trace runs a skill against a real language model inside an instrumented, isolated environment and records everything the model does: every file it reads, every network request it makes, every environment variable it accesses, every binary it probes. The output is a structured, machine-readable trace report.

It is the dynamic analysis counterpart to [skillscan](https://github.com/kurtpayne/skillscan-security), which performs static analysis. Together they form two legs of the skillscan family:

```
skillscan family
├── skillscan        — static analysis (pattern matching, ML classifier)
├── skillscan-trace  — behavioral execution engine  ← this repo
└── skillscan-lint   — schema and format validation (planned)
```

---

## What it does

A skill is a Markdown file that becomes a system prompt for an AI agent. Most skills are benign. Some are malicious — they instruct the agent to exfiltrate credentials, probe the filesystem, call attacker-controlled servers, or hijack the agent's behavior through prompt injection embedded in tool output.

Static analysis catches the obvious cases. Behavioral analysis catches the rest: conditional payloads that only activate in certain environments, obfuscated instructions that decode at runtime, and prompt injection delivered through external content the skill fetches.

skillscan-trace works by:

1. Loading the skill's `SKILL.md` as the system prompt for a local language model
2. Sending a realistic user prompt that exercises the skill's stated functionality
3. Driving the model's tool-use loop through an **instrumented MCP server** that intercepts every tool call
4. Checking each call against a canary taxonomy (credential files, wallet paths, ENV vars, binary probing, network destinations)
5. Emitting a structured trace report (JSON + SARIF) with every observed behavior and any findings

The model runs locally via [Ollama](https://ollama.com/) — no API key required, no cloud dependency. API providers (OpenAI, OpenRouter, Anthropic) are supported for users who prefer them or want access to more capable models.

---

## Status

**v0.1.0 — core CLI complete.** Phases 1–5 are implemented and 144/144 tests pass. The tool is installable and usable today.

See [`SPEC.md`](./SPEC.md) for the full behavioral specification.  
See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the system design.  
See [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) for the build plan and phase status.

---

## Quick start

```bash
# Install from source
git clone https://github.com/kurtpayne/skillscan-trace
cd skillscan-trace
pip install -e .

# Run a trace with OpenAI
export OPENAI_API_KEY=sk-...
skillscan-trace run ./path/to/skill/

# Run with OpenRouter (200+ models via one key)
export OPENROUTER_API_KEY=sk-or-...
skillscan-trace run ./skill/ --provider openrouter --model mistralai/mistral-7b-instruct

# Run with a local Ollama model (no API key required)
skillscan-trace run ./skill/ --provider ollama --model qwen2.5:7b

# Run with explicit base URL (Azure, Mistral, etc.)
skillscan-trace run ./skill/ --base-url https://api.mistral.ai/v1 --api-key $MISTRAL_KEY

# Output formats
skillscan-trace run ./skill/ --format sarif   # SARIF 2.1.0 for CI
skillscan-trace run ./skill/ --format json    # native trace format
skillscan-trace run ./skill/ --format text    # human-readable summary

# Verify connectivity
skillscan-trace check
skillscan-trace check --provider openrouter
skillscan-trace check --provider ollama
```

---

## Skill format support

skillscan-trace handles all skill formats found in the wild:

| Format | Description | Example |
|---|---|---|
| Single `SKILL.md` | Standard Claude Code / MCP skill | `./my-skill/SKILL.md` |
| Single `.md` file | Flat file, no directory | `./my-skill.md` |
| Directory with `SKILL.md` | Standard with supporting files | `./my-skill/` |
| Frontmatter + body | YAML frontmatter + Markdown body | `name:`, `allowed-tools:` |
| Plain Markdown | No frontmatter | Any `.md` file |
| Multi-file skill | Directory with multiple `.md` files | Loaded in alphabetical order |

---

## Output: Trace Report

Every trace produces a JSON trace report and optionally a SARIF report.

```json
{
  "schema_version": "1.0.0",
  "trace_id": "trc_20260320_abc123",
  "skill": {
    "path": "./my-skill/SKILL.md",
    "name": "git-helper",
    "sha256": "a1b2c3..."
  },
  "model": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "version": "..."
  },
  "prompt": "Help me commit my changes",
  "duration_ms": 4823,
  "tool_calls": [...],
  "findings": [...],
  "summary": {
    "total_tool_calls": 7,
    "finding_count": 1,
    "severity_max": "HIGH",
    "clean": false
  }
}
```

---

## Relationship to skillscan-security

skillscan-trace is a sibling project to [skillscan-security](https://github.com/kurtpayne/skillscan-security). The two projects share:

- **Finding schema**: The same finding IDs (`EXF-001`, `MAL-001`, `IOC-001`, etc.) and severity levels
- **Canary taxonomy**: The same list of high-value target paths and ENV var names
- **Domain allowlist**: `trace/domains/verified.yml` from skillscan-security is the source of truth; skillscan-trace consumes it
- **Corpus feedback loop**: Traces that produce findings can be reviewed and added to the skillscan-security corpus as `sandbox_verified/` examples, improving the ML classifier's recall on behavioral patterns that static analysis misses

---

## Privacy & Key Handling

Your API key goes directly to the LLM provider you chose. The canary server runs in-process on your machine. Nothing leaves your network except the LLM API calls you explicitly authorize. SkillScan has no server-side component in local mode.

See [`PRIVACY.md`](./PRIVACY.md) for the full data flow explanation.

---

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

---

## License

MIT
