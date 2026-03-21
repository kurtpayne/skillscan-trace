# skillscan-trace Architecture

**Status:** Pre-implementation design document  
**Last updated:** 2026-03-20

This document describes the system architecture for skillscan-trace v1.0. It is intended to give an implementing engineer (or agent) a complete picture of the system before writing any code.

---

## Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  skillscan-trace CLI                                            │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐  │
│  │  Skill       │    │  Trace Execution Engine              │  │
│  │  Resolver    │    │                                      │  │
│  │              │    │  ┌─────────────┐  ┌───────────────┐  │  │
│  │  - Detects   │───▶│  │  Agent      │  │  Instrumented │  │  │
│  │    format    │    │  │  Harness    │◀▶│  MCP Server   │  │  │
│  │  - Loads     │    │  │             │  │               │  │  │
│  │    content   │    │  │  - Loads    │  │  read_file ──▶│  │  │
│  │  - Computes  │    │  │    skill as │  │  write_file──▶│  │  │
│  │    SHA-256   │    │  │    system   │  │  bash ───────▶│  │  │
│  └──────────────┘    │  │    prompt   │  │  http_fetch──▶│  │  │
│                      │  │  - Sends    │  │               │  │  │
│  ┌──────────────┐    │  │    user     │  │  Each call:   │  │  │
│  │  Config      │    │  │    prompt   │  │  1. Log       │  │  │
│  │  Resolver    │    │  │  - Drives   │  │  2. Check     │  │  │
│  │              │    │  │    tool     │  │  3. Respond   │  │  │
│  │  - CLI flags │───▶│  │    loop     │  └───────┬───────┘  │  │
│  │  - config    │    │  └──────┬──────┘          │          │  │
│  │    .yml      │    │         │                 │          │  │
│  │  - verified  │    │  ┌──────▼─────────────────▼──────┐  │  │
│  │    .yml      │    │  │  Trace Log (in-memory)        │  │  │
│  └──────────────┘    │  │  Append-only list of events   │  │  │
│                      │  └──────────────┬────────────────┘  │  │
│  ┌──────────────┐    │                 │                    │  │
│  │  Canary      │    │  ┌──────────────▼────────────────┐  │  │
│  │  Filesystem  │    │  │  Analyzer + Report Emitter    │  │  │
│  │  Builder     │───▶│  │                               │  │  │
│  │              │    │  │  - Maps events to findings    │  │  │
│  │  - Creates   │    │  │  - Correlates sequences       │  │  │
│  │    tmpfs     │    │  │  - Emits JSON / SARIF / text  │  │  │
│  │  - Plants    │    │  └───────────────────────────────┘  │  │
│  │    canaries  │    │                                      │  │
│  └──────────────┘    └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
skillscan_trace/
├── __init__.py
├── cli.py                    # Click CLI entry point
├── config.py                 # Config resolution (CLI + config.yml + verified.yml)
├── resolver.py               # Skill format detection and loading
├── canary.py                 # Canary filesystem builder and manager
├── harness.py                # Agent harness (model driver, tool loop)
├── mcp_server.py             # Instrumented MCP server
├── interceptors/
│   ├── __init__.py
│   ├── file_interceptor.py   # read_file / write_file interception
│   ├── bash_interceptor.py   # bash command interception and parsing
│   ├── network_interceptor.py # http_fetch interception and allowlist
│   └── env_interceptor.py    # ENV var access detection
├── analyzer.py               # Trace log → findings
├── emitter.py                # Findings → JSON / SARIF / text
├── domains/
│   └── verified.yml          # Bundled domain allowlist (copied from skillscan-security)
└── schemas/
    ├── trace_report.json     # JSON Schema for trace report
    └── sarif_template.json   # SARIF 2.1.0 template
```

---

## Key Design Decisions

### 1. MCP Server as the interception layer

The instrumented MCP server is the central component. It implements the standard MCP tool interface but wraps every tool call with:

1. **Pre-call check:** Before executing the tool, check the inputs against the canary taxonomy and detection rules. Append a `tool_call_start` event to the trace log.
2. **Execution:** Execute the tool (or return a synthetic response).
3. **Post-call check:** After execution, check the outputs for injection patterns and canary value leakage. Append a `tool_call_end` event to the trace log.

The MCP server runs as a subprocess started by the agent harness. The harness connects to it via the MCP stdio transport.

### 2. Agent harness uses the OpenAI-compatible API

Ollama exposes an OpenAI-compatible API at `http://localhost:11434/v1`. The agent harness uses the `openai` Python SDK to drive the tool-use loop, with the model configured to point at the Ollama base URL. This means:

- The same harness code works with Ollama and with real OpenAI/Anthropic models (via their respective base URLs)
- No custom model integration code is needed per provider
- The tool-use loop is standard: send messages, receive tool_call response, execute tool via MCP server, append result, repeat

### 3. Canary filesystem is tmpfs-backed

The canary filesystem is created fresh for each trace run using Python's `tempfile.mkdtemp()`. On Linux, this can be backed by `tmpfs` for performance. The MCP server's `read_file` and `write_file` implementations are rooted at `$CANARY_ROOT` — path traversal outside this root is rejected.

The canary files are populated with realistic-looking but non-functional values. The values are randomized per run (using a seeded PRNG for reproducibility when `--seed` is specified) to prevent the model from learning to recognize specific canary patterns.

### 4. Trace log is append-only and in-memory

The trace log is an in-memory list of event dicts, appended to by the MCP server interceptors. At the end of the trace, the analyzer reads the complete log and produces findings. This design:

- Avoids I/O overhead during execution
- Preserves the full event sequence for correlation analysis (e.g., detecting that a network call followed a credential read)
- Is simple to serialize to JSON at the end

### 5. Bash interception is regex-first, AST-second

The `bash` tool interceptor uses a two-pass approach:

1. **Regex pass:** Check the full command string against a list of known-dangerous patterns. Fast, catches the obvious cases.
2. **Token pass:** Split the command into tokens and check each token against watchlists (binary names, path patterns, ENV var names). Catches cases the regex misses.

A full shell AST parser (`bashlex`) is more accurate but adds complexity and a dependency. It is a v1.1 upgrade.

---

## Data Flow

### Trace execution sequence

```
1. CLI parses arguments and resolves config
2. Skill resolver loads and validates skill content
3. Canary filesystem builder creates tmpfs and plants canary files
4. Instrumented MCP server starts as subprocess
5. Agent harness initializes:
   a. Loads skill content as system prompt
   b. Connects to MCP server
   c. Sends user prompt to model
6. Tool-use loop begins:
   a. Model responds with tool_call
   b. Harness sends tool call to MCP server
   c. MCP server interceptor:
      - Logs tool_call_start event
      - Checks inputs against canary taxonomy
      - Executes tool (or returns synthetic response)
      - Checks outputs for injection patterns
      - Logs tool_call_end event
   d. Harness appends tool result to message history
   e. Harness sends updated history to model
   f. Repeat until model responds without tool_call or max_turns reached
7. Trace log is finalized
8. Analyzer reads trace log and produces findings
9. Report emitter serializes findings to JSON / SARIF / text
10. Canary filesystem is cleaned up
11. MCP server subprocess is terminated
```

---

## External Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| `click` | ≥8.0 | CLI framework |
| `openai` | ≥1.0 | Model API client (Ollama-compatible) |
| `mcp` | ≥1.0 | MCP server SDK |
| `pyyaml` | ≥6.0 | YAML parsing (config, frontmatter) |
| `python-frontmatter` | ≥1.0 | Markdown frontmatter parsing |
| `jsonschema` | ≥4.0 | Trace report schema validation |
| `rich` | ≥13.0 | Terminal output formatting |
| `requests` | ≥2.0 | HTTP client for domain allowlist updates |

**Runtime requirements:**
- Python 3.11+
- [Ollama](https://ollama.com/) (for local model execution)
- Default model: `qwen2.5:7b` (pulled separately via `ollama pull qwen2.5:7b`)

**Optional:**
- Docker (for containerized execution with stronger isolation)

---

## Testing Strategy

### Unit tests

Each interceptor should have unit tests that verify:
- Canary paths are correctly detected
- Non-canary paths are not flagged
- Pattern matching covers the documented patterns
- Edge cases: path traversal, symlinks, relative paths

### Integration tests

The integration test suite runs a set of known-malicious and known-benign skills through the full trace pipeline and verifies:
- Malicious skills produce the expected findings
- Benign skills produce no findings (or only expected low-severity findings)
- The trace report schema is valid
- The SARIF output is valid

The skillscan-security corpus provides the test cases:
- `corpus/malicious/` → should produce findings
- `corpus/benign/` → should produce no findings
- `corpus/benchmark_injection/` → should produce PINJ findings

### Model-independent tests

The MCP server and interceptors should be testable without a running model. The test suite should include a mock agent harness that sends pre-scripted tool calls to the MCP server and verifies the interceptor behavior.

---

## Docker Image

The Docker image packages the full trace environment:

```dockerfile
FROM python:3.11-slim

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Pull default model
RUN ollama serve & sleep 5 && ollama pull qwen2.5:7b

# Install skillscan-trace
RUN pip install skillscan-trace

ENTRYPOINT ["skillscan-trace"]
```

The image is ~6GB (Python + Ollama + qwen2.5:7b model weights). It is published to Docker Hub as `skillscan/trace:latest`.

Users who want a smaller image can use the `--no-model` variant and mount a local Ollama socket.

---

## Batch Execution (Corpus Generation)

For batch trace runs against the full skillscan-security corpus, a Modal Labs script (`scripts/modal_trace_batch.py`) runs traces in parallel:

```python
import modal

app = modal.App("skillscan-trace-batch")

@app.function(
    gpu="L4",
    image=modal.Image.from_registry("skillscan/trace:latest"),
    timeout=300,
)
def run_trace(skill_path: str, prompt: str) -> dict:
    import subprocess
    result = subprocess.run(
        ["skillscan-trace", "run", skill_path, "--prompt", prompt, "--format", "json"],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)
```

Cost estimate: ~$0.006/trace on Modal L4 GPU. 1,000 traces/week ≈ $6/week.
