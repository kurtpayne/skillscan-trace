# Contributing to skillscan-trace

## Context

skillscan-trace is the behavioral execution engine in the SkillScan family. It is a sibling project to [skillscan-security](https://github.com/kurtpayne/skillscan-security), which contains the static analyzer, ML classifier, and skill corpus.

If you are picking up this project for the first time, read these documents in order:

1. [`README.md`](./README.md) — what the tool does and why
2. [`SPEC.md`](./SPEC.md) — the complete behavioral specification (authoritative)
3. [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design and component overview
4. [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) — ordered build plan with acceptance criteria
5. [`skillscan-security/docs/TRACE_RESEARCH.md`](https://github.com/kurtpayne/skillscan-security/blob/main/docs/TRACE_RESEARCH.md) — research notes on prior art, canary taxonomy, and domain allowlist design

## Repository relationship

The two repos share artifacts. When working on skillscan-trace, you may need to reference or update:

| Artifact | Location | Notes |
|---|---|---|
| Canary taxonomy | `skillscan-security/docs/TRACE_RESEARCH.md` | Source of truth for what to detect |
| Domain allowlist | `skillscan-security/trace/domains/verified.yml` | Bundled into skillscan-trace at build time |
| Finding ID namespace | `skillscan-security/src/skillscan/rules/` | Finding IDs must not conflict |
| Skill corpus | `skillscan-security/corpus/` | Used for integration tests and batch tracing |

## Development setup

```bash
git clone https://github.com/kurtpayne/skillscan-trace
cd skillscan-trace
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Verify Ollama is running
ollama serve &
ollama pull qwen2.5:7b

# Run tests
pytest
```

## Implementation guidance

The `IMPLEMENTATION_PLAN.md` defines 10 milestones in dependency order. Start with Milestone 1 (instrumented MCP server) — it is the novel component with no prior art and everything else depends on it.

The MCP server should be testable standalone before the agent harness exists. Write a simple test client that sends tool calls directly to the server and verifies the interceptor behavior. This avoids needing a running model for unit tests.

The agent harness uses the OpenAI-compatible API that Ollama exposes at `http://localhost:11434/v1`. The same harness code works with real OpenAI/Anthropic models by changing the `base_url`. Do not write model-specific integration code.

## Testing

Every interceptor must have unit tests. The integration test suite runs known-malicious and known-benign skills through the full pipeline. The skillscan-security corpus provides the test cases — clone it alongside this repo and set `SKILLSCAN_CORPUS_PATH` to point at it.

```bash
export SKILLSCAN_CORPUS_PATH=../skillscan-security/corpus
pytest tests/integration/
```

## Design constraints

**No GPU required.** The default path must work on a laptop with 8GB RAM and no GPU. Do not add GPU-only dependencies to the core package.

**No API key required by default.** Ollama is the zero-friction path. API model support is a configuration option, not the default.

**Low compliance model.** The default model (`qwen2.5:7b`) is chosen for its low refusal rate, not its safety properties. This is intentional — see SPEC.md Section 4.1 for the rationale.

**Structured output first.** Every trace produces a machine-readable JSON report. Human-readable text is a formatting layer on top. Do not design the data model around the text output.

## Versioning

skillscan-trace follows semantic versioning. The v1.0 milestone is defined by the acceptance criteria in `IMPLEMENTATION_PLAN.md`. Breaking changes to the trace report schema require a major version bump.
