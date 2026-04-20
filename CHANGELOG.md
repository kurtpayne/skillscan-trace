# Changelog

All notable changes to `skillscan-trace` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-04-20

### Added
- `-h` help shorthand and `--version` flag
- Verdict banner (MALICIOUS/REVIEW/BENIGN) in CLI output
- PRIVACY.md with data flow documentation
- Bash AST analysis via bashlex (6 BASH-* rule IDs)
- Multi-mode Docker image (run + serve)
- release-docker.yml for automated multi-arch builds

### Fixed
- Version strings unified to single source (was 3 different values)
- `models` command crash on unavailable provider
- mypy errors in canary server and CLI
- README: removed Anthropic as provider, nonexistent doc references

---

## [Unreleased]

---

## [0.2.0] — 2026-03-17

### Added
- **Rich verdict banner** (A7): `skillscan-trace run` now emits a color-coded verdict panel at the end of each trace — green `CLEAN`, yellow `WARN`, red `BLOCK` — with finding count, severity max, and duration. Mirrors the `skillscan` terminal UX.
- **Full Python 3.13 CI matrix**: CI now tests 3.11, 3.12, and 3.13 on every push.
- **`PULL_REQUEST_TEMPLATE.md`**: contributor checklist covering ruff, mypy, pytest, provider verification, and no-debug-code requirements.
- **`CHANGELOG.md`**: this file.

### Changed
- License corrected from MIT to Apache-2.0 (matches `pyproject.toml` and `LICENSE`).
- Default Ollama example model updated from `qwen2.5:7b` (insufficient tool-calling support) to `llama3.1:8b` (verified tool-calling support).

---

## [0.1.0] — 2026-03-01

### Added
- Core CLI: `skillscan-trace run`, `skillscan-trace check`, `skillscan-trace jobs list/get/cancel`.
- Instrumented MCP server intercepting all tool calls with canary taxonomy checks.
- Providers: Ollama (local), OpenAI, OpenRouter, Anthropic, and any OpenAI-compatible base URL.
- Output formats: JSON trace report, SARIF 2.1.0, human-readable text summary.
- Canary taxonomy: credential files, wallet paths, ENV vars, binary probing, network destinations.
- 144 tests across all phases.

[Unreleased]: https://github.com/kurtpayne/skillscan-trace/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kurtpayne/skillscan-trace/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kurtpayne/skillscan-trace/releases/tag/v0.1.0
