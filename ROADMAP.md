# skillscan-trace Roadmap

**Last updated:** 2026-03-28

skillscan-trace is a behavioral execution engine for MCP-based AI agent skills. The core CLI is complete (v0.1.0, 176 tests passing). This roadmap covers the path from current state to public open-source release and an optional hosted scan service.

---

## Phase A — Public Release Readiness (✅ Complete)

All Phase A items are done. The repo is ready to go public.

| Item | Description | Status |
|---|---|---|
| A1 | `--provider` shortcut (openrouter, ollama, openai) + env var resolution | ✅ Done |
| A2 | Three-tier config system (CLI > env/.env > skillscan-trace.yaml > defaults) | ✅ Done |
| A3 | `PRIVACY.md` — plain-language key handling and data flow explanation | ✅ Done |
| A4 | Docker image with `run` mode and `serve` mode + docker-compose.yml | ✅ Done |
| A5 | Bash AST upgrade (`bashlex`) — catches obfuscation the regex misses | ✅ Done |
| A6 | Fix stale docs (ROADMAP, README, IMPLEMENTATION_PLAN version table) | ✅ Done |

**A1 — Provider UX.** `--provider openrouter | ollama | openai` on `run` and `check` commands. Env var resolution: `OPENROUTER_API_KEY` for OpenRouter, no key for Ollama. `--api-key` and `--base-url` still work as overrides.

**A2 — Config system.** Three-tier priority: CLI flags > env vars / .env > skillscan-trace.yaml > built-in defaults. API keys intentionally excluded from YAML config.

**A3 — Privacy.** `PRIVACY.md` committed. Plain language: API key goes directly to the provider you chose; canary server runs in-process; nothing leaves your network except the LLM API calls you authorize.

**A4 — Docker image.** Single image, two modes:
- `docker run skillscan/trace run ./skill.md` — existing behavior, containerized
- `docker run -p 8080:8080 skillscan/trace serve` — HTTP server for self-hosting and the hosted service

The `serve` mode exposes three endpoints: `POST /v1/submit`, `GET /v1/report/{id}`, `GET /v1/health`. `docker-compose.yml` included for self-hosted deployments.

**A5 — Bash AST.** `canary/bash_ast.py` uses `bashlex` for structural analysis of bash commands. Falls back to regex if bashlex fails to parse. Catches obfuscation patterns the regex approach misses.

---

## Phase B — Open-Source Launch

| Item | Description | Status |
|---|---|---|
| B1 | Make `skillscan-trace` repo public | Planned |
| B2 | Website /trace page (data flow diagram, provider guides, sample report, quick-start) | Planned |
| B3 | GitHub Action (`skillscan/trace-action` — OIDC-based for public repos, PR comment with report URL) | Planned |
| B4 | Multi-model trace (run against 2+ models via OpenRouter, report agreement/disagreement) | Planned |
| B5 | `--remote` flag in CLI + `source_url` URL-reachability verification on server side | Planned |

---

## Phase C — Hosted Scan Service (BYOK, deferred)

The hosted service is a thin wrapper around the same Docker image. The user brings their own API key; SkillScan provides the compute and report hosting. The key goes directly to the chosen provider — SkillScan never stores or logs it.

**Infrastructure:** Fly.io Machines (compute) + Cloudflare R2 (report storage) + Cloudflare Workers (submission API + cache lookup). Estimated cost at 5,000 scans/day: ~$20–25/month.

**Authentication model:**
- Free tier (public OSS skills): URL-reachability check only. Submit a raw GitHub URL; the service fetches it, verifies it returns 200 without auth, runs the trace. No account required.
- GitHub Actions: OIDC token verification. The Action presents a GitHub OIDC token; the service verifies the token's `repository` claim matches the submitted skill URL. No secrets to manage.
- Self-hosted: `--remote-host` flag points the CLI at a self-hosted `serve` instance. The Docker image is the deployment artifact.

**What we are not building (yet):**
- Private repo scanning — self-hosted trace is the right path for private code
- Managed inference (we pay the LLM) — BYOK until we have demand data
- Subscription model — not the right pricing model for a developer tool

| Item | Description | Status |
|---|---|---|
| C1 | Report storage (Cloudflare R2) + permanent report URLs | Planned |
| C2 | SHA-based report cache (avoid re-scanning identical skills) | Planned |
| C3 | GitHub OIDC verification for Actions integration | Planned |
| C4 | Corpus feedback loop — batch traces against skillscan-security corpus | Planned |
| C5 | Falco + eBPF secondary layer (catches subprocess spawning, raw syscalls) | Future |

**Launch gate for hosted service:** False positive rate on benign skills below 2% and detection rate on `corpus/malicious/` above 85%.

---

## Version Summary

| Version | Status | Description |
|---|---|---|
| 0.1.0 | ✅ Released | Core CLI complete — Phases 1–5 implemented, 176/176 tests passing |
| 0.2.0 | ✅ Ready to tag | Phase A complete — provider UX, config system, Docker image, PRIVACY.md, bashlex |
| 0.3.0 | Planned | Phase B — open-source public launch, website /trace page, GitHub Action |
| 1.0.0 | Future | Phase C — hosted BYOK service, detection quality gate met |
