# skillscan-trace Roadmap

**Last updated:** 2026-03-27

skillscan-trace is a behavioral execution engine for MCP-based AI agent skills. The core CLI is complete (v0.1.0, 144 tests passing). This roadmap covers the path from current state to public open-source release and an optional hosted scan service.

---

## Phase A — Public Release Readiness (current)

The tool works. The goal of Phase A is to make the repo not embarrassing when it goes public: accurate docs, clean provider UX, and a clear privacy story.

| Item | Description | Status |
|---|---|---|
| A1 | `--provider` shortcut (openrouter, ollama, openai) + env var resolution | 🔄 In progress |
| A3 | `PRIVACY.md` — plain-language key handling and data flow explanation | 🔄 In progress |
| A4 | Docker image with `run` mode and `serve` mode (for self-hosting) | Planned |
| A5 | Bash AST upgrade (`bashlex`) — catches obfuscation the regex misses | Planned |
| A6 | Fix stale docs (ROADMAP, README, IMPLEMENTATION_PLAN version table) | ✅ Done |

**A1 — Provider UX.** Add `--provider openrouter | ollama | openai` to `run` and `check` commands. Wire env var resolution: `OPENROUTER_API_KEY` for OpenRouter, no key for Ollama. `--api-key` and `--base-url` still work as overrides. OpenRouter gives access to 200+ models through one key — a meaningful unlock for multi-model traces.

**A3 — Privacy.** Write `PRIVACY.md`. One page, plain language: your API key goes directly to the provider you chose; the canary server runs in-process on your machine; nothing leaves your network except the LLM API calls you authorize; SkillScan has no server-side component in local mode.

**A4 — Docker image.** Single image, two modes:
- `docker run skillscan/trace run ./skill.md` — existing behavior, containerized
- `docker run -p 8080:8080 skillscan/trace serve` — HTTP server for self-hosting and the hosted service

The `serve` mode exposes three endpoints: `POST /v1/submit`, `GET /v1/report/{id}`, `GET /v1/health`. This is the foundation for both self-hosted deployments and the Fly.io hosted service.

---

## Phase B — Hosted Scan Service (BYOK)

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
| B1 | `--remote` flag in CLI + `source_url` URL-reachability check on server | Planned |
| B2 | Report storage (Cloudflare R2) + permanent report URLs | Planned |
| B3 | SHA-based report cache (avoid re-scanning identical skills) | Planned |
| B4 | GitHub OIDC verification for Actions integration | Planned |
| B5 | `skillscan/trace-action` GitHub Action | Planned |

---

## Phase C — Detection Quality (ongoing)

Detection quality improvements that can be shipped independently of the hosted service.

| Item | Description | Status |
|---|---|---|
| C1 | Corpus feedback loop — batch traces against skillscan-security corpus | Planned |
| C2 | Multi-model traces — run against 2+ models, report agreement | Planned |
| C3 | Falco + eBPF secondary layer (catches subprocess spawning, raw syscalls) | Future |

**Launch gate for hosted service:** False positive rate on benign skills below 2% and detection rate on `corpus/malicious/` above 85%. Selling scans with a high false positive rate damages trust faster than any marketing can recover.

---

## Version Summary

| Version | Status | Description |
|---|---|---|
| 0.1.0 | ✅ Current | Core CLI complete — Phases 1–5 implemented, 144/144 tests passing |
| 0.2.0 | Planned | Phase A complete — provider UX, Docker image, PRIVACY.md |
| 0.3.0 | Planned | Phase B MVP — hosted BYOK scan service, report URLs |
| 1.0.0 | Future | Phase C — detection quality gate met, production-ready |
