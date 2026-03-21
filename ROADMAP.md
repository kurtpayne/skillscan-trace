# skillscan-trace Roadmap

**Last updated:** 2026-03-20

This roadmap covers the implementation of skillscan-trace from its current pre-implementation state through the scanner-as-a-service offering. It is organized into three phases: building the core tool, making it production-ready, and the hosted service layer.

---

## Phase 1 — Core Tool (v1.0)

The ten milestones in `IMPLEMENTATION_PLAN.md` constitute v1.0. The goal is a working CLI that any developer can install locally, run against a skill, and get a reliable behavioral trace report. No hosted infrastructure, no accounts, no tokens.

**Milestone sequence:** Instrumented MCP server → Canary filesystem → ENV var interceptor → Agent harness → Skill resolver → Analyzer + report emitter → CLI → Config system → Docker image → Batch trace script (Modal)

The acceptance criteria for each milestone are defined in `IMPLEMENTATION_PLAN.md`. v1.0 is complete when the integration test suite passes against the skillscan-security corpus with a false positive rate below 5% on the `corpus/benign/` set.

**Compute for v1.0:** Ollama + `qwen2.5:7b` on CPU. No GPU required. No API key required. A developer with a standard laptop and 8GB RAM can run a trace in 30–60 seconds.

---

## Phase 2 — Reliability and Corpus Feedback (v1.1)

After v1.0 is working, the priority is improving detection quality through the corpus feedback loop and hardening the tool for use in CI/CD pipelines.

**Corpus feedback loop.** Run batch traces against the full skillscan-security corpus using Modal. Review traces that produce findings for skills the static analyzer missed. Add confirmed true positives to `corpus/sandbox_verified/` in skillscan-security. Re-train the ML classifier and measure F1 improvement. This is the primary mechanism for improving recall on behavioral patterns that static analysis misses — conditional payloads, obfuscated instructions, indirect injection via fetched content.

**Bash AST parser (v1.1).** Upgrade the bash interceptor from regex-based to `bashlex`-based command parsing. Catches obfuscation patterns the regex misses: variable expansion, subshell execution, heredoc payloads, `eval` with encoded strings.

**Falco secondary layer (v1.1).** Add Falco + eBPF as a secondary detection layer inside the Docker container. Catches behaviors that bypass the MCP layer — direct subprocess spawning, raw syscalls to canary paths. Not required for v1.0 but a meaningful improvement in detection depth.

**Multi-model traces (v1.1).** Support running a skill against multiple models in sequence and reporting agreement/disagreement. Agreement across models increases confidence in findings; disagreement surfaces model-specific behavior.

**GitHub Action (v1.1).** A GitHub Action that runs `skillscan-trace` as part of a PR check and posts results as a PR comment. This is the sticky CI/CD integration use case.

---

## Phase 3 — Scanner as a Service (v2.0)

The hosted service layer turns skillscan-trace into a developer product. The core value proposition: submit a skill URL or file, get a permanent report URL back. No local installation, no model download, no infrastructure to manage.

### Why this makes sense

Running skillscan-trace locally requires Ollama, a 5GB model download, and Python 3.11+. That is a meaningful barrier for a developer who wants a quick answer about a skill they found on GitHub. The hosted version removes that barrier entirely. The static scanner has the same friction problem — a hosted version is genuinely more convenient even for developers who could run it locally.

The report hosting angle is a distribution mechanism. A skill author with a clean report at `skillscan.dev/reports/<id>` can link to it from their README as a trust signal. Every skill author who wants to signal trustworthiness becomes a marketing channel.

### Token model

Scans are gated by tokens. Tokens are purchased in packs and do not expire. The no-expiry policy is important for a developer tool — subscription fatigue is real, and infrequent users should not feel pressured to use tokens before they expire.

| Scan type | Token cost | Notes |
|---|---|---|
| Static scan only | 1 token | Fast; no model inference |
| Static + behavioral trace | 3 tokens | ~60s on our infrastructure |
| Multi-model trace (2 models) | 5 tokens | Higher confidence findings |
| Batch scan (GitHub repo) | Per-skill pricing | Scales with skill count |

Initial token pack pricing is TBD pending cost modeling. At ~$0.006/trace on Modal L4 GPU, a 100-token pack at $10 would be roughly 3× margin on trace scans. Static-only scans are nearly free to run.

### Infrastructure required

The hosted service requires four components beyond the trace tool itself:

**Report storage.** Scan results are stored in S3 and served at a permanent URL on the skillscan domain. The report viewer is a static page that renders the JSON trace report in a readable format. Reports are public by default (shareable link); a private report option (visible only to the submitting account) is a v2.1 feature.

**Token API.** Issues tokens on purchase, validates tokens on scan submission, decrements on successful scan completion. Stripe handles payment. The token API is a thin service — issue, validate, decrement, list balance.

**Scan queue.** Scans are async jobs. The user submits a skill and gets a job ID back immediately. The job runs on Modal (same infrastructure as the corpus generation batch script). When complete, the report URL is returned and optionally emailed. Queue depth and estimated wait time are surfaced in the API response.

**GitHub Action.** A `skillscan/trace-action` GitHub Action that submits a skill to the hosted API using a token stored in repository secrets, waits for the report, and posts the report URL as a PR comment. This is the primary CI/CD integration path.

### What we are not building

A CA or notary model for skill signing. The overhead and liability are prohibitive. Report signing (signing our own reports with our public key) is a v2.1 consideration — it adds tamper protection to hosted reports but is not required for the initial launch.

A subscription model. Token packs are the right pricing model for this product. Subscriptions imply ongoing value delivery that we are not ready to commit to at this stage.

An enterprise tier. Not yet. The self-serve token model is the right starting point.

### Prerequisite for launch

The hosted service should not launch until the false positive rate on benign skills is below 2% and the detection rate on the `corpus/malicious/` set is above 85%. Selling scans with a high false positive rate damages trust faster than any marketing can recover.

---

## Relationship to skillscan-security

The SaaS layer sits above both skillscan (static) and skillscan-trace (behavioral). A hosted scan runs both pipelines and returns a unified report. The finding ID namespace, severity levels, and report schema are shared across both tools — the hosted report is a superset of what either tool produces independently.

---

## Version Summary

| Version | Status | Description |
|---|---|---|
| v0.1-dev | Current | Spec only, no implementation |
| v1.0 | Planned | Core CLI, local execution, Ollama default |
| v1.1 | Planned | Corpus feedback loop, bash AST, GitHub Action |
| v2.0 | Future | Hosted scanner-as-a-service, token model, report hosting |
