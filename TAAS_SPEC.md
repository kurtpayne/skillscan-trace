# SkillScan Trace-as-a-Service (TaaS) — Technical Specification

> **Status:** Draft v0.1 — 2026-03-26
> **Authors:** Kurt Payne (design), Manus (specification)
> **Scope:** Hosted scanning service built on top of `skillscan` (static) and `skillscan-trace` (behavioral). Covers infrastructure, authentication, payment, token model, queue, live results, admin panel, CLI integration, data storage, HA, backups, audit logging, and test environment.

---

## 1. Overview and Goals

SkillScan TaaS turns the offline CLI tools into a hosted developer product. A user submits a skill file or GitHub URL, selects scan options (model, fuzz rounds, MCP allow/deny list, policy profile), and receives a permanent report URL. No local installation, no model download, no infrastructure to manage.

The service has two distinct value propositions. For individual developers and skill authors, it provides a frictionless way to get a trusted scan result and a shareable report link. For enterprise buyers, it provides a hosted API with webhook delivery, a skill registry, and continuous monitoring — the same capabilities as the offline product but without the operational burden of running the scanner in CI.

**Design constraints that must be preserved throughout:**

The offline product's privacy-first positioning must not be undermined. TaaS is an *optional* hosted layer — the offline CLI remains fully functional and independent. Users who do not want to submit skills to a hosted service should never be pressured to do so. The `online-trace` subcommand must be clearly named and documented as distinct from the offline features.

The service must be economically self-sustaining from the first paying customer. The cost model is designed so that infrastructure costs are covered by the platform fee (token overhead), and LLM inference costs are covered either by the user's BYOK key or by the token price for managed inference. There is no scenario where SkillScan absorbs unbounded LLM costs.

---

## 2. Service Architecture

### 2.1 High-Level Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Client Layer                               │
│  Web UI (trace.skillscan.dev)  │  CLI (skillscan online-trace)      │
│  GitHub Action                 │  API (direct POST /scan)           │
└────────────────────┬────────────────────────────────────────────────┘
                     │ HTTPS
┌────────────────────▼────────────────────────────────────────────────┐
│                         API Gateway                                 │
│  FastAPI · rate limiting · auth middleware · request validation     │
│  Hosted: Hetzner CX21 (primary) + CX21 (standby, cold)             │
└────────────────────┬────────────────────────────────────────────────┘
                     │
        ┌────────────┴─────────────┐
        │                          │
┌───────▼──────────┐    ┌──────────▼──────────┐
│   Job Queue      │    │   Token/Auth DB      │
│   Redis (BRPOP)  │    │   PostgreSQL         │
│   Hetzner CX11   │    │   Hetzner CX21       │
│   + replica      │    │   + daily snapshot   │
└───────┬──────────┘    └─────────────────────┘
        │
┌───────▼──────────────────────────────────────┐
│              Worker Pool                      │
│  2–4 × Hetzner CX31 (4 vCPU, 8GB RAM)        │
│  Each: systemd skillscan-worker service       │
│  Autoscale: cron checks queue depth → SSH     │
└───────┬──────────────────────────────────────┘
        │
┌───────▼──────────────────────────────────────┐
│           Result / Report Store               │
│  Hetzner Object Storage (S3-compatible)       │
│  Reports: public by default, token-gated opt  │
│  TTL: 90 days (configurable per tier)         │
└──────────────────────────────────────────────┘
```

### 2.2 Subdomains and Environments

| Subdomain | Purpose |
|---|---|
| `trace.skillscan.dev` | Production web UI |
| `api.skillscan.dev` | Production API endpoint |
| `staging.skillscan.dev` | Staging web UI (mirrors production, separate DB) |
| `staging-api.skillscan.dev` | Staging API endpoint |
| `admin.skillscan.dev` | Admin panel (IP-restricted, separate auth) |

The staging environment is a full replica of production with a separate database, separate Redis instance, and separate object storage bucket. It shares no data with production. Staging workers use the same Docker image as production, deployed from the same CI pipeline with a `staging` tag. This is the environment used for iterating on new features before production rollout.

### 2.3 Worker Architecture

Workers are long-running Python processes managed by `systemd`. Each worker runs a tight loop: `BRPOP skillscan:jobs 30` → deserialize job → run scan → write result to object storage → update job status in PostgreSQL → `LPUSH skillscan:events:<job_id>` for live streaming.

Workers do not share state. Each worker is stateless with respect to job data — all state lives in PostgreSQL and Redis. A worker crash loses nothing; the job is requeued automatically via a Redis `RPOPLPUSH` pattern (job is moved to a `skillscan:jobs:processing` list on pickup; a watchdog process re-enqueues jobs that have been in `processing` for more than 10 minutes without a heartbeat update).

**Worker sizing:** A single Hetzner CX31 (4 vCPU, 8GB RAM, €11.90/mo) can run 2 concurrent trace jobs (each trace uses ~2 vCPU and ~3GB RAM for the Ollama model + Python process). The static-only scan path uses ~0.5 vCPU and ~512MB RAM and can run 8 concurrent jobs per worker. Start with 2 workers (4 concurrent trace slots, 16 concurrent static slots) and scale to 4 workers at sustained queue depth > 8.

**Autoscaling:** A cron job runs every 5 minutes on the API gateway host. It reads `LLEN skillscan:jobs` from Redis. If queue depth > 8 and worker count < 4, it starts an additional worker via the Hetzner API (not SSH — use the Hetzner Cloud API to start a pre-provisioned server from a snapshot). If queue depth < 2 and worker count > 2, it stops the most recently started worker after it drains its current job. This is fully automated and requires no browser or SSH.

---

## 3. Authentication and Accounts

### 3.1 Account Model

Accounts are created via GitHub OAuth or email/password. GitHub OAuth is the preferred path — it eliminates password management and provides a natural link to the user's skill repositories.

| Field | Type | Notes |
|---|---|---|
| `user_id` | UUID | Internal identifier |
| `email` | string | Required; verified on signup |
| `github_id` | integer | Optional; set on GitHub OAuth |
| `created_at` | timestamp | |
| `token_balance` | integer | Current token balance |
| `tier` | enum | `free`, `verified`, `professional`, `enterprise` |
| `api_key` | string | SHA-256 hashed; used for CLI and API access |
| `is_admin` | boolean | Admin panel access |
| `byok_keys` | JSONB | Encrypted BYOK key store (see §3.3) |

Sessions use JWT with a 24-hour expiry for web UI access. API access uses a long-lived API key (no expiry, revocable). The API key is displayed once on creation and stored as a SHA-256 hash — it cannot be recovered, only rotated.

### 3.2 Session Security

All cookies are `HttpOnly`, `Secure`, and `SameSite=Strict`. CSRF protection is enforced on all state-mutating endpoints via the `double-submit cookie` pattern. Rate limiting is applied at the API gateway: 10 requests/second per IP for unauthenticated endpoints, 30 requests/second per authenticated user.

Password-based accounts use Argon2id with a minimum cost factor of `m=65536, t=3, p=4`. Password reset tokens are single-use, expire in 1 hour, and are delivered via email only (no SMS to avoid SIM-swap risk).

### 3.3 BYOK Key Storage

Users can store LLM API keys (Anthropic, OpenAI, Mistral, etc.) in their account for reuse across scans. Keys are encrypted at rest using AES-256-GCM with a key derived from a server-side master key (stored in a Hetzner Cloud Secret, not in the database). The encryption key is rotated quarterly.

Keys are never logged, never included in error messages, and never returned in API responses after initial storage. The API returns only the key prefix (first 8 characters + `...`) for display purposes. Keys are decrypted in worker memory only for the duration of the scan and are not written to disk in plaintext at any point.

If a user submits a key inline with a scan request (rather than storing it), the key is held in Redis job payload for the duration of the job only. The job payload is encrypted at rest in Redis using the same AES-256-GCM scheme. After the job completes, the payload is deleted from Redis immediately.

---

## 4. Token Model and Payments

### 4.1 Token Pricing

Tokens are purchased in packs and do not expire. The no-expiry policy is deliberate — developer tools with expiring credits create subscription fatigue and penalize infrequent users.

| Pack | Tokens | Price | Per-token cost |
|---|---|---|---|
| Starter | 20 | $5 | $0.25 |
| Standard | 100 | $20 | $0.20 |
| Pro | 500 | $80 | $0.16 |
| Team | 2,000 | $250 | $0.125 |

### 4.2 Token Cost per Scan Type

| Scan type | Tokens | Infrastructure cost | Margin |
|---|---|---|---|
| Static only (no model) | 1 | ~$0.002 | ~$0.20 |
| Static + behavioral trace (BYOK, 1 model, 3 rounds) | 3 | ~$0.015 | ~$0.585 |
| Static + behavioral trace (managed inference, 1 model, 3 rounds) | 5 | ~$0.10–0.20 | ~$0.80–1.00 |
| Multi-model trace (BYOK, 2 models, 3 rounds each) | 8 | ~$0.025 | ~$1.575 |
| Multi-model trace (managed inference, 2 models) | 15 | ~$0.25–0.40 | ~$2.60–2.75 |

**Managed inference** means SkillScan runs the model on its own infrastructure (Ollama on the worker, or a third-party API). BYOK means the user supplies their own API key and SkillScan bears zero inference cost. BYOK scans cost fewer tokens because the infrastructure overhead is lower.

The token cost for managed inference is set conservatively to ensure margin even at low volume. At 1,000 managed trace scans/month, infrastructure cost is ~$150–200/month (workers + storage + Redis + DB). Revenue at 1,000 × 5 tokens × $0.20/token = $1,000/month. Margin is strong.

### 4.3 Stripe Integration

Stripe Checkout is used for token pack purchases. The flow is:

1. User selects a token pack on the billing page.
2. Frontend calls `POST /api/billing/checkout` with `pack_id`.
3. API creates a Stripe Checkout Session and returns the session URL.
4. User is redirected to Stripe Checkout (hosted by Stripe — no card data touches our servers).
5. On success, Stripe sends a `checkout.session.completed` webhook to `POST /api/webhooks/stripe`.
6. Webhook handler verifies the Stripe signature, looks up the user by `client_reference_id`, and credits the token balance atomically in PostgreSQL.
7. User is redirected back to the billing page with a success message.

Stripe webhook events are idempotent — the handler checks for duplicate `payment_intent_id` before crediting tokens. All Stripe events are logged to the audit log (see §8).

**Refund policy:** Unused tokens are refundable within 30 days of purchase. Partial refunds (for partially used packs) are not supported in v1.0. Refunds are processed manually by the admin via the Stripe dashboard.

---

## 5. Scan Job Lifecycle

### 5.1 Job Submission

`POST /api/scan` accepts a multipart form or JSON body:

```json
{
  "skill_url": "https://github.com/user/repo/blob/main/skills/SKILL.md",
  "skill_content": "<inline SKILL.md content>",
  "options": {
    "model": "claude-3-5-sonnet",
    "rounds": 3,
    "fuzz_inputs": 5,
    "url_follow_depth": 2,
    "mcp_allow": ["filesystem", "fetch"],
    "mcp_deny": ["bash", "computer"],
    "policy_profile": "strict",
    "include_observe_profile": true,
    "byok_key_id": "key_abc123",
    "byok_key_inline": "<raw API key, not stored>"
  },
  "webhook_url": "https://your-server.com/scan-complete",
  "private_report": false
}
```

Either `skill_url` or `skill_content` is required. `skill_url` must be a public GitHub URL or a raw content URL; the API fetches the content server-side (not via the user's browser). The URL is validated against an allowlist of trusted domains (github.com, raw.githubusercontent.com, gitlab.com) — arbitrary URLs are not followed to prevent SSRF.

The API validates the token balance, deducts tokens optimistically (with a hold), creates a job record in PostgreSQL, pushes the job to Redis, and returns a `202 Accepted` with the `job_id`.

### 5.2 Scan Options Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `model` | string | `qwen2.5:7b` (managed) | LLM model for behavioral trace. Accepted: `claude-3-5-sonnet`, `gpt-4o`, `gpt-4.1`, `mistral-large`, `qwen2.5:7b` (local) |
| `rounds` | integer | 3 | Number of fuzz rounds per input. Range: 1–10 |
| `fuzz_inputs` | integer | 3 | Number of distinct fuzz inputs per round. Range: 1–10 |
| `url_follow_depth` | integer | 0 | How many hops to follow URLs found in the skill. 0 = no following |
| `mcp_allow` | string[] | all standard | MCP tools to allow in the canary environment |
| `mcp_deny` | string[] | `[]` | MCP tools to explicitly deny (overrides allow) |
| `policy_profile` | string | `strict` | Policy profile: `strict`, `ci`, `balanced`, `permissive`, `enterprise`, `paranoid`, `observe` |
| `include_observe_profile` | boolean | false | Run an additional pass with the `observe` profile and include the full event log in the report |
| `byok_key_id` | string | null | ID of a stored BYOK key to use for inference |
| `byok_key_inline` | string | null | Raw API key (not stored; used for this scan only) |
| `private_report` | boolean | false | If true, report URL requires authentication to view |

### 5.3 Live Results and Queue Position

The API provides a Server-Sent Events (SSE) stream at `GET /api/scan/{job_id}/stream`. The web UI connects to this stream immediately after job submission and renders live updates.

Events emitted during a scan:

| Event type | Payload | When |
|---|---|---|
| `queued` | `{position: N, estimated_wait_seconds: N}` | Immediately on submission |
| `position_update` | `{position: N, estimated_wait_seconds: N}` | Every 15s while in queue |
| `started` | `{worker_id, started_at}` | When worker picks up the job |
| `phase` | `{phase: "static" \| "trace" \| "compile", message: string}` | At each scan phase transition |
| `finding` | `{rule_id, severity, file, line, message}` | As each finding is produced (static phase) |
| `tool_call` | `{tool, inputs_summary, verdict: "allow"\|"block"\|"canary_hit"}` | During trace phase (behavioral events) |
| `trace_round_complete` | `{round: N, findings_count: N}` | After each fuzz round |
| `complete` | `{report_url, verdict, score, findings_count, duration_seconds}` | On completion |
| `error` | `{code, message}` | On failure |

The web UI renders a terminal-style live feed of `finding` and `tool_call` events, a progress bar across phases, and a queue position indicator. The final `complete` event triggers a redirect to the report URL.

For CLI users, `skillscan online-trace` polls `GET /api/scan/{job_id}` every 3 seconds and renders a compact progress display. The `--stream` flag switches to SSE for real-time output.

### 5.4 Job Failure and Retry

Jobs that fail due to worker crash or timeout are automatically requeued up to 3 times. After 3 failures, the job is marked `failed` and the token hold is released (tokens are not deducted for failed scans). The user is notified via email and the web UI.

If a job fails due to an invalid BYOK key (authentication error from the LLM provider), it is not retried — the failure is surfaced immediately with a clear error message and the token hold is released.

---

## 6. Report Storage and TTL

### 6.1 Storage Layout

Reports are stored in Hetzner Object Storage (S3-compatible) under the following key structure:

```
reports/
  {year}/{month}/
    {job_id}/
      report.json          # Full machine-readable report
      report.html          # Rendered HTML report (static, no JS dependencies)
      report.sarif         # SARIF output for CI/SIEM integration
      skill.md             # The scanned skill file (for reference)
      trace.jsonl          # Full trace event log (if trace was run)
      meta.json            # Job metadata: user_id, scan options, timestamps
```

The HTML report is a self-contained static file with no external dependencies — it embeds all CSS and JavaScript inline. This ensures reports remain readable even if the SkillScan domain changes or the service is discontinued.

### 6.2 Report TTL

| Tier | Report TTL | Extension |
|---|---|---|
| Free (static only) | 30 days | Not extendable |
| Verified (trace, BYOK) | 90 days | Extendable by re-scanning |
| Professional | 1 year | Extendable |
| Enterprise | Indefinite | Managed by contract |

TTL is enforced by a daily cleanup job that reads `meta.json` for each report and deletes the object storage prefix when the TTL has expired. The PostgreSQL job record is retained for 90 days after report deletion for audit purposes.

A report approaching expiry (within 14 days) triggers an email notification to the submitting user with a link to re-scan.

### 6.3 Report Privacy

Reports are public by default — the report URL is the only access control. The URL contains the `job_id` (a UUID), which is not guessable. Users who require stricter access control can set `private_report: true` at submission time, which requires a valid session cookie or API key to view the report.

Private reports are not indexed by the public scan feed (M14) and are not included in any aggregate statistics.

---

## 7. Admin Panel

The admin panel is served at `admin.skillscan.dev` and is restricted to IP addresses in an allowlist (configurable via environment variable). It requires a separate admin session — admin accounts cannot be created via the public signup flow.

### 7.1 Admin Capabilities

**Token management:**

- View any user's token balance and transaction history
- Credit tokens to any account (for testing, compensation, or promotional grants)
- Debit tokens from any account
- Issue promo codes (a promo code credits a fixed number of tokens on first use)
- View aggregate token issuance and consumption by day/week/month

**User management:**

- Search users by email, GitHub username, or user ID
- View account details, scan history, and BYOK key list (key prefixes only — full keys are never shown)
- Suspend or unsuspend accounts
- Promote accounts to admin
- Delete accounts (GDPR right-to-erasure; deletes all user data except audit log entries, which are anonymized)

**Job management:**

- View the current job queue (job ID, user, status, position, age)
- Cancel any queued or running job
- Retry any failed job
- View full job details including scan options and error messages

**Infrastructure:**

- View worker status (running, idle, CPU/memory usage via Hetzner API)
- Start or stop workers (via Hetzner Cloud API — no SSH required)
- View Redis queue depth and processing list length
- View object storage usage by bucket

**Audit log:**

- Search and filter the audit log by user, event type, date range, and IP address
- Export audit log entries as CSV

### 7.2 Admin Authentication

Admin accounts use TOTP (time-based one-time password) as a mandatory second factor. There is no "remember this device" option for admin accounts. Admin sessions expire after 4 hours of inactivity. All admin actions are written to the audit log with the admin's user ID, IP address, and a description of the action.

---

## 8. Audit Logging

All security-relevant events are written to an append-only audit log table in PostgreSQL. The table is never updated or deleted — only inserted. Entries older than 90 days are archived to object storage in compressed JSONL format and deleted from the live table.

### 8.1 Audited Events

| Event | Fields logged |
|---|---|
| User signup | user_id, email, method (github/email), IP |
| Login | user_id, IP, success/failure, MFA used |
| Password change | user_id, IP |
| API key rotation | user_id, IP |
| BYOK key added | user_id, key_prefix, provider |
| BYOK key deleted | user_id, key_prefix |
| Token purchase | user_id, pack_id, stripe_payment_intent_id, tokens_credited |
| Token deduction | user_id, job_id, tokens_deducted, balance_before, balance_after |
| Scan submitted | user_id, job_id, scan_options (redacted: no keys), IP |
| Scan completed | job_id, verdict, duration_seconds, report_url |
| Scan failed | job_id, error_code, retry_count |
| Report accessed | job_id, accessor_user_id (null if public), IP |
| Admin action | admin_user_id, action_type, target_user_id, details, IP |
| Account suspended | admin_user_id, target_user_id, reason |
| Account deleted | admin_user_id, target_user_id (anonymized after deletion) |

### 8.2 Audit Log Retention

The live audit log retains 90 days of entries. Archived entries (compressed JSONL in object storage) are retained for 3 years. The archive is stored in a separate object storage bucket with versioning enabled and deletion protection — even admin accounts cannot delete archived audit entries.

---

## 9. `skillscan online-trace` CLI Subcommand

The `online-trace` subcommand is added to the `skillscan-security` package. It is explicitly named to delineate it from the offline features. The subcommand requires an API key, which can be provided via `--api-key`, the `SKILLSCAN_API_KEY` environment variable, or a `.env` file in the current directory.

### 9.1 Usage

```
skillscan online-trace [OPTIONS] PATH

Arguments:
  PATH                    Skill file or directory to scan

Options:
  --api-key TEXT          SkillScan API key (or set SKILLSCAN_API_KEY)
  --env-file PATH         .env file containing SKILLSCAN_API_KEY and BYOK keys
                          (default: .env in current directory if present)
  --model TEXT            LLM model for trace [default: qwen2.5:7b]
  --rounds INTEGER        Fuzz rounds per input [default: 3, max: 10]
  --fuzz-inputs INTEGER   Fuzz inputs per round [default: 3, max: 10]
  --url-depth INTEGER     URL follow depth [default: 0]
  --mcp-allow TEXT        Allow specific MCP tool (repeatable)
  --mcp-deny TEXT         Deny specific MCP tool (repeatable)
  --policy PROFILE        Policy profile [default: strict]
  --observe               Include observe-profile pass in report
  --byok TEXT             Inline BYOK API key (not stored; use --env-file for safety)
  --byok-provider TEXT    BYOK provider: anthropic|openai|mistral [default: auto-detect]
  --private               Make report private (requires auth to view)
  --format [compact|json|sarif]
                          Output format [default: compact]
  --output PATH           Write report to file
  --stream                Stream live results to stdout (SSE)
  --no-wait               Submit job and exit immediately (prints job ID)
  --webhook URL           Webhook URL for completion notification
  --help                  Show this message
```

### 9.2 .env File Support

The `.env` file pattern allows teams to store API keys outside of shell history and CI secrets:

```dotenv
# .skillscan.env
SKILLSCAN_API_KEY=sk-live-...
ANTHROPIC_API_KEY=sk-ant-...   # used as BYOK if --byok-provider=anthropic
OPENAI_API_KEY=sk-...          # used as BYOK if --byok-provider=openai
```

The CLI reads `.env` (or the file specified by `--env-file`) using `python-dotenv`. Keys are never echoed to stdout or written to log files.

### 9.3 Account-free Mode

An account is required to use `online-trace`. The reasons are: token deduction requires an account, BYOK key storage requires an account, and report history requires an account. There is no anonymous scan mode for `online-trace` — the static offline `skillscan scan` is the anonymous path.

This is a deliberate design decision. The `online-trace` subcommand is a paid feature. Making it account-free would require either a free tier with no rate limiting (abuse vector) or a per-request payment flow (too much friction). The account requirement is the right tradeoff.

---

## 10. Infrastructure, HA, and Backups

### 10.1 Hosting Stack

All production infrastructure runs on Hetzner Cloud (Nuremberg, EU). Hetzner is chosen for its combination of low cost, no egress fees, S3-compatible object storage, and a full-featured API that allows Manus to manage infrastructure programmatically without a browser.

| Component | Instance | Monthly cost | Notes |
|---|---|---|---|
| API gateway (primary) | CX21 (2 vCPU, 4GB) | €5.83 | Runs FastAPI + Nginx + Redis |
| API gateway (standby) | CX21 | €5.83 | Cold standby; promoted via floating IP |
| PostgreSQL | CX21 | €5.83 | Primary; with daily snapshot |
| Worker 1 | CX31 (4 vCPU, 8GB) | €11.90 | Always-on |
| Worker 2 | CX31 | €11.90 | Always-on |
| Worker 3–4 | CX31 | €11.90 each | Autoscaled; stopped when idle |
| Object storage | 1TB bucket | ~€5.00 | Reports + audit archives |
| **Total (2 workers)** | | **~€46/mo** | |
| **Total (4 workers)** | | **~€68/mo** | |

The staging environment uses smaller instances (CX11 for everything) at ~€15/mo.

### 10.2 High Availability

The API gateway uses a Hetzner floating IP. The primary gateway holds the floating IP. If the primary fails, a health check cron job (running on the standby) detects the failure and reassigns the floating IP to the standby via the Hetzner API. Failover takes approximately 30 seconds. This is not zero-downtime HA, but it is sufficient for the initial launch — a 30-second failover window is acceptable for a developer tool.

Redis runs on the API gateway host. Redis data is persisted with `appendonly yes` (AOF) and snapshots every 60 seconds. In the event of a Redis failure, jobs in the `processing` list are recovered by the watchdog on restart. Jobs in the `jobs` queue are recovered from AOF. The maximum data loss window is 60 seconds of queued jobs.

PostgreSQL uses daily snapshots (Hetzner volume snapshots). Point-in-time recovery is not configured in v1.0 — daily snapshots are sufficient for the initial launch. The maximum data loss window is 24 hours of transaction history. This is acceptable for token balances (which can be recovered from Stripe) and user accounts (which can be re-created). It is not acceptable for audit logs — audit log writes are synchronous and confirmed before returning to the caller.

### 10.3 Backups

| Data | Backup method | Frequency | Retention |
|---|---|---|---|
| PostgreSQL | Hetzner volume snapshot | Daily | 7 daily, 4 weekly, 3 monthly |
| Redis AOF | Copied to object storage | Hourly | 48 hours |
| Object storage (reports) | Versioning enabled | Continuous | Per-object TTL |
| Audit archive (object storage) | Separate bucket, deletion protection | Continuous | 3 years |
| Worker Docker images | GitHub Container Registry | On push | Indefinite |

Backup restoration is tested monthly in the staging environment. The test procedure is automated: a GitHub Actions workflow restores the latest PostgreSQL snapshot to a temporary Hetzner instance, runs a smoke test suite against it, and reports pass/fail. No manual intervention required.

### 10.4 Deployment and Updates

The deployment pipeline is fully automated via GitHub Actions. The workflow for a production deployment:

1. Push to `main` branch of `skillscan-trace` (or `skillscan-security` for the CLI).
2. GitHub Actions builds a Docker image, runs the test suite, and pushes to GitHub Container Registry.
3. A `deploy.yml` workflow SSHes into the API gateway and workers, pulls the new image, and restarts the service with a rolling restart (one worker at a time, with a health check between each).
4. If any health check fails, the deployment is rolled back automatically.

The API gateway and workers run the same Docker image. The image contains the FastAPI application, the worker loop, and all dependencies. Configuration is injected via environment variables (stored as Hetzner Cloud Secrets, not in the image).

**No manual SSH is required for routine operations.** The only time SSH is used is for debugging a specific failure that cannot be diagnosed via logs. All routine operations (deploy, scale, restart, config change) are handled via the Hetzner API and GitHub Actions.

---

## 11. Test Environment and Iteration

### 11.1 Staging Environment

The staging environment (`staging.skillscan.dev`) is a full replica of production. It is deployed from the same Docker image as production, with a `staging` tag. Staging uses a separate PostgreSQL database, separate Redis instance, and separate object storage bucket.

Stripe is configured in test mode for staging — no real payments are processed. Test token packs can be purchased using Stripe test card numbers. The staging environment has a pre-seeded admin account and several test user accounts with varying token balances.

### 11.2 Local Development

Developers (and Manus) can run the full stack locally using Docker Compose:

```yaml
services:
  api:
    image: skillscan/taas-api:dev
    environment:
      - DATABASE_URL=postgresql://...
      - REDIS_URL=redis://redis:6379
      - STORAGE_ENDPOINT=http://minio:9000
  worker:
    image: skillscan/taas-worker:dev
  redis:
    image: redis:7-alpine
  postgres:
    image: postgres:16-alpine
  minio:
    image: minio/minio
    command: server /data
```

The local environment uses MinIO as an S3-compatible object storage substitute. No Hetzner account or API keys are required for local development.

### 11.3 Feature Flags

New features are deployed behind feature flags stored in PostgreSQL. The admin panel provides a UI for enabling/disabling flags per environment (staging/production) and per user (for beta testing with specific accounts). Feature flags are read at request time — no restart required to toggle a flag.

---

## 12. Data Model (PostgreSQL Schema)

```sql
-- Users and authentication
CREATE TABLE users (
  user_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  github_id     BIGINT UNIQUE,
  password_hash TEXT,                    -- NULL for GitHub OAuth users
  api_key_hash  TEXT UNIQUE,
  token_balance INTEGER NOT NULL DEFAULT 0,
  tier          TEXT NOT NULL DEFAULT 'free',
  is_admin      BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  suspended_at  TIMESTAMPTZ
);

-- Encrypted BYOK key store
CREATE TABLE byok_keys (
  key_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  provider      TEXT NOT NULL,           -- 'anthropic', 'openai', 'mistral'
  key_prefix    TEXT NOT NULL,           -- first 8 chars for display
  encrypted_key BYTEA NOT NULL,          -- AES-256-GCM encrypted
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ
);

-- Scan jobs
CREATE TABLE jobs (
  job_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(user_id),
  status        TEXT NOT NULL DEFAULT 'queued',  -- queued|processing|complete|failed|cancelled
  scan_options  JSONB NOT NULL,
  skill_url     TEXT,
  tokens_held   INTEGER NOT NULL DEFAULT 0,
  tokens_charged INTEGER,
  report_url    TEXT,
  verdict       TEXT,
  score         INTEGER,
  findings_count INTEGER,
  worker_id     TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  error_code    TEXT,
  error_message TEXT,
  retry_count   INTEGER NOT NULL DEFAULT 0
);

-- Token transactions
CREATE TABLE token_transactions (
  tx_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL REFERENCES users(user_id),
  type          TEXT NOT NULL,           -- 'purchase', 'deduction', 'credit', 'hold', 'release'
  amount        INTEGER NOT NULL,        -- positive = credit, negative = debit
  balance_after INTEGER NOT NULL,
  job_id        UUID REFERENCES jobs(job_id),
  stripe_payment_intent_id TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit log (append-only)
CREATE TABLE audit_log (
  log_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type    TEXT NOT NULL,
  user_id       UUID,                    -- NULL for system events
  actor_user_id UUID,                    -- admin who performed the action
  ip_address    INET,
  details       JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Feature flags
CREATE TABLE feature_flags (
  flag_name     TEXT NOT NULL,
  environment   TEXT NOT NULL,           -- 'production', 'staging'
  enabled       BOOLEAN NOT NULL DEFAULT false,
  enabled_for   UUID[],                  -- specific user IDs; NULL = all users
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (flag_name, environment)
);
```

---

## 13. API Surface

### 13.1 Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/auth/signup` | None | Create account (email/password) |
| `POST` | `/api/auth/login` | None | Login; returns JWT |
| `GET` | `/api/auth/github` | None | GitHub OAuth redirect |
| `POST` | `/api/auth/logout` | Session | Invalidate session |
| `GET` | `/api/me` | Session/API key | Current user profile and token balance |
| `POST` | `/api/me/api-key` | Session | Rotate API key |
| `GET` | `/api/me/byok` | Session | List stored BYOK keys (prefixes only) |
| `POST` | `/api/me/byok` | Session | Store a new BYOK key |
| `DELETE` | `/api/me/byok/{key_id}` | Session | Delete a BYOK key |
| `GET` | `/api/me/usage` | Session | Token usage history and scan list |
| `POST` | `/api/billing/checkout` | Session | Create Stripe Checkout session |
| `POST` | `/api/webhooks/stripe` | Stripe sig | Stripe webhook handler |
| `POST` | `/api/scan` | Session/API key | Submit a scan job |
| `GET` | `/api/scan/{job_id}` | Session/API key | Poll job status |
| `GET` | `/api/scan/{job_id}/stream` | Session/API key | SSE live results stream |
| `DELETE` | `/api/scan/{job_id}` | Session/API key | Cancel a queued job |
| `GET` | `/api/report/{job_id}` | Optional (private reports) | View report metadata |
| `GET` | `/api/report/{job_id}/json` | Optional | Download full JSON report |
| `GET` | `/api/report/{job_id}/sarif` | Optional | Download SARIF report |
| `GET` | `/api/admin/*` | Admin session | Admin panel API |

### 13.2 Versioning

The API is versioned via URL prefix (`/api/v1/`). The initial launch uses `/api/` (unversioned) for simplicity. When a breaking change is required, `/api/v2/` is introduced and `/api/v1/` is maintained for 6 months. The CLI `online-trace` subcommand pins to a specific API version.

---

## 14. Open Questions and Deferred Decisions

The following items require a decision before implementation begins but are not blocking the spec:

| Question | Options | Recommendation |
|---|---|---|
| **Managed inference provider** | Ollama on worker (self-hosted), Anthropic API, OpenAI API | Ollama on worker for v1.0 (zero inference cost, predictable); add Anthropic/OpenAI as BYOK providers |
| **Email provider** | AWS SES, Postmark, Resend | Resend (simple API, generous free tier, good deliverability) |
| **Report viewer** | Static HTML embedded in report, separate React app | Static HTML embedded (no dependency on service being up) |
| **GitHub Action** | Separate `skillscan/trace-action` repo, or bundled in `skillscan-security` | Separate repo; follows GitHub Action conventions |
| **Private report auth** | Session cookie, signed URL with expiry | Signed URL with 7-day expiry (shareable without requiring an account) |
| **Multi-region** | Single region (Nuremberg) for v1.0, add US region later | Single region for v1.0; add US region when latency complaints arise |
| **GDPR DPA** | Self-serve DPA on website, or manual | Self-serve DPA PDF on website (standard template) |

---

## 15. Implementation Phases

### Phase 1 — Foundation (prerequisite: M14 public scan feed validates the worker pipeline)

- PostgreSQL schema, migrations, and seed data
- FastAPI application skeleton with auth middleware
- Redis queue and worker loop (static scan only, no trace)
- Object storage integration (report write/read)
- Stripe Checkout integration (token purchase)
- Basic web UI: signup, login, submit scan, view report
- `skillscan online-trace` CLI subcommand (static only)
- Staging environment

### Phase 2 — Trace Integration

- Worker integration with `skillscan-trace` (behavioral scan)
- SSE live results stream
- BYOK key storage and encryption
- Queue position and wait time estimation
- Full scan options (model, rounds, fuzz inputs, MCP allow/deny)
- Observe profile integration
- Report HTML renderer

### Phase 3 — Admin and Operations

- Admin panel (token management, user management, job management)
- Audit log viewer and export
- Worker autoscaling via Hetzner API
- Backup verification automation
- Monitoring and alerting (Hetzner metrics + custom health checks)

### Phase 4 — Polish and Launch

- Email notifications (scan complete, report expiry, token low balance)
- GitHub Action (`skillscan/trace-action`)
- Public scan feed integration (M14 results surfaced on website)
- Rate limiting and abuse prevention
- GDPR compliance (right-to-erasure, DPA)
- Load testing and capacity planning

---

*This document is the authoritative specification for the SkillScan TaaS platform. It should be updated as decisions are made and implementation progresses. The ROADMAP.md in `skillscan-security` references this document for the M20 milestone.*

---

## 16. Gap Analysis: Research Findings and Spec Revisions

> **Added:** 2026-03-26. Based on review of Cisco's MCP behavioral scanner, OWASP Agentic Skills Top 10 (AST10), and cross-referencing with the existing SPEC.md and ARCHITECTURE.md.

---

### 16.1 Gaps Identified in the Current Spec

**Gap 1 — Token usage is not tracked in trace reports**

The SPEC.md trace report schema (§7.1) does not include token consumption data. Cisco's scanner logs prompt tokens, completion tokens, and cost-per-trace for every run. This matters for the TaaS cost model: without per-trace token usage, it is impossible to accurately calibrate the managed inference token price or detect runaway traces that consume disproportionate tokens (a potential abuse vector). The `model` block in the JSON report should include `prompt_tokens`, `completion_tokens`, and `estimated_cost_usd`. The TaaS job record should store these for billing reconciliation.

**Action:** Add `token_usage` to the trace report schema and to the `jobs` table in the PostgreSQL schema.

---

**Gap 2 — No rate limiting on trace depth (URL follow depth)**

The `url_follow_depth` option (§5.2) allows up to 2 hops. There is no cap on the number of URLs discovered per hop, which means a skill that fetches a page with 100 links could trigger 100 additional fetches at depth 1, and 10,000 at depth 2. This is both an abuse vector and a cost vector. A per-trace URL budget (e.g., max 20 URLs total across all depths) must be enforced at the worker level, not just at the option level.

**Action:** Add `max_urls_total` (default: 20, hard cap: 50) to the scan options reference table. Enforce in the worker before dispatching the trace job.

---

**Gap 3 — No detection for MCP tool poisoning via description injection**

OWASP AST10 item AS-004 ("Tool Poisoning") describes a class of attack where a malicious MCP server injects instructions into the tool *description* field rather than the tool *output*. The current SPEC.md detection taxonomy covers prompt injection in tool *outputs* (PINJ-TRACE-001, PINJ-TRACE-002) but does not cover injection in tool *descriptions* or *parameter schemas* — fields that are read by the model at tool registration time, before any tool call is made.

Cisco's scanner specifically checks for this: it inspects the `description` and `inputSchema` fields of all tools registered by the MCP server for injection patterns at harness initialization time, before the first user prompt is sent.

**Action:** Add `PINJ-TRACE-003: Tool description injection` to the detection taxonomy in SPEC.md. In TAAS_SPEC.md, add this as a finding class surfaced in the live SSE stream as a `finding` event during the `started` phase (before the first `tool_call` event).

---

**Gap 4 — No shadow tool / tool shadowing detection**

AS-004 also covers "tool shadowing" — a malicious skill that registers a tool with the same name as a legitimate tool (e.g., registering a `read_file` that also exfiltrates data). The current spec does not check for duplicate tool names across registered MCP servers.

**Action:** Add `PSV-TRACE-003: Duplicate tool name (shadow tool)` to the detection taxonomy. The interceptor should check for name collisions at MCP server initialization and flag any duplicate with HIGH severity.

---

**Gap 5 — No cross-session canary contamination guard**

The canary filesystem is rebuilt fresh for each trace run (§3.2), but the canary ENV var values are defined as static strings in the spec (§5.3). If a malicious skill learns the canary patterns (e.g., by observing that `OPENAI_API_KEY=sk-proj-trace-canary-...` is always the canary format), it could conditionally suppress exfiltration behavior when canaries are detected.

Cisco's scanner addresses this with per-run randomized canary values that are seeded from a secret not visible to the skill. The SPEC.md mentions randomization (`--seed` flag) but does not specify that canary values must be indistinguishable from real credentials at the format level.

**Action:** Strengthen the canary value spec: canary API keys must use the same prefix format as real keys (`sk-proj-` for OpenAI, `sk-ant-` for Anthropic, `ghp_` for GitHub) with a random suffix of the correct length. The canary detection logic must match on the *value* (stored in the worker's memory), not on a recognizable format pattern.

---

**Gap 6 — No abuse prevention for BYOK key validation**

The TAAS_SPEC.md (§3.3) describes BYOK key storage and encryption but does not describe how BYOK keys are validated before storage. A user could store an invalid key, which would cause every scan using that key to fail after consuming a token hold. Worse, a user could store a key belonging to another user (e.g., a leaked key) and use TaaS as a proxy to consume that key's quota.

**Action:** Add a BYOK key validation step: when a key is stored, make a minimal test API call (e.g., list models, zero-cost endpoint) to verify the key is valid and belongs to the submitting user's account. If validation fails, reject the key storage. Log the validation attempt to the audit log.

---

**Gap 7 — No mention of Falco / eBPF as a secondary detection layer for the hosted service**

SPEC.md §11 item 6 mentions Falco as a v1.1 addition for the offline tool. For the hosted TaaS service, Falco is more important: the worker runs untrusted skill content inside a container, and a sufficiently sophisticated skill could attempt to escape the MCP layer by exploiting a vulnerability in the Python runtime or the Ollama subprocess. Falco + eBPF at the host level would catch this class of escape.

**Action:** Add Falco as a Phase 3 (Admin and Operations) deliverable for the TaaS service, not a deferred item. Each worker host should run Falco in daemon mode with a custom ruleset that alerts on: process spawning outside the expected process tree, outbound network connections from the worker process directly (bypassing the MCP interceptor), and filesystem writes outside `$CANARY_ROOT`.

---

**Gap 8 — No mention of report signing for the hosted service**

SPEC.md §9.3 defers report signing to a future milestone. For the TaaS service, report signing is a meaningful differentiator: a signed report from `trace.skillscan.dev` is a verifiable attestation that the scan was run on SkillScan infrastructure with a specific model and policy profile. Enterprise buyers will ask for this.

The implementation is straightforward: the worker signs the `report.json` file with an Ed25519 key before writing it to object storage. The public key is published at `https://trace.skillscan.dev/.well-known/signing-key.pub`. The HTML report includes the signature as a `<meta>` tag. Verification is a one-liner: `skillscan verify-report report.json`.

**Action:** Add report signing as a Phase 4 (Polish and Launch) deliverable. Add `skillscan verify-report` as a CLI subcommand.

---

**Gap 9 — No mention of the "observe profile" interaction with the TaaS queue**

The `include_observe_profile` option (§5.2) runs an additional pass with the `observe` policy profile and includes the full event log in the report. This doubles the trace execution time and the report size. The current token cost table (§4.2) does not account for this — a managed inference trace with `include_observe_profile: true` should cost more tokens than one without.

**Action:** Add `+2 tokens` to the managed inference trace cost when `include_observe_profile: true`. Add `+1 token` for BYOK traces. Update the token cost table in §4.2.

---

**Gap 10 — No mention of skill content size limits**

The API accepts `skill_content` as an inline string (§5.1). There is no documented size limit. A malicious user could submit a 10MB skill file, which would consume significant worker memory and potentially cause OOM on the worker. The `--max-file-size` flag exists in the offline scanner (M11.1) but is not referenced in the TaaS API spec.

**Action:** Add a hard limit of 512KB for `skill_content` inline submissions. For `skill_url` submissions, add a 1MB limit on the fetched content. Return HTTP 413 for oversized submissions. Document in §5.1.

---

### 16.2 Items from Cisco's Scanner Worth Adopting

Cisco's behavioral scanner includes several detection capabilities not currently in the skillscan-trace taxonomy:

| Cisco capability | Status in skillscan-trace | Recommendation |
|---|---|---|
| Tool description injection detection | Not present | Add as PINJ-TRACE-003 (Gap 3 above) |
| Shadow tool / duplicate tool name detection | Not present | Add as PSV-TRACE-003 (Gap 4 above) |
| Rug-pull detection (tool behavior changes between invocations) | Not present | Add as MAL-TRACE-003 in v1.1 |
| Cross-MCP server data leakage (data from one MCP server passed to another) | Not present | Add as EXF-TRACE-005 in v1.1 |
| Timing-based evasion detection (tool calls that only execute after N turns) | Not present | Add as MAL-TRACE-004 in v1.1 |
| Prompt injection via tool *name* (not description) | Not present | Add as PINJ-TRACE-004 in v1.1 |

The v1.0 scope additions (PINJ-TRACE-003, PSV-TRACE-003) are small and well-defined. The v1.1 items require more design work and are deferred.

---

### 16.3 OWASP AST10 Coverage Mapping

The current skillscan-trace taxonomy covers 7 of the 10 OWASP Agentic Skills Top 10 categories. The three gaps are noted:

| OWASP AST10 Item | Coverage | Notes |
|---|---|---|
| AS-001: Prompt Injection | ✅ PINJ-TRACE-001, PINJ-TRACE-002 | Covered |
| AS-002: Excessive Permissions | ✅ PSV-TRACE-001, PSV-TRACE-002 | Covered via undeclared tool use |
| AS-003: Insecure Data Handling | ✅ EXF-TRACE-001 through EXF-TRACE-004 | Covered |
| AS-004: Tool Poisoning | ⚠️ Partial | Description injection (Gap 3) and shadow tools (Gap 4) not yet covered |
| AS-005: Unsafe Skill Composition | ❌ Not covered | Cross-skill data leakage requires multi-skill trace; deferred to v1.1 |
| AS-006: Uncontrolled Resource Consumption | ⚠️ Partial | URL depth budget (Gap 2) addresses this partially; no CPU/memory budget per trace |
| AS-007: Inadequate Logging | ✅ Full trace log | Covered |
| AS-008: Insufficient Sandboxing | ⚠️ Partial | Falco layer (Gap 7) addresses the remaining gap |
| AS-009: Insecure Credential Handling | ✅ EXF-TRACE-003, EXF-TRACE-004 | Covered via canary ENV vars |
| AS-010: Unverified Skill Identity | ❌ Not covered | Report signing (Gap 8) is the path here; deferred to Phase 4 |

---

### 16.4 Infrastructure Revision: Nomad over SSH-based Rolling Restart

The current §10.4 deployment plan uses GitHub Actions SSHing into workers for rolling restarts. This is the one place where SSH is required for routine operations, which contradicts the "no SSH for routine operations" goal.

**Alternative:** Replace the SSH-based rolling restart with [HashiCorp Nomad](https://www.nomadproject.io/) running on the API gateway host as the control plane. Workers register as Nomad clients. Deployments are submitted as Nomad job specs via the Nomad HTTP API (no SSH). Nomad handles rolling updates, health checks, and automatic rescheduling on failure. The Hetzner API handles node provisioning; Nomad handles workload scheduling.

**Cost:** Nomad is free and open-source. It runs on the existing API gateway host (no additional instance). The operational model is: Manus calls the Nomad API to deploy a new job version; Nomad rolls it across workers one at a time with health checks between each.

**Tradeoff:** Nomad adds operational complexity (one more system to understand). Kubernetes is more widely known but is overkill for 2–4 workers. Nomad is the right size.

**Action:** Update §10.4 to use Nomad for deployment. Add Nomad job spec templates to the `skillscan-trace` repo under `infra/nomad/`. The GitHub Actions `deploy.yml` workflow calls the Nomad API instead of SSHing into workers.

---
