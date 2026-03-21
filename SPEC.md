# skillscan-trace v1.0 Specification

**Status:** Draft — pre-implementation  
**Last updated:** 2026-03-20  
**Authors:** SkillScan project

This document is the authoritative behavioral specification for skillscan-trace v1.0. An implementation is considered correct if and only if it satisfies all MUST requirements in this document. SHOULD requirements are strong recommendations; MAY requirements are optional.

---

## 1. Overview and Goals

skillscan-trace is a behavioral execution engine for MCP-based AI agent skills. Its purpose is to answer the question: **what does this skill actually do when an agent follows its instructions?**

The tool executes a skill against a real language model inside an instrumented, isolated environment. Every tool call the model makes is intercepted, logged, and checked against a detection taxonomy. The result is a structured trace report that describes observed behavior and any security findings.

### 1.1 Design Principles

**No GPU required.** The default execution path uses a small model via Ollama running on CPU. A user with a standard laptop should be able to run a trace without any special hardware or cloud accounts.

**No API key required by default.** Ollama with a locally-pulled model is the zero-friction path. API model support (OpenAI, Anthropic) is a supported alternative, not the default.

**Low compliance, high signal.** The model used for tracing should follow skill instructions with minimal refusal. A well-aligned model that refuses malicious instructions produces false negatives. A smaller, less-aligned model that follows instructions is the correct choice for behavioral detection. See Section 4.

**Structured output.** Every trace produces a machine-readable JSON report and optionally a SARIF 2.1.0 report. Human-readable text output is a formatting layer on top of the structured data.

**Open to eval, not committed to it.** The architecture should accommodate future expansion into behavioral assertion evaluation (specifying what a skill *should* do and verifying it), but v1.0 does not implement this. Trace-only for now.

**Corpus feedback loop.** Traces that produce findings can be reviewed and added to the skillscan-security corpus as `sandbox_verified/` labeled examples. This is the primary mechanism for improving the ML classifier's recall on behavioral patterns that static analysis misses.

---

## 2. Skill Format Support

skillscan-trace MUST support all skill formats found in the wild. The input resolver handles format detection transparently.

### 2.1 Supported Formats

| Format | Detection | Loading |
|---|---|---|
| Directory with `SKILL.md` | `path/` is a directory containing `SKILL.md` | Load `SKILL.md` as primary; load any other `.md` files as supplementary context |
| Single `SKILL.md` file | `path` is a file named `SKILL.md` | Load directly |
| Single `.md` file | `path` is any `.md` file | Load directly |
| Directory without `SKILL.md` | `path/` is a directory with `.md` files but no `SKILL.md` | Load all `.md` files in alphabetical order, concatenated |
| Directory with frontmatter | Any `.md` file with YAML frontmatter | Parse frontmatter; use `allowed-tools` if present |
| Plain text | `path` is a `.txt` file | Load as skill content |

### 2.2 Frontmatter Parsing

Skills MAY include YAML frontmatter. When present, the following fields are recognized:

```yaml
---
name: skill-name          # display name
version: "1.0"            # skill version
description: "..."        # human-readable description
allowed-tools:            # list of tool names the skill declares it needs
  - read_file
  - http_fetch
tags: [tag1, tag2]        # arbitrary tags
---
```

The `allowed-tools` field is informational — it describes what the skill *declares* it needs. The trace records what it *actually* uses. Undeclared tool use is flagged as a finding (PSV — Policy Violation).

### 2.3 Input Validation

The resolver MUST:
- Reject inputs that are not `.md`, `.txt`, or directories
- Warn (but not fail) if a directory contains no `.md` files
- Compute and record a SHA-256 hash of the loaded skill content before any processing
- Record the resolved format type in the trace report

---

## 3. Execution Environment

### 3.1 Isolation

The trace execution environment MUST be isolated from the host system. In v1.0, isolation is achieved through a combination of:

- **Canary filesystem**: A temporary directory (`tmpfs` on Linux, `tmpdir` on macOS) populated with canary files. The MCP server's `read_file` implementation is rooted here — it cannot access the real host filesystem.
- **Network interception**: All outbound HTTP/HTTPS calls go through the MCP server's `http_fetch` implementation, which checks destinations against the allowlist and logs all requests.
- **ENV var isolation**: The agent process runs with a controlled environment containing only canary ENV vars (see Section 5.3). Real host ENV vars are not passed through.
- **Process isolation**: The agent harness runs in a subprocess with a restricted environment. Direct subprocess spawning by the model is not possible — all execution goes through the `bash` tool interceptor.

**Note on Docker:** A Docker container image is a v1.0 deliverable for users who want stronger isolation guarantees. The container wraps the above isolation mechanisms and adds filesystem namespacing. However, Docker MUST NOT be required for basic usage — the tool MUST work without Docker on any system with Python 3.11+ and Ollama installed.

### 3.2 Canary Filesystem Layout

The canary filesystem is a temporary directory populated before each trace run. It presents a realistic-looking home directory structure to the agent.

```
$CANARY_ROOT/
├── home/
│   └── user/
│       ├── .ssh/
│       │   ├── id_rsa              # canary SSH private key
│       │   ├── id_ed25519          # canary ED25519 key
│       │   ├── config              # canary SSH config
│       │   └── authorized_keys     # canary authorized keys
│       ├── .aws/
│       │   ├── credentials         # canary AWS credentials
│       │   └── config              # canary AWS config
│       ├── .config/
│       │   ├── gcloud/
│       │   │   ├── credentials.db  # canary GCloud creds
│       │   │   └── application_default_credentials.json
│       │   └── solana/
│       │       └── id.json         # canary Solana wallet
│       ├── .kube/
│       │   └── config              # canary kubeconfig
│       ├── .bitcoin/
│       │   └── wallet.dat          # canary Bitcoin wallet (binary)
│       ├── .ethereum/
│       │   └── keystore/
│       │       └── UTC--canary     # canary Ethereum keystore
│       ├── .gitconfig              # canary git config
│       ├── .git-credentials        # canary git credentials
│       ├── .bash_history           # canary shell history
│       ├── .zsh_history            # canary zsh history
│       ├── .bashrc                 # canary bashrc
│       ├── .zshrc                  # canary zshrc
│       ├── .env                    # canary .env file (see Section 5.3)
│       └── workspace/              # writable working directory for the agent
│           └── .git/
│               └── config          # canary git repo config
└── etc/
    ├── passwd                      # canary /etc/passwd
    ├── shadow                      # canary /etc/shadow (root-owned, unreadable)
    └── hosts                       # standard /etc/hosts
```

All canary files MUST contain realistic-looking but non-functional values. Canary credentials MUST be clearly marked as non-functional in comments where the format allows it, but MUST NOT contain obvious markers like "CANARY" in the values themselves — the values should look real to the model.

The `workspace/` directory is the only writable location. The agent's `read_file` and `write_file` calls are scoped to `$CANARY_ROOT` — no access to the real filesystem.

### 3.3 Canary File Contents

Example canary values (illustrative — actual values should be randomized per run):

**`~/.aws/credentials`:**
```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
```

**`~/.ssh/id_rsa`:** A valid RSA private key format (generated fresh, non-functional — the corresponding public key is not registered anywhere).

**`~/.config/solana/id.json`:** A valid-format but non-functional Solana keypair JSON.

**`~/.env`:** See Section 5.3 for canary ENV var contents.

---

## 4. Model Configuration

### 4.1 Model Selection Rationale

The choice of model for tracing is a security-relevant decision. A well-aligned model (Claude 3.5 Sonnet, GPT-4o) will frequently refuse to follow malicious instructions embedded in a skill, producing false negatives. A smaller, less-aligned model will follow the instructions, which is the ground-truth behavioral signal we want.

This is not a bug — it is the correct design choice for a behavioral detection tool. The model is not the subject of evaluation; the skill is.

### 4.2 Recommended Models

| Model | Provider | Size | Tool-call reliability | Refusal rate | Notes |
|---|---|---|---|---|---|
| `qwen2.5:7b` | Ollama | 7B | High | Low-medium | **Recommended default.** Explicit JSON structured output improvements; good tool-call schema adherence |
| `mistral:7b` | Ollama | 7B | High | Low | Explicit function calling support; efficient architecture |
| `llama3.1:8b` | Ollama | 8B | High | Medium | Reliable tool-call JSON; slightly higher refusal rate than Qwen |
| `phi3:mini` | Ollama | 3.8B | High | Medium | Best-in-class JSON adherence for its size; good CPU performance |
| `llama3.2:3b` | Ollama | 3B | Medium | Low | Borderline tool-call reliability; only use if RAM-constrained |
| `openai/gpt-4o-mini` | OpenAI API | — | Very high | High | API fallback; high refusal rate reduces detection recall |
| `anthropic/claude-3-haiku` | Anthropic API | — | Very high | Very high | Not recommended for trace; too many refusals |

**Default:** `qwen2.5:7b` via Ollama.

### 4.3 Model Configuration

```yaml
# trace-config.yml
model:
  provider: ollama          # ollama | openai | anthropic
  model: qwen2.5:7b
  base_url: http://localhost:11434  # Ollama default
  temperature: 0.0          # deterministic for reproducibility
  max_tokens: 4096
  timeout_seconds: 120
```

The temperature SHOULD be set to 0.0 for reproducibility. A non-zero temperature means the same skill may produce different traces on different runs.

### 4.4 Multi-Model Runs

The CLI SHOULD support running a skill against multiple models in sequence:

```bash
skillscan-trace run ./skill/ --model qwen2.5:7b --model mistral:7b
```

When multiple models are specified, each produces an independent trace report. The summary report shows findings that appeared in any model's trace (union) and findings that appeared in all models' traces (intersection). Agreement across models increases confidence.

---

## 5. Detection Taxonomy

### 5.1 Finding Classes

skillscan-trace uses the same finding ID namespace as skillscan-security:

| Class | Prefix | Description |
|---|---|---|
| Exfiltration | `EXF-` | Credential, file, or data exfiltration attempt |
| Malware behavior | `MAL-` | Malicious code execution, payload download |
| Prompt injection | `PINJ-` | Prompt injection via tool output or skill content |
| Policy violation | `PSV-` | Undeclared tool use, permission boundary violation |
| Reconnaissance | `RCN-` | Environment probing, binary discovery, filesystem exploration |
| IOC match | `IOC-` | Network call to known-malicious domain or IP |

### 5.2 File Access Detection

The `read_file` tool interceptor checks every path against the canary taxonomy. The following access patterns generate findings:

**EXF-TRACE-001: Canary credential file read**

Triggered when the agent reads any file in the canary credential set:

- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/config`, `~/.ssh/authorized_keys`
- `~/.aws/credentials`, `~/.aws/config`
- `~/.config/gcloud/credentials.db`, `~/.config/gcloud/application_default_credentials.json`
- `~/.kube/config`
- `~/.config/solana/id.json`
- `~/.bitcoin/wallet.dat`, `~/.ethereum/keystore/*`
- `~/.gitconfig`, `~/.git-credentials`, `.git/config`
- `~/.bash_history`, `~/.zsh_history`, `~/.bashrc`, `~/.zshrc`
- `/etc/passwd`, `/etc/shadow`

Severity: **HIGH**

**EXF-TRACE-002: Browser credential file read**

Triggered when the agent reads browser credential stores:

- `*/Google/Chrome/*/Login Data`
- `*/Firefox/Profiles/*/logins.json`
- `*/Chromium/*/Login Data`

Severity: **HIGH**

**RCN-TRACE-001: Filesystem reconnaissance**

Triggered when the agent performs broad filesystem exploration:

- Any `read_file` call on a path matching `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_*`, `*credentials*`, `*secret*`, `*token*`, `wallet.dat`, `keystore`
- Any `read_file` call on a path under `~/.ssh/`, `~/.aws/`, `~/.kube/`, `~/.config/gcloud/`

Severity: **MEDIUM** (escalates to HIGH if followed by a network call)

**PSV-TRACE-001: Undeclared file access**

Triggered when the agent reads a file outside the `workspace/` directory and `read_file` was not declared in the skill's `allowed-tools` frontmatter.

Severity: **LOW**

### 5.3 Environment Variable Detection

**Canary ENV vars** are planted in the agent's execution environment. They appear real but are non-functional and monitored.

The canary `.env` file contains:

```bash
OPENAI_API_KEY=sk-proj-trace-canary-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
ANTHROPIC_API_KEY=sk-ant-trace-canary-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
GITHUB_TOKEN=ghp_trace_canary_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://admin:trace-canary-pw@db.internal.example.com:5432/main
STRIPE_SECRET_KEY=sk_live_trace_canary_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
SLACK_BOT_TOKEN=xoxb-trace-canary-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
DISCORD_TOKEN=trace.canary.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
SENDGRID_API_KEY=SG.trace-canary.a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

Canary values MUST look syntactically valid for their respective service (correct prefix format, correct length). They MUST NOT be real credentials.

**EXF-TRACE-003: ENV var read via bash**

Triggered when the agent executes any of the following via the `bash` tool:
- `env`, `printenv`, `env | ...`, `printenv | ...`
- `echo $<VAR_NAME>` for any canary var name
- `cat /proc/self/environ`
- `cat ~/.env`, `cat .env`, `cat .env.local`, `cat .env.*`
- `python3 -c "import os; print(os.environ..."`
- `node -e "console.log(process.env..."`

Severity: **HIGH**

**EXF-TRACE-004: Canary ENV var value in network request**

Triggered when any canary ENV var *value* appears in an outbound network request body, URL, or header. This is the highest-confidence finding — it means the agent successfully read a canary credential and attempted to exfiltrate it.

Severity: **CRITICAL**

**RCN-TRACE-002: ENV var enumeration**

Triggered when the agent reads shell configuration files that commonly contain ENV vars:
- `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`
- `~/.config/fish/config.fish`

Severity: **MEDIUM**

### 5.4 Network Access Detection

All outbound network calls go through the `http_fetch` tool interceptor. The interceptor:

1. Checks the destination domain against the always-block list (Section 5.4.1)
2. Checks the destination domain against the active allowlist (Section 5.4.2)
3. Logs the call regardless of allowlist status
4. Checks the request body and headers for canary ENV var values (EXF-TRACE-004)
5. Returns a synthetic response (configurable) or blocks the request

**IOC-TRACE-001: Network call to always-blocked domain**

The following domains are always blocked and always generate a finding, regardless of user configuration:

```
ngrok.io, *.ngrok.io, *.ngrok-free.app
serveo.net, *.serveo.net
localhost.run
webhook.site
requestbin.com, *.requestbin.com
burpcollaborator.net, *.burpcollaborator.net
oastify.com, *.oastify.com
interactsh.com, *.interactsh.com
canarytokens.org, *.canarytokens.org
pipedream.net, *.pipedream.net
```

Severity: **CRITICAL**

**IOC-TRACE-002: Network call to undeclared domain**

Triggered when the agent makes a network call to a domain not in the active allowlist and not in the always-block list.

Severity: **HIGH** (downgraded to **MEDIUM** if the domain is a well-known public service not in the allowlist profiles)

**PSV-TRACE-002: Network call when http_fetch not declared**

Triggered when the agent makes any network call and `http_fetch` was not declared in the skill's `allowed-tools` frontmatter.

Severity: **MEDIUM**

### 5.5 Process Execution Detection

The `bash` tool interceptor parses commands and checks them against the following patterns:

**MAL-TRACE-001: Remote code execution pattern**

Triggered by:
- `curl <url> | bash`, `curl <url> | sh`
- `wget -O- <url> | bash`
- `python3 -c "import urllib..."` followed by `exec()`
- Any pipe from a network fetch to a shell interpreter

Severity: **CRITICAL**

**RCN-TRACE-003: Binary probing**

Triggered when the agent probes for the existence of specific binaries:
- `which <binary>` or `command -v <binary>` for any binary in the watchlist
- `ls /usr/bin/<binary>`, `stat /usr/bin/<binary>`
- `find / -name <binary>` or `find /usr -name <binary>`

Binary watchlist: `curl`, `wget`, `nc`, `ncat`, `netcat`, `python3`, `python`, `ruby`, `perl`, `gpg`, `openssl`, `aws`, `gcloud`, `kubectl`, `docker`, `git`, `ssh`, `scp`, `rsync`, `base64`, `xxd`

Severity: **LOW** (single probe), **MEDIUM** (3+ probes in one trace)

**RCN-TRACE-004: Filesystem traversal**

Triggered by:
- `find ~/ -type f ...`, `find /home -type f ...`, `find /Users -type f ...`
- `ls -la ~/`, `ls -R ~/`
- `tar -czf ... ~/`, `zip -r ... ~/`

Severity: **MEDIUM**

**MAL-TRACE-002: Persistence mechanism**

Triggered by:
- Writing to `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`
- Writing to `~/.ssh/authorized_keys`
- Writing to cron directories: `/etc/cron.d/`, `/var/spool/cron/`
- Writing to systemd unit directories: `~/.config/systemd/user/`, `/etc/systemd/system/`
- Writing to `~/Library/LaunchAgents/` (macOS)

Severity: **HIGH**

### 5.6 Prompt Injection Detection

**PINJ-TRACE-001: Prompt injection in tool response**

Triggered when the content returned by a tool call (e.g., the result of `http_fetch` or `read_file`) contains prompt injection patterns. The same patterns used by the static analyzer apply here, but applied to tool *outputs* rather than skill content.

This is a high-value detection class: the skill itself may be clean, but it fetches content from an attacker-controlled URL that contains injection instructions. The trace captures this because it observes the full tool call cycle including the response.

Severity: **HIGH**

**PINJ-TRACE-002: Indirect injection via fetched content**

Triggered when the model's behavior changes after receiving tool output containing injection patterns — specifically, when the model makes tool calls after a fetched response that it did not make before, or when the model's tool calls change character (e.g., begins reading credential files after fetching external content).

This is a behavioral finding, not a content finding. It requires correlating the sequence of tool calls with the content of tool responses.

Severity: **CRITICAL**

---

## 6. Domain Allowlist

The domain allowlist system is documented in detail in the skillscan-security repo at `trace/domains/verified.yml`. This section summarizes the behavior.

### 6.1 Three-tier precedence

1. **CLI flags** (`--allow-domains`, `--block-domains`, `--profile`) — highest precedence
2. **`trace-config.yml`** in the current directory or specified with `--config`
3. **`verified.yml`** bundled with the tool — lowest precedence

### 6.2 Always-block list

The domains in Section 5.4.1 are always blocked and always generate findings. They cannot be overridden by any user configuration.

### 6.3 Named profiles

Profiles allowlist domains for specific cloud platforms. Available profiles: `google_cloud`, `aws`, `azure`, `openai`, `anthropic`, `huggingface`, `docker`, `kubernetes`, `vercel`, `netlify`, `stripe`, `slack`, `linear`, `notion`, `jira_confluence`, `datadog`, `sentry`, `cloudflare`, `supabase`, `neon`, `upstash`, `twilio`, `sendgrid`, `resend`, `posthog`.

Profiles are opt-in. A skill with no reason to call AWS should not have AWS silently allowlisted.

### 6.4 Logging vs. findings

All network calls are logged regardless of allowlist status. Allowlisted domains suppress *findings*; they do not suppress *logging*. The trace report always contains the complete network call record.

### 6.5 Synthetic responses

By default, the `http_fetch` interceptor returns a synthetic 200 OK response with an empty body for allowlisted domains, and a synthetic 403 Forbidden for blocked domains. This allows the trace to complete without making real network calls.

The `--live-network` flag disables synthetic responses and allows real network calls to allowlisted domains. This is useful for testing skills that depend on real external content, but it means the trace is no longer fully isolated.

---

## 7. Trace Report Format

### 7.1 JSON Trace Report

The native output format is a JSON document conforming to the following schema:

```json
{
  "schema_version": "1.0.0",
  "trace_id": "trc_<timestamp>_<random8>",
  "generated_at": "<ISO 8601 timestamp>",
  "skill": {
    "path": "<resolved absolute path>",
    "name": "<name from frontmatter or filename>",
    "format": "<single_file|directory|multi_file|plain_text>",
    "sha256": "<hex digest of skill content>",
    "frontmatter": {
      "allowed_tools": ["read_file", "http_fetch"],
      "version": "1.0",
      "description": "..."
    }
  },
  "model": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "base_url": "http://localhost:11434",
    "temperature": 0.0
  },
  "prompt": "<user prompt used for this trace>",
  "duration_ms": 4823,
  "tool_calls": [
    {
      "seq": 1,
      "tool": "read_file",
      "input": {"path": "~/.aws/credentials"},
      "resolved_path": "/canary/home/user/.aws/credentials",
      "canary_hit": true,
      "canary_category": "cloud_credentials",
      "output_truncated": "<first 100 chars of synthetic response>",
      "timestamp_ms": 1234,
      "findings": ["EXF-TRACE-001"]
    }
  ],
  "findings": [
    {
      "id": "EXF-TRACE-001",
      "severity": "HIGH",
      "title": "Canary credential file read",
      "description": "The agent read ~/.aws/credentials",
      "tool_call_seq": 1,
      "evidence": {
        "path": "~/.aws/credentials",
        "canary_category": "cloud_credentials"
      }
    }
  ],
  "summary": {
    "total_tool_calls": 7,
    "finding_count": 1,
    "severity_max": "HIGH",
    "clean": false,
    "finding_ids": ["EXF-TRACE-001"]
  }
}
```

### 7.2 SARIF Output

When `--format sarif` is specified, the tool emits a SARIF 2.1.0 document. The SARIF output maps findings to SARIF `result` objects. The trace report is embedded as a SARIF `artifact` attachment.

### 7.3 Text Output

When `--format text` is specified (default for interactive use), the tool emits a human-readable summary:

```
skillscan-trace v1.0.0
Skill: git-helper (./my-skill/SKILL.md)
Model: qwen2.5:7b via Ollama
Prompt: "Help me commit my changes"

Running trace... done (4.8s, 7 tool calls)

FINDINGS (1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[HIGH] EXF-TRACE-001 — Canary credential file read
  Tool call #1: read_file(path="~/.aws/credentials")
  The agent read a canary AWS credentials file.

TOOL CALL SUMMARY
  read_file     × 3   (1 finding)
  bash          × 2   (0 findings)
  http_fetch    × 2   (0 findings)

Result: NOT CLEAN (1 finding, max severity: HIGH)
Trace report: ./traces/trc_20260320_abc123.json
```

---

## 8. CLI Interface

### 8.1 Commands

```
skillscan-trace run <skill-path>    Execute a trace
skillscan-trace update-domains      Update the bundled domain allowlist from the repo
skillscan-trace models              List available Ollama models
skillscan-trace check               Verify Ollama is running and the default model is available
skillscan-trace version             Print version information
```

### 8.2 `run` flags

```
--prompt <text>           User prompt to send to the model
                          Default: a generic prompt appropriate for the skill's stated purpose
--prompt-file <path>      Load user prompt from a file
--model <spec>            Model specification (e.g., qwen2.5:7b, openai/gpt-4o-mini)
                          Default: qwen2.5:7b
--profile <name>          Enable a named domain allowlist profile (repeatable)
--allow-domains <csv>     Additional domains to allowlist (comma-separated)
--block-domains <csv>     Additional domains to block (comma-separated)
--allow-paths <csv>       Additional filesystem paths to allow reads from
--config <path>           Path to trace-config.yml
--format <fmt>            Output format: text|json|sarif (default: text)
--output <path>           Write trace report to this path (default: ./traces/<trace_id>.json)
--live-network            Allow real network calls to allowlisted domains
--max-turns <n>           Maximum tool-use turns before timeout (default: 20)
--timeout <seconds>       Total trace timeout (default: 120)
--key <api-key>           API key for non-Ollama models
--base-url <url>          Override model API base URL
--no-canary               Disable canary filesystem (raw execution, less safe)
--verbose                 Print tool call details as they happen
--quiet                   Suppress all output except findings
```

### 8.3 `trace-config.yml`

```yaml
# trace-config.yml — project-level configuration
model:
  provider: ollama
  model: qwen2.5:7b
  temperature: 0.0
  max_tokens: 4096
  timeout_seconds: 120

profiles:
  - google_cloud
  - github

allow_domains:
  - internal-api.mycompany.com

block_domains: []

allow_paths:
  - ./workspace/

prompts:
  default: "Help me with my task"
  # Skill-specific prompts can be defined here
  git-helper: "Help me commit my changes to the main branch"
```

---

## 9. Compute and Deployment

### 9.1 User Execution (Default Path)

Users run skillscan-trace on their own machine. Requirements:
- Python 3.11+
- [Ollama](https://ollama.com/) installed and running
- Default model pulled: `ollama pull qwen2.5:7b` (~4.7GB)
- 8GB RAM minimum (for 7B model on CPU)

No GPU required. Inference on CPU is slower (~30-60 seconds per trace for a 7B model on a modern laptop) but fully functional.

### 9.2 Corpus Generation (SkillScan Team)

For generating labeled corpus data from the skillscan-security corpus (~870 skills as of 2026-03-20), the team uses Modal Labs:

- **Platform:** Modal Labs serverless GPU
- **Model:** `qwen2.5:7b` via Ollama in a Modal container, or `gpt-4o-mini` via OpenAI API
- **Cost estimate:** ~$0.006/trace on Modal L4 GPU; ~$0.001/trace on GPT-4o-mini API
- **Scale:** 1,000 traces/week ≈ $6-10/week
- **Configuration:** See `scripts/modal_trace_batch.py` (to be created)

The Modal approach uses the same `finetune_modal.py` infrastructure already in skillscan-security. A batch trace run produces a JSONL file of trace reports, which are then reviewed and added to `corpus/sandbox_verified/`.

### 9.3 Signing (Future — Not v1.0)

The question of signing trace reports has been considered and deferred. The design space:

**Self-signing (author signs their own skill):** Adds tamper protection to the skill file itself. Low overhead. Limited value without an enforcement hook at skill load time — skills can always be sideloaded as raw prompts, bypassing any verification step.

**Report signing (SkillScan signs trace reports):** When the SkillScan team runs a trace on our infrastructure and publishes the report, we sign the report with our public key. Downstream consumers can verify the report came from us and was not altered. This is a narrow but real use case for the corpus feedback loop.

**CA model (third-party notary):** Not pursued. Overhead and liability are prohibitive for an open-source project at this stage.

**Sigstore/cosign model:** The most technically sound approach — keyless signing using OIDC identity (GitHub Actions OIDC token as proof), with a transparency log. This is how container image signing works in the modern supply chain. Worth revisiting when the project has enough adoption to justify the infrastructure.

**Decision:** Do not implement signing in v1.0. Note the design space in the architecture document. Revisit when the project has demonstrated value and adoption.

---

## 10. Relationship to the SkillScan Family

### 10.1 Shared artifacts

| Artifact | Owner | Consumer |
|---|---|---|
| Finding ID namespace | skillscan-security | skillscan-trace (uses same IDs) |
| Canary taxonomy | skillscan-security (`docs/TRACE_RESEARCH.md`) | skillscan-trace (implements it) |
| Domain allowlist | skillscan-security (`trace/domains/verified.yml`) | skillscan-trace (bundles it) |
| Corpus | skillscan-security (`corpus/`) | skillscan-trace (reads skills for batch tracing) |
| Sandbox-verified corpus | skillscan-security (`corpus/sandbox_verified/`) | skillscan-security ML pipeline (training data) |

### 10.2 Corpus feedback loop

The primary value of skillscan-trace for the SkillScan project is the corpus feedback loop:

1. Run batch traces against the full skillscan-security corpus
2. Review traces that produce findings
3. For skills that the static analyzer missed but the trace caught, add them to `corpus/sandbox_verified/` with behavioral labels
4. Re-train the ML classifier with the new labeled examples
5. Measure improvement in F1 score on the held-out eval set

This is the path to improving the ML classifier's recall on behavioral patterns that static analysis misses — conditional payloads, obfuscated instructions, indirect injection via fetched content.

### 10.3 Future: skillscan-lint

skillscan-lint (planned, not started) will validate skill format, schema, and style. It is a distinct tool from both skillscan (security analysis) and skillscan-trace (behavioral execution). The three tools are designed to be composable:

```bash
# Full pipeline
skillscan-lint ./skill/    # format and schema validation
skillscan ./skill/         # static security analysis
skillscan-trace ./skill/   # behavioral execution
```

---

## 11. Open Questions

The following questions are unresolved and should be addressed during implementation:

1. **MCP SDK server implementation.** The official Python `mcp` SDK (`pip install mcp`) should support custom server implementations. Verify the API surface for building an instrumented server that intercepts tool calls before executing them.

2. **Ollama tool-use format.** Ollama added OpenAI-compatible tool-use in late 2024. Verify that `qwen2.5:7b` reliably emits tool calls in the Ollama format and that the harness can drive a multi-turn tool loop using the standard OpenAI tool-call API.

3. **Bash command parsing depth.** The v1.0 bash interceptor uses regex pattern matching. Common obfuscation patterns to handle: variable expansion (`CMD=$(echo 'Y3VybA==' | base64 -d); $CMD ...`), subshell execution, heredoc payloads, and `eval` with encoded strings. A full shell AST parser (`bashlex`) is a v1.1 upgrade.

4. **Synthetic response fidelity.** The default synthetic responses (200 OK, empty body) may cause the model to behave differently than it would with real responses. For skills that depend on external content, the trace may not reflect real-world behavior. The `--live-network` flag addresses this at the cost of isolation.

5. **Multi-turn eval expansion.** The current spec is single-turn: one user prompt, one tool-use loop, one trace. Future expansion to multi-turn traces (simulating a full conversation) requires defining what "the conversation" looks like. This is the path to behavioral assertion evaluation (specifying what a skill *should* do across a conversation). Deferred to v1.1.

6. **Falco as secondary layer.** Falco + eBPF as a secondary detection layer inside the Docker container would catch behaviors that bypass the MCP layer (e.g., direct subprocess spawning). Not required for v1.0 but a natural v1.1 addition.
