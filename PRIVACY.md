# Privacy & Key Handling

skillscan-trace is a local-first tool. **Your API keys are passed directly to the LLM provider and are never stored, logged, or transmitted by SkillScan.** Your skill files, API keys, and trace results never leave your machine except for the LLM API calls you explicitly authorize.

---

## Data flow

```
                        HTTPS
  You  ──────────►  skillscan-trace  ──────────►  LLM Provider
                    (your machine)                (OpenAI / OpenRouter / Ollama)
                         │                              ▲
                         │                              │
                         │   API key goes here only ────┘
                         │
                         ▼
                    Trace report
                    (local files)
```

API keys are read from your environment (`.env`, shell export, or `--api-key` flag), held in memory for the duration of the run, and passed directly to the LLM provider over HTTPS. They are never written to disk, never logged, and never sent to any SkillScan server or third party.

---

## What happens during a trace

When you run `skillscan-trace run ./skill.md`, the following happens entirely on your machine:

1. **Skill loading.** The skill file is read from your local filesystem. It is not uploaded anywhere.
2. **Canary environment setup.** A temporary directory is created in-process with synthetic credential files, wallet paths, and environment variables. These are randomly generated per run and have no real value.
3. **LLM API call.** The skill's content is sent to the LLM provider you configured (`--provider openai`, `--provider openrouter`, or `--provider ollama`). This is the only network request skillscan-trace makes. The request goes directly from your machine to the provider — it does not pass through any SkillScan server.
4. **Canary server.** The instrumented MCP server runs in-process. It intercepts every tool call the model makes and checks it against the canary taxonomy. No subprocess is spawned; no data is written to disk except the trace report you explicitly request.
5. **Report output.** The trace report is written to your local `./trace-output/` directory (or the path you specify with `--output-dir`). It is not uploaded anywhere.

---

## Your API key

Your API key is passed directly to the LLM provider you chose. It is not:

- Stored by skillscan-trace (it is read from your `.env` file, environment variable, or `--api-key` flag and used only for the duration of the run)
- Transmitted to any SkillScan server (there is no SkillScan server in local mode)
- Logged to disk (the trace report does not include your API key)
- Shared with any third party other than the LLM provider you selected

If you use `--provider openrouter`, your key goes to [OpenRouter](https://openrouter.ai). If you use `--provider openai`, it goes to [OpenAI](https://openai.com). If you use `--provider ollama`, no key is required and no network request is made to any external service.

### Storing keys in .env

skillscan-trace reads a `.env` file automatically from the current directory and all parent directories (nearest file wins). This is the recommended way to store API keys:

```
# .env  — add this file to .gitignore, never commit it
OPENAI_API_KEY=sk-...
OPENROUTER_API_KEY=sk-or-...
ANTHROPIC_API_KEY=sk-ant-...   # only needed when --judge is enabled
```

Priority order (highest wins):
1. `--api-key` CLI flag
2. Shell environment variable (`export OPENAI_API_KEY=...`)
3. `.env` file in the current or nearest ancestor directory
4. `skillscan-trace.yaml` config file (API keys are **not** supported here — use `.env` instead)

The `.env` file is loaded with `override=False`, meaning shell variables you have already exported always take precedence over `.env` values. If no `.env` file is found, skillscan-trace falls back to the shell environment silently.

---

## What is sent to the LLM provider

The LLM API call contains:

- The skill's `SKILL.md` content (as the system prompt)
- A generated user message that exercises the skill's stated functionality
- The canary tool definitions (the list of tools the model can call)

The canary tool definitions describe the tool interface (names, parameter schemas) but do not contain any real credential values. The canary values (fake AWS keys, fake wallet seeds, etc.) are only present in the tool *responses* that the canary server returns when the model calls a tool — those responses stay on your machine and are never sent back to the LLM provider in a way that would expose them.

---

## Ollama (fully local)

If you use `--provider ollama`, the entire trace runs on your machine with no external network requests. The model runs locally via [Ollama](https://ollama.com/). No API key is required. No data leaves your machine.

---

## Trace reports

Trace reports (JSON, SARIF, text) are written to your local filesystem only. They contain:

- The skill path and SHA-256 hash of the skill content
- The model and provider used
- All tool calls the model made (tool name, arguments, canary server response)
- Any findings (rule ID, severity, description)
- Token usage for the run

They do not contain your API key, your system's real credential files, or any data from outside the canary environment.

---

## Hosted service (trace.skillscan.sh)

The hosted service at `trace.skillscan.sh` follows the **BYOK (Bring Your Own Key)** model:

- Your API key is forwarded to the LLM provider over HTTPS. It is never stored, logged, or cached by the hosted service.
- Trace reports are cached in Cloudflare R2 storage, keyed by `sha256(skill content + model + parameters)`. **Only the report is cached — never your API key.**
- Errored traces are not cached.
- The Cloudflare Worker enforces rate limits and CORS, but does not inspect or store API keys.
- Skill file content is held in memory during the trace run and discarded after the report is generated. It is not stored beyond the trace session.

```
                     HTTPS                          HTTPS
  You  ──────────►  trace.skillscan.sh  ──────────►  LLM Provider
                    (CF Worker + Fly.io)              (OpenAI / OpenRouter)
                         │                                  ▲
                         │                                  │
                         │   API key forwarded here only ───┘
                         │
                         ▼
                    R2 Cache
                    (report only, no keys)
```

---

## What is NOT stored

- **API keys** — never stored, logged, or cached anywhere by SkillScan (local or hosted)
- **Skill file contents** — not retained beyond the trace session
- **User identity** — no accounts, no login, no tracking
- **Telemetry** — skillscan-trace has no telemetry, no analytics, and no phone-home behavior

---

## What IS stored

- **Trace reports** (local mode) — written to `--output-dir` (default: `./trace-output/`) on your local filesystem
- **Cached reports** (serve mode) — stored in `--cache-dir` on the server's local filesystem
- **Cached reports** (hosted service) — stored in Cloudflare R2, keyed by content hash

---

## Summary

| Data | Where it goes |
|---|---|
| Skill file content | LLM provider (as system prompt) |
| API key | LLM provider only (never stored or logged) |
| Canary tool definitions | LLM provider (tool schemas, no real values) |
| Canary credential values | Your machine only (in-process canary server) |
| Trace report | Local filesystem / R2 cache (hosted mode) |
| Your real credential files | Not accessed (canary uses synthetic files) |
| `.env` file contents | Your machine only (never transmitted) |
| Telemetry / analytics | None — no phone-home, no tracking |

If you have questions or concerns about data handling, open an issue at [github.com/kurtpayne/skillscan-trace](https://github.com/kurtpayne/skillscan-trace/issues).
