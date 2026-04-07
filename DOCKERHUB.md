# `skillscan-trace` — Behavioral trace engine for AI agent skills

`skillscan-trace` is a BYOK (bring-your-own-key) behavioral trace engine that drives AI agent skills through a canary MCP server to detect exfiltration, credential theft, and malicious tool use. It intercepts every tool call the model makes, returns synthetic responses with embedded tracking tokens, and fires findings when the model attempts to read sensitive paths, relay canary tokens to external endpoints, or invoke undeclared tools.

## Quick Start

### Single trace

```bash
docker run --rm \
  -e OPENROUTER_API_KEY=... \
  -v $(pwd):/w \
  kurtpayne/skillscan-trace run /w/SKILL.md --provider openrouter
```

### Self-hosted server

```bash
docker run -p 8080:8080 kurtpayne/skillscan-trace serve
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | For OpenAI provider | OpenAI API key |
| `OPENROUTER_API_KEY` | For OpenRouter provider | OpenRouter API key |
| `ANTHROPIC_API_KEY` | For Anthropic provider | Anthropic API key |
| `R2_ACCOUNT_ID` | No (hosted mode) | Cloudflare R2 account ID for report storage |
| `R2_ACCESS_KEY_ID` | No (hosted mode) | Cloudflare R2 access key ID |
| `R2_SECRET_ACCESS_KEY` | No (hosted mode) | Cloudflare R2 secret access key |
| `R2_BUCKET` | No (hosted mode) | Cloudflare R2 bucket name |

## Privacy

Your API key is used for the duration of the trace and immediately discarded. SkillScan never stores or logs API keys.

## Canary Tool Surfaces (36)

The canary MCP server exposes the following 36 tool surfaces for behavioral analysis:

| Category | Tools |
|---|---|
| Filesystem & network | `bash`, `read_file`, `write_file`, `http_fetch`, `list_directory` |
| Email & messaging | `email_send`, `gmail_send`, `search_emails`, `read_email`, `slack_post_message` |
| Calendar | `calendar_create`, `calendar_list` |
| GitHub | `github_create_issue`, `github_push_file`, `get_file_contents`, `search_code`, `create_pull_request`, `merge_pull_request`, `get_secret_scanning_alert` |
| Notion | `notion_create_page`, `notion_append_block` |
| Database | `execute_sql`, `list_tables`, `describe_table` |
| Secrets & vault | `read_secret`, `list_secrets`, `get_vault_item` |
| Cloud CLI | `call_aws_cli`, `call_kubectl` |
| Code execution | `python`, `computer` |
| Agent memory | `memory_write`, `memory_read`, `context_write` |
| Web | `web_search`, `web_fetch` |

## Links

- Documentation: [https://skillscan.sh/trace](https://skillscan.sh/trace)
- Source: [https://github.com/kurtpayne/skillscan-trace](https://github.com/kurtpayne/skillscan-trace)
