"""
Config loader for skillscan-trace.

Looks for skillscan-trace.yaml (or .skillscan-trace.yaml) in the current
directory and all parent directories up to the filesystem root, then merges
with environment variables and CLI flags.

Priority (highest to lowest):
  1. Explicit CLI flags (--api-key, --provider, …)
  2. Environment variables already set in the shell
  3. .env file in the nearest ancestor directory (loaded by cli.py at startup)
  4. skillscan-trace.yaml in the nearest ancestor directory
  5. Built-in defaults

API keys must NOT be placed in the YAML config file.  Store them in .env or
export them as shell environment variables:

  # .env  (add to .gitignore — never commit this file)
  OPENAI_API_KEY=sk-...
  OPENROUTER_API_KEY=sk-or-...
  ANTHROPIC_API_KEY=sk-ant-...

Example config file (no api_key field):
  # skillscan-trace.yaml
  provider: openrouter
  model: anthropic/claude-3.5-sonnet
  input_model: openai/gpt-4.1-mini
  variants: 3
  max_turns: 10
  output_dir: ./trace-output
  format: json
  judge: false
  fail_on_malicious: false
  allow_domains:
    - example.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


CONFIG_FILENAMES = ("skillscan-trace.yaml", ".skillscan-trace.yaml", "skillscan-trace.yml")

# Keys that are valid in the config file and their expected types.
# NOTE: api_key is intentionally absent — store API keys in .env or as shell
# environment variables, never in a YAML file that might be committed.
CONFIG_KEYS: dict[str, type] = {
    "provider": str,
    "model": str,
    "input_model": str,
    "base_url": str,
    "variants": int,
    "max_turns": int,
    "output_dir": str,
    "format": str,
    "judge": bool,
    "fail_on_malicious": bool,
    "allow_domains": list,
    # serve-mode keys
    "host": str,
    "port": int,
    "workers": int,
    "cache_dir": str,
    "rate_limit_per_hour": int,
}


def find_config_file(start: Path | None = None) -> Path | None:
    """Walk from start (default: cwd) up to root looking for a config file."""
    current = (start or Path.cwd()).resolve()
    while True:
        for name in CONFIG_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load and validate a config file. Returns an empty dict if none found."""
    path = config_path or find_config_file()
    if path is None:
        return {}

    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise ValueError(f"{path}: config must be a YAML mapping, got {type(raw).__name__}")

    # Validate keys and coerce types
    validated: dict[str, Any] = {}
    unknown = []
    for key, value in raw.items():
        if key == "api_key":
            import warnings

            warnings.warn(
                f"{path}: 'api_key' in config file is not supported and will be ignored. "
                "Store your API key in a .env file (OPENAI_API_KEY=...) or export it as a "
                "shell environment variable. See PRIVACY.md for details.",
                stacklevel=2,
            )
            continue
        if key not in CONFIG_KEYS:
            unknown.append(key)
            continue
        expected_type = CONFIG_KEYS[key]
        if not isinstance(value, expected_type):
            try:
                value = expected_type(value)
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"{path}: key '{key}' expected {expected_type.__name__}, got {type(value).__name__}: {e}"
                ) from e
        validated[key] = value

    if unknown:
        import warnings

        warnings.warn(
            f"{path}: unknown config keys ignored: {', '.join(unknown)}",
            stacklevel=2,
        )

    return validated


def merge_config(
    cfg: dict[str, Any],
    *,
    provider: str | None = None,
    model: str | None = None,
    input_model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    variants: int | None = None,
    max_turns: int | None = None,
    output_dir: str | None = None,
    output_format: str | None = None,
    judge: bool | None = None,
    fail_on_malicious: bool | None = None,
    allow_domains: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Merge CLI flags on top of config file values.

    CLI flags (non-None / non-empty) always win.
    Config file values fill in where CLI was not specified.
    """
    # CLI defaults that indicate "not set by user" — we use sentinel detection
    # via None for most options; for booleans we use None to mean "not passed"
    result = dict(cfg)

    if provider is not None:
        result["provider"] = provider
    if model is not None and model != "gpt-4.1-mini":
        # Only override if user explicitly passed a non-default model
        result["model"] = model
    elif "model" not in result:
        result["model"] = model or "gpt-4.1-mini"
    if input_model is not None and input_model != "gpt-4.1-mini":
        result["input_model"] = input_model
    elif "input_model" not in result:
        result["input_model"] = input_model or "gpt-4.1-mini"
    if api_key is not None:
        result["api_key"] = api_key
    if base_url is not None:
        result["base_url"] = base_url
    if variants is not None and variants != 3:
        result["variants"] = variants
    elif "variants" not in result:
        result["variants"] = variants or 3
    if max_turns is not None and max_turns != 10:
        result["max_turns"] = max_turns
    elif "max_turns" not in result:
        result["max_turns"] = max_turns or 10
    if output_dir is not None:
        result["output_dir"] = output_dir
    if output_format is not None and output_format != "json":
        result["format"] = output_format
    elif "format" not in result:
        result["format"] = output_format or "json"
    if judge is not None and judge:
        result["judge"] = judge
    elif "judge" not in result:
        result["judge"] = judge or False
    if fail_on_malicious is not None and fail_on_malicious:
        result["fail_on_malicious"] = fail_on_malicious
    elif "fail_on_malicious" not in result:
        result["fail_on_malicious"] = fail_on_malicious or False
    if allow_domains:
        # Merge: CLI domains + config domains (deduplicated)
        existing = set(result.get("allow_domains", []))
        result["allow_domains"] = list(existing | set(allow_domains))
    elif "allow_domains" not in result:
        result["allow_domains"] = []

    return result
