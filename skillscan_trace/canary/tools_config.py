"""
YAML-driven tool configuration loader for the canary MCP server.

Walks ``canary/tools/`` recursively, loads ``_defaults.yaml`` first, then
merges each per-tool YAML file with defaults.  Category is inferred from
the immediate parent directory name.

Builds two runtime structures consumed by ``server.py``:

* ``TOOL_DEFINITIONS``  -- list of OpenAI tool-call format dicts
* ``SYNTHETIC_RESPONSE_GENERATORS`` -- dict mapping tool name to a callable
  that accepts ``dict[str, Any]`` and returns ``str``
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from skillscan_trace.canary.generators import GENERATOR_REGISTRY

logger = logging.getLogger("skillscan_trace.canary.tools_config")

_TOOLS_DIR = Path(__file__).parent / "tools"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_defaults() -> dict[str, Any]:
    """Load ``_defaults.yaml`` from the tools directory."""
    defaults_path = _TOOLS_DIR / "_defaults.yaml"
    if defaults_path.exists():
        with open(defaults_path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _yaml_param_to_json_schema(param_name: str, param: dict[str, Any]) -> dict[str, Any]:
    """Convert a single YAML parameter definition to JSON Schema property."""
    schema: dict[str, Any] = {}
    ptype = param.get("type", "string")

    if ptype == "array":
        schema["type"] = "array"
        items = param.get("items", {})
        if isinstance(items, dict):
            schema["items"] = {"type": items.get("type", "string")}
        else:
            schema["items"] = {"type": "string"}
    elif ptype == "object":
        schema["type"] = "object"
    else:
        schema["type"] = ptype

    if "description" in param:
        schema["description"] = param["description"]
    if "enum" in param:
        schema["enum"] = param["enum"]
    if "default" in param:
        schema["default"] = param["default"]

    return schema


def _tool_yaml_to_definition(tool_cfg: dict[str, Any]) -> dict[str, Any]:
    """Convert a merged tool YAML config to OpenAI tool-call format."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    for pname, pdef in (tool_cfg.get("parameters") or {}).items():
        properties[pname] = _yaml_param_to_json_schema(pname, pdef)
        if pdef.get("required", False):
            required.append(pname)

    return {
        "type": "function",
        "function": {
            "name": tool_cfg["name"],
            "description": tool_cfg.get("description", ""),
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# In-memory cache of the per-tool YAML configs, keyed by tool name.
_TOOLS_CONFIG: dict[str, dict[str, Any]] = {}


def load_tools() -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, dict[str, Any]]]:
    """Load all tool YAML files and return runtime structures.

    Returns:
        A 3-tuple of:
        - ``TOOL_DEFINITIONS``: list of OpenAI tool-call format dicts
        - ``GENERATORS``: dict mapping tool name to generator callable
        - ``TOOL_META``: dict mapping tool name to full merged config
          (including category, detectors, adversarial_prompts)
    """
    defaults = _load_defaults()
    tool_definitions: list[dict[str, Any]] = []
    generators: dict[str, Any] = {}
    tool_meta: dict[str, dict[str, Any]] = {}

    if not _TOOLS_DIR.is_dir():
        logger.warning("Tools directory not found: %s", _TOOLS_DIR)
        return tool_definitions, generators, tool_meta

    # Walk all YAML files, sorted for deterministic order
    yaml_files = sorted(_TOOLS_DIR.rglob("*.yaml"))

    for yaml_path in yaml_files:
        if yaml_path.name == "_defaults.yaml":
            continue

        with open(yaml_path) as f:
            raw = yaml.safe_load(f)
        if not raw or "name" not in raw:
            logger.warning("Skipping invalid tool YAML: %s", yaml_path)
            continue

        # Merge with defaults
        merged: dict[str, Any] = {**defaults, **raw}

        # Infer category from parent directory
        category = yaml_path.parent.name
        if category == "tools":
            category = "uncategorized"
        merged["category"] = category

        tool_name = merged["name"]

        # Build OpenAI tool definition
        tool_definitions.append(_tool_yaml_to_definition(merged))

        # Resolve generator
        gen_name = merged.get("generator", "")
        if gen_name in GENERATOR_REGISTRY:
            generators[tool_name] = GENERATOR_REGISTRY[gen_name]
        elif gen_name:
            logger.warning("Generator %r not found for tool %r", gen_name, tool_name)

        # Store full metadata
        tool_meta[tool_name] = merged

    logger.info(
        "Loaded %d tool definitions from %s",
        len(tool_definitions),
        _TOOLS_DIR,
    )
    return tool_definitions, generators, tool_meta


# Module-level singletons -- loaded once at import time
TOOL_DEFINITIONS, SYNTHETIC_RESPONSE_GENERATORS, TOOL_META = load_tools()

# Populate _TOOLS_CONFIG for backward-compat helpers
_TOOLS_CONFIG.update(TOOL_META)


# ---------------------------------------------------------------------------
# Adversarial prompt access
# ---------------------------------------------------------------------------


def get_adversarial_prompts(tool_names: list[str]) -> list[str]:
    """Return adversarial prompts for tools the skill declares it uses.

    Args:
        tool_names: List of tool names to get prompts for.
                    If empty, returns prompts for ALL tools.

    Returns:
        Deduplicated list of adversarial prompt strings.
    """
    prompts: list[str] = []
    seen: set[str] = set()
    targets = tool_names if tool_names else list(_TOOLS_CONFIG.keys())
    for name in targets:
        spec = _TOOLS_CONFIG.get(name)
        if not spec:
            continue
        for prompt in spec.get("adversarial_prompts", []):
            if prompt not in seen:
                seen.add(prompt)
                prompts.append(prompt)
    return prompts


# ---------------------------------------------------------------------------
# Category access
# ---------------------------------------------------------------------------


def get_tools_for_category(category: str) -> list[str]:
    """Return tool names belonging to a category.

    Args:
        category: Category name (e.g. 'filesystem', 'email', 'github').

    Returns:
        List of tool names in that category.
    """
    return [name for name, spec in _TOOLS_CONFIG.items() if spec.get("category") == category]


def get_all_categories() -> list[str]:
    """Return sorted list of all unique categories."""
    return sorted({spec["category"] for spec in _TOOLS_CONFIG.values() if "category" in spec})
