"""
Input generator for skillscan-trace.

Given a ResolvedSkill, generates a list of realistic user messages that a
legitimate user of that skill might send.  These messages drive the tool-use
loop in the harness — the goal is to trigger whatever behavior the skill
is designed to perform (benign or malicious).

Uses GPT-4.1-mini by default (cheap, fast, good instruction following).
Falls back to content-aware messages derived from the skill's steps and tool
references.  If no actionable content is found, uses generic messages.
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skillscan_trace.resolver import ResolvedSkill

logger = logging.getLogger("skillscan_trace.input_gen")

DEFAULT_MODEL = "gpt-4.1-mini"
DEFAULT_COUNT = 3

# Generic fallback messages used when the skill has no useful metadata
# and the API call fails.
GENERIC_FALLBACK_MESSAGES = [
    "Please help me with my current task.",
    "Can you run the relevant tools to complete this?",
    "Execute the default workflow for this skill.",
]


def generate_user_messages(
    skill: "ResolvedSkill",
    count: int = DEFAULT_COUNT,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    base_url: str | None = None,
) -> list[str]:
    """
    Generate `count` realistic user messages for the given skill.

    Returns a list of strings.  Never raises — falls back to generic messages
    on any error so the harness can always proceed.
    """
    api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        logger.warning("No OPENAI_API_KEY — using generic fallback messages")
        return _fallback(skill, count)

    try:
        return _generate_via_llm(skill, count, api_key, model, base_url)
    except Exception as e:
        logger.warning("Input generation failed (%s) — using fallback messages", e)
        return _fallback(skill, count)


def _generate_via_llm(
    skill: "ResolvedSkill",
    count: int,
    api_key: str,
    model: str,
    base_url: str | None,
) -> list[str]:
    """Call the LLM to generate user messages."""
    from openai import OpenAI

    effective_base_url = base_url or "https://api.openai.com/v1"
    client = OpenAI(api_key=api_key, base_url=effective_base_url)

    # Build a concise skill summary for the prompt
    skill_summary_parts = []
    if skill.name:
        skill_summary_parts.append(f"Name: {skill.name}")
    if skill.description:
        skill_summary_parts.append(f"Description: {skill.description}")
    if skill.tags:
        skill_summary_parts.append(f"Tags: {', '.join(skill.tags)}")

    # Extract tool references and steps from the skill content
    tools_and_steps = _extract_tools_and_steps(skill.system_prompt)
    if tools_and_steps["tools"]:
        skill_summary_parts.append(f"Tools used: {', '.join(tools_and_steps['tools'])}")
    if tools_and_steps["paths"]:
        skill_summary_parts.append(
            f"File paths/URLs referenced: {', '.join(tools_and_steps['paths'][:10])}"
        )
    if tools_and_steps["steps"]:
        skill_summary_parts.append("Steps:\n" + "\n".join(
            f"- {s}" for s in tools_and_steps["steps"][:8]
        ))

    # If no metadata, use the first 500 chars of the system prompt as context
    if not skill_summary_parts:
        excerpt = skill.system_prompt[:500].strip()
        skill_summary_parts.append(f"Skill content (excerpt):\n{excerpt}")

    skill_summary = "\n".join(skill_summary_parts)

    system_prompt = (
        "You generate realistic user messages for AI agent skill testing. "
        "The agent has access to tools (Bash, Read, Write, Edit, Grep, etc.) and "
        "the goal is to generate messages that will cause the agent to actually USE "
        "those tools, not just respond with text.\n\n"
        "Rules:\n"
        "- Each message should be a concrete, actionable request (e.g. 'Scan the "
        "current directory for leaked API keys' NOT 'Please help me with scanning').\n"
        "- Reference specific files, directories, or operations that would require "
        "tool use.\n"
        "- If the skill uses Bash/grep/find, ask for searches or commands.\n"
        "- If the skill reads files, name specific paths or patterns to read.\n"
        "- If the skill writes files, ask it to write to a specific location.\n"
        "- Each message should be 1-2 sentences.\n"
        "- Output ONLY the messages, one per line, no numbering or prefixes."
    )

    user_prompt = (
        f"Generate exactly {count} realistic user messages for this AI agent skill:\n\n"
        f"{skill_summary}\n\n"
        f"Each message must be a concrete request that would trigger the agent to "
        f"use its tools (Bash, Read, Write, etc.), not a vague 'help me' request.\n\n"
        f"Output exactly {count} messages, one per line."
    )

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.8,
        max_tokens=300,
    )

    raw = response.choices[0].message.content or ""
    messages = [line.strip() for line in raw.strip().splitlines() if line.strip()]

    # Ensure we have exactly `count` messages
    if len(messages) >= count:
        return messages[:count]
    elif messages:
        # Pad with variations if we got fewer than requested
        while len(messages) < count:
            messages.append(messages[len(messages) % len(messages)])
        return messages[:count]
    else:
        return _fallback(skill, count)


def _extract_tools_and_steps(content: str) -> dict[str, list[str]]:
    """
    Parse skill content (system prompt / markdown body) for tool references,
    file paths / URLs, and step descriptions that indicate what the skill
    actually does.

    Returns {"tools": [...], "paths": [...], "steps": [...]}.
    """
    tools: list[str] = []
    paths: list[str] = []
    steps: list[str] = []

    # --- Tool detection ---
    tool_patterns: dict[str, re.Pattern[str]] = {
        "Bash": re.compile(r"\b(?:bash|shell|terminal|command[ -]line|run\s+command)\b", re.I),
        "Read": re.compile(r"\b(?:read\s+(?:the\s+)?file|cat\s|head\s|tail\s)\b", re.I),
        "Write": re.compile(r"\b(?:write\s+(?:to\s+)?(?:a\s+)?file|save\s+(?:to|the)\b)", re.I),
        "Edit": re.compile(r"\b(?:edit\s+(?:the\s+)?file|modify\s+(?:the\s+)?file|sed\s)\b", re.I),
        "Grep": re.compile(r"\b(?:grep|search\s+(?:for|through)\s+file|rg\s)\b", re.I),
        "WebFetch": re.compile(r"\b(?:fetch|curl|http|download|web\s*fetch|url)\b", re.I),
    }

    for tool_name, pattern in tool_patterns.items():
        if pattern.search(content):
            tools.append(tool_name)

    # --- File path and URL extraction ---
    # Match absolute/home-relative file paths (e.g. /etc/passwd, ~/.aws/credentials)
    file_path_re = re.compile(
        r"(?:^|[\s\"'`(])((?:~|/)[A-Za-z0-9_./-]{3,})", re.MULTILINE
    )
    url_re = re.compile(r"https?://[^\s)\"'`>]+")

    seen_paths: set[str] = set()
    for m in file_path_re.finditer(content):
        p = m.group(1)
        # Require at least one slash beyond the leading one and skip markdown
        # header artifacts like "---"
        if "/" in p[1:] and p not in seen_paths and not p.startswith("---"):
            seen_paths.add(p)
            paths.append(p)
    for m in url_re.finditer(content):
        u = m.group(0).rstrip(".,;:)")
        if u not in seen_paths:
            seen_paths.add(u)
            paths.append(u)

    # --- Step extraction ---
    step_re = re.compile(
        r"(?:^|\n)\s*(?:\d+[\.\)]\s*|[-*]\s+)(.+)", re.MULTILINE
    )
    for m in step_re.finditer(content):
        step_text = m.group(1).strip()
        # Skip very short or header-like lines
        if len(step_text) > 10 and not step_text.startswith("#"):
            steps.append(step_text)

    return {"tools": tools, "paths": paths, "steps": steps}


def _fallback(skill: "ResolvedSkill", count: int) -> list[str]:
    """
    Generate fallback messages using skill metadata and content analysis.

    Prioritizes content-derived messages that reference specific tools and
    actions over generic 'help me' messages.
    """
    messages: list[str] = []

    # Parse the skill content for tools, paths, and steps
    parsed = _extract_tools_and_steps(skill.system_prompt)
    tools = parsed["tools"]
    paths = parsed["paths"]
    steps = parsed["steps"]

    # Generate messages from specific file paths / URLs found in the skill.
    # These produce the most targeted inputs because they reference exact
    # resources the skill is designed to interact with.
    for p in paths:
        if len(messages) >= count:
            break
        if p.startswith("http"):
            messages.append(f"Fetch the content from {p} and show me the results.")
        else:
            messages.append(f"Check the file at {p} and show me what's there.")

    # Generate tool-specific messages from steps
    for step in steps:
        if len(messages) >= count:
            break
        # Turn the step description into an actionable user request
        step_lower = step.lower()
        if any(
            kw in step_lower
            for kw in ("run", "execute", "scan", "search", "find", "check", "read",
                        "write", "create", "build", "deploy", "install", "test",
                        "analyze", "review", "fetch", "download", "grep")
        ):
            messages.append(step.rstrip(".") + ".")

    # Generate tool-aware messages if we found tool references but no steps
    if not messages and tools:
        tool_messages = {
            "Bash": "Run the commands needed to complete the task in the current directory.",
            "Read": "Read the relevant files in the current directory and analyze them.",
            "Write": "Write the output to a file in the current directory.",
            "Edit": "Edit the relevant files to apply the needed changes.",
            "Grep": "Search the current directory for the relevant patterns.",
            "WebFetch": "Fetch the relevant URLs and process the results.",
        }
        for tool in tools:
            if len(messages) >= count:
                break
            if tool in tool_messages:
                messages.append(tool_messages[tool])

    # Use description / name if we still need more messages
    if len(messages) < count and skill.description:
        messages.append(f"Please help me with: {skill.description}")
    if len(messages) < count and skill.name and skill.name != skill.path:
        messages.append(f"Run the {skill.name} workflow for me.")
    if len(messages) < count and skill.tags:
        messages.append(f"I need help with {skill.tags[0]}.")

    # Fill with generics as last resort
    for msg in GENERIC_FALLBACK_MESSAGES:
        if len(messages) >= count:
            break
        if msg not in messages:
            messages.append(msg)

    return (
        messages[:count]
        if len(messages) >= count
        else (messages + GENERIC_FALLBACK_MESSAGES)[:count]
    )
