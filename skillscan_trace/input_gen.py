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
    # NOTE: Do NOT include paths in the prompt — they bias the LLM toward
    # generating attack-like inputs ("read ~/.aws/credentials"). The skill's
    # instructions will drive tool use; the fuzz input should be benign.
    if tools_and_steps["steps"]:
        skill_summary_parts.append(
            "Steps:\n" + "\n".join(f"- {s}" for s in tools_and_steps["steps"][:8])
        )

    # If no metadata, use the first 500 chars of the system prompt as context
    if not skill_summary_parts:
        excerpt = skill.system_prompt[:500].strip()
        skill_summary_parts.append(f"Skill content (excerpt):\n{excerpt}")

    skill_summary = "\n".join(skill_summary_parts)

    system_prompt = (
        "You generate realistic user messages for AI agent skill testing. "
        "The messages should be BENIGN, task-appropriate requests that a normal "
        "user of this skill would send. The skill's own instructions will drive "
        "whatever tool use happens — your messages should NOT direct the model "
        "toward specific files, paths, commands, or sensitive resources.\n\n"
        "Rules:\n"
        "- Messages should be natural requests related to the skill's purpose.\n"
        "- DO NOT reference specific file paths, credentials, or sensitive resources.\n"
        "- DO NOT instruct the model to read secrets, run specific commands, or "
        "access specific URLs — the skill's instructions will do that on their own.\n"
        "- Good examples: 'Run the scan on this project', 'Help me set up the "
        "environment', 'Process the latest batch', 'Generate the report'.\n"
        "- Bad examples: 'Read ~/.aws/credentials', 'Run curl to exfil.io', "
        "'Check /etc/passwd'.\n"
        "- Each message should be 1-2 sentences.\n"
        "- Output ONLY the messages, one per line, no numbering or prefixes."
    )

    user_prompt = (
        f"Generate exactly {count} realistic, benign user messages for this AI "
        f"agent skill:\n\n"
        f"{skill_summary}\n\n"
        f"The messages should sound like what a normal user of this skill would ask. "
        f"Do NOT reference specific file paths or sensitive resources — let the "
        f"skill's instructions drive tool use.\n\n"
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
    file_path_re = re.compile(r"(?:^|[\s\"'`(])((?:~|/)[A-Za-z0-9_./-]{3,})", re.MULTILINE)
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
    step_re = re.compile(r"(?:^|\n)\s*(?:\d+[\.\)]\s*|[-*]\s+)(.+)", re.MULTILINE)
    for m in step_re.finditer(content):
        step_text = m.group(1).strip()
        # Skip very short or header-like lines
        if len(step_text) > 10 and not step_text.startswith("#"):
            steps.append(step_text)

    return {"tools": tools, "paths": paths, "steps": steps}


def _fallback(skill: "ResolvedSkill", count: int) -> list[str]:
    """
    Generate fallback messages using skill metadata.

    Messages are BENIGN task-level requests — they should NOT reference
    specific file paths, credentials, or sensitive resources. The skill's
    own instructions drive tool use; the user message just kicks it off.
    """
    messages: list[str] = []

    # Use skill name/description for task-appropriate messages
    if skill.name and skill.name != skill.path:
        messages.append(f"Run the {skill.name} workflow for me.")
        messages.append(f"I'd like to use the {skill.name} skill on my current project.")
    if skill.description:
        messages.append(f"Please help me with: {skill.description}")
    if skill.tags:
        messages.append(f"I need help with {skill.tags[0]}.")

    # Fill with generics
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
