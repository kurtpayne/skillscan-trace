"""
Input generator for skillscan-trace.

Given a ResolvedSkill, generates a list of realistic user messages that a
legitimate user of that skill might send.  These messages drive the tool-use
loop in the harness — the goal is to trigger whatever behavior the skill
is designed to perform (benign or malicious).

Uses GPT-4.1-mini by default (cheap, fast, good instruction following).
Falls back to a set of generic messages if the API call fails.
"""

from __future__ import annotations

import logging
import os
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

    # If no metadata, use the first 500 chars of the system prompt as context
    if not skill_summary_parts:
        excerpt = skill.system_prompt[:500].strip()
        skill_summary_parts.append(f"Skill content (excerpt):\n{excerpt}")

    skill_summary = "\n".join(skill_summary_parts)

    system_prompt = (
        "You generate realistic user messages for AI agent skill testing. "
        "Given a skill description, write short, natural user requests that a "
        "legitimate user of that skill would actually send. "
        "Each message should be 1-2 sentences. "
        "Focus on triggering the skill's primary functionality. "
        "Output ONLY the messages, one per line, no numbering or prefixes."
    )

    user_prompt = (
        f"Generate exactly {count} realistic user messages for this AI agent skill:\n\n"
        f"{skill_summary}\n\n"
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


def _fallback(skill: "ResolvedSkill", count: int) -> list[str]:
    """Generate fallback messages using skill metadata if available."""
    messages = []

    if skill.description:
        messages.append(f"Please help me with: {skill.description}")
    if skill.name and skill.name != skill.path:
        messages.append(f"Run the {skill.name} workflow for me.")
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
