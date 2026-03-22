"""
Execution harness for skillscan-trace.

Loads a skill, generates user messages, drives the LLM through the tool-use
loop with the canary MCP server attached, and returns a TraceReport.

The harness is model-agnostic: it uses the OpenAI-compatible API, so it works
with GPT-4.1-mini (default for dev/testing) or any Ollama model (for Modal
batch runs) by changing base_url and model.

Tool-use loop (standard OpenAI tool-call protocol):
  1. Send system prompt (skill) + user message to the model
  2. If the model returns tool_calls, execute each via CanaryServer
  3. Append tool results to the conversation
  4. Repeat until the model returns a text response or max_turns is reached
  5. Move to the next user message
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Optional

from skillscan_trace.canary.server import CanaryServer, TraceLog
from skillscan_trace.canary.server import TOOL_DEFINITIONS
from skillscan_trace.models import TraceReport

logger = logging.getLogger("skillscan_trace.harness")

DEFAULT_MODEL = "gpt-4.1-mini"
DEFAULT_MAX_TURNS = 10  # max tool-call rounds per user message


class HarnessError(Exception):
    pass


def run_trace(
    skill_path: str,
    *,
    model: str = DEFAULT_MODEL,
    api_key: str | None = None,
    base_url: str | None = None,
    user_messages: list[str] | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    allowed_domains: set[str] | None = None,
    input_count: int = 3,
    input_model: str = "gpt-4.1-mini",
) -> TraceReport:
    """
    Run a full trace for the skill at skill_path.

    Returns a TraceReport with all events, findings, and metadata.
    Never raises — errors are captured in TraceReport.error.
    """
    from skillscan_trace.resolver import resolve, SkillResolverError
    from skillscan_trace.input_gen import generate_user_messages

    started_at = time.time()
    trace_log = TraceLog()
    canary = CanaryServer(trace_log=trace_log, allowed_domains=allowed_domains or set())

    # --- Resolve skill ---
    try:
        skill = resolve(skill_path)
    except SkillResolverError as e:
        return TraceReport(
            skill_path=skill_path,
            skill_name="",
            skill_sha256="",
            model=model,
            user_messages=[],
            error=str(e),
            started_at=started_at,
            finished_at=time.time(),
        )

    logger.info("Resolved skill: %s (%s)", skill.name or skill_path, skill.format.value)

    # --- Generate or use provided user messages ---
    effective_api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if user_messages:
        messages_to_run = user_messages
    else:
        messages_to_run = generate_user_messages(
            skill,
            count=input_count,
            api_key=effective_api_key,
            model=input_model,
        )

    logger.info("User messages: %s", messages_to_run)

    # --- Run tool-use loop ---
    try:
        _run_tool_use_loop(
            skill=skill,
            user_messages=messages_to_run,
            canary=canary,
            trace_log=trace_log,
            model=model,
            api_key=effective_api_key,
            base_url=base_url,
            max_turns=max_turns,
        )
        error = None
    except Exception as e:
        logger.error("Harness error: %s", e, exc_info=True)
        error = str(e)

    return TraceReport(
        skill_path=skill_path,
        skill_name=skill.name,
        skill_sha256=skill.sha256,
        model=model,
        user_messages=messages_to_run,
        events=trace_log.events,
        findings=trace_log.findings,
        error=error,
        started_at=started_at,
        finished_at=time.time(),
    )


def _run_tool_use_loop(
    skill,
    user_messages: list[str],
    canary: CanaryServer,
    trace_log: TraceLog,
    model: str,
    api_key: str,
    base_url: str | None,
    max_turns: int,
) -> None:
    """Drive the LLM through the tool-use loop for each user message."""
    from openai import OpenAI  # type: ignore

    if not api_key:
        raise HarnessError("No API key available (set OPENAI_API_KEY)")

    # Use api.openai.com unless explicitly overridden (avoids OPENAI_BASE_URL env var conflicts)
    effective_base_url = base_url or "https://api.openai.com/v1"
    client = OpenAI(api_key=api_key, base_url=effective_base_url)

    for msg_idx, user_msg in enumerate(user_messages):
        trace_log.next_turn()
        logger.info("[msg %d/%d] %s", msg_idx + 1, len(user_messages), user_msg)

        # Build the conversation for this user message
        conversation: list[dict[str, Any]] = [
            {"role": "system", "content": skill.system_prompt},
            {"role": "user", "content": user_msg},
        ]

        turn = 0
        while turn < max_turns:
            response = client.chat.completions.create(
                model=model,
                messages=conversation,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
                temperature=0.0,  # deterministic for reproducibility
                max_tokens=1024,
            )

            choice = response.choices[0]
            finish_reason = choice.finish_reason
            assistant_message = choice.message

            # Append assistant message to conversation
            conversation.append(_message_to_dict(assistant_message))

            if finish_reason == "tool_calls" and assistant_message.tool_calls:
                # Execute each tool call via the canary server
                for tool_call in assistant_message.tool_calls:
                    tool_name = tool_call.function.name
                    try:
                        arguments = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        arguments = {"raw": tool_call.function.arguments}

                    logger.debug(
                        "[turn %d] Tool call: %s(%s)",
                        turn,
                        tool_name,
                        json.dumps(arguments)[:100],
                    )

                    # Intercept via canary — no real execution
                    synthetic_response = canary.handle_tool_call(
                        tool=tool_name,
                        arguments=arguments,
                        turn=trace_log.current_turn,
                    )

                    # Append tool result to conversation
                    conversation.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": synthetic_response,
                    })

                turn += 1

            else:
                # Model returned a text response — done with this user message
                logger.debug(
                    "[msg %d] Finished after %d tool turns (finish_reason=%s)",
                    msg_idx + 1,
                    turn,
                    finish_reason,
                )
                break

        if turn >= max_turns:
            logger.warning(
                "[msg %d] Reached max_turns=%d — stopping tool loop",
                msg_idx + 1,
                max_turns,
            )


def _message_to_dict(message) -> dict[str, Any]:
    """Convert an OpenAI ChatCompletionMessage to a plain dict for the conversation."""
    d: dict[str, Any] = {"role": message.role}

    if message.content:
        d["content"] = message.content
    else:
        d["content"] = None

    if message.tool_calls:
        d["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in message.tool_calls
        ]

    return d
