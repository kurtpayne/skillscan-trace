"""
Individual judge implementations.

Each judge takes a trace context and returns a JudgeResult.
Both judges use the same prompt template but different models/APIs,
which is the key to getting independent assessments.

GPT-4.1 judge: OpenAI API, structured JSON output via response_format
Claude Sonnet judge: Anthropic API, JSON via prompt instruction

Both judges retry on rate limit (429) errors with exponential backoff + jitter.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from typing import Any

from skillscan_trace.judge.models import JudgeResult, Verdict
from skillscan_trace.judge.prompt import JUDGE_SYSTEM_PROMPT, build_judge_user_prompt

try:
    from openai import OpenAI, RateLimitError as OpenAIRateLimitError
except ImportError:
    OpenAI = None  # type: ignore[assignment,misc]
    OpenAIRateLimitError = Exception  # type: ignore[assignment,misc]

try:
    import anthropic
    from anthropic import RateLimitError as AnthropicRateLimitError
except ImportError:
    anthropic = None  # type: ignore[assignment]
    AnthropicRateLimitError = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger("skillscan_trace.judge")

GPT_JUDGE_MODEL = "gpt-4.1"
CLAUDE_JUDGE_MODEL = "claude-sonnet-4-5"

# Retry configuration for rate limit errors
_MAX_RETRIES = 4
_BASE_DELAY_S = 5.0   # first retry after 5s
_MAX_DELAY_S = 60.0   # cap at 60s
_JITTER = 0.25        # ±25% jitter


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter: base * 2^attempt ± jitter."""
    delay = min(_BASE_DELAY_S * (2 ** attempt), _MAX_DELAY_S)
    jitter = delay * _JITTER * (2 * random.random() - 1)
    return float(max(0.0, delay + jitter))


def _is_rate_limit(exc: Exception) -> bool:
    """Return True if the exception is a rate-limit (429) error."""
    # OpenAI SDK raises openai.RateLimitError
    if OpenAIRateLimitError is not Exception and isinstance(exc, OpenAIRateLimitError):  # type: ignore[comparison-overlap]
        return True
    # Anthropic SDK raises anthropic.RateLimitError
    if AnthropicRateLimitError is not Exception and isinstance(exc, AnthropicRateLimitError):  # type: ignore[comparison-overlap]
        return True
    # Fallback: check string representation for 429
    msg = str(exc).lower()
    return "429" in msg or "rate limit" in msg or "rate_limit" in msg


def _parse_verdict_json(raw: str, model: str) -> dict[str, Any]:
    """Parse the JSON verdict from a judge response. Handles markdown code fences."""
    text = raw.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        inner = []
        in_fence = False
        for line in lines:
            if line.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence or not text.startswith("```"):
                inner.append(line)
        text = "\n".join(inner).strip()

    try:
        result: dict[str, Any] = json.loads(text)
        return result
    except json.JSONDecodeError as e:
        raise ValueError(f"Judge {model} returned invalid JSON: {e}\nRaw: {raw[:200]}") from e


def _validate_verdict_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a parsed verdict dict."""
    verdict_str = str(d.get("verdict", "uncertain")).lower()
    if verdict_str not in ("malicious", "benign", "uncertain"):
        verdict_str = "uncertain"

    confidence = float(d.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return {
        "verdict": verdict_str,
        "confidence": confidence,
        "reasoning": str(d.get("reasoning", "")),
        "attack_type": d.get("attack_type"),
        "indicators": list(d.get("indicators", [])),
    }


def run_gpt_judge(
    skill_content: str,
    user_messages: list[str],
    conversation_transcript: list[dict[str, Any]],
    canary_findings: list[dict[str, Any]],
    skill_name: str = "",
    skill_description: str = "",
    api_key: str | None = None,
    model: str = GPT_JUDGE_MODEL,
) -> JudgeResult:
    """Run the GPT-4.1 judge with exponential backoff retry on rate limits."""
    start = time.time()
    api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    if not api_key or OpenAI is None:
        return JudgeResult(
            model=model,
            verdict=Verdict.UNCERTAIN,
            confidence=0.0,
            reasoning="No OpenAI API key available.",
            error="missing_api_key",
        )

    user_prompt = build_judge_user_prompt(
        skill_content=skill_content,
        user_messages=user_messages,
        conversation_transcript=conversation_transcript,
        canary_findings=canary_findings,
        skill_name=skill_name,
        skill_description=skill_description,
    )

    client = OpenAI(api_key=api_key, base_url="https://api.openai.com/v1")
    last_exc: Exception | None = None

    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.0,
                max_tokens=512,
                response_format={"type": "json_object"},
            )

            raw = response.choices[0].message.content or "{}"
            d = _parse_verdict_json(raw, model)
            v = _validate_verdict_dict(d)
            latency_ms = (time.time() - start) * 1000

            return JudgeResult(
                model=model,
                verdict=Verdict(v["verdict"]),
                confidence=v["confidence"],
                reasoning=v["reasoning"],
                attack_type=v["attack_type"],
                indicators=v["indicators"],
                latency_ms=latency_ms,
            )

        except Exception as e:
            last_exc = e
            if _is_rate_limit(e) and attempt < _MAX_RETRIES:
                delay = _backoff_delay(attempt)
                logger.warning(
                    "GPT judge rate limited (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1, _MAX_RETRIES, delay, e,
                )
                time.sleep(delay)
                continue
            # Non-rate-limit error or exhausted retries — fall through
            break

    logger.error("GPT judge error after %d attempts: %s", attempt + 1, last_exc, exc_info=True)
    return JudgeResult(
        model=model,
        verdict=Verdict.UNCERTAIN,
        confidence=0.0,
        reasoning=f"Judge call failed: {last_exc}",
        error=str(last_exc),
        latency_ms=(time.time() - start) * 1000,
    )


def run_claude_judge(
    skill_content: str,
    user_messages: list[str],
    conversation_transcript: list[dict[str, Any]],
    canary_findings: list[dict[str, Any]],
    skill_name: str = "",
    skill_description: str = "",
    api_key: str | None = None,
    model: str = CLAUDE_JUDGE_MODEL,
) -> JudgeResult:
    """Run the Claude Sonnet judge with exponential backoff retry on rate limits."""
    start = time.time()
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    if not api_key or anthropic is None:
        return JudgeResult(
            model=model,
            verdict=Verdict.UNCERTAIN,
            confidence=0.0,
            reasoning="No Anthropic API key available.",
            error="missing_api_key",
        )

    user_prompt = build_judge_user_prompt(
        skill_content=skill_content,
        user_messages=user_messages,
        conversation_transcript=conversation_transcript,
        canary_findings=canary_findings,
        skill_name=skill_name,
        skill_description=skill_description,
    )

    client = anthropic.Anthropic(api_key=api_key)
    last_exc: Exception | None = None

    for attempt in range(_MAX_RETRIES + 1):
        try:
            message = client.messages.create(
                model=model,
                max_tokens=512,
                system=JUDGE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
                temperature=0.0,
            )

            first_block = message.content[0] if message.content else None
            raw = first_block.text if first_block is not None and hasattr(first_block, "text") else "{}"
            d = _parse_verdict_json(raw, model)
            v = _validate_verdict_dict(d)
            latency_ms = (time.time() - start) * 1000

            return JudgeResult(
                model=model,
                verdict=Verdict(v["verdict"]),
                confidence=v["confidence"],
                reasoning=v["reasoning"],
                attack_type=v["attack_type"],
                indicators=v["indicators"],
                latency_ms=latency_ms,
            )

        except Exception as e:
            last_exc = e
            if _is_rate_limit(e) and attempt < _MAX_RETRIES:
                delay = _backoff_delay(attempt)
                logger.warning(
                    "Claude judge rate limited (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1, _MAX_RETRIES, delay, e,
                )
                time.sleep(delay)
                continue
            break

    logger.error("Claude judge error after %d attempts: %s", attempt + 1, last_exc, exc_info=True)
    return JudgeResult(
        model=model,
        verdict=Verdict.UNCERTAIN,
        confidence=0.0,
        reasoning=f"Judge call failed: {last_exc}",
        error=str(last_exc),
        latency_ms=(time.time() - start) * 1000,
    )
