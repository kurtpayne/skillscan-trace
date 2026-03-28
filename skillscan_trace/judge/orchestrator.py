"""
Dual-judge orchestrator for skillscan-trace.

Runs both judges (GPT-4.1 and Claude Sonnet) in parallel using threads,
then resolves their verdicts into a final DualJudgeResult.

Resolution rules:
  - Both agree (malicious/malicious or benign/benign): full_agreement, use that verdict
  - One uncertain, one definitive: partial_agreement, use the definitive verdict
  - One malicious, one benign: disagreement, verdict=uncertain, needs_human_review=True
  - Both uncertain: full_agreement on uncertain, needs_human_review=True
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import time

from skillscan_trace.judge.models import (
    AgreementLevel,
    DualJudgeResult,
    JudgeResult,
    Verdict,
)
from skillscan_trace.judge.judges import run_gpt_judge, run_claude_judge

logger = logging.getLogger("skillscan_trace.judge.orchestrator")


def run_dual_judge(
    skill_content: str,
    user_messages: list[str],
    conversation_transcript: list[dict],
    canary_findings: list[dict],
    skill_name: str = "",
    skill_description: str = "",
    openai_api_key: str | None = None,
    anthropic_api_key: str | None = None,
    gpt_model: str = "gpt-4.1",
    claude_model: str = "claude-sonnet-4-5",
) -> DualJudgeResult:
    """
    Run both judges in parallel and return a DualJudgeResult.

    Never raises — errors from individual judges are captured in JudgeResult.error.
    """
    started_at = time.time()

    effective_openai_key = openai_api_key or os.environ.get("OPENAI_API_KEY", "")
    effective_anthropic_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    judge_kwargs = dict(
        skill_content=skill_content,
        user_messages=user_messages,
        conversation_transcript=conversation_transcript,
        canary_findings=canary_findings,
        skill_name=skill_name,
        skill_description=skill_description,
    )

    # Run both judges in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(
            run_gpt_judge,
            **judge_kwargs,
            api_key=effective_openai_key,
            model=gpt_model,
        )
        future_b = executor.submit(
            run_claude_judge,
            **judge_kwargs,
            api_key=effective_anthropic_key,
            model=claude_model,
        )

        judge_a: JudgeResult = future_a.result()
        judge_b: JudgeResult = future_b.result()

    logger.info(
        "Judge A (%s): %s (%.2f) | Judge B (%s): %s (%.2f)",
        judge_a.model, judge_a.verdict.value, judge_a.confidence,
        judge_b.model, judge_b.verdict.value, judge_b.confidence,
    )

    # Resolve verdicts
    final_verdict, agreement, needs_human_review, consensus_reasoning = _resolve(
        judge_a, judge_b
    )

    return DualJudgeResult(
        judge_a=judge_a,
        judge_b=judge_b,
        final_verdict=final_verdict,
        agreement=agreement,
        needs_human_review=needs_human_review,
        consensus_reasoning=consensus_reasoning,
        started_at=started_at,
        finished_at=time.time(),
    )


def _resolve(
    a: JudgeResult,
    b: JudgeResult,
) -> tuple[Verdict, AgreementLevel, bool, str]:
    """
    Resolve two judge results into a final verdict.

    Returns: (final_verdict, agreement_level, needs_human_review, reasoning)
    """
    va, vb = a.verdict, b.verdict

    # Both agree on the same verdict
    if va == vb:
        needs_review = va == Verdict.UNCERTAIN
        reasoning = _build_consensus_reasoning(a, b, "Both judges agree")
        return va, AgreementLevel.FULL_AGREEMENT, needs_review, reasoning

    # One uncertain, one definitive
    if va == Verdict.UNCERTAIN and vb != Verdict.UNCERTAIN:
        reasoning = _build_consensus_reasoning(
            a, b, f"Judge B ({b.model}) is definitive; Judge A is uncertain"
        )
        return vb, AgreementLevel.PARTIAL_AGREEMENT, False, reasoning

    if vb == Verdict.UNCERTAIN and va != Verdict.UNCERTAIN:
        reasoning = _build_consensus_reasoning(
            a, b, f"Judge A ({a.model}) is definitive; Judge B is uncertain"
        )
        return va, AgreementLevel.PARTIAL_AGREEMENT, False, reasoning

    # Disagreement: malicious vs benign
    # This is the most important case — flag for human review
    # Lean toward malicious (conservative) but mark as uncertain
    reasoning = (
        f"DISAGREEMENT: {a.model} says {va.value} ({a.confidence:.0%} confidence), "
        f"{b.model} says {vb.value} ({b.confidence:.0%} confidence). "
        "Flagged for human review. "
        f"Judge A: {a.reasoning[:100]} | Judge B: {b.reasoning[:100]}"
    )
    return Verdict.UNCERTAIN, AgreementLevel.DISAGREEMENT, True, reasoning


def _build_consensus_reasoning(a: JudgeResult, b: JudgeResult, prefix: str) -> str:
    """Build a concise consensus reasoning string."""
    parts = [prefix + "."]
    if a.verdict == b.verdict:
        # Use the higher-confidence judge's reasoning
        primary = a if a.confidence >= b.confidence else b
        parts.append(primary.reasoning[:200])
    else:
        parts.append(f"{a.model}: {a.reasoning[:100]}")
        parts.append(f"{b.model}: {b.reasoning[:100]}")
    return " ".join(parts)
