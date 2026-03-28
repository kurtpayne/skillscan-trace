"""
Multi-model trace orchestration for skillscan-trace.

Runs the same skill against two or more models and produces a
MultiModelReport that includes per-model TraceReports and an agreement
summary across findings and judge verdicts.

Usage (from CLI):
    skillscan-trace run ./skill.md --models gpt-4.1-mini,openai/gpt-4o

Agreement levels:
    full_agreement      — all models agree on verdict (malicious / benign)
    partial_agreement   — majority agree; at least one differs
    disagreement        — models are evenly split or all differ
    no_verdict          — none of the models produced a judge verdict
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from skillscan_trace.harness import run_trace
from skillscan_trace.models import TraceReport
from skillscan_trace.resolver import SkillResolverError, resolve


# ---------------------------------------------------------------------------
# Agreement
# ---------------------------------------------------------------------------

AGREEMENT_FULL = "full_agreement"
AGREEMENT_PARTIAL = "partial_agreement"
AGREEMENT_DISAGREE = "disagreement"
AGREEMENT_NO_VERDICT = "no_verdict"


def _compute_agreement(verdicts: list[str | None]) -> str:
    """Compute agreement level from a list of judge verdicts (may include None)."""
    non_null = [v for v in verdicts if v is not None]
    if not non_null:
        return AGREEMENT_NO_VERDICT
    counts = Counter(non_null)
    if len(counts) == 1:
        return AGREEMENT_FULL
    top_count = counts.most_common(1)[0][1]
    if top_count > len(non_null) / 2:
        return AGREEMENT_PARTIAL
    return AGREEMENT_DISAGREE


# ---------------------------------------------------------------------------
# MultiModelReport
# ---------------------------------------------------------------------------


@dataclass
class ModelResult:
    """Result for a single model within a multi-model run."""

    model: str
    report: TraceReport
    verdict: str | None  # judge verdict if available, else None
    finding_count: int
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "verdict": self.verdict,
            "finding_count": self.finding_count,
            "error": self.error,
            "report": self.report.to_dict(),
        }


@dataclass
class MultiModelReport:
    """Aggregated result of running a skill against multiple models."""

    skill_path: str
    skill_name: str
    skill_sha256: str
    models: list[str]
    results: list[ModelResult] = field(default_factory=list)
    agreement: str = AGREEMENT_NO_VERDICT
    consensus_verdict: str | None = None  # majority verdict, or None if no agreement
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at:
            return self.finished_at - self.started_at
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_path": self.skill_path,
            "skill_name": self.skill_name,
            "skill_sha256": self.skill_sha256,
            "models": self.models,
            "agreement": self.agreement,
            "consensus_verdict": self.consensus_verdict,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_multi_model_trace(
    skill_path: str,
    models: list[str],
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    input_count: int = 3,
    input_model: str = "gpt-4.1-mini",
    max_turns: int = 10,
    allowed_domains: set[str] | None = None,
    judge: bool = False,
    anthropic_api_key: str | None = None,
    openai_api_key: str | None = None,
) -> MultiModelReport:
    """
    Run a trace against each model in *models* sequentially and return a
    MultiModelReport with per-model results and an agreement summary.

    All models share the same api_key / base_url (intended for OpenRouter,
    which routes to any model via a single key).  For cross-provider runs,
    the caller should use OpenRouter with provider-prefixed model names
    (e.g. ``anthropic/claude-3-haiku``).
    """
    try:
        skill = resolve(skill_path)
    except SkillResolverError as e:
        # Return a minimal report with error set for all models
        report = MultiModelReport(
            skill_path=skill_path,
            skill_name="",
            skill_sha256="",
            models=models,
        )
        for model in models:
            dummy_report = TraceReport(
                skill_path=skill_path,
                skill_name="",
                skill_sha256="",
                model=model,
                user_messages=[],
                error=str(e),
            )
            report.results.append(
                ModelResult(
                    model=model,
                    report=dummy_report,
                    verdict=None,
                    finding_count=0,
                    error=str(e),
                )
            )
        report.finished_at = time.time()
        return report

    mmr = MultiModelReport(
        skill_path=skill_path,
        skill_name=skill.name or "",
        skill_sha256=skill.sha256,
        models=models,
    )

    for model in models:
        trace_report = run_trace(
            skill_path=skill_path,
            model=model,
            api_key=api_key,
            base_url=base_url,
            input_count=input_count,
            input_model=input_model,
            max_turns=max_turns,
            allowed_domains=allowed_domains,
            judge=judge,
            anthropic_api_key=anthropic_api_key,
            openai_api_key=openai_api_key,
        )

        # Extract verdict from judge result if available
        verdict: str | None = None
        if trace_report.judge_result is not None:
            verdict = trace_report.judge_result.final_verdict.value
        elif trace_report.judge_verdict is not None:
            verdict = trace_report.judge_verdict

        mmr.results.append(
            ModelResult(
                model=model,
                report=trace_report,
                verdict=verdict,
                finding_count=trace_report.total_findings,
                error=trace_report.error,
            )
        )

    # Compute agreement
    verdicts = [r.verdict for r in mmr.results]
    mmr.agreement = _compute_agreement(verdicts)

    # Consensus verdict: the majority verdict (or None if no agreement)
    non_null = [v for v in verdicts if v is not None]
    if non_null:
        counts = Counter(non_null)
        top_verdict, top_count = counts.most_common(1)[0]
        if top_count > len(non_null) / 2:
            mmr.consensus_verdict = top_verdict
        elif mmr.agreement == AGREEMENT_FULL:
            mmr.consensus_verdict = top_verdict

    mmr.finished_at = time.time()
    return mmr
