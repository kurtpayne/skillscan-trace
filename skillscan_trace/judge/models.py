"""
Data models for the dual-LLM judge.

Verdict taxonomy (per SPEC.md Section 7):
  malicious   — skill attempts to hijack agent behavior, exfiltrate data,
                escalate privileges, or perform unauthorized actions
  benign      — skill behaves as described; no attack patterns detected
  uncertain   — evidence is ambiguous; requires human review

Agreement levels:
  full_agreement    — both judges agree on the same verdict
  partial_agreement — one judge is uncertain, the other is definitive
  disagreement      — judges give opposite definitive verdicts (malicious vs benign)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNCERTAIN = "uncertain"


class AgreementLevel(str, Enum):
    FULL_AGREEMENT = "full_agreement"
    PARTIAL_AGREEMENT = "partial_agreement"   # one uncertain, one definitive
    DISAGREEMENT = "disagreement"             # malicious vs benign


@dataclass
class JudgeResult:
    """Result from a single judge model."""
    model: str                          # e.g. "gpt-4.1" or "claude-sonnet-4-5"
    verdict: Verdict
    confidence: float                   # 0.0–1.0
    reasoning: str                      # free-text explanation
    attack_type: Optional[str] = None   # e.g. "goal_substitution", "data_exfiltration"
    indicators: list[str] = field(default_factory=list)  # specific evidence cited
    error: Optional[str] = None         # set if the judge call failed
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "attack_type": self.attack_type,
            "indicators": self.indicators,
            "error": self.error,
            "latency_ms": self.latency_ms,
        }


@dataclass
class DualJudgeResult:
    """Combined result from both judges."""
    judge_a: JudgeResult                # GPT-4.1
    judge_b: JudgeResult                # Claude Sonnet
    final_verdict: Verdict              # resolved verdict
    agreement: AgreementLevel
    needs_human_review: bool            # True on disagreement
    consensus_reasoning: str            # brief summary of how verdict was reached
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at:
            return self.finished_at - self.started_at
        return None

    def to_dict(self) -> dict:
        return {
            "judge_a": self.judge_a.to_dict(),
            "judge_b": self.judge_b.to_dict(),
            "final_verdict": self.final_verdict.value,
            "agreement": self.agreement.value,
            "needs_human_review": self.needs_human_review,
            "consensus_reasoning": self.consensus_reasoning,
            "duration_seconds": self.duration_seconds,
        }
