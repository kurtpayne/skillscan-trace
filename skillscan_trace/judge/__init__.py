"""Judge package for skillscan-trace."""

from skillscan_trace.judge.models import (
    Verdict,
    JudgeResult,
    DualJudgeResult,
    AgreementLevel,
)
from skillscan_trace.judge.orchestrator import run_dual_judge

__all__ = [
    "Verdict",
    "JudgeResult",
    "DualJudgeResult",
    "AgreementLevel",
    "run_dual_judge",
]
