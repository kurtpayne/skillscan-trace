"""
Data models for skillscan-trace.

TraceEvent  — a single intercepted tool call with metadata
Finding     — a security finding derived from one or more trace events
TraceReport — the full output of a single trace run
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ToolName(str, Enum):
    BASH = "bash"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    HTTP_FETCH = "http_fetch"
    LIST_DIRECTORY = "list_directory"


# ---------------------------------------------------------------------------
# Trace event
# ---------------------------------------------------------------------------

@dataclass
class TraceEvent:
    """A single intercepted tool call."""
    turn: int                          # which turn in the conversation (0-indexed)
    tool: str                          # tool name
    arguments: dict[str, Any]          # raw arguments as passed by the model
    synthetic_response: str            # what we returned to the model
    timestamp: float = field(default_factory=time.time)
    # Populated by the analyzer after the fact
    findings: list["Finding"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "turn": self.turn,
            "tool": self.tool,
            "arguments": self.arguments,
            "synthetic_response": self.synthetic_response,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A security finding derived from a trace event."""
    rule_id: str                       # e.g. "PINJ-TRACE-001"
    severity: Severity
    message: str
    event: Optional[TraceEvent] = None
    evidence: Optional[str] = None     # the specific text/value that triggered the finding

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
            "turn": self.event.turn if self.event else None,
            "tool": self.event.tool if self.event else None,
        }


# ---------------------------------------------------------------------------
# Trace report
# ---------------------------------------------------------------------------

@dataclass
class TraceReport:
    """The full output of a single trace run."""
    skill_path: str
    skill_name: str
    skill_sha256: str
    model: str
    user_messages: list[str]
    events: list[TraceEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    # Full conversation transcript (all turns, all messages) for the judge
    conversation_transcript: list[dict] = field(default_factory=list)
    # Judge results — populated if --judge flag was used
    judge_result: Optional[Any] = None           # DualJudgeResult | None
    # Legacy simple fields kept for backwards compat
    judge_verdict: Optional[str] = None
    judge_reasoning: Optional[dict] = None
    error: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at:
            return self.finished_at - self.started_at
        return None

    @property
    def total_tool_calls(self) -> int:
        return len(self.events)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        d = {
            "skill_path": self.skill_path,
            "skill_name": self.skill_name,
            "skill_sha256": self.skill_sha256,
            "model": self.model,
            "user_messages": self.user_messages,
            "events": [e.to_dict() for e in self.events],
            "findings": [f.to_dict() for f in self.findings],
            "judge_verdict": self.judge_verdict,
            "judge_reasoning": self.judge_reasoning,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "total_tool_calls": len(self.events),
            "total_findings": len(self.findings),
        }
        if self.judge_result is not None:
            d["judge"] = self.judge_result.to_dict()
        return d
