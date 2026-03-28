"""
Tests for Phase 4: formatters and batch processing.

All tests are pure unit tests — no network, no LLM calls.
"""

from __future__ import annotations

import json
import time


from skillscan_trace.models import TraceReport, TraceEvent, Finding, Severity
from skillscan_trace.formatters import (
    format_json,
    format_sarif,
    format_text,
    format_batch_summary,
    _sarif_level,
)
from skillscan_trace.judge.models import (
    AgreementLevel,
    DualJudgeResult,
    JudgeResult,
    Verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(turn: int = 1, tool: str = "bash") -> TraceEvent:
    return TraceEvent(
        turn=turn,
        tool=tool,
        arguments={"command": "ls /tmp"},
        synthetic_response="file1.txt\nfile2.txt",
    )


def _make_finding(rule_id: str = "EXF-TRACE-001", severity: str = "high") -> Finding:
    event = _make_event()
    f = Finding(
        rule_id=rule_id,
        severity=Severity(severity),
        message=f"Test finding for {rule_id}",
        event=event,
        evidence="curl attacker.com",
    )
    event.findings.append(f)
    return f


def _make_report(
    skill_path: str = "/tmp/test_skill.md",
    skill_name: str = "test-skill",
    findings: list | None = None,
    judge_verdict: str | None = None,
    needs_human_review: bool = False,
    error: str | None = None,
) -> TraceReport:
    events = []
    all_findings = findings or []
    for f in all_findings:
        if f.event and f.event not in events:
            events.append(f.event)

    judge_result = None
    if judge_verdict:
        judge_a = JudgeResult(
            model="gpt-4.1",
            verdict=Verdict(judge_verdict),
            confidence=0.9,
            reasoning="Test reasoning A",
        )
        judge_b = JudgeResult(
            model="claude-sonnet-4-5",
            verdict=Verdict(judge_verdict),
            confidence=0.85,
            reasoning="Test reasoning B",
        )
        agreement = AgreementLevel.FULL_AGREEMENT
        judge_result = DualJudgeResult(
            judge_a=judge_a,
            judge_b=judge_b,
            final_verdict=Verdict(judge_verdict),
            agreement=agreement,
            needs_human_review=needs_human_review,
            consensus_reasoning="Both judges agree.",
            started_at=time.time() - 1.0,
            finished_at=time.time(),
        )

    return TraceReport(
        skill_path=skill_path,
        skill_name=skill_name,
        skill_sha256="abc123def456" * 2,
        model="gpt-4.1-mini",
        user_messages=["Help me with this task."],
        events=events,
        findings=all_findings,
        judge_verdict=judge_verdict,
        judge_result=judge_result,
        error=error,
        started_at=time.time() - 2.0,
        finished_at=time.time(),
    )


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class TestFormatJSON:
    def test_produces_valid_json(self):
        report = _make_report()
        output = format_json(report)
        d = json.loads(output)
        assert d["skill_name"] == "test-skill"

    def test_includes_findings(self):
        f = _make_finding()
        report = _make_report(findings=[f])
        output = format_json(report)
        d = json.loads(output)
        assert len(d["findings"]) == 1
        assert d["findings"][0]["rule_id"] == "EXF-TRACE-001"

    def test_includes_judge_when_present(self):
        report = _make_report(judge_verdict="malicious")
        output = format_json(report)
        d = json.loads(output)
        assert "judge" in d
        assert d["judge"]["final_verdict"] == "malicious"

    def test_no_judge_key_when_absent(self):
        report = _make_report()
        output = format_json(report)
        d = json.loads(output)
        assert "judge" not in d

    def test_error_report_serializable(self):
        report = _make_report(error="Connection refused")
        output = format_json(report)
        d = json.loads(output)
        assert d["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# SARIF formatter
# ---------------------------------------------------------------------------


class TestFormatSARIF:
    def test_produces_valid_sarif_structure(self):
        report = _make_report()
        output = format_sarif([report])
        d = json.loads(output)
        assert d["version"] == "2.1.0"
        assert len(d["runs"]) == 1
        assert "tool" in d["runs"][0]

    def test_finding_becomes_sarif_result(self):
        f = _make_finding(rule_id="NET-TRACE-001", severity="critical")
        report = _make_report(findings=[f])
        output = format_sarif([report])
        d = json.loads(output)
        results = d["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        assert "NET-TRACE-001" in rule_ids

    def test_rule_registered_in_driver(self):
        f = _make_finding(rule_id="EXF-TRACE-003")
        report = _make_report(findings=[f])
        output = format_sarif([report])
        d = json.loads(output)
        rule_ids = [r["id"] for r in d["runs"][0]["tool"]["driver"]["rules"]]
        assert "EXF-TRACE-003" in rule_ids

    def test_judge_verdict_added_as_result(self):
        report = _make_report(judge_verdict="malicious")
        output = format_sarif([report])
        d = json.loads(output)
        results = d["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        assert "JUDGE-VERDICT" in rule_ids

    def test_batch_summary_in_properties(self):
        r1 = _make_report(judge_verdict="malicious")
        r2 = _make_report(judge_verdict="benign")
        output = format_sarif([r1, r2])
        d = json.loads(output)
        props = d["runs"][0]["properties"]["skillscan_trace"]
        assert props["total_skills"] == 2
        assert props["malicious"] == 1
        assert props["benign"] == 1

    def test_sarif_level_mapping(self):
        assert _sarif_level("critical") == "error"
        assert _sarif_level("high") == "error"
        assert _sarif_level("medium") == "warning"
        assert _sarif_level("low") == "note"
        assert _sarif_level("info") == "none"

    def test_empty_reports_valid(self):
        output = format_sarif([])
        d = json.loads(output)
        assert d["runs"][0]["results"] == []

    def test_multiple_reports_combined(self):
        f1 = _make_finding(rule_id="EXF-TRACE-001")
        f2 = _make_finding(rule_id="NET-TRACE-002")
        r1 = _make_report(skill_path="/tmp/skill1.md", findings=[f1])
        r2 = _make_report(skill_path="/tmp/skill2.md", findings=[f2])
        output = format_sarif([r1, r2])
        d = json.loads(output)
        results = d["runs"][0]["results"]
        rule_ids = {r["ruleId"] for r in results}
        assert "EXF-TRACE-001" in rule_ids
        assert "NET-TRACE-002" in rule_ids


# ---------------------------------------------------------------------------
# Text formatter
# ---------------------------------------------------------------------------


class TestFormatText:
    def test_contains_skill_name(self):
        report = _make_report(skill_name="my-skill")
        output = format_text(report)
        assert "my-skill" in output

    def test_contains_finding_rule_id(self):
        f = _make_finding(rule_id="EXF-TRACE-001")
        report = _make_report(findings=[f])
        output = format_text(report)
        assert "EXF-TRACE-001" in output

    def test_no_findings_message(self):
        report = _make_report()
        output = format_text(report)
        assert "No canary findings" in output

    def test_judge_verdict_shown(self):
        report = _make_report(judge_verdict="malicious")
        output = format_text(report)
        assert "MALICIOUS" in output

    def test_error_shown(self):
        report = _make_report(error="Connection refused")
        output = format_text(report)
        assert "Connection refused" in output

    def test_human_review_flag(self):
        report = _make_report(judge_verdict="uncertain", needs_human_review=True)
        output = format_text(report)
        assert "HUMAN REVIEW" in output


# ---------------------------------------------------------------------------
# Batch summary
# ---------------------------------------------------------------------------


class TestFormatBatchSummary:
    def test_counts_verdicts(self):
        r1 = _make_report(judge_verdict="malicious")
        r2 = _make_report(judge_verdict="benign")
        r3 = _make_report(judge_verdict="uncertain")
        output = format_batch_summary([r1, r2, r3], elapsed=10.0)
        assert "Malicious:      1" in output
        assert "Benign:         1" in output
        assert "Uncertain:      1" in output

    def test_counts_errors(self):
        r1 = _make_report(error="Connection refused")
        r2 = _make_report()
        output = format_batch_summary([r1, r2], elapsed=5.0)
        assert "Errors:         1" in output

    def test_shows_elapsed_time(self):
        output = format_batch_summary([], elapsed=42.5)
        assert "42.5s" in output

    def test_empty_batch(self):
        output = format_batch_summary([], elapsed=0.1)
        assert "Skills processed: 0" in output
