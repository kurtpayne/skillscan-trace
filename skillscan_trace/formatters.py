"""
Output formatters for skillscan-trace.

Supported formats:
  json  — full TraceReport as JSON (default)
  sarif — SARIF 2.1.0 for CI/CD integration (GitHub Code Scanning, etc.)
  text  — human-readable plain text summary

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json

from typing import Any
from skillscan_trace.models import TraceReport

TOOL_NAME = "skillscan-trace"
TOOL_VERSION = "0.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

def format_json(report: TraceReport, indent: int = 2) -> str:
    """Serialize a TraceReport to pretty-printed JSON."""
    return json.dumps(report.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# SARIF formatter
# ---------------------------------------------------------------------------

def format_sarif(reports: list[TraceReport]) -> str:
    """
    Serialize one or more TraceReports to a SARIF 2.1.0 document.

    Each Finding becomes a SARIF result. The judge verdict is encoded as
    a property bag on the run. Designed for GitHub Code Scanning upload.
    """
    results = []
    rules: dict[str, dict[str, Any]] = {}

    for report in reports:
        for finding in report.findings:
            rule_id = finding.rule_id
            if rule_id not in rules:
                rules[rule_id] = _sarif_rule(finding)

            result = {
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity.value),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": report.skill_path,
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
                "properties": {
                    "tool": finding.event.tool if finding.event else None,
                    "turn": finding.event.turn if finding.event else None,
                    "evidence": finding.evidence,
                    "skill_sha256": report.skill_sha256,
                },
            }
            results.append(result)

        # Add judge verdict as a suppression or property on the run
        if report.judge_verdict:
            results.append(_sarif_judge_result(report))

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/kurtpayne/skillscan-trace",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "skillscan_trace": {
                        "total_skills": len(reports),
                        "malicious": sum(
                            1 for r in reports if r.judge_verdict == "malicious"
                        ),
                        "benign": sum(
                            1 for r in reports if r.judge_verdict == "benign"
                        ),
                        "uncertain": sum(
                            1 for r in reports if r.judge_verdict == "uncertain"
                        ),
                        "needs_human_review": sum(
                            1 for r in reports
                            if r.judge_result and r.judge_result.needs_human_review
                        ),
                    }
                },
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2, default=str)


def _sarif_level(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }
    return mapping.get(severity.lower(), "warning")


def _sarif_rule(finding: Any) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("-", "_"),
        "shortDescription": {"text": finding.message},
        "fullDescription": {"text": finding.message},
        "defaultConfiguration": {
            "level": _sarif_level(finding.severity.value)
        },
        "properties": {
            "tags": ["security", "skillscan-trace"],
        },
    }


def _sarif_judge_result(report: TraceReport) -> dict[str, Any]:
    """Encode the judge verdict as a SARIF result with rule JUDGE-VERDICT."""
    verdict = report.judge_verdict or "uncertain"
    level = "error" if verdict == "malicious" else (
        "warning" if verdict == "uncertain" else "none"
    )
    reasoning = ""
    if report.judge_reasoning:
        reasoning = report.judge_reasoning.get("consensus", "")
    return {
        "ruleId": "JUDGE-VERDICT",
        "level": level,
        "message": {
            "text": f"Judge verdict: {verdict.upper()} — {reasoning[:200]}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": report.skill_path,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
        "properties": {
            "verdict": verdict,
            "needs_human_review": (
                report.judge_result.needs_human_review
                if report.judge_result else False
            ),
            "agreement": (
                report.judge_result.agreement.value
                if report.judge_result else None
            ),
        },
    }


# ---------------------------------------------------------------------------
# Text formatter
# ---------------------------------------------------------------------------

def format_text(report: TraceReport) -> str:
    """Format a TraceReport as human-readable plain text."""
    lines = []
    lines.append(f"{'=' * 60}")
    lines.append(f"Skill:    {report.skill_name or report.skill_path}")
    lines.append(f"SHA256:   {report.skill_sha256[:16]}...")
    lines.append(f"Model:    {report.model}")
    lines.append(f"Duration: {report.duration_seconds:.1f}s" if report.duration_seconds else "Duration: N/A")
    lines.append(f"{'=' * 60}")

    if report.error:
        lines.append(f"ERROR: {report.error}")
        return "\n".join(lines)

    lines.append(f"Tool calls: {report.total_tool_calls}")
    lines.append(f"Findings:   {report.total_findings}")
    lines.append("")

    if report.findings:
        lines.append("FINDINGS:")
        for f in report.findings:
            tool = f.event.tool if f.event else "?"
            turn = f.event.turn if f.event else "?"
            lines.append(
                f"  [{f.severity.value.upper():8s}] {f.rule_id:20s} "
                f"turn={turn} tool={tool}"
            )
            lines.append(f"           {f.message}")
            if f.evidence:
                lines.append(f"           Evidence: {f.evidence[:80]}")
    else:
        lines.append("No canary findings.")

    if report.judge_verdict:
        lines.append("")
        lines.append(f"JUDGE VERDICT: {report.judge_verdict.upper()}")
        if report.judge_result:
            jr = report.judge_result
            lines.append(f"  Agreement: {jr.agreement.value}")
            if jr.needs_human_review:
                lines.append("  *** FLAGGED FOR HUMAN REVIEW ***")
            lines.append(
                f"  GPT-4.1:  {jr.judge_a.verdict.value} "
                f"({jr.judge_a.confidence:.0%}) — {jr.judge_a.reasoning[:120]}"
            )
            lines.append(
                f"  Claude:   {jr.judge_b.verdict.value} "
                f"({jr.judge_b.confidence:.0%}) — {jr.judge_b.reasoning[:120]}"
            )

    lines.append(f"{'=' * 60}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Batch summary
# ---------------------------------------------------------------------------

def format_batch_summary(reports: list[TraceReport], elapsed: float) -> str:
    """Format a summary table for a batch run."""
    total = len(reports)
    malicious = sum(1 for r in reports if r.judge_verdict == "malicious")
    benign = sum(1 for r in reports if r.judge_verdict == "benign")
    uncertain = sum(1 for r in reports if r.judge_verdict == "uncertain")
    no_judge = sum(1 for r in reports if r.judge_verdict is None)
    errors = sum(1 for r in reports if r.error)
    needs_review = sum(
        1 for r in reports
        if r.judge_result and r.judge_result.needs_human_review
    )
    total_findings = sum(r.total_findings for r in reports)

    lines = [
        "",
        "=" * 60,
        "BATCH SUMMARY",
        "=" * 60,
        f"  Skills processed: {total}",
        f"  Elapsed:          {elapsed:.1f}s",
        f"  Total findings:   {total_findings}",
        "",
        "  Judge verdicts:",
        f"    Malicious:      {malicious}",
        f"    Benign:         {benign}",
        f"    Uncertain:      {uncertain}",
        f"    No judge:       {no_judge}",
        f"    Needs review:   {needs_review}",
        f"    Errors:         {errors}",
        "=" * 60,
    ]
    return "\n".join(lines)
