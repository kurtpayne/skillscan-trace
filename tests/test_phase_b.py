"""
Tests for Phase B features:
  B4 — Multi-model trace (run_multi_model_trace, MultiModelReport, agreement logic)
  B5 — Remote trace (--remote-host CLI flag, _run_remote polling logic)

All tests are pure unit tests — no network, no LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from skillscan_trace.cli import main
from skillscan_trace.models import Finding, Severity, TraceEvent, TraceReport
from skillscan_trace.multi_model import (
    AGREEMENT_DISAGREE,
    AGREEMENT_FULL,
    AGREEMENT_NO_VERDICT,
    AGREEMENT_PARTIAL,
    ModelResult,
    MultiModelReport,
    _compute_agreement,
    run_multi_model_trace,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_trace_report(
    model: str = "gpt-4.1-mini",
    verdict: str | None = None,
    finding_count: int = 0,
    error: str | None = None,
) -> TraceReport:
    """Build a minimal TraceReport for testing."""
    report = TraceReport(
        skill_path="/tmp/test.md",
        skill_name="test-skill",
        skill_sha256="abc123",
        model=model,
        user_messages=["hello"],
        error=error,
    )
    if verdict:
        report.judge_verdict = verdict
    for i in range(finding_count):
        event = TraceEvent(turn=0, tool="bash", arguments={}, synthetic_response="ok")
        report.findings.append(
            Finding(
                rule_id=f"TEST-{i:03d}",
                severity=Severity.HIGH,
                message="test finding",
                event=event,
            )
        )
    return report


def _make_skill_file(tmp_path: Path, content: str = "# Test Skill\nDo stuff.") -> Path:
    """Write a minimal skill file to a temp directory."""
    p = tmp_path / "SKILL.md"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# B4 — Agreement logic (_compute_agreement)
# ---------------------------------------------------------------------------


class TestComputeAgreement:
    def test_all_none_returns_no_verdict(self) -> None:
        assert _compute_agreement([None, None]) == AGREEMENT_NO_VERDICT

    def test_empty_list_returns_no_verdict(self) -> None:
        assert _compute_agreement([]) == AGREEMENT_NO_VERDICT

    def test_single_verdict_full_agreement(self) -> None:
        assert _compute_agreement(["malicious"]) == AGREEMENT_FULL

    def test_all_same_verdict_full_agreement(self) -> None:
        assert _compute_agreement(["malicious", "malicious", "malicious"]) == AGREEMENT_FULL

    def test_majority_verdict_partial_agreement(self) -> None:
        assert _compute_agreement(["malicious", "malicious", "benign"]) == AGREEMENT_PARTIAL

    def test_even_split_is_disagreement(self) -> None:
        assert _compute_agreement(["malicious", "benign"]) == AGREEMENT_DISAGREE

    def test_three_way_split_is_disagreement(self) -> None:
        assert _compute_agreement(["malicious", "benign", "uncertain"]) == AGREEMENT_DISAGREE

    def test_none_values_ignored_in_majority(self) -> None:
        # Two malicious, one None — should be full agreement on non-null
        assert _compute_agreement(["malicious", "malicious", None]) == AGREEMENT_FULL

    def test_mixed_none_and_split(self) -> None:
        # One malicious, one benign, one None — split on non-null
        assert _compute_agreement(["malicious", "benign", None]) == AGREEMENT_DISAGREE


# ---------------------------------------------------------------------------
# B4 — MultiModelReport dataclass
# ---------------------------------------------------------------------------


class TestMultiModelReport:
    def test_to_dict_round_trip(self) -> None:
        r1 = _make_trace_report("gpt-4.1-mini", verdict="benign")
        r2 = _make_trace_report("openai/gpt-4o", verdict="benign")
        mmr = MultiModelReport(
            skill_path="/tmp/test.md",
            skill_name="test-skill",
            skill_sha256="abc123",
            models=["gpt-4.1-mini", "openai/gpt-4o"],
            results=[
                ModelResult(
                    model="gpt-4.1-mini",
                    report=r1,
                    verdict="benign",
                    finding_count=0,
                ),
                ModelResult(
                    model="openai/gpt-4o",
                    report=r2,
                    verdict="benign",
                    finding_count=0,
                ),
            ],
            agreement=AGREEMENT_FULL,
            consensus_verdict="benign",
            started_at=1000.0,
            finished_at=1005.0,
        )
        d = mmr.to_dict()
        assert d["agreement"] == AGREEMENT_FULL
        assert d["consensus_verdict"] == "benign"
        assert d["duration_seconds"] == pytest.approx(5.0)
        assert len(d["results"]) == 2
        assert d["results"][0]["model"] == "gpt-4.1-mini"

    def test_duration_none_when_not_finished(self) -> None:
        mmr = MultiModelReport(
            skill_path="/tmp/test.md",
            skill_name="test",
            skill_sha256="abc",
            models=["m1"],
        )
        assert mmr.duration_seconds is None

    def test_model_result_to_dict_includes_report(self) -> None:
        report = _make_trace_report("m1", verdict="malicious", finding_count=2)
        mr = ModelResult(model="m1", report=report, verdict="malicious", finding_count=2)
        d = mr.to_dict()
        assert d["model"] == "m1"
        assert d["verdict"] == "malicious"
        assert d["finding_count"] == 2
        assert "report" in d
        assert d["report"]["model"] == "m1"


# ---------------------------------------------------------------------------
# B4 — run_multi_model_trace (mocked harness)
# ---------------------------------------------------------------------------


class TestRunMultiModelTrace:
    def _mock_run_trace(self, model: str, verdict: str | None = None) -> TraceReport:
        return _make_trace_report(model=model, verdict=verdict)

    def test_two_models_full_agreement_benign(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)

        call_log: list[str] = []

        def fake_run_trace(skill_path: str, *, model: str, **kwargs: object) -> TraceReport:
            call_log.append(model)
            return _make_trace_report(model=model, verdict="benign")

        with (
            patch("skillscan_trace.multi_model.run_trace", side_effect=fake_run_trace),
            patch("skillscan_trace.multi_model.resolve") as mock_resolve,
        ):
            mock_skill = MagicMock()
            mock_skill.name = "test-skill"
            mock_skill.sha256 = "abc123"
            mock_resolve.return_value = mock_skill

            mmr = run_multi_model_trace(
                skill_path=str(skill_file),
                models=["gpt-4.1-mini", "openai/gpt-4o"],
                api_key="test-key",
            )

        assert len(call_log) == 2
        assert mmr.agreement == AGREEMENT_FULL
        assert mmr.consensus_verdict == "benign"
        assert len(mmr.results) == 2
        assert mmr.finished_at is not None

    def test_two_models_disagreement(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)
        verdicts = iter(["malicious", "benign"])

        def fake_run_trace(skill_path: str, *, model: str, **kwargs: object) -> TraceReport:
            return _make_trace_report(model=model, verdict=next(verdicts))

        with (
            patch("skillscan_trace.multi_model.run_trace", side_effect=fake_run_trace),
            patch("skillscan_trace.multi_model.resolve") as mock_resolve,
        ):
            mock_skill = MagicMock()
            mock_skill.name = "test"
            mock_skill.sha256 = "xyz"
            mock_resolve.return_value = mock_skill

            mmr = run_multi_model_trace(
                skill_path=str(skill_file),
                models=["m1", "m2"],
            )

        assert mmr.agreement == AGREEMENT_DISAGREE
        assert mmr.consensus_verdict is None

    def test_three_models_partial_agreement(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)
        verdicts = iter(["malicious", "malicious", "benign"])

        def fake_run_trace(skill_path: str, *, model: str, **kwargs: object) -> TraceReport:
            return _make_trace_report(model=model, verdict=next(verdicts))

        with (
            patch("skillscan_trace.multi_model.run_trace", side_effect=fake_run_trace),
            patch("skillscan_trace.multi_model.resolve") as mock_resolve,
        ):
            mock_skill = MagicMock()
            mock_skill.name = "test"
            mock_skill.sha256 = "xyz"
            mock_resolve.return_value = mock_skill

            mmr = run_multi_model_trace(
                skill_path=str(skill_file),
                models=["m1", "m2", "m3"],
            )

        assert mmr.agreement == AGREEMENT_PARTIAL
        assert mmr.consensus_verdict == "malicious"

    def test_resolver_error_returns_error_report(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)

        from skillscan_trace.resolver import SkillResolverError

        with patch(
            "skillscan_trace.multi_model.resolve",
            side_effect=SkillResolverError("not found"),
        ):
            mmr = run_multi_model_trace(
                skill_path=str(skill_file),
                models=["m1", "m2"],
            )

        assert mmr.agreement == AGREEMENT_NO_VERDICT
        assert all(r.error is not None for r in mmr.results)
        assert mmr.finished_at is not None

    def test_no_judge_verdict_uses_judge_result(self, tmp_path: Path) -> None:
        """If judge_result is set on the TraceReport, use its final_verdict."""
        skill_file = _make_skill_file(tmp_path)

        def fake_run_trace(skill_path: str, *, model: str, **kwargs: object) -> TraceReport:
            report = _make_trace_report(model=model)
            # Simulate a judge_result with final_verdict
            jr = MagicMock()
            jr.final_verdict.value = "malicious"
            report.judge_result = jr
            return report

        with (
            patch("skillscan_trace.multi_model.run_trace", side_effect=fake_run_trace),
            patch("skillscan_trace.multi_model.resolve") as mock_resolve,
        ):
            mock_skill = MagicMock()
            mock_skill.name = "test"
            mock_skill.sha256 = "abc"
            mock_resolve.return_value = mock_skill

            mmr = run_multi_model_trace(
                skill_path=str(skill_file),
                models=["m1", "m2"],
            )

        assert mmr.agreement == AGREEMENT_FULL
        assert mmr.consensus_verdict == "malicious"


# ---------------------------------------------------------------------------
# B4 — CLI --models flag
# ---------------------------------------------------------------------------


class TestCliMultiModels:
    def test_models_flag_requires_two_models(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["run", str(skill_file), "--models", "gpt-4.1-mini"],
            catch_exceptions=False,
        )
        assert result.exit_code != 0
        assert "at least two" in result.output.lower() or "at least two" in str(result.exception)

    def test_models_flag_dispatches_to_multi_model(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)
        runner = CliRunner()

        with patch("skillscan_trace.cli._run_multi_model") as mock_mm:
            runner.invoke(
                main,
                [
                    "run",
                    str(skill_file),
                    "--models",
                    "gpt-4.1-mini,openai/gpt-4o",
                    "--api-key",
                    "test-key",
                ],
                catch_exceptions=False,
            )
        assert mock_mm.called
        call_kwargs = mock_mm.call_args
        assert "gpt-4.1-mini" in call_kwargs.kwargs["models"]
        assert "openai/gpt-4o" in call_kwargs.kwargs["models"]


# ---------------------------------------------------------------------------
# B5 — CLI --remote-host flag
# ---------------------------------------------------------------------------


class TestCliRemoteHost:
    def test_remote_host_dispatches_to_run_remote(self, tmp_path: Path) -> None:
        skill_file = _make_skill_file(tmp_path)
        runner = CliRunner()

        with patch("skillscan_trace.cli._run_remote") as mock_remote:
            runner.invoke(
                main,
                [
                    "run",
                    str(skill_file),
                    "--remote-host",
                    "https://trace.example.com",
                    "--api-key",
                    "test-key",
                ],
                catch_exceptions=False,
            )
        assert mock_remote.called
        call_kwargs = mock_remote.call_args
        assert call_kwargs.kwargs["remote_host"] == "https://trace.example.com"

    def test_remote_host_env_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        skill_file = _make_skill_file(tmp_path)
        monkeypatch.setenv("SKILLSCAN_TRACE_REMOTE_HOST", "https://env-host.example.com")
        runner = CliRunner()

        with patch("skillscan_trace.cli._run_remote") as mock_remote:
            runner.invoke(
                main,
                ["run", str(skill_file), "--api-key", "test-key"],
                catch_exceptions=False,
            )
        assert mock_remote.called
        call_kwargs = mock_remote.call_args
        assert "env-host.example.com" in call_kwargs.kwargs["remote_host"]


# ---------------------------------------------------------------------------
# B5 — _run_remote polling logic (mocked requests)
# ---------------------------------------------------------------------------


class TestRunRemote:
    def test_successful_poll(self, tmp_path: Path) -> None:
        """Submit → 202 pending → 200 done → write output file."""
        from skillscan_trace.cli import _run_remote

        skill_file = _make_skill_file(tmp_path)
        out_dir = tmp_path / "out"

        submit_resp = MagicMock()
        submit_resp.raise_for_status = MagicMock()
        submit_resp.json.return_value = {"job_id": "job-abc123"}

        pending_resp = MagicMock()
        pending_resp.status_code = 202
        pending_resp.json.return_value = {"status": "running"}

        done_resp = MagicMock()
        done_resp.status_code = 200
        done_resp.json.return_value = {
            "skill_path": str(skill_file),
            "total_tool_calls": 2,
            "findings": [],
        }

        with (
            patch("skillscan_trace.cli.time.sleep"),
            patch("skillscan_trace.cli.req_lib") as mock_req,
        ):
            mock_req.post.return_value = submit_resp
            # First poll → pending, second poll → done
            mock_req.get.side_effect = [pending_resp, done_resp]

            _run_remote(
                skill=str(skill_file),
                remote_host="https://trace.example.com",
                api_key="test-key",
                provider=None,
                model="gpt-4.1-mini",
                variants=3,
                max_turns=10,
                output_dir=str(out_dir),
                output_format="json",
                judge=False,
                quiet=True,
            )

        out_files = list(out_dir.glob("*.remote.json"))
        assert len(out_files) == 1
        data = json.loads(out_files[0].read_text())
        assert data["total_tool_calls"] == 2

    def test_missing_job_id_exits(self, tmp_path: Path) -> None:
        from skillscan_trace.cli import _run_remote

        skill_file = _make_skill_file(tmp_path)

        submit_resp = MagicMock()
        submit_resp.raise_for_status = MagicMock()
        submit_resp.json.return_value = {}  # no job_id

        with (
            patch("skillscan_trace.cli.req_lib") as mock_req,
            pytest.raises(SystemExit) as exc_info,
        ):
            mock_req.post.return_value = submit_resp
            _run_remote(
                skill=str(skill_file),
                remote_host="https://trace.example.com",
                api_key=None,
                provider=None,
                model="gpt-4.1-mini",
                variants=3,
                max_turns=10,
                output_dir=str(tmp_path / "out"),
                output_format="json",
                judge=False,
                quiet=True,
            )

        assert exc_info.value.code == 1
