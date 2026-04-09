"""
Tests for Phase 5: corpus integration (import_to_corpus.py).

All tests use temp directories — no network, no Modal, no LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# We import the functions directly from the scripts module
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

try:
    from import_to_corpus import should_import, import_results  # noqa: E402
except ImportError:
    pytestmark = pytest.mark.skip(reason="import_to_corpus script not available")
    should_import = None  # type: ignore[assignment]
    import_results = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    skill_name: str = "test_skill",
    skill_path: str = "/tmp/test_skill.md",
    verdict: str = "malicious",
    agreement: str = "full_agreement",
    needs_human_review: bool = False,
    status: str = "ok",
    error: str | None = None,
    run_id: str = "20260321_000000",
) -> dict:
    result = {
        "skill_path": skill_path,
        "skill_name": skill_name,
        "run_id": run_id,
        "status": status,
    }
    if error:
        result["error"] = error
    if status == "ok":
        result["judge"] = {
            "final_verdict": verdict,
            "agreement": agreement,
            "needs_human_review": needs_human_review,
            "judge_a": {
                "verdict": verdict,
                "confidence": 0.9,
                "reasoning": "Test reasoning A",
            },
            "judge_b": {
                "verdict": verdict,
                "confidence": 0.85,
                "reasoning": "Test reasoning B",
            },
        }
    return result


def _write_jsonl(path: Path, results: list[dict]) -> None:
    with path.open("w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")


# ---------------------------------------------------------------------------
# should_import filtering
# ---------------------------------------------------------------------------


class TestShouldImport:
    def test_full_agreement_malicious_imports(self):
        r = _make_result(verdict="malicious", agreement="full_agreement")
        do_import, reason = should_import(r)
        assert do_import is True
        assert "malicious" in reason

    def test_partial_agreement_malicious_imports(self):
        r = _make_result(verdict="malicious", agreement="partial_agreement")
        do_import, reason = should_import(r)
        assert do_import is True

    def test_disagreement_malicious_skips(self):
        r = _make_result(verdict="malicious", agreement="disagreement")
        do_import, reason = should_import(r)
        assert do_import is False
        assert "disagreement" in reason

    def test_benign_skips(self):
        r = _make_result(verdict="benign", agreement="full_agreement")
        do_import, reason = should_import(r)
        assert do_import is False

    def test_uncertain_skips(self):
        r = _make_result(verdict="uncertain", agreement="full_agreement")
        do_import, reason = should_import(r)
        assert do_import is False

    def test_needs_human_review_skips(self):
        r = _make_result(
            verdict="malicious",
            agreement="full_agreement",
            needs_human_review=True,
        )
        do_import, reason = should_import(r)
        assert do_import is False
        assert "needs_human_review" in reason

    def test_error_status_skips(self):
        r = _make_result(status="error", error="Connection refused")
        do_import, reason = should_import(r)
        assert do_import is False
        assert "error" in reason

    def test_no_judge_skips(self):
        r = {"skill_name": "x", "status": "ok"}
        do_import, reason = should_import(r)
        assert do_import is False
        assert "no judge" in reason


# ---------------------------------------------------------------------------
# import_results — dry run
# ---------------------------------------------------------------------------


class TestImportResultsDryRun:
    def test_dry_run_does_not_write_files(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        r = _make_result(verdict="malicious", agreement="full_agreement")
        _write_jsonl(results_file, [r])

        summary = import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=True,
            run_id="test_run",
        )

        assert summary["imported"] == 1
        assert summary["skipped"] == 0
        # No files written in dry run
        assert not (corpus_dir / "sandbox_verified").exists()

    def test_dry_run_counts_skipped(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        results = [
            _make_result(skill_name="malicious1", verdict="malicious", agreement="full_agreement"),
            _make_result(skill_name="benign1", verdict="benign", agreement="full_agreement"),
            _make_result(skill_name="uncertain1", verdict="uncertain", agreement="full_agreement"),
        ]
        _write_jsonl(results_file, results)

        summary = import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=True,
            run_id="test_run",
        )

        assert summary["imported"] == 1
        assert summary["skipped"] == 2
        assert summary["errors"] == 0

    def test_dry_run_counts_errors(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        results = [
            _make_result(skill_name="err1", status="error", error="timeout"),
            _make_result(skill_name="ok1", verdict="malicious", agreement="full_agreement"),
        ]
        _write_jsonl(results_file, results)

        summary = import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=True,
            run_id="test_run",
        )

        assert summary["errors"] == 1
        assert summary["imported"] == 1


# ---------------------------------------------------------------------------
# import_results — actual write
# ---------------------------------------------------------------------------


class TestImportResultsWrite:
    def test_writes_trace_json(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        r = _make_result(
            skill_name="ah01_test",
            verdict="malicious",
            agreement="full_agreement",
            run_id="run001",
        )
        _write_jsonl(results_file, [r])

        import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=False,
            run_id="run001",
        )

        trace_file = corpus_dir / "sandbox_verified" / "trace_run001" / "ah01_test.trace.json"
        assert trace_file.exists()
        data = json.loads(trace_file.read_text())
        assert data["skill_name"] == "ah01_test"

    def test_updates_manifest(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        r = _make_result(
            skill_name="ah02_test",
            verdict="malicious",
            agreement="full_agreement",
            run_id="run002",
        )
        _write_jsonl(results_file, [r])

        import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=False,
            run_id="run002",
        )

        manifest_path = corpus_dir / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert "sandbox_verified" in manifest
        assert any("ah02_test" in e for e in manifest["sandbox_verified"])

    def test_writes_run_summary(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        r = _make_result(
            skill_name="ah03_test",
            verdict="malicious",
            agreement="full_agreement",
            run_id="run003",
        )
        _write_jsonl(results_file, [r])

        import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=False,
            run_id="run003",
        )

        summary_file = corpus_dir / "docs" / "trace_runs" / "run003_summary.md"
        assert summary_file.exists()
        content = summary_file.read_text()
        assert "ah03_test" in content
        assert "malicious" in content

    def test_copies_skill_file_when_found(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        # Create a source skill file
        skill_file = source_dir / "ah04_test.md"
        skill_file.write_text("# Test Skill\nThis is malicious.")

        r = _make_result(
            skill_name="ah04_test",
            skill_path=str(skill_file),
            verdict="malicious",
            agreement="full_agreement",
            run_id="run004",
        )
        _write_jsonl(results_file, [r])

        import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=source_dir,
            dry_run=False,
            run_id="run004",
        )

        dest = corpus_dir / "sandbox_verified" / "trace_run004" / "ah04_test.md"
        assert dest.exists()
        assert "malicious" in dest.read_text()

    def test_existing_manifest_preserved(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "results.jsonl"

        # Pre-existing manifest
        manifest_path = corpus_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "benign": ["benign/existing.md"],
                    "injection": ["injection/existing.md"],
                }
            )
        )

        r = _make_result(
            skill_name="new_skill",
            verdict="malicious",
            agreement="full_agreement",
            run_id="run005",
        )
        _write_jsonl(results_file, [r])

        import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=False,
            run_id="run005",
        )

        manifest = json.loads(manifest_path.read_text())
        # Existing keys preserved
        assert "benign" in manifest
        assert "injection" in manifest
        # New key added
        assert "sandbox_verified" in manifest

    def test_empty_results_file(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        results_file = tmp_path / "empty.jsonl"
        results_file.write_text("")

        summary = import_results(
            results_path=results_file,
            corpus_dir=corpus_dir,
            source_dir=None,
            dry_run=False,
        )

        assert summary["imported"] == 0

    def test_missing_results_file_raises(self, tmp_path):
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        with pytest.raises(FileNotFoundError):
            import_results(
                results_path=tmp_path / "nonexistent.jsonl",
                corpus_dir=corpus_dir,
                source_dir=None,
            )
