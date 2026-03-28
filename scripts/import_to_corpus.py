"""
import_to_corpus.py — Corpus integration helper for skillscan-trace.

Reads a JSONL file of trace run results and imports qualifying findings
(malicious, non-disagreement, no human review needed) into a corpus directory
under ``sandbox_verified/trace_<run_id>/``.

Usage (CLI)::

    python scripts/import_to_corpus.py \\
        --results results.jsonl \\
        --corpus-dir /path/to/corpus \\
        --run-id 20260321_120000

Programmatic usage::

    from import_to_corpus import should_import, import_results
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Filtering logic
# ---------------------------------------------------------------------------

IMPORTABLE_VERDICTS = {"malicious"}
IMPORTABLE_AGREEMENTS = {"full_agreement", "partial_agreement"}


def should_import(result: dict[str, Any]) -> tuple[bool, str]:
    """Return (do_import, reason) for a single trace result dict."""
    if result.get("status") != "ok":
        return False, f"status={result.get('status', 'unknown')} error={result.get('error', '')}"

    judge = result.get("judge")
    if not judge:
        return False, "no judge block"

    if judge.get("needs_human_review"):
        return False, "needs_human_review=True"

    verdict = judge.get("final_verdict", "")
    agreement = judge.get("agreement", "")

    if verdict not in IMPORTABLE_VERDICTS:
        return False, f"verdict={verdict} not importable"

    if agreement not in IMPORTABLE_AGREEMENTS:
        return False, f"agreement={agreement} (disagreement skipped)"

    return True, f"verdict={verdict} agreement={agreement}"


# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------


def import_results(
    results_path: Path,
    corpus_dir: Path,
    source_dir: Path | None = None,
    dry_run: bool = False,
    run_id: str | None = None,
) -> dict[str, Any]:
    """
    Read *results_path* (JSONL) and import qualifying results into *corpus_dir*.

    Parameters
    ----------
    results_path:
        Path to a ``.jsonl`` file produced by a trace run.
    corpus_dir:
        Root of the corpus directory.  Imported files land in
        ``corpus_dir/sandbox_verified/trace_<run_id>/``.
    source_dir:
        If provided, the original skill ``.md`` files are copied from here.
    dry_run:
        Count only — do not write any files.
    run_id:
        Identifier appended to the destination subdirectory name.

    Returns
    -------
    dict with keys ``imported``, ``skipped``, ``errors``.
    """
    if not results_path.exists():
        raise FileNotFoundError(f"Results file not found: {results_path}")

    run_label = run_id or "unknown"
    dest_subdir = corpus_dir / "sandbox_verified" / f"trace_{run_label}"
    manifest_path = corpus_dir / "manifest.json"

    summary: dict[str, Any] = {"imported": 0, "skipped": 0, "errors": 0}
    imported_paths: list[str] = []

    lines = results_path.read_text().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            summary["errors"] += 1
            continue

        do_import, _reason = should_import(result)

        if result.get("status") == "error":
            summary["errors"] += 1
            if not do_import:
                continue
        elif not do_import:
            summary["skipped"] += 1
            continue

        summary["imported"] += 1

        if dry_run:
            continue

        # --- Write to corpus ---
        dest_subdir.mkdir(parents=True, exist_ok=True)
        skill_name = result.get("skill_name", "unknown")
        dest_file = dest_subdir / f"{skill_name}.md"

        skill_path = result.get("skill_path")
        if source_dir and skill_path:
            src = Path(skill_path)
            if src.exists():
                shutil.copy2(src, dest_file)
            else:
                # Try relative to source_dir
                candidate = source_dir / src.name
                if candidate.exists():
                    shutil.copy2(candidate, dest_file)
                else:
                    dest_file.write_text(f"# {skill_name}\n\n(source not found)\n")
        elif skill_path and Path(skill_path).exists():
            shutil.copy2(Path(skill_path), dest_file)
        else:
            # Write a stub
            verdict = result.get("judge", {}).get("final_verdict", "unknown")
            dest_file.write_text(f"# {skill_name}\n\nverdict: {verdict}\n")

        imported_paths.append(str(dest_file.relative_to(corpus_dir)))

        # --- Write per-result trace.json ---
        trace_file = dest_subdir / f"{skill_name}.trace.json"
        trace_data: dict[str, Any] = {
            "skill_name": skill_name,
            "skill_path": result.get("skill_path"),
            "run_id": run_label,
            "verdict": result.get("judge", {}).get("final_verdict"),
            "agreement": result.get("judge", {}).get("agreement"),
            "judge": result.get("judge"),
        }
        trace_file.write_text(json.dumps(trace_data, indent=2))

    # --- Update manifest ---
    if not dry_run and imported_paths:
        manifest: dict[str, list[str]] = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
            except json.JSONDecodeError:
                manifest = {}
        existing = manifest.get("sandbox_verified", [])
        manifest["sandbox_verified"] = existing + imported_paths
        manifest_path.write_text(json.dumps(manifest, indent=2))

    # --- Write summary JSON ---
    if not dry_run:
        dest_subdir.mkdir(parents=True, exist_ok=True)
        summary_path = dest_subdir / "_import_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2))

    # --- Write human-readable run summary markdown ---
    if not dry_run and run_id:
        docs_dir = corpus_dir / "docs" / "trace_runs"
        docs_dir.mkdir(parents=True, exist_ok=True)
        summary_md = docs_dir / f"{run_id}_summary.md"
        lines_md: list[str] = [
            f"# Trace Run: {run_id}",
            "",
            f"- **Imported**: {summary['imported']}",
            f"- **Skipped**: {summary['skipped']}",
            f"- **Errors**: {summary['errors']}",
            "",
            "## Imported Skills",
            "",
        ]
        for p in imported_paths:
            skill = Path(p).stem.replace(".trace", "")
            lines_md.append(f"- `{skill}` — malicious")
        summary_md.write_text("\n".join(lines_md) + "\n")

    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Import trace results into corpus.")
    parser.add_argument("--results", required=True, type=Path, help="Path to results.jsonl")
    parser.add_argument("--corpus-dir", required=True, type=Path, help="Corpus root directory")
    parser.add_argument("--source-dir", type=Path, default=None, help="Source skill directory")
    parser.add_argument("--run-id", type=str, default=None, help="Run identifier")
    parser.add_argument("--dry-run", action="store_true", help="Count only, do not write files")
    args = parser.parse_args()

    result = import_results(
        results_path=args.results,
        corpus_dir=args.corpus_dir,
        source_dir=args.source_dir,
        dry_run=args.dry_run,
        run_id=args.run_id,
    )
    print(json.dumps(result, indent=2))
