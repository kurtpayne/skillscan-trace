"""
import_to_corpus.py — Import trace results into skillscan-corpus.

Reads a JSONL file produced by modal_trace_batch.py and:
1. Copies confirmed malicious skills to corpus/sandbox_verified/
2. Updates manifest.json with new entries
3. Writes a run summary to docs/trace_runs/

Usage:
  python scripts/import_to_corpus.py \\
    --results trace-results.jsonl \\
    --corpus-dir /path/to/skillscan-corpus \\
    --source-dir /path/to/skillscan-security/corpus \\
    --dry-run

Filtering rules:
  - full_agreement malicious → import unconditionally
  - partial_agreement malicious → import (one definitive judge)
  - disagreement / uncertain → skip (needs human review)
  - benign → skip (not added to adversarial corpus)
  - errors → skip and log

Output structure in skillscan-corpus:
  sandbox_verified/
    trace_<run_id>/
      <skill_stem>.md          ← copy of the skill file
      <skill_stem>.trace.json  ← full trace report
  docs/trace_runs/
    <run_id>_summary.md        ← human-readable run summary
  manifest.json                ← updated with new entries
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def should_import(result: dict) -> tuple[bool, str]:
    """
    Decide whether a trace result should be imported into the corpus.

    Returns (import: bool, reason: str).
    """
    if result.get("status") != "ok":
        return False, f"error: {result.get('error', 'unknown')}"

    judge = result.get("judge")
    if not judge:
        return False, "no judge result"

    verdict = judge.get("final_verdict", "uncertain")
    agreement = judge.get("agreement", "")
    needs_review = judge.get("needs_human_review", False)

    if needs_review:
        return False, f"needs_human_review (agreement={agreement})"

    if verdict == "malicious" and agreement in ("full_agreement", "partial_agreement"):
        return True, f"malicious ({agreement})"

    if verdict == "malicious" and agreement == "disagreement":
        return False, "disagreement — skip"

    return False, f"verdict={verdict}"


# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------

def import_results(
    results_path: Path,
    corpus_dir: Path,
    source_dir: Path | None,
    dry_run: bool = False,
    run_id: str | None = None,
) -> dict:
    """
    Import trace results into the corpus.

    Returns a summary dict.
    """
    if not results_path.exists():
        raise FileNotFoundError(f"Results file not found: {results_path}")

    # Load results
    results = []
    with results_path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                results.append(json.loads(line))

    if not results:
        print("No results to import.")
        return {"imported": 0, "skipped": 0, "errors": 0}

    # Determine run_id
    if not run_id:
        # Try to get from first result
        run_id = results[0].get("run_id") or datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    print(f"Run ID: {run_id}")
    print(f"Results: {len(results)}")

    # Prepare output directories
    sandbox_dir = corpus_dir / "sandbox_verified" / f"trace_{run_id}"
    docs_dir = corpus_dir / "docs" / "trace_runs"

    if not dry_run:
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        docs_dir.mkdir(parents=True, exist_ok=True)

    # Process each result
    imported = []
    skipped = []
    errors = []

    for result in results:
        skill_path = result.get("skill_path", "")
        skill_name = result.get("skill_name") or Path(skill_path).stem

        do_import, reason = should_import(result)

        if result.get("status") != "ok":
            errors.append({"skill": skill_name, "reason": reason})
            print(f"  [ERROR]  {skill_name}: {reason}")
            continue

        if not do_import:
            skipped.append({"skill": skill_name, "reason": reason})
            print(f"  [SKIP]   {skill_name}: {reason}")
            continue

        print(f"  [IMPORT] {skill_name}: {reason}")
        imported.append({"skill": skill_name, "path": skill_path, "reason": reason})

        if dry_run:
            continue

        # Copy skill file
        skill_file = Path(skill_path)
        if not skill_file.exists() and source_dir:
            # Try to find it relative to source_dir
            candidates = list(source_dir.rglob(skill_file.name))
            if candidates:
                skill_file = candidates[0]

        dest_skill = sandbox_dir / f"{skill_name}.md"
        if skill_file.exists():
            shutil.copy2(skill_file, dest_skill)
        else:
            # Write the skill content from the trace result if available
            skill_content = result.get("skill_content")
            if skill_content:
                dest_skill.write_text(skill_content)
            else:
                print(f"    Warning: could not find skill file {skill_path}")

        # Write trace JSON
        dest_trace = sandbox_dir / f"{skill_name}.trace.json"
        dest_trace.write_text(json.dumps(result, indent=2))

    # Update manifest.json
    if not dry_run and imported:
        _update_manifest(corpus_dir, run_id, imported)

    # Write run summary
    summary = {
        "run_id": run_id,
        "results_file": str(results_path),
        "total": len(results),
        "imported": len(imported),
        "skipped": len(skipped),
        "errors": len(errors),
        "imported_skills": imported,
        "skipped_skills": skipped,
        "error_skills": errors,
    }

    if not dry_run:
        _write_run_summary(docs_dir, run_id, summary, results)

    # Print summary
    print()
    print("=" * 50)
    print("IMPORT SUMMARY")
    print("=" * 50)
    print(f"  Total results:  {len(results)}")
    print(f"  Imported:       {len(imported)}")
    print(f"  Skipped:        {len(skipped)}")
    print(f"  Errors:         {len(errors)}")
    if not dry_run and imported:
        print(f"  Output dir:     {sandbox_dir}")
    print("=" * 50)

    return summary


def _update_manifest(corpus_dir: Path, run_id: str, imported: list[dict]) -> None:
    """Add new entries to manifest.json."""
    manifest_path = corpus_dir / "manifest.json"

    if manifest_path.exists():
        with manifest_path.open() as f:
            manifest = json.load(f)
    else:
        manifest = {}

    # Add sandbox_verified section if not present
    if "sandbox_verified" not in manifest:
        manifest["sandbox_verified"] = []

    for item in imported:
        entry = f"sandbox_verified/trace_{run_id}/{item['skill']}.md"
        if entry not in manifest["sandbox_verified"]:
            manifest["sandbox_verified"].append(entry)

    # Record the trace run
    if "trace_runs" not in manifest:
        manifest["trace_runs"] = []
    manifest["trace_runs"].append({
        "run_id": run_id,
        "imported": len(imported),
        "timestamp": datetime.utcnow().isoformat(),
    })

    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)

    print(f"  manifest.json updated ({len(imported)} new entries)")


def _write_run_summary(
    docs_dir: Path,
    run_id: str,
    summary: dict,
    results: list[dict],
) -> None:
    """Write a human-readable Markdown summary of the trace run."""
    summary_path = docs_dir / f"{run_id}_summary.md"

    lines = [
        f"# Trace Run: {run_id}",
        "",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total skills:** {summary['total']}",
        f"**Imported:** {summary['imported']}",
        f"**Skipped:** {summary['skipped']}",
        f"**Errors:** {summary['errors']}",
        "",
        "## Imported (confirmed malicious)",
        "",
    ]

    for item in summary["imported_skills"]:
        lines.append(f"- `{item['skill']}` — {item['reason']}")

    lines += [
        "",
        "## Verdict breakdown",
        "",
        "| Skill | Verdict | Agreement | Confidence |",
        "|-------|---------|-----------|------------|",
    ]

    for r in results:
        if r.get("status") != "ok":
            continue
        judge = r.get("judge", {})
        if not judge:
            continue
        skill = r.get("skill_name") or Path(r.get("skill_path", "?")).stem
        verdict = judge.get("final_verdict", "?")
        agreement = judge.get("agreement", "?")
        # Average confidence of the two judges
        ja = judge.get("judge_a", {})
        jb = judge.get("judge_b", {})
        conf_a = ja.get("confidence", 0) if ja else 0
        conf_b = jb.get("confidence", 0) if jb else 0
        avg_conf = (conf_a + conf_b) / 2 if (conf_a or conf_b) else 0
        lines.append(f"| `{skill}` | {verdict} | {agreement} | {avg_conf:.0%} |")

    lines += ["", "## Skipped", ""]
    for item in summary["skipped_skills"]:
        lines.append(f"- `{item['skill']}` — {item['reason']}")

    if summary["error_skills"]:
        lines += ["", "## Errors", ""]
        for item in summary["error_skills"]:
            lines.append(f"- `{item['skill']}` — {item['reason']}")

    summary_path.write_text("\n".join(lines) + "\n")
    print(f"  Run summary written to {summary_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import trace results into skillscan-corpus"
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Path to JSONL results file from modal_trace_batch.py",
    )
    parser.add_argument(
        "--corpus-dir",
        required=True,
        help="Path to skillscan-corpus directory",
    )
    parser.add_argument(
        "--source-dir",
        default=None,
        help="Path to skillscan-security/corpus (for finding original skill files)",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Override run ID (default: from results file)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be imported without writing anything",
    )

    args = parser.parse_args()

    import_results(
        results_path=Path(args.results),
        corpus_dir=Path(args.corpus_dir),
        source_dir=Path(args.source_dir) if args.source_dir else None,
        dry_run=args.dry_run,
        run_id=args.run_id,
    )


if __name__ == "__main__":
    main()
