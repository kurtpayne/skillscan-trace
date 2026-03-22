"""
modal_trace_batch.py — Run skillscan-trace against a corpus directory on Modal.

Architecture:
  - One Modal container per skill (parallelism = up to 50 concurrent)
  - GPT-4.1-mini as the execution model (fast, cheap, reliable tool-use)
  - GPT-4.1 + Claude Sonnet as the dual judge
  - Results written locally as JSONL

Execution model choice:
  - GPT-4.1-mini: fast (~5s/skill), reliable tool-use, ~$0.002/skill
  - Ollama (future): swap base_url to localhost:11434 in a GPU container for
    a more realistic "dumb model" baseline. See scripts/modal_trace_ollama.py.

Cost estimate (GPT-4.1-mini execution + GPT-4.1 + Claude Sonnet judge):
  Execution (GPT-4.1-mini): ~$0.002/skill
  Judge (GPT-4.1 + Claude Sonnet): ~$0.01/skill
  95 skills: ~$1.14 total

Usage:
  # Dry run (no LLM calls, verify setup)
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --dry-run

  # Full run with judge
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --judge

  # Run against all corpus categories
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/ --judge --recursive
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import modal

# ---------------------------------------------------------------------------
# Modal app definition
# ---------------------------------------------------------------------------

app = modal.App("skillscan-trace-batch")

# Results volume — JSONL output from each run
results_volume = modal.Volume.from_name("skillscan-trace-results", create_if_missing=True)

# Container image — lightweight, no Ollama needed
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "openai>=1.30.0",
        "anthropic>=0.25.0",
        "pyyaml>=6.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    )
    # Install skillscan-trace from the repo (copy=True so pip install can follow)
    .add_local_dir(
        local_path=".",
        remote_path="/app/skillscan-trace",
        copy=True,
    )
    .run_commands("pip install -e /app/skillscan-trace")
)

RESULTS_VOLUME_PATH = "/results"

# Execution model — GPT-4.1-mini for speed and reliable tool-use
EXECUTION_MODEL = "gpt-4.1-mini"
EXECUTION_BASE_URL = "https://api.openai.com/v1"


# ---------------------------------------------------------------------------
# Modal function: trace a single skill
# ---------------------------------------------------------------------------

@app.function(
    image=image,
    volumes={
        RESULTS_VOLUME_PATH: results_volume,
    },
    cpu=1.0,
    memory=1024,
    timeout=120,  # 2 min max per skill (GPT-4.1-mini is fast)
    secrets=[
        modal.Secret.from_name("skillscan-api-keys"),
    ],
    retries=1,
    max_containers=50,
)
def trace_skill(
    skill_content: str,
    skill_path: str,
    skill_name: str,
    run_id: str,
    variants: int = 1,
    judge: bool = True,
    dry_run: bool = False,
) -> dict:
    """
    Trace a single skill inside a Modal container using GPT-4.1-mini.

    Returns a dict with the trace result, suitable for JSONL output.
    """
    import tempfile
    from skillscan_trace.harness import run_trace

    # Write skill content to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", delete=False, prefix="skill_"
    ) as f:
        f.write(skill_content)
        tmp_path = f.name

    try:
        if dry_run:
            return {
                "skill_path": skill_path,
                "skill_name": skill_name,
                "run_id": run_id,
                "dry_run": True,
                "status": "ok",
            }

        openai_key = os.environ.get("OPENAI_API_KEY", "")
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")

        # Run trace using GPT-4.1-mini as the execution model
        report = run_trace(
            skill_path=tmp_path,
            model=EXECUTION_MODEL,
            api_key=openai_key,
            base_url=EXECUTION_BASE_URL,
            input_count=variants,
            input_model=EXECUTION_MODEL,
            max_turns=8,
            judge=judge,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
        )

        result = report.to_dict()
        result["skill_path"] = skill_path  # use original path, not tmp
        result["skill_name"] = skill_name
        result["run_id"] = run_id
        result["execution_model"] = EXECUTION_MODEL
        result["status"] = "ok"

        return result

    except Exception as e:
        return {
            "skill_path": skill_path,
            "skill_name": skill_name,
            "run_id": run_id,
            "status": "error",
            "error": str(e),
            "execution_model": EXECUTION_MODEL,
        }
    finally:
        Path(tmp_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Wrapper: accepts a single dict so .map() can dispatch it
# ---------------------------------------------------------------------------

@app.function(
    image=image,
    volumes={
        RESULTS_VOLUME_PATH: results_volume,
    },
    cpu=1.0,
    memory=1024,
    timeout=120,
    secrets=[
        modal.Secret.from_name("skillscan-api-keys"),
    ],
    retries=1,
    max_containers=50,
)
def trace_skill_wrapper(skill_input: dict) -> dict:
    """
    Thin wrapper around trace_skill that accepts a single dict.
    Used with .map() for parallel dispatch.
    """
    return trace_skill.local(
        skill_input["skill_content"],
        skill_input["skill_path"],
        skill_input["skill_name"],
        skill_input["run_id"],
        skill_input.get("variants", 1),
        skill_input.get("judge", False),
        skill_input.get("dry_run", False),
    )


# ---------------------------------------------------------------------------
# Local entrypoint: collect skills, dispatch, collect results
# ---------------------------------------------------------------------------

@app.local_entrypoint()
def main(
    corpus_dir: str = "./corpus/agent_hijacker",
    output_file: str = "./trace-results.jsonl",
    variants: int = 1,
    judge: bool = False,
    dry_run: bool = False,
    recursive: bool = False,
    max_parallel: int = 50,
):
    """
    Run batch traces against a corpus directory.

    Args:
        corpus_dir:      Path to directory containing skill .md files
        output_file:     Local path for JSONL output
        variants:        Number of user messages per skill
        judge:           Run dual-LLM judge after each trace
        dry_run:         Verify setup without running LLM
        recursive:       Recurse into subdirectories
        max_parallel:    Maximum concurrent Modal containers
    """
    import datetime

    # Collect skill files
    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        print(f"Error: corpus_dir {corpus_dir} does not exist")
        sys.exit(1)

    if recursive:
        skill_files = list(corpus_path.rglob("*.md"))
    else:
        skill_files = list(corpus_path.glob("*.md"))

    if not skill_files:
        print(f"No .md files found in {corpus_dir}")
        sys.exit(1)

    run_id = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    print(f"Run ID: {run_id}")
    print(f"Skills: {len(skill_files)}")
    print(f"Execution model: {EXECUTION_MODEL}")
    print(f"Variants: {variants}")
    print(f"Judge: {judge}")
    print(f"Dry run: {dry_run}")
    print(f"Max parallel: {max_parallel}")
    print()

    # Load skill contents
    skill_inputs = []
    for sf in skill_files:
        try:
            content = sf.read_text(encoding="utf-8")
            skill_inputs.append({
                "skill_content": content,
                "skill_path": str(sf),
                "skill_name": sf.stem,
                "run_id": run_id,
                "variants": variants,
                "judge": judge,
                "dry_run": dry_run,
            })
        except Exception as e:
            print(f"Warning: could not read {sf}: {e}")

    print(f"Dispatching {len(skill_inputs)} trace jobs...")
    start = time.time()

    # Dispatch all skills in parallel using .map()
    print(f"  Running all {len(skill_inputs)} skills in parallel (max {max_parallel} concurrent)...")
    results = list(
        trace_skill_wrapper.map(
            skill_inputs,
            order_outputs=False,
        )
    )

    elapsed = time.time() - start
    print(f"\nAll jobs complete in {elapsed:.1f}s")

    # Write JSONL output
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    print(f"Results written to {out_path}")

    # Print summary
    _print_summary(results, elapsed)


def _print_summary(results: list[dict], elapsed: float) -> None:
    """Print a summary table of batch results."""
    total = len(results)
    errors = sum(1 for r in results if r.get("status") == "error")
    ok = total - errors

    verdicts: dict[str, int] = {
        "malicious": 0,
        "benign": 0,
        "uncertain": 0,
        "no_judge": 0,
    }
    for r in results:
        if r.get("status") != "ok":
            continue
        jr = r.get("judge")
        if jr:
            v = jr.get("final_verdict", "uncertain")
            verdicts[v] = verdicts.get(v, 0) + 1
        else:
            verdicts["no_judge"] += 1

    print()
    print("=" * 50)
    print("BATCH SUMMARY")
    print("=" * 50)
    print(f"  Total:     {total}")
    print(f"  OK:        {ok}")
    print(f"  Errors:    {errors}")
    print(f"  Elapsed:   {elapsed:.1f}s")
    if total:
        print(f"  Avg/skill: {elapsed / total:.1f}s")
    print()
    print("  Judge verdicts:")
    print(f"    Malicious:  {verdicts['malicious']}")
    print(f"    Benign:     {verdicts['benign']}")
    print(f"    Uncertain:  {verdicts['uncertain']}")
    print(f"    No judge:   {verdicts['no_judge']}")
    print("=" * 50)

    # Flag malicious skills
    malicious = [
        r["skill_path"] for r in results
        if r.get("judge", {}) and r.get("judge", {}).get("final_verdict") == "malicious"
    ]
    if malicious:
        print(f"\nMALICIOUS SKILLS ({len(malicious)}):")
        for path in sorted(malicious):
            print(f"  {path}")

    # Flag errors
    error_skills = [r for r in results if r.get("status") == "error"]
    if error_skills:
        print(f"\nERRORS ({len(error_skills)}):")
        for r in error_skills:
            print(f"  {r.get('skill_name', '?')}: {r.get('error', '?')[:80]}")
