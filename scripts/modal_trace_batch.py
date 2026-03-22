"""
modal_trace_batch.py — Run skillscan-trace against a corpus directory on Modal.

Architecture:
  - Static-first triage: run `skillscan scan --ml --format json` locally first.
    Skip the trace if the skill is clearly clean (score <20, semantic <0.25,
    ML prob <0.30, zero findings). Only uncertain and flagged skills are traced.
  - One Modal container per skill (parallelism = up to 50 concurrent)
  - GPT-4.1-mini as the execution model (fast, cheap, reliable tool-use)
  - GPT-4.1 + Claude Sonnet as the dual judge
  - Results written locally as JSONL

Triage thresholds (--triage flag):
  Skip trace if ALL of the following are true:
    - skillscan score < 20  (well below warn threshold of 50)
    - semantic_injection_score < 0.25
    - social_engineering_score < 0.25
    - ml_injection_probability < 0.30 (or --ml not enabled)
    - zero findings

  Force trace if ANY of the following are true:
    - score >= 20
    - semantic_injection_score >= 0.25
    - social_engineering_score >= 0.25
    - ml_injection_probability >= 0.30
    - any findings (regardless of verdict)

Execution model choice:
  - GPT-4.1-mini: fast (~5s/skill), reliable tool-use, ~$0.002/skill
  - Ollama (future): swap base_url to localhost:11434 in a GPU container for
    a more realistic "dumb model" baseline. See scripts/modal_trace_ollama.py.

Cost estimate (GPT-4.1-mini execution + GPT-4.1 + Claude Sonnet judge):
  Execution (GPT-4.1-mini): ~$0.002/skill
  Judge (GPT-4.1 + Claude Sonnet): ~$0.01/skill
  With triage (typical 40% skip rate on benign corpus): ~$0.68 per 100 skills
  Without triage: ~$1.20 per 100 skills

Usage:
  # Dry run (no LLM calls, verify setup)
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --dry-run

  # Full run with judge and static-first triage
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --judge --triage

  # Full run without triage (trace everything)
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --judge

  # Run against all corpus categories
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/ --judge --triage --recursive

  # Fuzzer output (all malicious, no triage needed)
  modal run scripts/modal_trace_batch.py --corpus-dir ./fuzzer-output/ --judge --no-triage
"""

from __future__ import annotations

import json
import os
import subprocess
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

# Triage thresholds — skip trace if ALL signals are below these values
TRIAGE_SCORE_THRESHOLD = 20
TRIAGE_SEMANTIC_THRESHOLD = 0.25
TRIAGE_SE_THRESHOLD = 0.25
TRIAGE_ML_THRESHOLD = 0.30


# ---------------------------------------------------------------------------
# Static-first triage (runs locally, before Modal dispatch)
# ---------------------------------------------------------------------------

def _run_static_scan(skill_path: str, enable_ml: bool = True) -> dict | None:
    """
    Run `skillscan scan --format json` on a skill file and return the parsed report.

    Returns None if skillscan is not installed or the scan fails.
    """
    cmd = ["skillscan", "scan", "--format", "json"]
    if enable_ml:
        cmd.append("--ml")
    cmd.append(skill_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode in (0, 1, 2):  # 0=pass, 1=warn, 2=block
            return json.loads(result.stdout)
        return None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def _should_skip_trace(scan_report: dict | None) -> tuple[bool, str]:
    """
    Apply triage logic to a static scan report.

    Returns (skip, reason) where skip=True means the trace should be skipped.
    The reason string explains the decision for logging.
    """
    if scan_report is None:
        # Can't triage without a scan — trace it to be safe
        return False, "no_scan_result"

    score = scan_report.get("score", 0)
    findings = scan_report.get("findings", [])
    triage = scan_report.get("triage_metadata", {})

    sem_inj = triage.get("semantic_injection_score", 0.0)
    se_score = triage.get("social_engineering_score", 0.0)
    ml_prob = triage.get("ml_injection_probability")  # None if --ml not run

    # Any findings → must trace
    if findings:
        return False, f"has_findings({len(findings)})"

    # Score above threshold → must trace
    if score >= TRIAGE_SCORE_THRESHOLD:
        return False, f"score={score}"

    # Semantic signal above threshold → must trace
    if sem_inj >= TRIAGE_SEMANTIC_THRESHOLD:
        return False, f"semantic_injection={sem_inj:.3f}"

    if se_score >= TRIAGE_SE_THRESHOLD:
        return False, f"social_engineering={se_score:.3f}"

    # ML signal above threshold → must trace
    if ml_prob is not None and ml_prob >= TRIAGE_ML_THRESHOLD:
        return False, f"ml_prob={ml_prob:.3f}"

    # All signals below threshold — safe to skip
    return True, (
        f"score={score},sem={sem_inj:.3f},se={se_score:.3f},"
        f"ml={ml_prob:.3f if ml_prob is not None else 'N/A'}"
    )


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
# Local entrypoint: collect skills, triage, dispatch, collect results
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
    triage: bool = False,
    triage_ml: bool = True,
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
        triage:          Run static scan first; skip trace for clearly clean skills
        triage_ml:       Enable --ml flag during triage scan (default: True)
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
    print(f"Skills found: {len(skill_files)}")
    print(f"Execution model: {EXECUTION_MODEL}")
    print(f"Variants: {variants}")
    print(f"Judge: {judge}")
    print(f"Dry run: {dry_run}")
    print(f"Triage: {triage}")
    if triage:
        print(f"  Triage thresholds: score<{TRIAGE_SCORE_THRESHOLD}, "
              f"semantic<{TRIAGE_SEMANTIC_THRESHOLD}, "
              f"se<{TRIAGE_SE_THRESHOLD}, "
              f"ml<{TRIAGE_ML_THRESHOLD}")
    print(f"Max parallel: {max_parallel}")
    print()

    # ---------------------------------------------------------------------------
    # Static-first triage (local, before Modal dispatch)
    # ---------------------------------------------------------------------------
    skill_inputs = []
    skipped_skills = []

    for sf in skill_files:
        try:
            content = sf.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Warning: could not read {sf}: {e}")
            continue

        if triage and not dry_run:
            scan_report = _run_static_scan(str(sf), enable_ml=triage_ml)
            skip, reason = _should_skip_trace(scan_report)
            if skip:
                skipped_skills.append({
                    "skill_path": str(sf),
                    "skill_name": sf.stem,
                    "status": "skipped_by_triage",
                    "triage_reason": reason,
                    "run_id": run_id,
                })
                continue
            else:
                print(f"  Triage: TRACE {sf.name} ({reason})")

        skill_inputs.append({
            "skill_content": content,
            "skill_path": str(sf),
            "skill_name": sf.stem,
            "run_id": run_id,
            "variants": variants,
            "judge": judge,
            "dry_run": dry_run,
        })

    if triage and skipped_skills:
        print(f"\nTriage: skipped {len(skipped_skills)} clean skills "
              f"({len(skipped_skills) / len(skill_files) * 100:.0f}% skip rate)")

    if not skill_inputs:
        print("No skills to trace after triage. All skills passed static analysis.")
        # Still write the skipped records to the output file
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            for r in skipped_skills:
                f.write(json.dumps(r) + "\n")
        print(f"Skipped records written to {out_path}")
        return

    print(f"\nDispatching {len(skill_inputs)} trace jobs...")
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

    # Merge triage-skipped records into results
    all_results = results + skipped_skills

    # Write JSONL output
    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for r in all_results:
            f.write(json.dumps(r) + "\n")

    print(f"Results written to {out_path}")

    # Print summary
    _print_summary(results, elapsed, skipped=len(skipped_skills))


def _print_summary(results: list[dict], elapsed: float, skipped: int = 0) -> None:
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
    print("=" * 55)
    print("BATCH SUMMARY")
    print("=" * 55)
    print(f"  Total found:    {total + skipped}")
    print(f"  Triage skipped: {skipped}")
    print(f"  Traced:         {total}")
    print(f"  OK:             {ok}")
    print(f"  Errors:         {errors}")
    print(f"  Elapsed:        {elapsed:.1f}s")
    if total:
        print(f"  Avg/skill:      {elapsed / total:.1f}s")
    if skipped:
        skip_pct = skipped / (total + skipped) * 100
        print(f"  Skip rate:      {skip_pct:.0f}%")
    print()
    print("  Judge verdicts:")
    print(f"    Malicious:  {verdicts['malicious']}")
    print(f"    Benign:     {verdicts['benign']}")
    print(f"    Uncertain:  {verdicts['uncertain']}")
    print(f"    No judge:   {verdicts['no_judge']}")
    print("=" * 55)

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
