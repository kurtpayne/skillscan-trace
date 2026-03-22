"""
modal_trace_batch.py — Run skillscan-trace against a corpus directory on Modal.

Architecture:
  - One Modal container per skill (parallelism = up to 50 concurrent)
  - Ollama (qwen2.5:7b) runs as a subprocess inside each container
  - Model weights cached on a Modal Volume (downloaded once, reused)
  - GPT-4.1 + Claude Sonnet judge runs from the container (cloud API calls)
  - Results written to a Modal Volume as JSONL, then downloaded locally

Usage:
  # Dry run (no LLM calls, verify setup)
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --dry-run

  # Full run with judge
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/agent_hijacker --judge

  # Run against all corpus categories
  modal run scripts/modal_trace_batch.py --corpus-dir ./corpus/ --judge --recursive

  # Download results after run
  modal run scripts/modal_trace_batch.py --download-results

Cost estimate (CPU, no GPU):
  qwen2.5:7b on Modal CPU (2 vCPU, 4 GB): ~3 min/skill
  Modal CPU cost: ~$0.0002/sec → ~$0.036/skill
  84 skills (30 malicious + 54 benign): ~$3.00 total
  Judge (GPT-4.1 + Claude Sonnet): ~$0.01/skill → ~$0.84 total
  Total: ~$4/run
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

# Persistent volume for Ollama model weights (~4.7 GB for qwen2.5:7b)
# First run downloads the model; subsequent runs skip download (~30s cold start)
ollama_volume = modal.Volume.from_name("skillscan-ollama-models", create_if_missing=True)

# Results volume — JSONL output from each run
results_volume = modal.Volume.from_name("skillscan-trace-results", create_if_missing=True)

# Container image with all dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl", "wget", "ca-certificates")
    # Install Ollama
    .run_commands(
        "curl -fsSL https://ollama.com/install.sh | sh",
        gpu=None,
    )
    # Install Python deps
    .pip_install(
        "openai>=1.30.0",
        "anthropic>=0.25.0",
        "pyyaml>=6.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    )
    # Install skillscan-trace from the repo
    .copy_local_dir(
        local_path=".",
        remote_path="/app/skillscan-trace",
    )
    .run_commands("pip install -e /app/skillscan-trace")
)

OLLAMA_MODEL = "qwen2.5:7b"
OLLAMA_VOLUME_PATH = "/ollama-models"
RESULTS_VOLUME_PATH = "/results"


# ---------------------------------------------------------------------------
# Helper: start Ollama inside the container
# ---------------------------------------------------------------------------

def _start_ollama() -> subprocess.Popen:
    """Start the Ollama server as a background subprocess."""
    env = os.environ.copy()
    env["OLLAMA_MODELS"] = OLLAMA_VOLUME_PATH

    proc = subprocess.Popen(
        ["ollama", "serve"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait for Ollama to be ready
    import urllib.request
    for attempt in range(30):
        try:
            urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
            return proc
        except Exception:
            time.sleep(1)

    raise RuntimeError("Ollama failed to start after 30 seconds")


def _ensure_model_pulled() -> None:
    """Pull the model if not already cached in the volume."""
    import urllib.request
    import json as _json

    resp = urllib.request.urlopen("http://localhost:11434/api/tags")
    tags = _json.loads(resp.read())
    model_names = [m["name"] for m in tags.get("models", [])]

    if not any(OLLAMA_MODEL in name for name in model_names):
        print(f"Pulling {OLLAMA_MODEL} (first run, ~4.7 GB)...")
        result = subprocess.run(
            ["ollama", "pull", OLLAMA_MODEL],
            env={**os.environ, "OLLAMA_MODELS": OLLAMA_VOLUME_PATH},
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to pull {OLLAMA_MODEL}: {result.stderr}")
        # Commit the volume so the model persists
        ollama_volume.commit()
        print(f"Model pulled and cached.")
    else:
        print(f"Model {OLLAMA_MODEL} already cached.")


# ---------------------------------------------------------------------------
# Modal function: trace a single skill
# ---------------------------------------------------------------------------

@app.function(
    image=image,
    volumes={
        OLLAMA_VOLUME_PATH: ollama_volume,
        RESULTS_VOLUME_PATH: results_volume,
    },
    cpu=2.0,
    memory=4096,
    timeout=600,  # 10 min max per skill
    secrets=[
        modal.Secret.from_name("skillscan-api-keys"),
    ],
    retries=1,
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
    Trace a single skill inside a Modal container.

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

    ollama_proc = None

    try:
        if dry_run:
            return {
                "skill_path": skill_path,
                "skill_name": skill_name,
                "run_id": run_id,
                "dry_run": True,
                "status": "ok",
            }

        # Start Ollama
        ollama_proc = _start_ollama()
        _ensure_model_pulled()

        # Run trace using Ollama as the execution model
        report = run_trace(
            skill_path=tmp_path,
            model=OLLAMA_MODEL,
            api_key="ollama",
            base_url="http://localhost:11434/v1",
            input_count=variants,
            input_model="gpt-4.1-mini",  # GPT for input generation (fast + cheap)
            max_turns=8,
            judge=judge,
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
        )

        result = report.to_dict()
        result["skill_path"] = skill_path  # use original path, not tmp
        result["run_id"] = run_id
        result["status"] = "ok"

        return result

    except Exception as e:
        return {
            "skill_path": skill_path,
            "skill_name": skill_name,
            "run_id": run_id,
            "status": "error",
            "error": str(e),
        }
    finally:
        if ollama_proc:
            ollama_proc.terminate()
        Path(tmp_path).unlink(missing_ok=True)


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
    max_parallel: int = 20,
    download_results: bool = False,
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
        download_results: Download results from the Modal volume instead of running
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

    # Dispatch in parallel batches
    results = []
    batch_size = max_parallel
    for i in range(0, len(skill_inputs), batch_size):
        batch = skill_inputs[i:i + batch_size]
        print(f"  Batch {i // batch_size + 1}: {len(batch)} skills...")
        batch_results = list(
            trace_skill.starmap(
                [(s["skill_content"], s["skill_path"], s["skill_name"],
                  s["run_id"], s["variants"], s["judge"], s["dry_run"])
                 for s in batch]
            )
        )
        results.extend(batch_results)

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

    verdicts = {
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
    print(f"  Avg/skill: {elapsed / total:.1f}s" if total else "")
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
        if r.get("judge", {}).get("final_verdict") == "malicious"
    ]
    if malicious:
        print(f"\nMALICIOUS SKILLS ({len(malicious)}):")
        for path in malicious:
            print(f"  {path}")
