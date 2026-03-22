# skillscan-trace Scripts

Batch processing and corpus integration scripts.

## Prerequisites

```bash
pip install modal
modal setup   # authenticate with Modal
```

Create a Modal secret named `skillscan-api-keys` with your API keys:

```bash
modal secret create skillscan-api-keys \
  OPENAI_API_KEY=sk-... \
  ANTHROPIC_API_KEY=sk-ant-...
```

## modal_trace_batch.py

Runs skillscan-trace against a corpus directory on Modal. Uses Ollama
(`qwen2.5:7b`) as the execution model inside each container, with GPT-4.1
and Claude Sonnet as judges.

### Usage

```bash
# Dry run — verify setup, no LLM calls
modal run scripts/modal_trace_batch.py \
  --corpus-dir ./corpus/agent_hijacker \
  --dry-run

# Full run with judge on malicious corpus
modal run scripts/modal_trace_batch.py \
  --corpus-dir ./corpus/agent_hijacker \
  --judge \
  --output-file ./results/agent_hijacker.jsonl

# Full run on all corpus categories (recursive)
modal run scripts/modal_trace_batch.py \
  --corpus-dir ./corpus \
  --judge \
  --recursive \
  --output-file ./results/full_corpus.jsonl

# Run on benign corpus (for false-positive measurement)
modal run scripts/modal_trace_batch.py \
  --corpus-dir ./corpus/benign \
  --judge \
  --output-file ./results/benign.jsonl
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--corpus-dir` | `./corpus/agent_hijacker` | Directory of skill .md files |
| `--output-file` | `./trace-results.jsonl` | Local JSONL output path |
| `--variants` | `1` | User messages per skill |
| `--judge` | `False` | Run dual-LLM judge |
| `--dry-run` | `False` | No LLM calls |
| `--recursive` | `False` | Recurse into subdirectories |
| `--max-parallel` | `20` | Max concurrent containers |

### Cost estimate

| Component | Cost/skill | 84 skills |
|-----------|-----------|-----------|
| Modal CPU (3 min) | ~$0.036 | ~$3.00 |
| GPT-4.1 judge | ~$0.005 | ~$0.42 |
| Claude Sonnet judge | ~$0.005 | ~$0.42 |
| GPT-4.1-mini input gen | ~$0.001 | ~$0.08 |
| **Total** | **~$0.047** | **~$4.00** |

First run adds ~$0.50 for model download (one-time, cached in Modal Volume).

### Output format (JSONL)

Each line is a JSON object with the full `TraceReport.to_dict()` output plus:

```json
{
  "skill_path": "/path/to/skill.md",
  "skill_name": "ah01_goal_substitution_calendar",
  "run_id": "20260321_142300",
  "status": "ok",
  "model": "qwen2.5:7b",
  "total_tool_calls": 0,
  "total_findings": 0,
  "judge": {
    "final_verdict": "malicious",
    "agreement": "full_agreement",
    "needs_human_review": false,
    "judge_a": {"verdict": "malicious", "confidence": 0.95, "reasoning": "..."},
    "judge_b": {"verdict": "malicious", "confidence": 0.95, "reasoning": "..."}
  }
}
```

---

## import_to_corpus.py

Reads a JSONL file from `modal_trace_batch.py` and imports confirmed malicious
skills into `skillscan-corpus`.

### Usage

```bash
# Dry run — show what would be imported
python scripts/import_to_corpus.py \
  --results ./results/agent_hijacker.jsonl \
  --corpus-dir /path/to/skillscan-corpus \
  --source-dir /path/to/skillscan-security/corpus \
  --dry-run

# Import confirmed malicious skills
python scripts/import_to_corpus.py \
  --results ./results/agent_hijacker.jsonl \
  --corpus-dir /path/to/skillscan-corpus \
  --source-dir /path/to/skillscan-security/corpus
```

### Filtering rules

| Verdict | Agreement | Action |
|---------|-----------|--------|
| malicious | full_agreement | Import |
| malicious | partial_agreement | Import |
| malicious | disagreement | Skip (needs human review) |
| uncertain | any | Skip |
| benign | any | Skip |
| error | — | Log and skip |

### Output in skillscan-corpus

```
sandbox_verified/
  trace_20260321_142300/
    ah01_goal_substitution_calendar.md        ← skill file copy
    ah01_goal_substitution_calendar.trace.json ← full trace report
docs/trace_runs/
  20260321_142300_summary.md                  ← human-readable summary
manifest.json                                 ← updated with new entries
```

---

## Full workflow

```bash
# 1. Run traces on Modal
modal run scripts/modal_trace_batch.py \
  --corpus-dir ./corpus/agent_hijacker \
  --judge \
  --output-file ./results/run1.jsonl

# 2. Import confirmed malicious skills into corpus
python scripts/import_to_corpus.py \
  --results ./results/run1.jsonl \
  --corpus-dir ~/skillscan-corpus \
  --source-dir ./corpus

# 3. Commit new corpus entries
cd ~/skillscan-corpus
git add sandbox_verified/ docs/ manifest.json
git commit -m "feat: add trace-verified malicious skills from run 20260321_142300"
git push

# 4. Trigger model retraining (if corpus size threshold crossed)
# See ROADMAP.md M16 for retraining pipeline
```
