"""
Serve mode for skillscan-trace.

Starts a lightweight HTTP API server that accepts trace job submissions,
runs them in a background thread pool, and returns results via polling.

Endpoints:
  POST /v1/submit       Submit a trace job (BYOK — caller provides api_key)
  GET  /v1/report/{id}  Poll for results (returns 202 while pending, 200 when done)
  GET  /v1/health       Health check

Designed for:
  - Self-hosted deployments: docker run skillscan/trace serve
  - Fly.io hosted service: same image, serve mode, Fly handles scaling
  - Local testing: skillscan-trace serve --port 8080

Privacy model:
  - api_key is accepted in the request body, used for the duration of the job,
    and discarded immediately. It is never logged or stored.
  - Skill content is stored in memory only for the duration of the job.
  - Reports are stored in cache_dir (default: ./trace-cache) keyed by
    sha256(skill_content + model). Identical skill+model combos return
    the cached report without re-running.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Job state ──────────────────────────────────────────────────────────────────


class JobStatus:
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


class Job:
    def __init__(self, job_id: str, params: dict[str, Any]) -> None:
        self.job_id = job_id
        self.params = params
        self.status = JobStatus.PENDING
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self.created_at = time.time()
        self.finished_at: float | None = None


# ── In-memory job store (suitable for single-instance deployments) ─────────────

_jobs: dict[str, Job] = {}
_jobs_lock = threading.Lock()


def _get_job(job_id: str) -> Job | None:
    with _jobs_lock:
        return _jobs.get(job_id)


def _put_job(job: Job) -> None:
    with _jobs_lock:
        _jobs[job.job_id] = job


# ── Cache ──────────────────────────────────────────────────────────────────────


def _cache_key(skill_content: str, model: str, **kwargs: Any) -> str:
    """Cache key based on ALL inputs that affect the result."""
    parts = [skill_content.strip(), model]
    # Include options that change the output
    for k in sorted(kwargs):
        v = kwargs[k]
        if v is not None and v != [] and v != "":
            parts.append(f"{k}={v}")
    return hashlib.sha256("::".join(str(p) for p in parts).encode()).hexdigest()


def _read_cache(cache_dir: Path, key: str) -> dict[str, Any] | None:
    path = cache_dir / f"{key}.json"
    if path.exists():
        try:
            data: dict[str, Any] = json.loads(path.read_text())
            return data
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _write_cache(cache_dir: Path, key: str, result: dict[str, Any]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{key}.json"
    try:
        path.write_text(json.dumps(result, indent=2))
    except OSError as e:
        logger.warning("Failed to write cache: %s", e)


# ── Integrated scan + lint ─────────────────────────────────────────────────────


def _render_html_report(result: dict[str, Any]) -> str:
    """Render a self-contained HTML page from a trace report dict."""
    import html as html_mod

    def esc(val: object) -> str:
        return html_mod.escape(str(val)) if val is not None else ""

    skill_name = esc(result.get("skill_name") or result.get("skill_path", "unknown"))
    model = esc(result.get("model", ""))
    verdict = result.get("verdict") or result.get("judge_verdict") or "none"
    verdict_esc = esc(verdict)
    report_url = esc(result.get("report_url", ""))

    # Verdict badge colors (oklch palette)
    verdict_lower = verdict.lower()
    if "malicious" in verdict_lower or "block" in verdict_lower:
        badge_bg = "oklch(0.45 0.22 25)"
        badge_fg = "oklch(0.95 0.03 25)"
    elif "benign" in verdict_lower or "pass" in verdict_lower:
        badge_bg = "oklch(0.45 0.18 155)"
        badge_fg = "oklch(0.95 0.03 155)"
    else:
        badge_bg = "oklch(0.40 0.12 60)"
        badge_fg = "oklch(0.95 0.03 60)"

    # Stats
    total_calls = result.get("total_tool_calls", 0)
    total_findings = len(result.get("findings", []))
    duration = result.get("duration_seconds") or result.get("elapsed_seconds", "")
    started = result.get("started_at", "")
    finished = result.get("finished_at", "")

    # Findings list
    findings_html = ""
    for f in result.get("findings", []):
        rule_id = esc(f.get("rule_id", ""))
        sev = esc(f.get("severity", ""))
        msg = esc(f.get("message", ""))
        source = esc(f.get("source", ""))
        source_tag = f' <span class="tag">{source}</span>' if source else ""
        findings_html += (
            f'<div class="finding">'
            f'<span class="rule-id">{rule_id}</span>'
            f'<span class="severity {sev.lower()}">{sev}</span>'
            f"{source_tag}"
            f'<p class="msg">{msg}</p>'
            f"</div>\n"
        )
    if not findings_html:
        findings_html = '<p class="muted">No findings.</p>'

    # Event timeline
    events_html = ""
    for ev in result.get("events", []):
        turn = esc(ev.get("turn", ""))
        tool = esc(ev.get("tool", ""))
        args_raw = ev.get("arguments", {})
        args_str = esc(json.dumps(args_raw, ensure_ascii=False)[:300]) if args_raw else ""
        events_html += (
            f'<tr><td>{turn}</td><td class="tool-name">{tool}</td>'
            f"<td><code>{args_str}</code></td></tr>\n"
        )
    if not events_html:
        events_html = '<tr><td colspan="3" class="muted">No events recorded.</td></tr>'

    # Provenance
    prov = result.get("provenance", {})
    prov_html = ""
    for k, v in prov.items():
        prov_html += f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>\n"
    if not prov_html:
        prov_html = '<tr><td colspan="2" class="muted">No provenance data.</td></tr>'

    # Static findings
    static_section = ""
    static_findings = result.get("static_findings", [])
    if static_findings:
        static_items = ""
        for sf in static_findings:
            static_items += (
                f'<div class="finding">'
                f'<span class="rule-id">{esc(sf.get("rule_id", ""))}</span>'
                f'<span class="severity {esc(sf.get("severity", "")).lower()}">'
                f"{esc(sf.get('severity', ''))}</span>"
                f'<p class="msg">{esc(sf.get("message", ""))}</p>'
                f"</div>\n"
            )
        static_section = f"<section><h2>Static Scan Findings</h2>{static_items}</section>"

    # Lint findings
    lint_section = ""
    lint_findings = result.get("lint_findings", [])
    if lint_findings:
        lint_items = ""
        for lf in lint_findings:
            lint_items += (
                f'<div class="finding">'
                f'<span class="rule-id">{esc(lf.get("rule_id", ""))}</span>'
                f'<p class="msg">{esc(lf.get("message", ""))}</p>'
                f"</div>\n"
            )
        lint_section = f"<section><h2>Lint Findings</h2>{lint_items}</section>"

    # JSON link
    json_link = ""
    if report_url:
        json_url = report_url if report_url.endswith(".json") else report_url + ".json"
        json_link = f'<a href="{esc(json_url)}" class="json-link">View JSON report</a>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SkillScan Trace Report — {skill_name}</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
body{{
  margin:0;padding:2rem;
  background:oklch(0.07 0.018 265);
  color:oklch(0.85 0.02 265);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  line-height:1.6;
}}
h1,h2{{color:oklch(0.78 0.18 290);margin-top:2rem}}
h1{{font-size:1.5rem;margin-top:0}}
h2{{font-size:1.15rem;border-bottom:1px solid oklch(0.25 0.02 265);padding-bottom:0.3rem}}
a{{color:oklch(0.78 0.18 290)}}
.container{{max-width:900px;margin:0 auto}}
.header{{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}}
.badge{{
  display:inline-block;padding:0.25rem 0.75rem;border-radius:4px;
  font-weight:700;font-size:0.9rem;text-transform:uppercase;
  background:{badge_bg};color:{badge_fg};
}}
.stats{{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
  gap:0.75rem;margin:1rem 0;
}}
.stat{{
  background:oklch(0.12 0.015 265);border-radius:6px;padding:0.75rem 1rem;
}}
.stat .label{{font-size:0.75rem;text-transform:uppercase;color:oklch(0.55 0.02 265)}}
.stat .value{{font-size:1.1rem;font-weight:600}}
.finding{{
  background:oklch(0.12 0.015 265);border-radius:6px;
  padding:0.75rem 1rem;margin:0.5rem 0;
}}
.rule-id{{font-weight:700;margin-right:0.5rem;color:oklch(0.78 0.18 290)}}
.severity{{
  font-size:0.75rem;text-transform:uppercase;font-weight:600;
  padding:0.1rem 0.4rem;border-radius:3px;
}}
.severity.high,.severity.critical{{background:oklch(0.40 0.18 25);color:oklch(0.95 0.03 25)}}
.severity.medium{{background:oklch(0.40 0.14 60);color:oklch(0.95 0.03 60)}}
.severity.low,.severity.info{{background:oklch(0.35 0.10 265);color:oklch(0.85 0.02 265)}}
.tag{{font-size:0.7rem;background:oklch(0.25 0.04 265);padding:0.1rem 0.4rem;border-radius:3px}}
.msg{{margin:0.3rem 0 0;font-size:0.9rem}}
table{{width:100%;border-collapse:collapse;margin:0.5rem 0;font-size:0.85rem}}
th{{text-align:left;color:oklch(0.55 0.02 265);font-weight:600;
    border-bottom:1px solid oklch(0.25 0.02 265);padding:0.4rem 0.5rem}}
td{{padding:0.4rem 0.5rem;border-bottom:1px solid oklch(0.15 0.01 265)}}
code{{
  font-family:"SF Mono",Monaco,Consolas,monospace;font-size:0.8rem;
  word-break:break-all;color:oklch(0.75 0.06 200);
}}
.tool-name{{font-weight:600;color:oklch(0.78 0.18 290)}}
.muted{{color:oklch(0.45 0.02 265);font-style:italic}}
.json-link{{
  display:inline-block;margin-top:1.5rem;padding:0.4rem 1rem;
  border:1px solid oklch(0.78 0.18 290);border-radius:4px;
  text-decoration:none;font-size:0.85rem;
}}
.json-link:hover{{background:oklch(0.15 0.03 290)}}
.footer{{margin-top:2rem;font-size:0.75rem;color:oklch(0.40 0.02 265)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>SkillScan Trace Report</h1>
    <span class="badge">{verdict_esc}</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="label">Skill</div><div class="value">{skill_name}</div></div>
    <div class="stat"><div class="label">Model</div><div class="value">{model}</div></div>
    <div class="stat"><div class="label">Tool Calls</div><div class="value">{total_calls}</div></div>
    <div class="stat"><div class="label">Findings</div><div class="value">{total_findings}</div></div>
    <div class="stat"><div class="label">Duration</div><div class="value">{esc(duration)}</div></div>
    <div class="stat"><div class="label">Started</div><div class="value">{esc(started)}</div></div>
    <div class="stat"><div class="label">Finished</div><div class="value">{esc(finished)}</div></div>
  </div>

  <section>
    <h2>Behavioral Findings</h2>
    {findings_html}
  </section>

  {static_section}
  {lint_section}

  <section>
    <h2>Event Timeline</h2>
    <table>
      <thead><tr><th>Turn</th><th>Tool</th><th>Arguments</th></tr></thead>
      <tbody>{events_html}</tbody>
    </table>
  </section>

  <section>
    <h2>Provenance</h2>
    <table>
      <thead><tr><th>Key</th><th>Value</th></tr></thead>
      <tbody>{prov_html}</tbody>
    </table>
  </section>

  {json_link}
  <div class="footer">Generated by skillscan-trace</div>
</div>
</body>
</html>"""


def _run_static_scan(skill_path: str) -> list[dict[str, Any]]:
    """Run skillscan static scan in audit profile. Returns findings as dicts."""
    try:
        import subprocess

        result = subprocess.run(
            ["skillscan", "scan", skill_path, "--policy-profile", "audit", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "SKILLSCAN_NO_USER_RULES": "1"},
        )
        # skillscan exits 1 on BLOCK — that's fine, we still want the JSON
        output = result.stdout.strip()
        if not output:
            return []
        data = json.loads(output)
        # Extract findings array from scan result
        findings = data.get("findings", [])
        # Tag each finding with source
        for f in findings:
            f["source"] = "static"
        return list(findings)
    except FileNotFoundError:
        logger.debug("skillscan not installed — skipping static scan")
        return []
    except Exception as e:
        logger.warning("Static scan failed: %s", e)
        return []


def _run_lint(skill_path: str) -> list[dict[str, Any]]:
    """Run skillscan-lint. Returns findings as dicts."""
    try:
        import subprocess

        result = subprocess.run(
            ["skillscan-lint", skill_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout.strip()
        if not output:
            return []
        data = json.loads(output)
        findings = data if isinstance(data, list) else data.get("findings", [])
        for f in findings:
            f["source"] = "lint"
        return list(findings)
    except FileNotFoundError:
        logger.debug("skillscan-lint not installed — skipping lint")
        return []
    except Exception as e:
        logger.warning("Lint failed: %s", e)
        return []


# ── Worker ─────────────────────────────────────────────────────────────────────


def _run_job(job: Job, cache_dir: Path) -> None:
    """Execute a trace job in a background thread."""
    job.status = JobStatus.RUNNING
    params = job.params

    try:
        import base64
        import shutil
        import tempfile
        import zipfile
        from skillscan_trace.harness import run_trace
        from skillscan_trace.formatters import format_json

        skill_content: str = str(params.get("skill_content") or "")
        model: str = str(params.get("model", "gpt-4.1-mini"))
        provider: str = str(params.get("provider", "openai"))
        api_key: str | None = params.get("api_key")
        base_url: str | None = params.get("base_url")
        max_turns: int = int(params.get("max_turns", 10))

        # ── ZIP extraction ──────────────────────────────────────────────────
        zip_temp_dir: str | None = None
        if params.get("skill_zip_b64"):
            import io

            _ALLOWED_ZIP_EXTS = {".md", ".txt", ".yaml", ".yml", ".json"}
            _MAX_ZIP_FILES = 50

            zip_bytes = base64.b64decode(params["skill_zip_b64"])
            zip_temp_dir = tempfile.mkdtemp(prefix="skillscan_zip_")
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    members = [m for m in zf.namelist() if not m.endswith("/")]
                    if len(members) > _MAX_ZIP_FILES:
                        raise ValueError(
                            f"ZIP contains {len(members)} files, max is {_MAX_ZIP_FILES}"
                        )
                    for member in members:
                        ext = Path(member).suffix.lower()
                        if ext not in _ALLOWED_ZIP_EXTS:
                            raise ValueError(
                                f"Disallowed file type in ZIP: {member} "
                                f"(allowed: {', '.join(sorted(_ALLOWED_ZIP_EXTS))})"
                            )
                    zf.extractall(zip_temp_dir)

                # Find SKILL.md or first .md file
                extracted = list(Path(zip_temp_dir).rglob("*"))
                extracted_files = [p for p in extracted if p.is_file()]
                skill_md = None
                first_md = None
                for p in extracted_files:
                    if p.name.upper() == "SKILL.MD" and skill_md is None:
                        skill_md = p
                    if p.suffix.lower() == ".md" and first_md is None:
                        first_md = p
                main_file = skill_md or first_md
                if not main_file:
                    raise ValueError("ZIP does not contain any .md files")

                skill_content = main_file.read_text()
                params["skill_content"] = skill_content
            except Exception:
                shutil.rmtree(zip_temp_dir, ignore_errors=True)
                raise

        # Check cache — key includes all options that affect the result
        variants: int = int(params.get("variants", 3))
        run_scan = bool(params.get("include_scan", False))
        run_lint = bool(params.get("include_lint", False))
        user_messages: list[str] | None = params.get("user_messages") or None

        cache_key = _cache_key(
            skill_content,
            model,
            max_turns=max_turns,
            variants=variants,
            include_scan=run_scan,
            include_lint=run_lint,
            user_messages=user_messages,
        )
        cached = _read_cache(cache_dir, cache_key)
        if cached:
            from skillscan_trace.r2 import read_report as _r2_read
            from skillscan_trace.r2 import _REPORT_BASE_URL as _base_url

            r2_cached = _r2_read(cache_key)
            report_url: str | None = (r2_cached or {}).get(
                "report_url", f"{_base_url}/report/{cache_key}"
            )
            job.result = {**cached, "cached": True, "job_id": job.job_id, "report_url": report_url}
            job.status = JobStatus.DONE
            job.finished_at = time.time()
            return

        # Resolve provider
        from skillscan_trace.cli import PROVIDER_CONFIGS

        cfg = PROVIDER_CONFIGS.get(provider, PROVIDER_CONFIGS["openai"])
        resolved_base_url: str = base_url or str(cfg["base_url"])
        if not api_key and cfg.get("env_key"):
            api_key = os.environ.get(str(cfg["env_key"])) or os.environ.get("OPENAI_API_KEY")

        # Write skill to a temp file or temp directory (multi-file / ZIP)
        skill_files: dict[str, str] | None = params.get("skill_files")
        temp_dir: str | None = None
        scan_target: str  # path for static scan / lint (file or directory)

        if zip_temp_dir:
            # ZIP mode: files already extracted to zip_temp_dir
            temp_dir = zip_temp_dir
            skill_path = str(main_file)
            scan_target = zip_temp_dir
        elif skill_files and isinstance(skill_files, dict) and len(skill_files) > 1:
            # Multi-file mode: write all files to a temp directory
            temp_dir = tempfile.mkdtemp(prefix="skillscan_multi_")
            skill_path = ""
            for fname, content in skill_files.items():
                # Sanitize filename: no path traversal
                safe_name = Path(fname).name
                if not safe_name:
                    continue
                fpath = Path(temp_dir) / safe_name
                fpath.write_text(str(content))
                # Use SKILL.md as the main skill file if present, else first .md file
                if not skill_path and safe_name.upper() == "SKILL.MD":
                    skill_path = str(fpath)
            # Fallback: if no SKILL.md, use the first .md file, then first file
            if not skill_path:
                md_files = list(Path(temp_dir).glob("*.md"))
                if md_files:
                    skill_path = str(md_files[0])
                else:
                    all_files = list(Path(temp_dir).iterdir())
                    skill_path = str(all_files[0]) if all_files else ""
            scan_target = temp_dir
        else:
            # Single-file mode (original behavior)
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".md", delete=False, prefix="skillscan_"
            ) as f:
                f.write(skill_content)
                skill_path = f.name
            scan_target = skill_path

        # Author declarations
        allow_domains: list[str] = list(params.get("allow_domains") or [])
        allow_commands: list[str] = list(params.get("allow_commands") or [])

        try:
            report = run_trace(
                skill_path,
                model=model,
                api_key=api_key,
                base_url=resolved_base_url,
                max_turns=max_turns,
                allowed_domains=set(allow_domains) if allow_domains else None,
                user_messages=user_messages,
            )
            result_dict = json.loads(format_json(report))

            # Include author declarations in the result
            if allow_domains:
                result_dict["allow_domains"] = allow_domains
            if allow_commands:
                result_dict["allow_commands"] = allow_commands

            # Run static scan + lint if requested (no API key needed)
            if run_scan:
                result_dict["static_findings"] = _run_static_scan(scan_target)
            if run_lint:
                result_dict["lint_findings"] = _run_lint(scan_target)
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            else:
                Path(skill_path).unlink(missing_ok=True)

        # Add provenance metadata
        result_dict["provenance"] = {
            "server_version": "0.2.0",
            "trace_engine": "skillscan-trace",
            "fly_region": os.environ.get("FLY_REGION", "unknown"),
            "fly_machine_id": os.environ.get("FLY_MACHINE_ID", "unknown"),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "report_sha256": hashlib.sha256(
                json.dumps(result_dict, sort_keys=True).encode()
            ).hexdigest(),
        }

        # Only cache successful traces — errored results (bad model, bad key, etc.)
        # should not be cached so the user can retry with corrected inputs.
        has_error = bool(result_dict.get("error"))
        report_url = None
        if not has_error:
            _write_cache(cache_dir, cache_key, result_dict)
            from skillscan_trace.r2 import write_report as _r2_write
            from skillscan_trace.r2 import write_html_report as _r2_write_html

            report_url = _r2_write(cache_key, result_dict)
            _r2_write_html(cache_key, _render_html_report(result_dict))

        job.result = {
            **result_dict,
            "cached": False,
            "job_id": job.job_id,
            "report_url": report_url,
        }
        job.status = JobStatus.DONE
        job.finished_at = time.time()

    except Exception as e:
        logger.exception("Job %s failed", job.job_id)
        job.error = str(e)
        job.status = JobStatus.ERROR
        job.finished_at = time.time()


# ── Request model (module-level so FastAPI can resolve the schema) ─────────────

try:
    from fastapi import Request
    from pydantic import BaseModel, Field, field_validator

    class SubmitRequest(BaseModel):
        skill_content: str = Field("", description="Raw SKILL.md content to trace")
        skill_zip_b64: str | None = Field(None, description="Base64-encoded ZIP of skill directory")
        source_url: str | None = Field(
            None,
            description=(
                "Public GitHub raw URL of the skill. If provided, the server "
                "fetches and verifies the content matches (OSS verification). "
                "Must be an https:// URL on github.com or raw.githubusercontent.com."
            ),
        )

        @field_validator("source_url")
        @classmethod
        def _validate_source_url(cls, v: str | None) -> str | None:
            if v is None:
                return v
            from urllib.parse import urlparse

            parsed = urlparse(v)
            if parsed.scheme != "https":
                raise ValueError("source_url must use the https:// scheme")
            host = (parsed.hostname or "").lower()
            _allowed = {"raw.githubusercontent.com", "github.com", "gist.githubusercontent.com"}
            if host not in _allowed:
                raise ValueError(
                    f"source_url host '{host}' is not allowed. "
                    "Only raw.githubusercontent.com, github.com, and "
                    "gist.githubusercontent.com are accepted."
                )
            return v

        api_key: str | None = Field(
            None,
            description=(
                "Your LLM API key. Passed directly to the provider, never stored. "
                "If omitted, the server's environment variable is used (if configured)."
            ),
        )
        provider: str = Field("openai", description="openai | openrouter | ollama")
        model: str = Field("gpt-4.1-mini", description="Any OpenAI-compatible model ID")
        input_model: str | None = Field(None, description="Model for generating user messages")
        base_url: str | None = Field(None, description="Custom API base URL")
        variants: int = Field(3, ge=1, le=10, description="Number of user messages to generate")
        max_turns: int = Field(10, ge=1, le=20, description="Max tool-call rounds per message")
        allow_domains: list[str] = Field(default_factory=list)
        allow_commands: list[str] = Field(default_factory=list)
        judge: bool = Field(False, description="Run dual-LLM judge after trace")
        judge_model: str | None = Field(None, description="Model for the judge (e.g. gpt-4.1)")
        include_scan: bool = Field(
            False, description="Run static scan (audit profile, no key needed)"
        )
        include_lint: bool = Field(False, description="Run lint quality check (no key needed)")
        skill_files: dict[str, str] | None = Field(
            None,
            description=(
                "Dict of filename->content for multi-file skills. "
                "When provided, files are written to a temp directory and "
                "processed as a skill directory (enables skill graph analysis)."
            ),
        )
        user_messages: list[str] | None = Field(
            None,
            description=(
                "Manual user messages to send to the model instead of LLM-generated "
                "fuzz inputs. Maximum 10 messages, one per entry."
            ),
        )

except ImportError:
    SubmitRequest = None  # type: ignore[assignment,misc]
    Request = None  # type: ignore[assignment,misc]


# ── FastAPI app factory ────────────────────────────────────────────────────────


def create_app(
    cache_dir: Path = Path("./trace-cache"),
    max_workers: int = 4,
    rate_limit_per_hour: int = 10,
) -> Any:
    """Create and return the FastAPI application."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import JSONResponse
    except ImportError as e:
        raise ImportError(
            "serve mode requires fastapi and pydantic. "
            "Install with: pip install skillscan-trace[serve]"
        ) from e

    if SubmitRequest is None:
        raise ImportError("pydantic is required for serve mode")

    app = FastAPI(
        title="skillscan-trace serve",
        description=(
            "Self-hosted behavioral trace server. "
            "BYOK: your API key is used for this request only and never stored."
        ),
        version="0.1.0",
    )

    executor = ThreadPoolExecutor(max_workers=max_workers)

    # Simple in-memory rate limiter: {ip: [timestamp, ...]}
    _rate_buckets: dict[str, list[float]] = {}
    _rate_lock = threading.Lock()

    def _check_rate_limit(ip: str) -> bool:
        now = time.time()
        window = 3600.0
        with _rate_lock:
            bucket = _rate_buckets.get(ip, [])
            bucket = [t for t in bucket if now - t < window]
            if len(bucket) >= rate_limit_per_hour:
                _rate_buckets[ip] = bucket
                return False
            bucket.append(now)
            _rate_buckets[ip] = bucket
            return True

    _ALLOWED_SOURCE_HOSTS: frozenset[str] = frozenset(
        {"raw.githubusercontent.com", "github.com", "gist.githubusercontent.com"}
    )

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/v1/submit", status_code=202)
    async def submit(req: SubmitRequest, request: Request) -> dict[str, str]:
        client_ip = request.client.host if request.client else "unknown"
        if not _check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {rate_limit_per_hour} scans per hour per IP.",
            )

        # OSS verification: if source_url provided, fetch and verify content matches.
        # source_url is validated by SubmitRequest._validate_source_url to be an
        # https:// URL on an allowed GitHub host, preventing SSRF.
        if req.source_url:
            try:
                import requests as req_lib

                resp = req_lib.get(req.source_url, timeout=10, allow_redirects=False)
                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=422,
                        detail=f"source_url returned HTTP {resp.status_code}. "
                        "Only public GitHub URLs are supported for free scans.",
                    )
                remote_content = resp.text.strip()
                local_content = req.skill_content.strip()
                if remote_content != local_content:
                    raise HTTPException(
                        status_code=422,
                        detail="skill_content does not match the content at source_url. "
                        "Submit the exact content of the public skill file.",
                    )
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=422,
                    detail=f"Could not verify source_url: {e}",
                ) from e

        job_id = str(uuid.uuid4())
        job = Job(job_id=job_id, params=req.model_dump())
        _put_job(job)
        executor.submit(_run_job, job, cache_dir)
        return {"job_id": job_id, "status": "pending"}

    @app.get("/v1/report/{job_id}")
    async def get_report(job_id: str) -> JSONResponse:
        job = _get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
            return JSONResponse(
                status_code=202,
                content={"job_id": job_id, "status": job.status},
            )
        if job.status == JobStatus.ERROR:
            return JSONResponse(
                status_code=500,
                content={"job_id": job_id, "status": "error", "error": job.error},
            )
        return JSONResponse(status_code=200, content=job.result)

    return app


# ── CLI entry point ────────────────────────────────────────────────────────────


def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    workers: int = 4,
    cache_dir: Path = Path("./trace-cache"),
    rate_limit_per_hour: int = 10,
) -> None:
    """Start the trace server (blocking)."""
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "serve mode requires uvicorn. Install with: pip install skillscan-trace[serve]"
        ) from e

    app = create_app(
        cache_dir=cache_dir,
        max_workers=workers,
        rate_limit_per_hour=rate_limit_per_hour,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")
