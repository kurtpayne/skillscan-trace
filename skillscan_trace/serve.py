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

def _cache_key(skill_content: str, model: str) -> str:
    return hashlib.sha256(f"{skill_content}::{model}".encode()).hexdigest()


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


# ── Worker ─────────────────────────────────────────────────────────────────────

def _run_job(job: Job, cache_dir: Path) -> None:
    """Execute a trace job in a background thread."""
    job.status = JobStatus.RUNNING
    params = job.params

    try:
        import tempfile
        from skillscan_trace.harness import run_trace
        from skillscan_trace.formatters import format_json

        skill_content: str = str(params["skill_content"])
        model: str = str(params.get("model", "gpt-4.1-mini"))
        provider: str = str(params.get("provider", "openai"))
        api_key: str | None = params.get("api_key")
        base_url: str | None = params.get("base_url")
        max_turns: int = int(params.get("max_turns", 10))

        # Check cache first
        cache_key = _cache_key(skill_content, model)
        cached = _read_cache(cache_dir, cache_key)
        if cached:
            job.result = {**cached, "cached": True, "job_id": job.job_id}
            job.status = JobStatus.DONE
            job.finished_at = time.time()
            return

        # Resolve provider
        from skillscan_trace.cli import PROVIDER_CONFIGS
        cfg = PROVIDER_CONFIGS.get(provider, PROVIDER_CONFIGS["openai"])
        resolved_base_url: str = base_url or str(cfg["base_url"])
        if not api_key and cfg.get("env_key"):
            api_key = os.environ.get(str(cfg["env_key"])) or os.environ.get("OPENAI_API_KEY")

        # Write skill to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, prefix="skillscan_"
        ) as f:
            f.write(skill_content)
            skill_path = f.name

        try:
            report = run_trace(
                skill_path,
                model=model,
                api_key=api_key,
                base_url=resolved_base_url,
                max_turns=max_turns,
            )
            result_dict = json.loads(format_json(report))
        finally:
            Path(skill_path).unlink(missing_ok=True)

        # Cache the result (without the api_key)
        _write_cache(cache_dir, cache_key, result_dict)

        job.result = {**result_dict, "cached": False, "job_id": job.job_id}
        job.status = JobStatus.DONE
        job.finished_at = time.time()

    except Exception as e:
        logger.exception("Job %s failed", job.job_id)
        job.error = str(e)
        job.status = JobStatus.ERROR
        job.finished_at = time.time()


# ── FastAPI app factory ────────────────────────────────────────────────────────

def create_app(
    cache_dir: Path = Path("./trace-cache"),
    max_workers: int = 4,
    rate_limit_per_hour: int = 10,
) -> Any:
    """Create and return the FastAPI application."""
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import JSONResponse
        from pydantic import BaseModel, Field
    except ImportError as e:
        raise ImportError(
            "serve mode requires fastapi and pydantic. "
            "Install with: pip install skillscan-trace[serve]"
        ) from e

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

    class SubmitRequest(BaseModel):
        skill_content: str = Field(..., description="Raw SKILL.md content to trace")
        source_url: str | None = Field(
            None,
            description=(
                "Public GitHub raw URL of the skill. If provided, the server "
                "fetches and verifies the content matches (OSS verification)."
            ),
        )
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

        # OSS verification: if source_url provided, fetch and verify content matches
        if req.source_url:
            try:
                import requests as req_lib
                resp = req_lib.get(req.source_url, timeout=10)
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
