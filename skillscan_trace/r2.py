"""
R2 report storage for skillscan-trace hosted service.

Writes completed trace reports to Cloudflare R2 (S3-compat API) so they
are accessible at a permanent URL after the Fly Machine finishes.

Activated when the following env vars are set:
  R2_ACCOUNT_ID       — Cloudflare account ID
  R2_BUCKET           — R2 bucket name (default: skillscan-trace-reports)
  R2_ACCESS_KEY_ID    — R2 API token access key
  R2_SECRET_ACCESS_KEY — R2 API token secret

If any variable is missing, all functions are no-ops and return None.
This keeps self-hosted deployments (no R2) working without any config.

Reports expire after 90 days via a bucket lifecycle rule (set once in
CF dashboard or wrangler — not per-object). This module just writes.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_REPORT_BASE_URL = os.environ.get("TRACE_REPORT_BASE_URL", "https://trace.skillscan.sh")


def _client() -> Any | None:
    """Return a boto3 S3 client pointed at R2, or None if not configured."""
    account_id = os.environ.get("R2_ACCOUNT_ID", "")
    access_key = os.environ.get("R2_ACCESS_KEY_ID", "")
    secret_key = os.environ.get("R2_SECRET_ACCESS_KEY", "")
    if not (account_id and access_key and secret_key):
        return None
    try:
        import boto3
        from botocore.config import Config

        return boto3.client(
            "s3",
            endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(signature_version="s3v4"),
            region_name="auto",
        )
    except ImportError:
        logger.warning("boto3 not installed — R2 writes disabled. pip install boto3")
        return None
    except Exception as e:
        logger.warning("R2 client init failed: %s", e)
        return None


def _bucket() -> str:
    return os.environ.get("R2_BUCKET", "skillscan-trace-reports")


def write_report(cache_key: str, result: dict[str, Any]) -> str | None:
    """
    Write a completed report to R2. Returns the public report URL, or None
    if R2 is not configured or the write fails.

    Writes two objects:
      reports/{cache_key}.json       — full report JSON
      reports/{cache_key}_meta.json  — small index record for listings
    """
    client = _client()
    if client is None:
        return None

    bucket = _bucket()
    report_url = f"{_REPORT_BASE_URL}/report/{cache_key}"

    try:
        # Full report
        report_body = json.dumps({**result, "report_url": report_url}, indent=2)
        client.put_object(
            Bucket=bucket,
            Key=f"reports/{cache_key}.json",
            Body=report_body.encode(),
            ContentType="application/json",
        )

        # Small meta record (for future report listings)
        meta = {
            "cache_key": cache_key,
            "report_url": report_url,
            "skill_name": result.get("skill_name") or result.get("skill_path", ""),
            "model": result.get("model", ""),
            "verdict": result.get("verdict", ""),
            "timestamp": result.get("started_at") or result.get("finished_at", ""),
        }
        client.put_object(
            Bucket=bucket,
            Key=f"reports/{cache_key}_meta.json",
            Body=json.dumps(meta).encode(),
            ContentType="application/json",
        )

        logger.info("Report written to R2: %s", report_url)
        return report_url

    except Exception as e:
        logger.warning("R2 write failed (non-fatal): %s", e)
        return None


def write_html_report(cache_key: str, html: str) -> str | None:
    """
    Write a rendered HTML report to R2. Returns the public HTML URL, or None
    if R2 is not configured or the write fails.
    """
    client = _client()
    if client is None:
        return None

    bucket = _bucket()
    html_url = f"{_REPORT_BASE_URL}/report/{cache_key}.html"

    try:
        client.put_object(
            Bucket=bucket,
            Key=f"reports/{cache_key}.html",
            Body=html.encode(),
            ContentType="text/html",
        )
        logger.info("HTML report written to R2: %s", html_url)
        return html_url
    except Exception as e:
        logger.warning("R2 HTML write failed (non-fatal): %s", e)
        return None


def read_report(cache_key: str) -> dict[str, Any] | None:
    """
    Fetch a report from R2 by cache key. Returns None if not found or
    R2 is not configured. Used by serve.py for cache-hit on startup.
    """
    client = _client()
    if client is None:
        return None

    bucket = _bucket()
    try:
        resp = client.get_object(Bucket=bucket, Key=f"reports/{cache_key}.json")
        data: dict[str, Any] = json.loads(resp["Body"].read())
        return data
    except client.exceptions.NoSuchKey:  # type: ignore[union-attr]
        return None
    except Exception as e:
        logger.warning("R2 read failed (non-fatal): %s", e)
        return None
