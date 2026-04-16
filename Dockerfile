# syntax=docker/dockerfile:1.7
#
# skillscan-trace Docker image
#
# Multi-mode: the same image supports both `run` (single trace) and `serve`
# (FastAPI HTTP API). Used for the Fly.io hosted service at trace.skillscan.sh
# AND for enterprise self-hosted deployments.
#
# Supports two modes:
#
#   Single trace (default):
#     docker run --rm \
#       -e OPENAI_API_KEY=$OPENAI_API_KEY \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       kurtpayne/skillscan-trace run /skill.md
#
#   Self-hosted server:
#     docker run -p 8080:8080 \
#       kurtpayne/skillscan-trace serve
#
#   OpenRouter:
#     docker run --rm \
#       -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       kurtpayne/skillscan-trace run /skill.md --provider openrouter
#
#   Ollama (fully local, no API key):
#     docker run --rm \
#       --network host \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       kurtpayne/skillscan-trace run /skill.md --provider ollama

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Install build dependencies needed to compile any sdists
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source, then install into a dedicated prefix that
# we can copy wholesale into the runtime stage. Includes scanner + linter so
# the trace report can emit integrated static-analysis findings.
COPY pyproject.toml README.md ./
COPY skillscan_trace ./skillscan_trace
RUN pip install --prefix=/install ".[serve]" \
        skillscan-security \
        skillscan-lint

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

# OCI image labels
LABEL org.opencontainers.image.title="skillscan-trace"
LABEL org.opencontainers.image.description="Behavioral execution engine for MCP-based AI agent skills"
LABEL org.opencontainers.image.source="https://github.com/kurtpayne/skillscan-trace"
LABEL org.opencontainers.image.url="https://trace.skillscan.sh"
LABEL org.opencontainers.image.documentation="https://github.com/kurtpayne/skillscan-trace#readme"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="SkillScan"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Runtime system dependencies: curl for HEALTHCHECK, git for optional git-based
# skill paths
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Security: run as non-root
RUN groupadd --gid 1001 skillscan && \
    useradd --uid 1001 --gid skillscan --shell /bin/bash --create-home skillscan && \
    mkdir -p /app /data /trace-output /trace-cache && \
    chown -R skillscan:skillscan /app /data /trace-output /trace-cache

# Copy the installed Python packages and console scripts from the builder stage
COPY --from=builder /install /usr/local

USER skillscan
WORKDIR /data

# Volumes for persistent trace data (serve mode)
VOLUME ["/trace-output", "/trace-cache"]

EXPOSE 8080

# Health check for serve mode (harmless when running `run` — will just fail)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

# Default: show help. Override with `run /data/skill.md` or `serve`.
ENTRYPOINT ["skillscan-trace"]
CMD ["--help"]
