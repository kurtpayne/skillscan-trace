# skillscan-trace Docker image
#
# Supports two modes:
#
#   Single trace (default):
#     docker run --rm \
#       -e OPENAI_API_KEY=$OPENAI_API_KEY \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       skillscan/trace run /skill.md
#
#   Self-hosted server:
#     docker run -p 8080:8080 \
#       skillscan/trace serve
#
#   OpenRouter:
#     docker run --rm \
#       -e OPENROUTER_API_KEY=$OPENROUTER_API_KEY \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       skillscan/trace run /skill.md --provider openrouter
#
#   Ollama (fully local, no API key):
#     docker run --rm \
#       --network host \
#       -v $(pwd)/my-skill.md:/skill.md:ro \
#       skillscan/trace run /skill.md --provider ollama

FROM python:3.11-slim

# Security: run as non-root
RUN groupadd --gid 1001 skillscan && \
    useradd --uid 1001 --gid skillscan --shell /bin/bash --create-home skillscan

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY skillscan_trace/ ./skillscan_trace/

# Install with serve extras
RUN pip install --no-cache-dir ".[serve]"

# Create directories with correct ownership
RUN mkdir -p /trace-output /trace-cache && \
    chown -R skillscan:skillscan /app /trace-output /trace-cache

USER skillscan

# Default output and cache directories
VOLUME ["/trace-output", "/trace-cache"]

# Health check for serve mode
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/v1/health || exit 1

# Default: show help. Override with `run /skill.md` or `serve`
ENTRYPOINT ["skillscan-trace"]
CMD ["--help"]
